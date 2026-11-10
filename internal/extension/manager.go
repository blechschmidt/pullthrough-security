package extension

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Manager loads and owns the configured extension modules and is the entry point
// the proxy wires as a late-stage admission gate. It evaluates the modules
// selected for a tenant, in configured order, and combines their verdicts. It
// supports hot-reload: Reload recompiles the modules from disk and swaps them in
// without dropping in-flight evaluations.
type Manager struct {
	cfg Config

	mu sync.RWMutex
	// modules is the ordered module set; order is the per-tenant evaluation order.
	modules []*Module
}

// NewManager constructs a Manager and compiles every configured module. It
// returns ErrDisabled (and a nil manager) when the config is disabled, so the
// wiring layer can cleanly skip it. A module that fails to compile does not fail
// construction — it is loaded in a not-loaded state and reported through the
// snapshot — so one bad module never prevents startup. Construction fails only on
// an invalid config (duplicate/empty names, no source).
func NewManager(ctx context.Context, cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return nil, ErrDisabled
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	m := &Manager{cfg: cfg}
	for _, mc := range cfg.Modules {
		mod, err := newModule(ctx, mc, cfg.effectiveLimits(mc))
		if err != nil {
			// Only a structurally invalid module config reaches here; clean up and fail.
			m.Close(ctx)
			return nil, fmt.Errorf("extension: module %q: %w", mc.Name, err)
		}
		m.modules = append(m.modules, mod)
	}
	return m, nil
}

// Enabled reports whether the manager is active and has at least one module
// configured.
func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Enabled && len(m.modules) > 0
}

// modulesFor returns the modules selected for a tenant, in evaluation order.
func (m *Manager) modulesFor(tenant string) []*Module {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Module, 0, len(m.modules))
	for _, mod := range m.modules {
		if mod.cfg.appliesTo(tenant) {
			out = append(out, mod)
		}
	}
	return out
}

// Evaluate runs every module selected for the input's tenant and returns the
// combined Result. It marshals the host input once and invokes each module on the
// same bytes. With no modules selected it returns an allow Result. Evaluate never
// returns an error: a marshal failure (which would indicate a host bug, not
// module input) yields an allow Result and is the caller's signal to log.
func (m *Manager) Evaluate(ctx context.Context, in HostInput) Result {
	tenant := in.Signals.Tenant
	mods := m.modulesFor(tenant)
	if len(mods) == 0 {
		return Result{Decision: DecisionAllow}
	}
	results := make([]ModuleResult, 0, len(mods))
	for _, mod := range mods {
		input, err := MarshalHostInput(mod.cfg.Name, in)
		if err != nil {
			// Treat a host-side marshal failure as a module error so the fail policy
			// still governs the outcome rather than silently admitting.
			res := ModuleResult{Module: mod.cfg.Name, Outcome: OutcomeError, Err: err, FailClosed: mod.cfg.FailClosed}
			res.Decision = mod.resolveTerminal()
			mod.metrics.record(res)
			results = append(results, res)
			continue
		}
		results = append(results, mod.Invoke(ctx, input))
	}
	return combine(results)
}

// Reload recompiles every module from its source and swaps the working sandboxes
// in. A module is kept online if its rebuild fails (keepOnError), so a bad new
// build never takes a previously-working gate offline; the failure is recorded in
// the module's snapshot. It returns the first reload error encountered (for
// surfacing to the operator) but always attempts every module.
func (m *Manager) Reload(ctx context.Context) error {
	m.mu.RLock()
	all := make([]*Module, len(m.modules))
	copy(all, m.modules)
	m.mu.RUnlock()

	var firstErr error
	for _, mod := range all {
		if err := mod.reload(ctx, true); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("extension: reload %q: %w", mod.cfg.Name, err)
		}
	}
	return firstErr
}

// Snapshot returns the manager and per-module state for the admin API.
func (m *Manager) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{Enabled: false, ABIVersion: ABIVersion}
	}
	m.mu.RLock()
	mods := make([]*Module, len(m.modules))
	copy(mods, m.modules)
	enabled := m.cfg.Enabled
	m.mu.RUnlock()

	out := Snapshot{Enabled: enabled, ABIVersion: ABIVersion, Modules: make([]ModuleSnapshot, 0, len(mods))}
	for _, mod := range mods {
		out.Modules = append(out.Modules, mod.snapshot())
	}
	return out
}

// MetricSamples projects the per-module counters as flat, labeled samples for the
// Prometheus bridge. Every series is labeled by module so each gate is its own
// time series; verdicts are additionally labeled by decision.
func (m *Manager) MetricSamples() []MetricSample {
	snap := m.Snapshot()
	out := make([]MetricSample, 0, len(snap.Modules)*8)
	for _, mod := range snap.Modules {
		lbl := func(extra map[string]string) map[string]string {
			l := map[string]string{"module": mod.Name}
			for k, v := range extra {
				l[k] = v
			}
			return l
		}
		out = append(out,
			MetricSample{Name: "pullthrough_extension_invocations_total", Help: "Extension module invocations.", Kind: "counter", Labels: lbl(nil), Value: float64(mod.Invocations)},
			MetricSample{Name: "pullthrough_extension_timeouts_total", Help: "Extension module CPU/time-budget timeouts.", Kind: "counter", Labels: lbl(nil), Value: float64(mod.Timeouts)},
			MetricSample{Name: "pullthrough_extension_fuel_exhausted_total", Help: "Extension module fuel-budget exhaustions.", Kind: "counter", Labels: lbl(nil), Value: float64(mod.FuelExhausted)},
			MetricSample{Name: "pullthrough_extension_errors_total", Help: "Extension module evaluation errors (traps, ABI violations, bad verdicts).", Kind: "counter", Labels: lbl(nil), Value: float64(mod.Errors)},
			MetricSample{Name: "pullthrough_extension_loaded", Help: "Whether the extension module compiled and verified its ABI (1) or not (0).", Kind: "gauge", Labels: lbl(nil), Value: b2f(mod.Loaded)},
			MetricSample{Name: "pullthrough_extension_last_duration_microseconds", Help: "Most recent extension invocation wall-clock time.", Kind: "gauge", Labels: lbl(nil), Value: float64(mod.LastDurationMicros)},
			MetricSample{Name: "pullthrough_extension_verdicts_total", Help: "Extension module verdicts by decision.", Kind: "counter", Labels: lbl(map[string]string{"decision": "allow"}), Value: float64(mod.Allow)},
			MetricSample{Name: "pullthrough_extension_verdicts_total", Help: "Extension module verdicts by decision.", Kind: "counter", Labels: lbl(map[string]string{"decision": "warn"}), Value: float64(mod.Warn)},
			MetricSample{Name: "pullthrough_extension_verdicts_total", Help: "Extension module verdicts by decision.", Kind: "counter", Labels: lbl(map[string]string{"decision": "block"}), Value: float64(mod.Block)},
		)
	}
	// Stable ordering so the exposition is deterministic.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Labels["module"]+out[i].Labels["decision"] < out[j].Labels["module"]+out[j].Labels["decision"]
	})
	return out
}

// Close releases every module's sandbox. The manager is unusable afterward.
func (m *Manager) Close(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	mods := m.modules
	m.modules = nil
	m.mu.Unlock()
	for _, mod := range mods {
		mod.close(ctx)
	}
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
