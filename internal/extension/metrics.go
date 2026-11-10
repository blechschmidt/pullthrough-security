package extension

import "sync/atomic"

// moduleMetrics accumulates the per-module telemetry the task requires:
// invocations, verdicts by decision, timeouts, fuel exhaustion, and other
// errors. All fields are updated with atomics so recording never contends with
// the request path's locks.
type moduleMetrics struct {
	invocations   atomic.Int64
	allow         atomic.Int64
	warn          atomic.Int64
	block         atomic.Int64
	timeouts      atomic.Int64
	fuelExhausted atomic.Int64
	errors        atomic.Int64
	// failOpen / failClosed count terminal outcomes resolved by the module's
	// fail policy, so an operator can see how often the policy actually fired.
	failOpenResolved   atomic.Int64
	failClosedResolved atomic.Int64
	// lastDurationMicros is the most recent invocation's wall-clock time.
	lastDurationMicros  atomic.Int64
	totalDurationMicros atomic.Int64
}

// record folds one module result into the counters.
func (m *moduleMetrics) record(r ModuleResult) {
	m.invocations.Add(1)
	m.lastDurationMicros.Store(r.DurationMicros)
	m.totalDurationMicros.Add(r.DurationMicros)
	switch r.Outcome {
	case OutcomeAllow:
		m.allow.Add(1)
	case OutcomeWarn:
		m.warn.Add(1)
	case OutcomeBlock:
		m.block.Add(1)
	case OutcomeTimeout:
		m.timeouts.Add(1)
	case OutcomeFuel:
		m.fuelExhausted.Add(1)
	case OutcomeError:
		m.errors.Add(1)
	}
	if r.Outcome.terminal() {
		if r.FailClosed {
			m.failClosedResolved.Add(1)
		} else {
			m.failOpenResolved.Add(1)
		}
	}
}

// ModuleSnapshot is the immutable view of one module's configuration and
// cumulative metrics, for the admin API and the Prometheus bridge.
type ModuleSnapshot struct {
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Tenants     []string `json:"tenants,omitempty"`
	FailClosed  bool     `json:"failClosed"`
	TimeoutMs   int64    `json:"timeoutMs"`
	MemoryBytes int64    `json:"memoryBytes"`
	Fuel        int64    `json:"fuel"`
	// Loaded reports whether the module compiled and verified its ABI. A module
	// that failed to load is reported with Loaded=false and LoadError set, and is
	// skipped at evaluation time (treated per its fail policy).
	Loaded    bool   `json:"loaded"`
	LoadError string `json:"loadError,omitempty"`

	Invocations   int64 `json:"invocations"`
	Allow         int64 `json:"allow"`
	Warn          int64 `json:"warn"`
	Block         int64 `json:"block"`
	Timeouts      int64 `json:"timeouts"`
	FuelExhausted int64 `json:"fuelExhausted"`
	Errors        int64 `json:"errors"`

	FailOpenResolved   int64 `json:"failOpenResolved"`
	FailClosedResolved int64 `json:"failClosedResolved"`

	LastDurationMicros int64 `json:"lastDurationMicros"`
	AvgDurationMicros  int64 `json:"avgDurationMicros"`
}

// Snapshot is the manager-level view for the admin API and metrics.
type Snapshot struct {
	Enabled    bool             `json:"enabled"`
	ABIVersion int              `json:"abiVersion"`
	Modules    []ModuleSnapshot `json:"modules"`
}

// snapshot builds a ModuleSnapshot from the live counters.
func (mod *Module) snapshot() ModuleSnapshot {
	m := &mod.metrics
	inv := m.invocations.Load()
	avg := int64(0)
	if inv > 0 {
		avg = m.totalDurationMicros.Load() / inv
	}
	tenants := mod.cfg.Tenants
	loadErr := ""
	mod.mu.RLock()
	loaded := mod.sb != nil
	if mod.loadErr != nil {
		loadErr = mod.loadErr.Error()
	}
	mod.mu.RUnlock()
	return ModuleSnapshot{
		Name:               mod.cfg.Name,
		Path:               mod.cfg.Path,
		Tenants:            tenants,
		FailClosed:         mod.cfg.FailClosed,
		TimeoutMs:          mod.limits.Timeout.Milliseconds(),
		MemoryBytes:        mod.limits.MemoryBytes,
		Fuel:               mod.limits.Fuel,
		Loaded:             loaded,
		LoadError:          loadErr,
		Invocations:        inv,
		Allow:              m.allow.Load(),
		Warn:               m.warn.Load(),
		Block:              m.block.Load(),
		Timeouts:           m.timeouts.Load(),
		FuelExhausted:      m.fuelExhausted.Load(),
		Errors:             m.errors.Load(),
		FailOpenResolved:   m.failOpenResolved.Load(),
		FailClosedResolved: m.failClosedResolved.Load(),
		LastDurationMicros: m.lastDurationMicros.Load(),
		AvgDurationMicros:  avg,
	}
}

// MetricSample is one labeled metric value for the Prometheus bridge. Kind is
// "counter" or "gauge"; Labels are keyed by label name.
type MetricSample struct {
	Name   string
	Help   string
	Kind   string
	Labels map[string]string
	Value  float64
}
