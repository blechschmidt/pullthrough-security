package extension

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Module is a loaded, ready-to-invoke extension gate: an immutable configuration
// plus a compiled wasm sandbox and live metrics. A Module is safe for concurrent
// Invoke; Reload swaps the sandbox atomically under a write lock.
type Module struct {
	cfg    ModuleConfig
	limits Limits

	mu sync.RWMutex
	// sb is the compiled sandbox; nil when the module failed to load (it is then
	// skipped at evaluation and resolved per its fail policy).
	sb *sandbox
	// loadErr records why the module failed to (re)load, surfaced in the snapshot.
	loadErr error
	// wasm is the binary the module was last loaded from, retained so a failed
	// reload can be distinguished and the source is known.
	wasm []byte

	metrics moduleMetrics
}

// newModule compiles a module from its config. A compile/ABI failure is NOT
// fatal: the module is returned in a not-loaded state with loadErr set, so one
// bad module never prevents the rest of the fleet (and the proxy) from starting.
// A genuinely invalid config (no source) is returned as an error.
func newModule(ctx context.Context, cfg ModuleConfig, limits Limits) (*Module, error) {
	m := &Module{cfg: cfg, limits: limits}
	wasm, err := loadWASM(cfg)
	if err != nil {
		m.loadErr = err
		return m, nil
	}
	m.wasm = wasm
	sb, err := newSandbox(ctx, wasm, limits)
	if err != nil {
		m.loadErr = err
		return m, nil
	}
	m.sb = sb
	return m, nil
}

// loadWASM resolves the module binary from inline bytes or the configured path.
func loadWASM(cfg ModuleConfig) ([]byte, error) {
	if len(cfg.WASM) > 0 {
		return cfg.WASM, nil
	}
	if cfg.Path == "" {
		return nil, errors.New("module has neither inline wasm nor a path")
	}
	b, err := os.ReadFile(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("read module %q: %w", cfg.Path, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("module file %q is empty", cfg.Path)
	}
	return b, nil
}

// loaded reports whether the module compiled successfully and can be invoked.
func (mod *Module) loaded() bool {
	mod.mu.RLock()
	defer mod.mu.RUnlock()
	return mod.sb != nil
}

// Invoke runs the module against the marshaled host input and returns a fully
// resolved ModuleResult: a completed invocation carries the module's verdict; a
// terminal outcome (timeout/fuel/error, or a not-loaded module) is resolved to
// block or allow per the module's fail-closed policy. Invoke never returns an
// error — every failure mode is captured in the result so the caller's combine
// step is total.
func (mod *Module) Invoke(ctx context.Context, input []byte) ModuleResult {
	start := time.Now()
	mod.mu.RLock()
	sb := mod.sb
	loadErr := mod.loadErr
	mod.mu.RUnlock()

	res := ModuleResult{Module: mod.cfg.Name, FailClosed: mod.cfg.FailClosed}

	if sb == nil {
		// Never loaded (or failed to compile): resolve per fail policy.
		res.Outcome = OutcomeError
		res.Err = loadErrOr(loadErr)
		res.Decision = mod.resolveTerminal()
		res.DurationMicros = micros(time.Since(start))
		mod.metrics.record(res)
		return res
	}

	verdict, outcome, err := sb.invoke(ctx, input)
	res.Outcome = outcome
	res.Err = err
	res.DurationMicros = micros(time.Since(start))
	if outcome.terminal() {
		res.Decision = mod.resolveTerminal()
	} else {
		v := verdict
		res.Verdict = &v
		res.Decision = verdict.Decision
	}
	mod.metrics.record(res)
	return res
}

// resolveTerminal maps a terminal outcome to a decision per the fail policy:
// fail-closed blocks, fail-open allows (skips).
func (mod *Module) resolveTerminal() Decision {
	if mod.cfg.FailClosed {
		return DecisionBlock
	}
	return DecisionAllow
}

// reload recompiles the module from its source (re-reading the file path when
// set) and atomically swaps the sandbox. On failure the previous sandbox is kept
// when keepOnError is true (a hot-reload should not take a working module offline
// because a new build is briefly bad); otherwise the module is marked not-loaded.
func (mod *Module) reload(ctx context.Context, keepOnError bool) error {
	wasm, err := loadWASM(mod.cfg)
	if err == nil {
		var sb *sandbox
		sb, err = newSandbox(ctx, wasm, mod.limits)
		if err == nil {
			mod.mu.Lock()
			old := mod.sb
			mod.sb = sb
			mod.wasm = wasm
			mod.loadErr = nil
			mod.mu.Unlock()
			if old != nil {
				_ = old.close(ctx)
			}
			return nil
		}
	}
	// Reload failed.
	mod.mu.Lock()
	mod.loadErr = err
	if !keepOnError {
		old := mod.sb
		mod.sb = nil
		mod.mu.Unlock()
		if old != nil {
			_ = old.close(ctx)
		}
	} else {
		mod.mu.Unlock()
	}
	return err
}

// close releases the module's sandbox.
func (mod *Module) close(ctx context.Context) {
	mod.mu.Lock()
	sb := mod.sb
	mod.sb = nil
	mod.mu.Unlock()
	if sb != nil {
		_ = sb.close(ctx)
	}
}

func loadErrOr(err error) error {
	if err != nil {
		return err
	}
	return errors.New("module not loaded")
}

func micros(d time.Duration) int64 { return d.Microseconds() }
