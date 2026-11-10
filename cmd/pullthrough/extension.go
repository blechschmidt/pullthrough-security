package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/extension"
)

// buildExtension constructs the sandboxed WASM extensibility manager (Task 59)
// when enabled and at least one module is configured. It translates the YAML
// module list and resource limits into the engine config, applying built-in
// defaults for any unset bound. A module that fails to compile does not fail
// startup — it loads in a not-loaded state and is reported through the admin
// surface and metrics — so one bad module never takes the proxy down. It returns
// nil when disabled or no modules are configured, in which case no extension gate
// runs.
func buildExtension(cfg *config.Config, logger *slog.Logger) (*extension.Manager, error) {
	ec := cfg.Extensions
	if !ec.Enabled || len(ec.Modules) == 0 {
		logger.Info("wasm extension gates disabled (configure extensions.modules to enable custom admission gates)")
		return nil, nil
	}

	xc := extension.Config{Enabled: true, Defaults: extLimits(ec.Defaults)}
	for _, m := range ec.Modules {
		xc.Modules = append(xc.Modules, extension.ModuleConfig{
			Name:       m.Name,
			Path:       m.Path,
			Tenants:    m.Tenants,
			FailClosed: m.FailClosed,
			Limits:     extLimits(m.Limits),
		})
	}

	mgr, err := extension.NewManager(context.Background(), xc)
	if err != nil {
		return nil, fmt.Errorf("wasm extensions: %w", err)
	}

	// Surface load outcomes: a module that failed to compile is reported but does
	// not abort startup (it is resolved per its fail policy at request time).
	snap := mgr.Snapshot()
	loaded := 0
	for _, m := range snap.Modules {
		if m.Loaded {
			loaded++
			continue
		}
		logger.Warn("wasm extension module failed to load; it will be resolved per its fail policy",
			"module", m.Name, "path", m.Path, "failClosed", m.FailClosed, "error", m.LoadError)
	}
	logger.Info("wasm extension gates enabled",
		"modules", len(snap.Modules), "loaded", loaded, "abiVersion", snap.ABIVersion)
	return mgr, nil
}

// extLimits translates the YAML limit block into the engine's Limits, leaving a
// zero field for the engine to fill from its built-in default.
func extLimits(l config.ExtensionLimits) extension.Limits {
	return extension.Limits{
		Timeout:        time.Duration(l.TimeoutMs) * time.Millisecond,
		MemoryBytes:    l.MemoryBytes,
		Fuel:           l.Fuel,
		MaxOutputBytes: l.MaxOutputBytes,
	}
}
