package extension

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Default resource bounds. They are deliberately generous enough for a
// language-runtime-backed module (a Go- or Rust-compiled gate) to initialize and
// run a typical metadata check, while still containing a runaway module. An
// operator tunes them per module for tighter or looser envelopes.
const (
	// DefaultTimeout bounds the wall-clock CPU time of a single invocation.
	DefaultTimeout = 250 * time.Millisecond
	// DefaultMemoryBytes caps a module's linear memory. 64 MiB accommodates a
	// garbage-collected language runtime's baseline footprint; a no_std/Rust
	// module needs far less and can be configured down.
	DefaultMemoryBytes = 64 << 20
	// DefaultMaxOutputBytes caps the verdict bytes the host reads back from a
	// module before JSON parsing, independent of the finer per-field ABI bounds.
	DefaultMaxOutputBytes = 64 << 10
	// wasmPageBytes is the WebAssembly linear-memory page size (64 KiB).
	wasmPageBytes = 64 << 10
	// maxMemoryPages is the wasm32 hard ceiling (4 GiB). A configured limit is
	// clamped to it.
	maxMemoryPages = 1 << 16
)

// Limits is the per-module resource envelope enforced on every invocation.
type Limits struct {
	// Timeout is the wall-clock CPU/time budget for one invocation. The runtime
	// closes a module that exceeds it (classified as OutcomeTimeout). Zero uses
	// DefaultTimeout.
	Timeout time.Duration
	// MemoryBytes caps the module's linear memory. It is rounded up to a whole
	// number of 64 KiB pages. Zero uses DefaultMemoryBytes.
	MemoryBytes int64
	// Fuel is an optional instruction-approximating budget: the maximum number of
	// wasm function calls one invocation may make before it is aborted
	// (OutcomeFuel). It bounds deep recursion and call-count explosions
	// deterministically, independent of wall-clock time. Zero disables fuel
	// metering (the time and memory bounds still apply), which is the default
	// because metering adds per-call overhead.
	Fuel int64
	// MaxOutputBytes caps the verdict bytes read back from a module. Zero uses
	// DefaultMaxOutputBytes.
	MaxOutputBytes int
}

// withDefaults returns a copy of l with zero fields filled from the built-in
// defaults and memory/output clamped to safe ranges.
func (l Limits) withDefaults() Limits {
	if l.Timeout <= 0 {
		l.Timeout = DefaultTimeout
	}
	if l.MemoryBytes <= 0 {
		l.MemoryBytes = DefaultMemoryBytes
	}
	if l.MaxOutputBytes <= 0 {
		l.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if l.Fuel < 0 {
		l.Fuel = 0
	}
	return l
}

// memoryPages returns the linear-memory cap in whole 64 KiB pages, clamped to the
// wasm32 ceiling.
func (l Limits) memoryPages() uint32 {
	pages := (l.MemoryBytes + wasmPageBytes - 1) / wasmPageBytes
	if pages < 1 {
		pages = 1
	}
	if pages > maxMemoryPages {
		pages = maxMemoryPages
	}
	return uint32(pages)
}

// ModuleConfig describes one operator-supplied extension module.
type ModuleConfig struct {
	// Name is the stable logical identifier for the module, used in metrics
	// labels, audit detail, the admin surface, and per-tenant selection. Required
	// and unique within a Config.
	Name string
	// Path is the filesystem path to the module's .wasm binary. Exactly one of
	// Path or WASM must be set; Path is the usual production form and is what
	// hot-reload re-reads.
	Path string
	// WASM is the module binary supplied inline (for tests or embedded modules).
	// When set, Path is ignored for the initial load (but Path, if also set, is
	// what Reload re-reads).
	WASM []byte
	// Tenants restricts the module to the listed tenant ids (team names). An empty
	// list applies the module to every tenant — the default. This is the
	// per-tenant module-selection control.
	Tenants []string
	// FailClosed selects the policy for a terminal outcome (timeout, fuel
	// exhaustion, trap, or a malformed verdict): when true the artifact is blocked
	// ("fail closed" — safety over availability); when false (the default) the
	// module is skipped and the artifact proceeds ("fail open" — availability over
	// safety), matching the project's other gates whose failure modes default to
	// open.
	FailClosed bool
	// Limits is the resource envelope for the module. Zero fields inherit the
	// Config-level Defaults, then the built-in defaults.
	Limits Limits
}

// appliesTo reports whether the module is selected for the given tenant.
func (m ModuleConfig) appliesTo(tenant string) bool {
	if len(m.Tenants) == 0 {
		return true
	}
	for _, t := range m.Tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// Config configures the extension subsystem.
type Config struct {
	// Enabled gates whether the manager is constructed and wired as a gate.
	Enabled bool
	// Defaults supplies the limit defaults applied to a module whose own Limits
	// leave a field zero. Zero fields here fall through to the built-in defaults.
	Defaults Limits
	// Modules is the ordered set of extension modules. Order is the evaluation
	// order within a tenant.
	Modules []ModuleConfig
}

// effectiveLimits resolves a module's limits by layering the module's own Limits
// over the Config-level Defaults over the built-in defaults.
func (c Config) effectiveLimits(m ModuleConfig) Limits {
	merged := m.Limits
	if merged.Timeout <= 0 {
		merged.Timeout = c.Defaults.Timeout
	}
	if merged.MemoryBytes <= 0 {
		merged.MemoryBytes = c.Defaults.MemoryBytes
	}
	if merged.Fuel == 0 {
		merged.Fuel = c.Defaults.Fuel
	}
	if merged.MaxOutputBytes <= 0 {
		merged.MaxOutputBytes = c.Defaults.MaxOutputBytes
	}
	return merged.withDefaults()
}

// validate checks the config for self-consistency before any module is compiled.
func (c Config) validate() error {
	seen := make(map[string]struct{}, len(c.Modules))
	for i, m := range c.Modules {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			return fmt.Errorf("extension: module %d has an empty name", i)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("extension: duplicate module name %q", name)
		}
		seen[name] = struct{}{}
		if m.Path == "" && len(m.WASM) == 0 {
			return fmt.Errorf("extension: module %q has neither a path nor inline wasm", name)
		}
	}
	return nil
}

// ErrDisabled is returned by NewManager when the config is disabled, so the
// caller can distinguish "off" from a real construction error.
var ErrDisabled = errors.New("extension: disabled")
