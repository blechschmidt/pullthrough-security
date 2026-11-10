package avscan

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Action is the gate's response to a positive malware detection.
type Action string

const (
	// ActionAnnotate records the detection (finding, admission signal, advisory
	// headers) but still serves the artifact — observe mode.
	ActionAnnotate Action = "annotate"
	// ActionQuarantine refuses the artifact (403) and evicts it from the cache so
	// an infected payload is neither served nor retained. This is the default.
	ActionQuarantine Action = "quarantine"
	// ActionBlock refuses the artifact (403) but leaves the cached bytes in place
	// for forensic review (no eviction).
	ActionBlock Action = "block"
)

// Refuses reports whether the action prevents the artifact from being served.
func (a Action) Refuses() bool { return a == ActionQuarantine || a == ActionBlock }

// Evicts reports whether the action removes the artifact from the cache.
func (a Action) Evicts() bool { return a == ActionQuarantine }

// Engine identifiers.
const (
	// EngineClamAV selects the built-in clamd INSTREAM client.
	EngineClamAV = "clamav"
)

// Default scan bounds and timeout.
const (
	defaultMaxScanBytes int64         = 128 << 20 // 128 MiB streamed per artifact
	defaultTimeout      time.Duration = 60 * time.Second
)

// Config configures the antivirus content-scanning gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// Engine selects the scanning backend. Only "clamav" (clamd INSTREAM) is
	// built in; an alternative Engine may be supplied via EngineImpl. Default
	// "clamav".
	Engine string
	// Address is the clamd endpoint: a "host:port" or "tcp://host:port" TCP
	// socket, or a "unix:///path" / filesystem-path UNIX socket. Required unless
	// EngineImpl is injected.
	Address string
	// Action is applied on a positive detection: "annotate" (serve + record),
	// "quarantine" (refuse + evict) or "block" (refuse, keep cached). Default
	// "quarantine".
	Action Action
	// MaxScanBytes bounds the bytes streamed to the engine per artifact (0 =>
	// default 128 MiB). A larger artifact is scanned up to the bound and flagged
	// truncated.
	MaxScanBytes int64
	// Timeout bounds a single scan, including connecting to the engine (0 =>
	// default 60s).
	Timeout time.Duration
	// FailOpen controls behaviour when the engine is unreachable or errors: true
	// admits the artifact (graceful degradation), false refuses it (fail-closed).
	// Default true.
	FailOpen bool
	// EngineImpl, when non-nil, overrides the built-in engine (tests and
	// alternative AV backends). When set, Engine/Address are not consulted.
	EngineImpl Engine
	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

// DefaultConfig returns the built-in defaults: off (opt-in), clamav engine,
// quarantine on detection, fail-open on engine-unavailable.
func DefaultConfig() Config {
	return Config{
		Enabled:      false,
		Engine:       EngineClamAV,
		Action:       ActionQuarantine,
		MaxScanBytes: defaultMaxScanBytes,
		Timeout:      defaultTimeout,
		FailOpen:     true,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults. FailOpen is
// intentionally NOT defaulted here (a deliberately-false value must be
// preserved); the config layer establishes the true default.
func (c Config) withDefaults() Config {
	if strings.TrimSpace(c.Engine) == "" {
		c.Engine = EngineClamAV
	}
	c.Engine = strings.ToLower(strings.TrimSpace(c.Engine))
	if c.Action == "" {
		c.Action = ActionQuarantine
	}
	c.Action = Action(strings.ToLower(strings.TrimSpace(string(c.Action))))
	// Only an exact zero takes the default; a negative value is preserved so
	// validate() can reject it.
	if c.MaxScanBytes == 0 {
		c.MaxScanBytes = defaultMaxScanBytes
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	switch c.Action {
	case ActionAnnotate, ActionQuarantine, ActionBlock:
	default:
		return fmt.Errorf("avscan: invalid action %q (want annotate|quarantine|block)", c.Action)
	}
	if c.MaxScanBytes < 0 {
		return fmt.Errorf("avscan: maxScanBytes must not be negative")
	}
	if c.Timeout < 0 {
		return fmt.Errorf("avscan: timeout must not be negative")
	}
	if c.EngineImpl != nil {
		return nil
	}
	switch c.Engine {
	case EngineClamAV:
	default:
		return fmt.Errorf("avscan: unknown engine %q (only %q is built in)", c.Engine, EngineClamAV)
	}
	if strings.TrimSpace(c.Address) == "" {
		return fmt.Errorf("avscan: engine %q requires an address (clamd host:port or unix socket path)", c.Engine)
	}
	return nil
}
