package rebuildverify

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Mode selects whether a confirmed reproducible-build mismatch influences
// serving.
type Mode string

const (
	// ModeObserve records the verdict and feeds it to the policy/risk engines and
	// the findings layer but never blocks a pull. This is the default.
	ModeObserve Mode = "observe"
	// ModeEnforce additionally quarantines an artifact on a confirmed mismatch
	// (composing with the break-glass workflow).
	ModeEnforce Mode = "enforce"
)

// Enforces reports whether the mode quarantines on a confirmed mismatch.
func (m Mode) Enforces() bool { return m == ModeEnforce }

// ParseMode normalizes a string into a Mode, returning ok=false for an
// unrecognized value.
func ParseMode(s string) (Mode, bool) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeObserve:
		return ModeObserve, true
	case ModeEnforce:
		return ModeEnforce, true
	case "":
		return ModeObserve, true
	default:
		return "", false
	}
}

// TenantConfig overrides the mode for a single tenant.
type TenantConfig struct {
	// Mode overrides the global mode (observe|enforce) for this tenant.
	Mode Mode
}

const (
	defaultMaxConcurrent = 2
	defaultBuildTimeout  = 10 * time.Minute
	defaultCacheSize     = 4096
	defaultRecentSize    = 100
)

// Config configures the reproducible-build verification gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// Mode is the global enforcement mode (observe|enforce). Default observe.
	Mode Mode
	// Async runs verification in a bounded background goroutine (non-blocking).
	// The wiring layer enables this by default; tests set it explicitly.
	Async bool
	// MaxConcurrent bounds in-flight background rebuilds (default 2). Rebuilds are
	// expensive, so this caps the subsystem's footprint independent of request
	// volume.
	MaxConcurrent int
	// BuildTimeout bounds a single background rebuild (default 10m).
	BuildTimeout time.Duration
	// CacheSize bounds the per-(coordinate,digest) result cache (default 4096).
	CacheSize int
	// RecentSize bounds the recent-result ring shown in the admin surface
	// (default 100).
	RecentSize int
	// Tenants holds per-tenant mode overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig

	// Registry supplies the pluggable builders; nil substitutes the built-in
	// toolchain-gated stub builders.
	Registry *Registry
	// Locator resolves a source-repository URL to a local clone (air-gap aware);
	// nil disables on-demand location (the caller must supply Source.RepoDir).
	Locator RepoLocator
	// Limiter optionally bounds background rebuild admission; nil disables it.
	Limiter Limiter
	// OnResult, when set, is invoked with every terminal Result (including
	// async-completed ones) so the wiring can emit notifications / audit entries.
	OnResult func(Result)
	// Now is an injectable clock for tests; nil substitutes time.Now.
	Now func() time.Time
	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

// DefaultConfig returns the built-in defaults: enabled, observe-only, async.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		Mode:          ModeObserve,
		Async:         true,
		MaxConcurrent: defaultMaxConcurrent,
		BuildTimeout:  defaultBuildTimeout,
		CacheSize:     defaultCacheSize,
		RecentSize:    defaultRecentSize,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults.
func (c Config) withDefaults() Config {
	if c.Mode == "" {
		c.Mode = ModeObserve
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = defaultMaxConcurrent
	}
	if c.BuildTimeout <= 0 {
		c.BuildTimeout = defaultBuildTimeout
	}
	if c.CacheSize <= 0 {
		c.CacheSize = defaultCacheSize
	}
	if c.RecentSize <= 0 {
		c.RecentSize = defaultRecentSize
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if _, ok := ParseMode(string(c.Mode)); !ok {
		return fmt.Errorf("rebuildverify: invalid mode %q (want observe|enforce)", c.Mode)
	}
	for tenant, t := range c.Tenants {
		if t.Mode != "" {
			if _, ok := ParseMode(string(t.Mode)); !ok {
				return fmt.Errorf("rebuildverify: tenants[%q] invalid mode %q", tenant, t.Mode)
			}
		}
	}
	return nil
}
