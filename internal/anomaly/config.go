package anomaly

import (
	"fmt"
	"time"
)

// Tunables groups the detector thresholds an operator can adjust. They are the
// part of the configuration a per-tenant override can replace. Zero values are
// filled from the built-in defaults at construction, so a partial override only
// needs to set the fields it cares about — except that an all-zero Tunables
// block is treated as "use defaults" rather than "every threshold is zero".
type Tunables struct {
	// FanoutWarn/FanoutHigh are the distinct-package counts per window at which
	// the fan-out detector warns / treats the scope as fully anomalous.
	FanoutWarn int `json:"fanoutWarn"`
	FanoutHigh int `json:"fanoutHigh"`
	// NewNamespaceWarn/High are the counts of first-ever-seen namespaces per
	// window at which the new-namespace detector warns / saturates.
	NewNamespaceWarn int `json:"newNamespaceWarn"`
	NewNamespaceHigh int `json:"newNamespaceHigh"`
	// OffHoursWarn/High are the request counts per window during off-hours at
	// which the off-hours-burst detector warns / saturates.
	OffHoursWarn int `json:"offHoursWarn"`
	OffHoursHigh int `json:"offHoursHigh"`
	// EnumerationWarn/High are the 404/negative-cache counts per window at which
	// the enumeration detector warns / saturates.
	EnumerationWarn int `json:"enumerationWarn"`
	EnumerationHigh int `json:"enumerationHigh"`
	// EgressZWarn/High are the egress-volume z-score cutoffs (deviations above the
	// scope's rolling baseline) at which the egress detector warns / saturates.
	EgressZWarn float64 `json:"egressZWarn"`
	EgressZHigh float64 `json:"egressZHigh"`
}

func (t Tunables) isZero() bool {
	return t == Tunables{}
}

// DefaultTunables is the built-in, conservative threshold model. The defaults
// are intentionally high enough that ordinary CI traffic stays silent and only
// genuinely unusual behavior crosses the warn line.
func DefaultTunables() Tunables {
	return Tunables{
		FanoutWarn:       40,
		FanoutHigh:       150,
		NewNamespaceWarn: 6,
		NewNamespaceHigh: 25,
		OffHoursWarn:     60,
		OffHoursHigh:     250,
		EnumerationWarn:  25,
		EnumerationHigh:  120,
		EgressZWarn:      3.5,
		EgressZHigh:      7,
	}
}

func (t Tunables) validate() error {
	pairs := []struct {
		name       string
		warn, high float64
	}{
		{"fanout", float64(t.FanoutWarn), float64(t.FanoutHigh)},
		{"newNamespace", float64(t.NewNamespaceWarn), float64(t.NewNamespaceHigh)},
		{"offHours", float64(t.OffHoursWarn), float64(t.OffHoursHigh)},
		{"enumeration", float64(t.EnumerationWarn), float64(t.EnumerationHigh)},
		{"egressZ", t.EgressZWarn, t.EgressZHigh},
	}
	for _, p := range pairs {
		if p.warn <= 0 || p.high <= 0 {
			return fmt.Errorf("%s thresholds must be positive (warn=%g high=%g)", p.name, p.warn, p.high)
		}
		if p.warn >= p.high {
			return fmt.Errorf("%s warn threshold (%g) must be below the high threshold (%g)", p.name, p.warn, p.high)
		}
	}
	return nil
}

// TenantOverride replaces parts of the global model for one tenant. A nil
// Tunables inherits the global thresholds; non-empty WarnLevel/BlockLevel
// override the action thresholds independently.
type TenantOverride struct {
	Tunables   *Tunables `json:"tunables,omitempty"`
	WarnLevel  Level     `json:"warnLevel,omitempty"`
	BlockLevel Level     `json:"blockLevel,omitempty"`
}

// Config configures the anomaly engine.
type Config struct {
	// Enabled gates whether the engine observes traffic and exposes its surfaces.
	Enabled bool
	// Window is the trailing duration over which the rolling-window detectors
	// (fan-out, new-namespace, off-hours, enumeration, egress volume) aggregate.
	// Zero substitutes defaultWindow.
	Window time.Duration
	// Tunables is the global detector threshold model. A zero block substitutes
	// DefaultTunables.
	Tunables Tunables

	// WarnLevel is the minimum overall Level at which an assessment emits a graded
	// notification. Empty substitutes defaultWarnLevel (medium).
	WarnLevel Level
	// BlockLevel is the minimum overall Level at which the scope is soft-blocked.
	// Empty or "none" disables soft-blocking entirely (observe + notify only), so
	// the subsystem is non-disruptive by default.
	BlockLevel Level

	// OffHoursStart/OffHoursEnd bound the off-hours interval as hours [0,24) in
	// Location. When Start == End the interval is empty (off-hours detection
	// disabled). When Start > End the interval wraps past midnight (the common
	// case, e.g. 20→6).
	OffHoursStart int
	OffHoursEnd   int
	// Location is the time zone the off-hours boundaries are interpreted in. Nil
	// substitutes time.UTC.
	Location *time.Location

	// LevelMedium/LevelHigh are the overall-score cutoffs (0..100) for the medium
	// and high levels. Zero substitutes the ramp-aligned defaults (50 / 100).
	LevelMedium float64
	LevelHigh   float64

	// EgressBaselineAlpha is the EWMA smoothing factor for the per-scope egress
	// baseline (0,1]. A small value adapts slowly so a burst spikes above the
	// baseline before it is absorbed. Zero substitutes defaultEgressAlpha.
	EgressBaselineAlpha float64
	// EgressWarmup is the number of egress samples a scope must accumulate before
	// its z-score is trusted, so a cold scope cannot alert on its first transfers.
	// Zero substitutes defaultEgressWarmup.
	EgressWarmup int
	// EgressMinVolume is the floor, in bytes of windowed volume, below which the
	// egress detector stays silent regardless of z-score, so a low-traffic scope
	// with a tiny absolute baseline does not alert on noise. Zero substitutes
	// defaultEgressMinVolume.
	EgressMinVolume int64

	// AlertCooldown is the minimum spacing between notifications for one scope at
	// the same (or a lower) level; an escalation to a higher level always alerts.
	// Zero substitutes defaultAlertCooldown.
	AlertCooldown time.Duration
	// HistorySize bounds the retained recent-trigger ring. Zero substitutes
	// defaultHistorySize.
	HistorySize int
	// MaxScopes caps the number of tracked scopes; the least-recently-updated
	// scope is evicted when the cap is exceeded. Zero substitutes defaultMaxScopes.
	MaxScopes int
	// ScopeTTL evicts scopes idle for longer than this on the next observation, so
	// long-dormant identities do not retain state forever. Zero substitutes
	// defaultScopeTTL.
	ScopeTTL time.Duration

	// TenantOverrides keys per-tenant model overrides by tenant id.
	TenantOverrides map[string]TenantOverride

	// Now is an injectable clock for stamping records; nil substitutes time.Now.
	// Detection itself never reads the clock — it uses Observation.Time — so this
	// only affects record timestamps when an observation omits its time.
	Now func() time.Time
}

const (
	defaultWindow          = time.Minute
	defaultWarnLevel       = LevelMedium
	defaultLevelMedium     = 50.0
	defaultLevelHigh       = 100.0
	defaultEWMAAlpha       = 0.3
	defaultEgressAlpha     = 0.05
	defaultEgressWarmup    = 12
	defaultEgressMinVolume = 4 << 20 // 4 MiB
	defaultAlertCooldown   = 5 * time.Minute
	defaultHistorySize     = 200
	defaultMaxScopes       = 4096
	defaultScopeTTL        = time.Hour
)

// withDefaults returns a copy of the config with all zero-valued fields filled
// from the built-in defaults.
func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = defaultWindow
	}
	if c.Tunables.isZero() {
		c.Tunables = DefaultTunables()
	}
	if c.WarnLevel == "" {
		c.WarnLevel = defaultWarnLevel
	}
	if c.LevelMedium <= 0 {
		c.LevelMedium = defaultLevelMedium
	}
	if c.LevelHigh <= 0 {
		c.LevelHigh = defaultLevelHigh
	}
	if c.Location == nil {
		c.Location = time.UTC
	}
	if c.EgressBaselineAlpha <= 0 || c.EgressBaselineAlpha > 1 {
		c.EgressBaselineAlpha = defaultEgressAlpha
	}
	if c.EgressWarmup <= 0 {
		c.EgressWarmup = defaultEgressWarmup
	}
	if c.EgressMinVolume <= 0 {
		c.EgressMinVolume = defaultEgressMinVolume
	}
	if c.AlertCooldown <= 0 {
		c.AlertCooldown = defaultAlertCooldown
	}
	if c.HistorySize <= 0 {
		c.HistorySize = defaultHistorySize
	}
	if c.MaxScopes <= 0 {
		c.MaxScopes = defaultMaxScopes
	}
	if c.ScopeTTL <= 0 {
		c.ScopeTTL = defaultScopeTTL
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// validate checks the defaults-applied config for self-consistency.
func (c Config) validate() error {
	if err := c.Tunables.validate(); err != nil {
		return fmt.Errorf("tunables: %w", err)
	}
	if _, ok := ParseLevel(string(c.WarnLevel)); !ok {
		return fmt.Errorf("invalid warnLevel %q", c.WarnLevel)
	}
	if c.BlockLevel != "" {
		if _, ok := ParseLevel(string(c.BlockLevel)); !ok {
			return fmt.Errorf("invalid blockLevel %q", c.BlockLevel)
		}
	}
	if c.LevelMedium >= c.LevelHigh {
		return fmt.Errorf("levelMedium (%g) must be below levelHigh (%g)", c.LevelMedium, c.LevelHigh)
	}
	if c.OffHoursStart < 0 || c.OffHoursStart > 23 || c.OffHoursEnd < 0 || c.OffHoursEnd > 23 {
		return fmt.Errorf("off-hours boundaries must be hours in [0,23] (start=%d end=%d)", c.OffHoursStart, c.OffHoursEnd)
	}
	for tenant, ov := range c.TenantOverrides {
		if ov.Tunables != nil {
			if err := ov.Tunables.validate(); err != nil {
				return fmt.Errorf("tenant %q tunables: %w", tenant, err)
			}
		}
		if ov.WarnLevel != "" {
			if _, ok := ParseLevel(string(ov.WarnLevel)); !ok {
				return fmt.Errorf("tenant %q invalid warnLevel %q", tenant, ov.WarnLevel)
			}
		}
		if ov.BlockLevel != "" {
			if _, ok := ParseLevel(string(ov.BlockLevel)); !ok {
				return fmt.Errorf("tenant %q invalid blockLevel %q", tenant, ov.BlockLevel)
			}
		}
	}
	return nil
}

// resolved is the effective model for a given tenant.
type resolved struct {
	tunables   Tunables
	warnLevel  Level
	blockLevel Level
}

// resolve computes the effective model for a tenant, layering any per-tenant
// override over the global defaults. Each part overrides independently.
func (c Config) resolve(tenant string) resolved {
	r := resolved{tunables: c.Tunables, warnLevel: c.WarnLevel, blockLevel: c.BlockLevel}
	ov, ok := c.TenantOverrides[tenant]
	if !ok || tenant == "" {
		return r
	}
	if ov.Tunables != nil && !ov.Tunables.isZero() {
		r.tunables = *ov.Tunables
	}
	if ov.WarnLevel != "" {
		r.warnLevel = ov.WarnLevel
	}
	if ov.BlockLevel != "" {
		r.blockLevel = ov.BlockLevel
	}
	return r
}

// blockEnabled reports whether soft-blocking is configured for this model.
func (r resolved) blockEnabled() bool {
	return r.blockLevel != "" && levelRank(r.blockLevel) > levelRank(LevelNone)
}
