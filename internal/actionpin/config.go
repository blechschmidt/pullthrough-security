package actionpin

import (
	"fmt"
	"log/slog"
	"strings"
)

// Action is the gate's effective decision for inspected content.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Blocked reports whether the action refuses the content.
func (a Action) Blocked() bool { return a == ActionBlock }

// TenantConfig overrides the gate's thresholds and allowlist for a single
// tenant. A zero/empty field inherits the global setting for that part.
type TenantConfig struct {
	// FailSeverity overrides the global block threshold for this tenant.
	FailSeverity Severity
	// WarnSeverity overrides the global warn threshold for this tenant.
	WarnSeverity Severity
	// Action overrides the global action taken at/above FailSeverity.
	Action Action
}

// Config configures the GitHub Actions pinning / provenance gate.
type Config struct {
	// Enabled gates whether the service is built and consulted.
	Enabled bool
	// FailSeverity is the minimum finding severity that triggers Action (block or
	// warn). Default "high" — so a disallowed owner blocks while a mutable-ref pin
	// only warns under the default configuration.
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold. Default "medium". Empty disables warnings.
	WarnSeverity Severity
	// Action is applied when a finding meets FailSeverity: "block" or "warn".
	// Default "block".
	Action Action
	// RequirePinning enables the pinning-hygiene checks (mutable-ref / unpinned).
	// Default true. Set false to enforce only the owner allowlist.
	RequirePinning bool
	// AllowedOwners is the optional allowlist of permitted action owners/orgs
	// (case-insensitive, e.g. "actions", "github", "docker"). Empty disables the
	// allowlist (any owner is permitted). A reference to an owner not in a
	// non-empty allowlist produces a disallowed-owner finding.
	AllowedOwners []string
	// MaxFindings caps the findings recorded per inspected content set (0 =>
	// default 200) so a pathological file cannot produce an unbounded finding set.
	MaxFindings int
	// Tenants holds per-tenant overrides keyed by tenant id.
	Tenants map[string]TenantConfig
	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

const defaultMaxFindings = 200

// DefaultConfig returns the built-in defaults: enabled, pinning required, block
// at high severity, warn at medium, no owner allowlist.
func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		FailSeverity:   SeverityHigh,
		WarnSeverity:   SeverityMedium,
		Action:         ActionBlock,
		RequirePinning: true,
		MaxFindings:    defaultMaxFindings,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults. WarnSeverity
// is intentionally NOT defaulted here: the wiring layer fills it from
// DefaultConfig when unset, so a deliberately-empty WarnSeverity (warnings off)
// is preserved through this path.
func (c Config) withDefaults() Config {
	if c.FailSeverity == "" {
		c.FailSeverity = SeverityHigh
	}
	if c.Action == "" {
		c.Action = ActionBlock
	}
	if c.MaxFindings == 0 {
		c.MaxFindings = defaultMaxFindings
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if _, ok := ParseSeverity(string(c.FailSeverity)); !ok {
		return fmt.Errorf("actionpin: invalid failSeverity %q", c.FailSeverity)
	}
	if c.WarnSeverity != "" {
		if _, ok := ParseSeverity(string(c.WarnSeverity)); !ok {
			return fmt.Errorf("actionpin: invalid warnSeverity %q", c.WarnSeverity)
		}
		if severityRank(c.WarnSeverity) > severityRank(c.FailSeverity) {
			return fmt.Errorf("actionpin: warnSeverity %q must not exceed failSeverity %q", c.WarnSeverity, c.FailSeverity)
		}
	}
	switch c.Action {
	case ActionBlock, ActionWarn:
	default:
		return fmt.Errorf("actionpin: invalid action %q (want block|warn)", c.Action)
	}
	if c.MaxFindings < 0 {
		return fmt.Errorf("actionpin: maxFindings must not be negative, got %d", c.MaxFindings)
	}
	for i, o := range c.AllowedOwners {
		if strings.TrimSpace(o) == "" {
			return fmt.Errorf("actionpin: allowedOwners[%d] is empty", i)
		}
	}
	for tenant, t := range c.Tenants {
		if t.FailSeverity != "" {
			if _, ok := ParseSeverity(string(t.FailSeverity)); !ok {
				return fmt.Errorf("actionpin: tenants[%q] invalid failSeverity %q", tenant, t.FailSeverity)
			}
		}
		if t.WarnSeverity != "" {
			if _, ok := ParseSeverity(string(t.WarnSeverity)); !ok {
				return fmt.Errorf("actionpin: tenants[%q] invalid warnSeverity %q", tenant, t.WarnSeverity)
			}
		}
		if t.Action != "" && t.Action != ActionBlock && t.Action != ActionWarn {
			return fmt.Errorf("actionpin: tenants[%q] invalid action %q", tenant, t.Action)
		}
	}
	return nil
}

// ownerSet lowercases an allowlist into a membership set, or nil when empty.
func ownerSet(owners []string) map[string]struct{} {
	if len(owners) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(owners))
	for _, o := range owners {
		o = strings.ToLower(strings.TrimSpace(o))
		if o != "" {
			set[o] = struct{}{}
		}
	}
	return set
}

// resolveThresholds returns the effective (failSeverity, warnSeverity, action)
// for a tenant, layering any per-tenant override over the global config. The
// owner allowlist is global (it governs which findings are produced in Assess).
func (s *Service) resolveThresholds(tenant string) (Severity, Severity, Action) {
	fail, warn, action := s.cfg.FailSeverity, s.cfg.WarnSeverity, s.cfg.Action
	if tenant == "" {
		return fail, warn, action
	}
	ov, ok := s.cfg.Tenants[tenant]
	if !ok {
		return fail, warn, action
	}
	if ov.FailSeverity != "" {
		fail = ov.FailSeverity
	}
	if ov.WarnSeverity != "" {
		warn = ov.WarnSeverity
	}
	if ov.Action != "" {
		action = ov.Action
	}
	return fail, warn, action
}
