package installhooks

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// Action is the gate's effective decision for an artifact.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Blocked reports whether the action refuses the artifact.
func (a Action) Blocked() bool { return a == ActionBlock }

// TenantConfig overrides the severity thresholds for a single tenant. A zero/
// empty field inherits the global setting for that part.
type TenantConfig struct {
	// FailSeverity overrides the global block threshold for this tenant.
	FailSeverity Severity
	// WarnSeverity overrides the global warn threshold for this tenant.
	WarnSeverity Severity
	// Action overrides the global action taken at/above FailSeverity.
	Action Action
}

// Config configures the install-hook risk-analysis gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// FailSeverity is the minimum finding severity that triggers Action (block or
	// warn). Default "high".
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold. Default "medium". Empty disables warnings.
	WarnSeverity Severity
	// Action is applied when a finding meets FailSeverity: "block" (refuse and
	// evict) or "warn" (advisory). Default "block".
	Action Action
	// DisabledRules names built-in rule ids to turn off (e.g. "native-extension"
	// for a tenant that compiles many native deps). An unknown id is ignored.
	DisabledRules []string
	// Rules adds or overrides rules. A rule whose ID matches a built-in replaces
	// it (so an operator can re-tune a pattern or severity); a new ID is appended
	// after the built-ins.
	Rules []RuleSpec
	// MaxFindingsPerHook caps findings recorded per hook (0 => default 50) so a
	// pathological script cannot produce an unbounded finding set.
	MaxFindingsPerHook int
	// Tenants holds per-tenant threshold overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig
	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

const defaultMaxFindingsPerHook = 50

// DefaultConfig returns the built-in defaults: enabled, block at high severity,
// warn at medium, all built-in rules active.
func DefaultConfig() Config {
	return Config{
		Enabled:            true,
		FailSeverity:       SeverityHigh,
		WarnSeverity:       SeverityMedium,
		Action:             ActionBlock,
		MaxFindingsPerHook: defaultMaxFindingsPerHook,
	}
}

// withDefaults fills zero-valued threshold fields from the built-in defaults.
// WarnSeverity is intentionally NOT defaulted here: the wiring layer fills it
// from DefaultConfig when unset, so a deliberately-empty WarnSeverity (warnings
// off) is preserved through this path.
func (c Config) withDefaults() Config {
	if c.FailSeverity == "" {
		c.FailSeverity = SeverityHigh
	}
	if c.Action == "" {
		c.Action = ActionBlock
	}
	if c.MaxFindingsPerHook == 0 {
		c.MaxFindingsPerHook = defaultMaxFindingsPerHook
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if _, ok := ParseSeverity(string(c.FailSeverity)); !ok {
		return fmt.Errorf("installhooks: invalid failSeverity %q", c.FailSeverity)
	}
	if c.WarnSeverity != "" {
		if _, ok := ParseSeverity(string(c.WarnSeverity)); !ok {
			return fmt.Errorf("installhooks: invalid warnSeverity %q", c.WarnSeverity)
		}
		if severityRank(c.WarnSeverity) > severityRank(c.FailSeverity) {
			return fmt.Errorf("installhooks: warnSeverity %q must not exceed failSeverity %q", c.WarnSeverity, c.FailSeverity)
		}
	}
	switch c.Action {
	case ActionBlock, ActionWarn:
	default:
		return fmt.Errorf("installhooks: invalid action %q (want block|warn)", c.Action)
	}
	for i, r := range c.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("installhooks: rules[%d] is missing an id", i)
		}
		if strings.TrimSpace(r.Pattern) == "" {
			return fmt.Errorf("installhooks: rules[%q] is missing a pattern", r.ID)
		}
		if _, err := regexp.Compile(r.Pattern); err != nil {
			return fmt.Errorf("installhooks: rules[%q] has an invalid pattern: %w", r.ID, err)
		}
		if r.Severity != "" {
			if _, ok := ParseSeverity(string(r.Severity)); !ok {
				return fmt.Errorf("installhooks: rules[%q] has an invalid severity %q", r.ID, r.Severity)
			}
		}
	}
	for tenant, t := range c.Tenants {
		if t.FailSeverity != "" {
			if _, ok := ParseSeverity(string(t.FailSeverity)); !ok {
				return fmt.Errorf("installhooks: tenants[%q] invalid failSeverity %q", tenant, t.FailSeverity)
			}
		}
		if t.WarnSeverity != "" {
			if _, ok := ParseSeverity(string(t.WarnSeverity)); !ok {
				return fmt.Errorf("installhooks: tenants[%q] invalid warnSeverity %q", tenant, t.WarnSeverity)
			}
		}
		if t.Action != "" && t.Action != ActionBlock && t.Action != ActionWarn {
			return fmt.Errorf("installhooks: tenants[%q] invalid action %q", tenant, t.Action)
		}
	}
	return nil
}

// compileRules builds the active rule set: the built-ins (minus DisabledRules),
// with any config Rules overriding a matching built-in id or appending a new
// rule. Output order is the canonical built-in order followed by new custom
// rules, so finding ordering is stable.
func (c Config) compileRules() ([]Rule, error) {
	disabled := make(map[string]bool, len(c.DisabledRules))
	for _, id := range c.DisabledRules {
		disabled[strings.TrimSpace(id)] = true
	}
	overrides := make(map[string]RuleSpec, len(c.Rules))
	var custom []RuleSpec
	for _, r := range c.Rules {
		isBuiltin := false
		for _, b := range builtinRuleSpecs {
			if b.ID == r.ID {
				isBuiltin = true
				break
			}
		}
		if isBuiltin {
			overrides[r.ID] = r
		} else {
			custom = append(custom, r)
		}
	}

	var out []Rule
	add := func(spec RuleSpec) error {
		if disabled[spec.ID] {
			return nil
		}
		rule, err := compileSpec(spec)
		if err != nil {
			return err
		}
		out = append(out, rule)
		return nil
	}
	for _, b := range builtinRuleSpecs {
		spec := b
		if ov, ok := overrides[b.ID]; ok {
			spec = mergeSpec(b, ov)
		}
		if err := add(spec); err != nil {
			return nil, err
		}
	}
	for _, r := range custom {
		if err := add(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// mergeSpec layers an override onto a built-in: a non-empty override field wins.
func mergeSpec(base, ov RuleSpec) RuleSpec {
	out := base
	if strings.TrimSpace(ov.Title) != "" {
		out.Title = ov.Title
	}
	if ov.Severity != "" {
		out.Severity = ov.Severity
	}
	if strings.TrimSpace(ov.Pattern) != "" {
		out.Pattern = ov.Pattern
	}
	return out
}

func compileSpec(spec RuleSpec) (Rule, error) {
	pattern := spec.Pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("installhooks: compiling rule %q: %w", spec.ID, err)
	}
	sev := spec.Severity
	if sev == "" {
		sev = SeverityMedium
	}
	title := spec.Title
	if strings.TrimSpace(title) == "" {
		title = spec.ID
	}
	return Rule{ID: spec.ID, Title: title, Severity: sev, re: re}, nil
}

// resolveThresholds returns the effective (failSeverity, warnSeverity, action)
// for a tenant, layering any per-tenant override over the global config.
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
