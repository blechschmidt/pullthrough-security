package mlguard

import (
	"fmt"
	"log/slog"
)

// Action is the gate's effective decision for a flagged weight file.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Blocked reports whether the action refuses the artifact.
func (a Action) Blocked() bool { return a == ActionBlock }

// Default scan bounds.
const (
	defaultMaxScanBytes  = 256 << 20 // 256 MiB buffered per weight file
	defaultMaxZipEntries = 64        // pickle entries scanned inside a PyTorch ZIP
)

// TenantConfig overrides the gate's thresholds for a single tenant. A zero/empty
// field inherits the global setting.
type TenantConfig struct {
	FailSeverity Severity
	WarnSeverity Severity
	Action       Action
}

// Config configures the ML weight-scanning gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// FailSeverity is the minimum finding severity that triggers Action. Default
	// "high".
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers an advisory warning below
	// the fail threshold. Default "medium"; empty disables warnings.
	WarnSeverity Severity
	// Action is applied when a finding meets FailSeverity: "block" (refuse and
	// evict) or "warn" (advisory). Default "block".
	Action Action
	// PreferSafetensors, when true, flags a served pickle weight file with an
	// advisory header recommending the safer safetensors format. Default true.
	PreferSafetensors bool
	// MaxScanBytes bounds the bytes buffered per weight file for disassembly
	// (0 => default 256 MiB). A larger file is scanned up to the bound and flagged
	// truncated.
	MaxScanBytes int
	// MaxZipEntries bounds the pickle entries scanned inside a PyTorch ZIP
	// container (0 => default 64).
	MaxZipEntries int
	// Tenants holds per-tenant threshold overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig
	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

// DefaultConfig returns the built-in defaults: enabled, block at high severity,
// warn at medium, prefer safetensors.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		FailSeverity:      SeverityHigh,
		WarnSeverity:      SeverityMedium,
		Action:            ActionBlock,
		PreferSafetensors: true,
		MaxScanBytes:      defaultMaxScanBytes,
		MaxZipEntries:     defaultMaxZipEntries,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults. WarnSeverity
// is intentionally NOT defaulted here so a deliberately-empty value (warnings
// off) is preserved; the wiring layer fills it from DefaultConfig when unset.
func (c Config) withDefaults() Config {
	if c.FailSeverity == "" {
		c.FailSeverity = SeverityHigh
	}
	if c.Action == "" {
		c.Action = ActionBlock
	}
	if c.MaxScanBytes <= 0 {
		c.MaxScanBytes = defaultMaxScanBytes
	}
	if c.MaxZipEntries <= 0 {
		c.MaxZipEntries = defaultMaxZipEntries
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if _, ok := ParseSeverity(string(c.FailSeverity)); !ok {
		return fmt.Errorf("mlguard: invalid failSeverity %q", c.FailSeverity)
	}
	if c.WarnSeverity != "" {
		if _, ok := ParseSeverity(string(c.WarnSeverity)); !ok {
			return fmt.Errorf("mlguard: invalid warnSeverity %q", c.WarnSeverity)
		}
		if severityRank(c.WarnSeverity) > severityRank(c.FailSeverity) {
			return fmt.Errorf("mlguard: warnSeverity %q must not exceed failSeverity %q", c.WarnSeverity, c.FailSeverity)
		}
	}
	switch c.Action {
	case ActionBlock, ActionWarn:
	default:
		return fmt.Errorf("mlguard: invalid action %q (want block|warn)", c.Action)
	}
	for tenant, t := range c.Tenants {
		if t.FailSeverity != "" {
			if _, ok := ParseSeverity(string(t.FailSeverity)); !ok {
				return fmt.Errorf("mlguard: tenants[%q] invalid failSeverity %q", tenant, t.FailSeverity)
			}
		}
		if t.WarnSeverity != "" {
			if _, ok := ParseSeverity(string(t.WarnSeverity)); !ok {
				return fmt.Errorf("mlguard: tenants[%q] invalid warnSeverity %q", tenant, t.WarnSeverity)
			}
		}
		if t.Action != "" && t.Action != ActionBlock && t.Action != ActionWarn {
			return fmt.Errorf("mlguard: tenants[%q] invalid action %q", tenant, t.Action)
		}
	}
	return nil
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

// PreferSafetensors reports whether the gate advises the safetensors format.
func (s *Service) PreferSafetensors() bool { return s != nil && s.cfg.PreferSafetensors }
