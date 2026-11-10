package buildprov

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Mode selects whether a build-provenance finding influences serving.
type Mode string

const (
	// ModeObserve records findings and feeds the policy/risk engines and the
	// findings layer but never blocks a pull. This is the default.
	ModeObserve Mode = "observe"
	// ModeEnforce additionally blocks/quarantines an artifact whose worst finding
	// meets the fail threshold (composing with the break-glass workflow).
	ModeEnforce Mode = "enforce"
)

// Enforces reports whether the mode blocks on a failing finding.
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

// TenantConfig overrides the mode and requirements for a single tenant.
type TenantConfig struct {
	// Mode overrides the global mode (observe|enforce) for this tenant.
	Mode Mode
	// RequireProvenance, when set, overrides the global requirement for this tenant.
	RequireProvenance *bool
}

const (
	defaultCacheMaxEntries = 1024
)

// Config configures the inbound build-provenance verification gate.
type Config struct {
	// Mode is the global enforcement mode (observe|enforce). Default observe.
	Mode Mode

	// Action is applied (in enforce mode) when a finding meets FailSeverity: warn,
	// block, or quarantine. Empty defaults to quarantine (so a refused artifact is
	// evicted from the cache).
	Action policy.Action
	// FailSeverity is the minimum finding severity that triggers Action in enforce
	// mode (default high). A source-mismatch is critical and so always meets it.
	FailSeverity Severity
	// WarnSeverity is the minimum severity that triggers a warning (default
	// medium). In observe mode every finding at/above this is surfaced as a warning.
	WarnSeverity Severity

	// RequireProvenance treats the absence of any inbound build-provenance
	// attestation as a finding (KindMissingProvenance). Off by default: most
	// packages publish no provenance, so requiring it is opt-in per deployment.
	RequireProvenance bool
	// RequireTrustedSource treats a digest-bound, cryptographically-valid
	// attestation whose signer is not trusted (no chain to a configured root, or
	// identity not in policy) as a finding (KindUntrustedSource). Off by default;
	// meaningful only when trust material (roots/identities) is configured.
	RequireTrustedSource bool

	// FailOnError controls behavior when provenance material cannot be fetched or
	// parsed (an infrastructure error): true blocks in enforce mode (fail-closed),
	// false serves with a warning (fail-open, default).
	FailOnError bool

	// Trust material (shared with the signature gate). When Roots/Identities are
	// empty the gate still verifies the DSSE signature against the embedded Fulcio
	// certificate (establishing Present/Verified and the proven source for the
	// mismatch cross-check), but cannot establish SourceVerified.
	Roots      *x509.CertPool
	Identities []sigverify.Identity
	Keys       []sigverify.TrustedKey
	RekorKeys  []crypto.PublicKey

	// Forges holds per-forge trust material (GitHub/GitLab/Bitbucket or self-hosted
	// instances). An attestation discovered from a forge's Source is verified
	// against its forge's trust material when present, else against the default
	// Roots/Identities above. This lets GitLab/Bitbucket provenance be trusted under
	// their own Fulcio roots and OIDC issuers independently of GitHub's.
	Forges []ForgeTrust

	// CacheTTL bounds how long a verification result is reused before re-checking
	// (0 = never expire). CacheMaxEntries bounds the result cache (0 => 1024).
	CacheTTL        time.Duration
	CacheMaxEntries int

	// Offline records that the deployment is air-gapped; informational for
	// reporting (the Source decides whether it can fetch material).
	Offline bool

	// Tenants holds per-tenant overrides keyed by tenant id (team).
	Tenants map[string]TenantConfig
}

// DefaultConfig returns the built-in defaults: observe-only, quarantine action,
// fail at high, warn at medium, provenance not required.
func DefaultConfig() Config {
	return Config{
		Mode:         ModeObserve,
		Action:       policy.ActionQuarantine,
		FailSeverity: SeverityHigh,
		WarnSeverity: SeverityMedium,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults.
func (c Config) withDefaults() Config {
	if c.Mode == "" {
		c.Mode = ModeObserve
	}
	if c.Action == "" {
		c.Action = policy.ActionQuarantine
	}
	if c.FailSeverity == "" {
		c.FailSeverity = SeverityHigh
	}
	if c.WarnSeverity == "" {
		c.WarnSeverity = SeverityMedium
	}
	if c.CacheMaxEntries <= 0 {
		c.CacheMaxEntries = defaultCacheMaxEntries
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	if _, ok := ParseMode(string(c.Mode)); !ok {
		return fmt.Errorf("buildprov: invalid mode %q (want observe|enforce)", c.Mode)
	}
	for tenant, t := range c.Tenants {
		if t.Mode != "" {
			if _, ok := ParseMode(string(t.Mode)); !ok {
				return fmt.Errorf("buildprov: tenants[%q] invalid mode %q", tenant, t.Mode)
			}
		}
	}
	return nil
}

// resolveMode returns the effective mode for a tenant.
func (c Config) resolveMode(tenant string) Mode {
	if tenant != "" {
		if t, ok := c.Tenants[tenant]; ok && t.Mode != "" {
			return t.Mode
		}
	}
	return c.Mode
}

// requireProvenance returns the effective RequireProvenance for a tenant.
func (c Config) requireProvenance(tenant string) bool {
	if tenant != "" {
		if t, ok := c.Tenants[tenant]; ok && t.RequireProvenance != nil {
			return *t.RequireProvenance
		}
	}
	return c.RequireProvenance
}
