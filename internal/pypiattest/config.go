package pypiattest

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// Action selects what the gate does to a served distribution whose worst finding
// meets the fail threshold. Unlike the other gates' observe/enforce + policy
// action split, PyPI attestation uses a single three-valued knob so operators
// configure the inbound behavior in one place:
//
//   - annotate: never block. Record findings, attach X-PyPI-Attestation-* headers,
//     and feed the policy/risk engines. This is the default (most PyPI releases
//     carry no attestation yet, so blocking would be disruptive).
//   - downgrade: serve, but mark the pull as a warning (headers + audit + notify),
//     so a client/CI step can treat the artifact as reduced-trust.
//   - block: refuse the pull (403) and evict the artifact from the cache.
type Action string

const (
	ActionAnnotate  Action = "annotate"
	ActionDowngrade Action = "downgrade"
	ActionBlock     Action = "block"
)

func (a Action) rank() int {
	switch a {
	case ActionBlock:
		return 2
	case ActionDowngrade:
		return 1
	default:
		return 0
	}
}

// Blocks reports whether the action refuses the pull.
func (a Action) Blocks() bool { return a == ActionBlock }

// capAt returns the less severe of a and ceiling, so a warn-level finding never
// escalates past the ceiling (downgrade).
func (a Action) capAt(ceiling Action) Action {
	if a.rank() > ceiling.rank() {
		return ceiling
	}
	return a
}

// ParseAction normalizes a string into an Action, returning ok=false for an
// unrecognized value. Empty defaults to annotate.
func ParseAction(s string) (Action, bool) {
	switch Action(strings.ToLower(strings.TrimSpace(s))) {
	case ActionAnnotate:
		return ActionAnnotate, true
	case ActionDowngrade:
		return ActionDowngrade, true
	case ActionBlock:
		return ActionBlock, true
	case "":
		return ActionAnnotate, true
	default:
		return "", false
	}
}

// TenantConfig overrides the action for a single tenant.
type TenantConfig struct {
	// Action overrides the global action (annotate|downgrade|block) for this tenant.
	Action Action
}

const defaultCacheMaxEntries = 1024

// Config configures the inbound PyPI PEP 740 attestation verification gate.
type Config struct {
	// Action is applied when a finding meets FailSeverity (annotate|downgrade|block).
	// Default annotate (never blocks).
	Action Action
	// FailSeverity is the minimum finding severity that triggers Action (default
	// high). A digest mismatch is critical and so always meets it.
	FailSeverity Severity
	// WarnSeverity is the minimum severity surfaced as a downgrade when the action
	// would otherwise allow (default medium). It caps a sub-fail finding at a
	// downgrade so the signal is still visible.
	WarnSeverity Severity

	// RequireAttestation treats the absence of any PEP 740 attestation as a finding
	// (KindMissingAttestation). Off by default: most PyPI releases publish none.
	RequireAttestation bool
	// RequireTrustedPublisher treats a digest-bound, cryptographically-valid
	// attestation whose publisher is not trusted (no chain to a configured root, or
	// identity not in policy) as a finding (KindUntrustedPublisher). Off by default;
	// meaningful only when trust material (roots/identities) is configured.
	RequireTrustedPublisher bool
	// RequireInclusionProof treats a verified attestation lacking a verifiable Rekor
	// transparency-log inclusion proof / SET as a finding (KindMissingTransparency).
	// Off by default; meaningful only when Rekor keys are configured.
	RequireInclusionProof bool

	// FailOnError controls behavior when attestation material cannot be fetched or
	// parsed (an infrastructure error): true applies Action (fail-closed); false
	// serves with an annotation/downgrade (fail-open, default).
	FailOnError bool

	// Trust material (shared with the signature gate). When Roots/Identities are
	// empty the gate still verifies the DSSE signature against the embedded Fulcio
	// certificate (establishing Present/Verified and the digest binding), but cannot
	// establish PublisherTrusted.
	Roots      *x509.CertPool
	Identities []sigverify.Identity
	Keys       []sigverify.TrustedKey
	RekorKeys  []crypto.PublicKey

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

// DefaultConfig returns the built-in defaults: annotate-only, fail at high, warn
// at medium, attestation not required.
func DefaultConfig() Config {
	return Config{
		Action:       ActionAnnotate,
		FailSeverity: SeverityHigh,
		WarnSeverity: SeverityMedium,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults.
func (c Config) withDefaults() Config {
	if c.Action == "" {
		c.Action = ActionAnnotate
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
	if _, ok := ParseAction(string(c.Action)); !ok {
		return fmt.Errorf("pypiattest: invalid action %q (want annotate|downgrade|block)", c.Action)
	}
	for tenant, t := range c.Tenants {
		if t.Action != "" {
			if _, ok := ParseAction(string(t.Action)); !ok {
				return fmt.Errorf("pypiattest: tenants[%q] invalid action %q", tenant, t.Action)
			}
		}
	}
	return nil
}

// resolveAction returns the effective action for a tenant.
func (c Config) resolveAction(tenant string) Action {
	if tenant != "" {
		if t, ok := c.Tenants[tenant]; ok && t.Action != "" {
			return t.Action
		}
	}
	return c.Action
}
