// Package nameguard inspects package coordinates at pull time for typosquatting
// and dependency-confusion risk across the pip, npm, cargo, nuget, and go
// ecosystems. It is a name-based admission check: it never reads artifact
// content, so it runs before any upstream fetch or cache fill, refusing a
// look-alike or namespace-shadowing package before it can enter the cache.
//
// Three families of heuristic are applied (see service.go for the orchestration):
//
//  1. Edit-distance / common-substitution similarity to a configurable list of
//     popular (and allowlisted) package names per ecosystem. A name one or two
//     Damerau-Levenshtein edits from a popular name — or equal to it after
//     collapsing visually-confusable character substitutions (rn→m, 0→o, 1→l) —
//     is flagged as a typosquat ("reqeusts" vs "requests").
//
//  2. Internal-namespace shadowing: a public-registry package whose normalized
//     name collides with a configured private/internal package name or namespace
//     prefix. This is the classic dependency-confusion vector and is the highest
//     severity finding.
//
//  3. Suspicious signals: homoglyph / mixed-script characters in the name,
//     scope/namespace near-misses, and (when an age oracle is wired) brand-new
//     packages.
//
// Findings carry a Severity so existing policy warn/block thresholds apply: the
// Service's Gate method maps the worst finding onto a policy.Action exactly as
// the vulnerability gate does.
package nameguard

import (
	"sort"
	"strings"
)

// Artifact is the package coordinate inspected by the guard. Version is optional:
// typosquatting and dependency-confusion are name-level properties, so the guard
// applies as soon as a name is known (e.g. at index lookup, before any specific
// version is downloaded).
type Artifact struct {
	// Ecosystem is the normalized ecosystem: pip, npm, cargo, nuget, or go.
	Ecosystem string
	// Name is the requested package coordinate name (raw, as the client asked).
	Name string
	// Version is the requested version, when known. Unused by the heuristics but
	// echoed into findings and audit detail.
	Version string
}

// Severity orders findings so the worst one drives the gate decision. It mirrors
// the vulnerability subsystem's severity vocabulary so operators configure both
// gates with the same words.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank orders severities (higher is worse). An unrecognized value ranks as none.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool { return s.rank() >= other.rank() }

// NormalizeSeverity coerces a configured severity string to a known value,
// defaulting unknown/empty input to none (the caller decides whether none
// disables the threshold).
func NormalizeSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ValidSeverity reports whether s is a recognized severity bucket (empty is valid
// and means the threshold is disabled). Used by config validation.
func ValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// Kind classifies a finding by the heuristic that produced it.
type Kind string

const (
	// KindTyposquat is a name within the edit-distance / substitution threshold of
	// a popular package name (but not equal to it).
	KindTyposquat Kind = "typosquat"
	// KindDependencyConfusion is a public-registry name that collides with a
	// configured internal/private package name or namespace prefix.
	KindDependencyConfusion Kind = "dependency-confusion"
	// KindHomoglyph is a name containing non-ASCII look-alike / mixed-script
	// characters (e.g. a Cyrillic 'а' standing in for Latin 'a').
	KindHomoglyph Kind = "homoglyph"
	// KindNamespaceMismatch is a scoped/namespaced name whose scope is a near-miss
	// of a known popular scope (npm @scope, go host/owner).
	KindNamespaceMismatch Kind = "namespace-mismatch"
	// KindNewPackage is a brand-new package (younger than the configured age),
	// surfaced only when an AgeOracle is wired.
	KindNewPackage Kind = "new-package"
)

// Finding is a single detected risk signal for a coordinate.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	// Name is the normalized form of the inspected package name.
	Name string `json:"name"`
	// Similar is the popular/internal name the finding relates to, when applicable
	// (the legitimate package being impersonated, or the shadowed internal name).
	Similar string `json:"similar,omitempty"`
	// Distance is the Damerau-Levenshtein edit distance to Similar, when the
	// finding is distance-based (0 for an exact post-substitution collision).
	Distance int `json:"distance,omitempty"`
	// Reason is a human-readable, actionable explanation.
	Reason string `json:"reason"`
}

// Report is the result of inspecting one coordinate.
type Report struct {
	Artifact Artifact  `json:"artifact"`
	Findings []Finding `json:"findings,omitempty"`
}

// Flagged reports whether any finding was produced.
func (r *Report) Flagged() bool { return r != nil && len(r.Findings) > 0 }

// Worst returns the highest-severity finding, or nil when none were produced.
// Ties are broken by kind precedence (dependency-confusion outranks the rest) so
// the most actionable signal is surfaced to the client.
func (r *Report) Worst() *Finding {
	if r == nil || len(r.Findings) == 0 {
		return nil
	}
	worst := &r.Findings[0]
	for i := 1; i < len(r.Findings); i++ {
		f := &r.Findings[i]
		if f.Severity.rank() > worst.Severity.rank() ||
			(f.Severity.rank() == worst.Severity.rank() && kindPrecedence(f.Kind) > kindPrecedence(worst.Kind)) {
			worst = f
		}
	}
	return worst
}

// kindPrecedence ranks finding kinds when severities tie.
func kindPrecedence(k Kind) int {
	switch k {
	case KindDependencyConfusion:
		return 5
	case KindHomoglyph:
		return 4
	case KindTyposquat:
		return 3
	case KindNamespaceMismatch:
		return 2
	default:
		return 1
	}
}

// AgeOracle reports how a package's age compares to the new-package threshold. It
// is an optional, pluggable dependency (a registry-metadata lookup): when nil,
// new-package detection is disabled. Implementations should be cheap/cached and
// must not block the pull path for long; an error is treated as "unknown" (no
// finding) so an oracle outage never blocks legitimate pulls.
type AgeOracle interface {
	// IsNew reports whether the named package in the ecosystem is newer than the
	// configured threshold. ok is false when the age cannot be determined.
	IsNew(ecosystem, name string) (isNew bool, ok bool)
}

// ecosystemSet is the per-ecosystem reference data, normalized once at
// construction so inspection is allocation-light.
type ecosystemSet struct {
	// popular maps a normalized popular name to its canonical (display) form. It
	// doubles as the typosquat-comparison target set and the exact-match allowlist.
	popular map[string]string
	// popularList is the deterministic iteration order over popular keys (sorted),
	// so distance scanning is stable and reproducible.
	popularList []string
	// allow is the set of normalized names to never flag (false-positive
	// suppression for legitimate near-neighbors like "preact" vs "react").
	allow map[string]bool
	// internal holds exact internal/private names; internalPrefixes holds namespace
	// prefixes (e.g. "@mycorp/", "mycorp-") that shadow the private registry.
	internal         map[string]bool
	internalPrefixes []string
	// scopes is the set of known popular scopes/owners for namespace-mismatch
	// detection (npm "@scope", go "host/owner").
	scopes map[string]bool
}

// normalizeName lowercases and applies ecosystem-specific separator folding so
// comparison is robust to the equivalences each registry treats as identical.
func newEcosystemSet(ecosystem string, popular, allow, internal []string) *ecosystemSet {
	es := &ecosystemSet{
		popular:  make(map[string]string),
		allow:    make(map[string]bool),
		internal: make(map[string]bool),
		scopes:   make(map[string]bool),
	}
	for _, p := range popular {
		key := normalizeName(ecosystem, p)
		if key == "" {
			continue
		}
		if _, ok := es.popular[key]; !ok {
			es.popular[key] = p
		}
		if sc := scopeOf(ecosystem, key); sc != "" {
			es.scopes[sc] = true
		}
	}
	for _, a := range allow {
		if key := normalizeName(ecosystem, a); key != "" {
			es.allow[key] = true
		}
	}
	for _, in := range internal {
		in = strings.TrimSpace(in)
		if in == "" {
			continue
		}
		// A trailing "*" or "/", or an npm "@scope" with no package, marks a namespace
		// prefix; otherwise an exact name. Prefixes are stored as lowercased literals
		// (not separator-folded) so boundary matching is precise; exact names are
		// normalized so registry separator-equivalences still collide.
		if strings.HasSuffix(in, "*") {
			es.internalPrefixes = append(es.internalPrefixes, strings.ToLower(strings.TrimSuffix(in, "*")))
			continue
		}
		if strings.HasSuffix(in, "/") || isScopePrefix(ecosystem, in) {
			es.internalPrefixes = append(es.internalPrefixes, strings.ToLower(in))
			continue
		}
		es.internal[normalizeName(ecosystem, in)] = true
	}
	es.popularList = make([]string, 0, len(es.popular))
	for k := range es.popular {
		es.popularList = append(es.popularList, k)
	}
	sort.Strings(es.popularList)
	return es
}
