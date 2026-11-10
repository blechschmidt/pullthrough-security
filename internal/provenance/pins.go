package provenance

import (
	"fmt"
	"strings"
	"time"
)

// PinResolverName is the ResolverName recorded on every link produced by an
// operator pin, so a pinned association is distinguishable — in the admin view,
// the audit trail, and the link store — from one a resolver discovered.
const PinResolverName = "operator-pin"

// Pin is an operator-asserted association between a package coordinate and the
// source commit it is built from.
//
// Attestations (SLSA / in-toto, GitHub build provenance, cosign) and registry
// metadata cover only part of the ecosystems the proxy fronts: most registries
// publish neither, and an internal package often has no public metadata at all.
// A pin lets the operator state the association explicitly — "this coordinate is
// built from this commit of this repository" — so the package's admission can be
// gated on that commit's scan verdict exactly as for an attested package.
//
// A pin is an assertion, not evidence: the resulting link carries
// ConfidenceClaimed and never satisfies a policy that requires attested
// provenance.
type Pin struct {
	// Ecosystem is the ecosystem (upstream type, e.g. "npm", "pip", "docker") the
	// pin applies to. Empty or "*" matches every ecosystem.
	Ecosystem string
	// Name is the package name exactly as the backend reports it (e.g.
	// "@scope/pkg", "org.apache.commons:commons-lang3", "library/alpine").
	// Matching is case-insensitive. Required.
	Name string
	// Version is the exact version the pin applies to. Empty or "*" matches every
	// version of the package.
	Version string
	// Repository is the canonical source repository URL. Optional but
	// recommended: it is surfaced next to the commit wherever the link is shown.
	Repository string
	// Commit is the full source commit hash (40 hex characters for SHA-1, 64 for
	// SHA-256). Required.
	Commit string
}

// PinSet is an immutable, validated set of pins indexed for lookup. The zero
// value and a nil *PinSet are both empty and safe to use.
type PinSet struct {
	// byName indexes pins by lower-cased package name; each bucket is ordered
	// most-specific first so Lookup returns the first match.
	byName map[string][]Pin
	n      int
}

// wildcard reports whether a pin field matches anything.
func wildcard(s string) bool { return s == "" || s == "*" }

// NewPinSet validates pins and builds the lookup index. It rejects a pin with no
// name, a malformed commit hash, and two pins that would match the same
// coordinate at the same specificity (an ambiguous assertion is a configuration
// error, not something to resolve by declaration order).
func NewPinSet(pins []Pin) (*PinSet, error) {
	set := &PinSet{byName: make(map[string][]Pin, len(pins))}
	seen := make(map[string]int, len(pins))
	for i, p := range pins {
		p.Ecosystem = strings.ToLower(strings.TrimSpace(p.Ecosystem))
		p.Name = strings.TrimSpace(p.Name)
		p.Version = strings.TrimSpace(p.Version)
		p.Repository = strings.TrimSpace(p.Repository)
		p.Commit = strings.ToLower(strings.TrimSpace(p.Commit))
		if wildcard(p.Ecosystem) {
			p.Ecosystem = ""
		}
		if wildcard(p.Version) {
			p.Version = ""
		}

		if p.Name == "" {
			return nil, fmt.Errorf("provenance pin #%d: name is required", i+1)
		}
		if strings.ContainsAny(p.Name, "*?") {
			return nil, fmt.Errorf("provenance pin #%d (%s): name must be an exact package name, not a pattern", i+1, p.Name)
		}
		if err := ValidateCommitHash(p.Commit); err != nil {
			return nil, fmt.Errorf("provenance pin #%d (%s): %w", i+1, p.Name, err)
		}

		key := p.Ecosystem + "\x00" + strings.ToLower(p.Name) + "\x00" + p.Version
		if j, dup := seen[key]; dup {
			return nil, fmt.Errorf("provenance pin #%d (%s): duplicates pin #%d for the same ecosystem, name and version",
				i+1, p.Name, j+1)
		}
		seen[key] = i

		name := strings.ToLower(p.Name)
		set.byName[name] = append(set.byName[name], p)
		set.n++
	}
	for name, bucket := range set.byName {
		sortPins(bucket)
		set.byName[name] = bucket
	}
	return set, nil
}

// ValidateCommitHash reports whether s is a full Git commit hash: 40 lowercase
// or uppercase hex characters (SHA-1) or 64 (SHA-256). Abbreviated hashes are
// rejected — a pin must name exactly one commit, and the scan verdict it joins
// against is keyed by the full hash.
func ValidateCommitHash(s string) error {
	if len(s) != 40 && len(s) != 64 {
		return fmt.Errorf("commit %q must be a full 40- or 64-character hex commit hash", s)
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return fmt.Errorf("commit %q must be a full 40- or 64-character hex commit hash", s)
		}
	}
	return nil
}

// specificity ranks a pin: an exact version outranks an exact ecosystem, which
// outranks a wildcard. The most specific matching pin wins.
func specificity(p Pin) int {
	rank := 0
	if p.Version != "" {
		rank += 2
	}
	if p.Ecosystem != "" {
		rank++
	}
	return rank
}

// sortPins orders a bucket most-specific first (insertion sort: buckets hold a
// handful of pins at most, and the order must be stable for equal ranks).
func sortPins(pins []Pin) {
	for i := 1; i < len(pins); i++ {
		for j := i; j > 0 && specificity(pins[j]) > specificity(pins[j-1]); j-- {
			pins[j], pins[j-1] = pins[j-1], pins[j]
		}
	}
}

// Len reports the number of pins in the set.
func (s *PinSet) Len() int {
	if s == nil {
		return 0
	}
	return s.n
}

// Match returns the most specific pin that applies to the artifact.
func (s *PinSet) Match(art Artifact) (Pin, bool) {
	if s == nil || s.n == 0 || art.Name == "" {
		return Pin{}, false
	}
	eco := strings.ToLower(art.Ecosystem)
	for _, p := range s.byName[strings.ToLower(art.Name)] {
		if p.Ecosystem != "" && p.Ecosystem != eco {
			continue
		}
		if p.Version != "" && p.Version != art.Version {
			continue
		}
		return p, true
	}
	return Pin{}, false
}

// Link returns the provenance link an operator pin asserts for the artifact, or
// false when no pin applies.
func (s *PinSet) Link(art Artifact, now time.Time) (*Link, bool) {
	p, ok := s.Match(art)
	if !ok {
		return nil, false
	}
	return &Link{
		Artifact:      art,
		RepositoryURL: p.Repository,
		CommitSHA:     p.Commit,
		Confidence:    ConfidenceClaimed,
		ResolverName:  PinResolverName,
		ResolvedAt:    now,
	}, true
}
