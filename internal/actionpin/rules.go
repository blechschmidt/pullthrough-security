package actionpin

import "strings"

// Stable finding rule identifiers for the pinning-hygiene checks. They are the
// per-finding identifiers surfaced in metrics, the admin view, and the SARIF
// property bag.
const (
	// RuleMutableRef flags an action pinned to a mutable git ref — a branch name
	// or a floating tag such as "@v4" — rather than a full 40-character commit
	// SHA. Whoever controls that ref can change the code that runs.
	RuleMutableRef = "mutable-ref"
	// RuleUnpinned flags an action reference with no ref at all ("owner/repo"),
	// which resolves to the default branch's latest commit.
	RuleUnpinned = "unpinned"
	// RuleDisallowedOwner flags (and, at the default threshold, blocks) a
	// reference to an owner/org that is not in the configured allowlist.
	RuleDisallowedOwner = "disallowed-owner"
)

// Severity is the gate's risk vocabulary, ordered info < low < medium < high <
// critical. It maps onto the canonical findings/SARIF severity scale by name.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// severityRank returns a comparable ordinal (info=1 .. critical=5), or 0 for an
// empty/unknown severity so it never accidentally meets a threshold.
func severityRank(s Severity) int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

// ParseSeverity normalizes a string into a Severity, returning ok=false for an
// unrecognized value (empty maps to ok=false so callers can substitute a
// default).
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityInfo:
		return SeverityInfo, true
	case SeverityLow:
		return SeverityLow, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityCritical:
		return SeverityCritical, true
	default:
		return "", false
	}
}

// Pinning classifies how a reference is pinned.
type Pinning string

const (
	// PinSHA is a full 40-character commit SHA — the immutable, hardened pin.
	PinSHA Pinning = "sha"
	// PinDigest is a docker image pinned by "@sha256:" digest — also immutable.
	PinDigest Pinning = "digest"
	// PinLocal is an in-repository (local) action; pinning does not apply.
	PinLocal Pinning = "local"
	// PinMutable is a mutable ref: a branch, a floating/semver tag, or a
	// truncated (short) SHA.
	PinMutable Pinning = "mutable"
	// PinNone is a remote reference with no ref at all (resolves to HEAD of the
	// default branch).
	PinNone Pinning = "none"
)

// OK reports whether the pinning is immutable (passes the pinning check).
func (p Pinning) OK() bool { return p == PinSHA || p == PinDigest || p == PinLocal }

// pinningOf classifies a reference's pinning. It never depends on the network:
// a ref that is a full 40-char hex string is treated as an immutable commit SHA;
// anything shorter or non-hex is a mutable tag/branch.
func (r Reference) pinningOf() Pinning {
	switch r.Kind {
	case KindLocal:
		return PinLocal
	case KindDocker:
		if isDockerDigest(r.Ref) {
			return PinDigest
		}
		return PinMutable
	default: // KindRemote
		switch {
		case r.Ref == "":
			return PinNone
		case isFullSHA(r.Ref):
			return PinSHA
		default:
			return PinMutable
		}
	}
}

// isFullSHA reports whether s is a full 40-character hexadecimal git commit SHA.
// A 64-char value (a future SHA-256 object id) also qualifies.
func isFullSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	return isHex(s)
}

// isDockerDigest reports whether s is an OCI content digest ("sha256:" + 64 hex).
func isDockerDigest(s string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := s[len(prefix):]
	return len(rest) == 64 && isHex(rest)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}

// looksLikeVersionTag reports whether a mutable ref looks like a version tag
// (e.g. "v4", "v4.2.2", "1.2.3") as opposed to a branch name. It is advisory
// only — used to enrich a finding's message — and never changes the verdict.
func looksLikeVersionTag(ref string) bool {
	if ref == "" {
		return false
	}
	s := ref
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return false
	}
	// A version tag is digits and dots only (allowing a trailing pre-release is
	// out of scope for this heuristic).
	seenDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			seenDigit = true
		case c == '.':
		default:
			return false
		}
	}
	return seenDigit
}
