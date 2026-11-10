package malfeed

import (
	"strconv"
	"strings"
)

// normalizeVersion canonicalizes a version string for exact-match comparison: it
// trims surrounding space and a single leading "v" (common in Go module and
// some npm tags), lowercasing the result. It is intentionally light — exact
// matching compares the published spelling, only smoothing the differences that
// are never semantically meaningful.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")
	return strings.ToLower(v)
}

// contains reports whether normalized version nv falls within the range for the
// given ecosystem. The bounds follow the OSV model: Introduced is inclusive
// (empty or "0" means "from the beginning"), Fixed is exclusive, LastAffected is
// inclusive. A range with neither upper bound extends to the latest version.
func (r VersionRange) contains(eco, nv string) bool {
	if intro := normalizeVersion(r.Introduced); intro != "" && intro != "0" {
		if compareVersions(eco, nv, intro) < 0 {
			return false
		}
	}
	if fixed := normalizeVersion(r.Fixed); fixed != "" {
		if compareVersions(eco, nv, fixed) >= 0 {
			return false
		}
	}
	if last := normalizeVersion(r.LastAffected); last != "" {
		if compareVersions(eco, nv, last) > 0 {
			return false
		}
	}
	return true
}

// compareVersions orders two normalized version strings, returning -1, 0, or 1.
//
// It is a single tolerant comparator rather than a per-ecosystem parser: it
// splits each version into dot/dash/plus-separated tokens and compares them
// pairwise, numerically when both tokens are integers and lexically otherwise.
// A purely-numeric core (1.2.3) therefore orders correctly, and a pre-release
// suffix (1.2.3-rc1) orders before its release because the shorter token list
// wins a missing-segment comparison only when the present segment is itself a
// release — to honor SemVer's "a pre-release has lower precedence than the
// associated release", a version that has *more* tokens but whose extra leading
// token is a pre-release marker is treated as lower.
//
// This is sufficient for membership tests against the curated feed (whose ranges
// are simple SemVer/PEP 440-style intervals); it is not a complete SemVer or PEP
// 440 implementation and does not attempt to model epoch or local-version
// segments.
func compareVersions(_, a, b string) int {
	if a == b {
		return 0
	}
	at, aPre := splitVersion(a)
	bt, bPre := splitVersion(b)

	n := len(at)
	if len(bt) > n {
		n = len(bt)
	}
	for i := 0; i < n; i++ {
		var ai, bi string
		if i < len(at) {
			ai = at[i]
		}
		if i < len(bt) {
			bi = bt[i]
		}
		if c := compareToken(ai, bi); c != 0 {
			return c
		}
	}

	// Equal release cores: the version *without* a pre-release suffix is greater
	// (1.0.0 > 1.0.0-rc1), and two pre-releases compare by their suffix tokens.
	switch {
	case aPre == "" && bPre == "":
		return 0
	case aPre == "":
		return 1
	case bPre == "":
		return -1
	default:
		return comparePreRelease(aPre, bPre)
	}
}

// splitVersion separates a version's release core from its pre-release suffix.
// The suffix is the portion after the first '-' (SemVer) or after the first
// non-numeric token boundary in a PEP 440 spelling (1.0.0rc1 / 1.0.0.dev1 are
// approximated by treating an alpha-leading token as pre-release).
func splitVersion(v string) (core []string, pre string) {
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	if i := strings.IndexByte(v, '+'); i >= 0 {
		// Build metadata is ignored for ordering.
		v = v[:i]
	}
	tokens := splitTokens(v)
	// Fold a trailing alpha token (PEP 440 "1.0.0rc1" tokenizes oddly; here we
	// catch the "1.0.0.dev1" / "1.0.0.rc1" dotted spelling) into the pre-release.
	for len(tokens) > 0 {
		last := tokens[len(tokens)-1]
		if isNumericToken(last) {
			break
		}
		if pre == "" {
			pre = last
		} else {
			pre = last + "." + pre
		}
		tokens = tokens[:len(tokens)-1]
	}
	return tokens, pre
}

// splitTokens breaks a version core into its dot-separated tokens, further
// splitting an embedded alpha/numeric boundary (so "1rc0" → ["1","rc0"]) is not
// attempted; only '.' separates here, which matches the common spellings.
func splitTokens(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ".")
}

// compareToken compares two release-core tokens. Numeric tokens compare
// numerically; a missing token counts as 0; a non-numeric token compares
// lexically against another non-numeric, and a numeric token outranks a
// non-numeric one.
func compareToken(a, b string) int {
	if a == b {
		return 0
	}
	an, aok := numTokenOrZero(a)
	bn, bok := numTokenOrZero(b)
	switch {
	case aok && bok:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	case aok && !bok:
		return 1
	case !aok && bok:
		return -1
	default:
		return strings.Compare(a, b)
	}
}

// comparePreRelease orders two pre-release suffixes token-by-token following the
// SemVer rule: numeric identifiers compare numerically, alphanumerics compare
// lexically, numeric identifiers have lower precedence than alphanumerics, and a
// larger set of pre-release fields (when all preceding are equal) has higher
// precedence.
func comparePreRelease(a, b string) int {
	at := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' })
	bt := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' })
	n := len(at)
	if len(bt) < n {
		n = len(bt)
	}
	for i := 0; i < n; i++ {
		an, aok := parseNum(at[i])
		bn, bok := parseNum(bt[i])
		switch {
		case aok && bok:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case aok && !bok:
			return -1
		case !aok && bok:
			return 1
		default:
			if c := strings.Compare(at[i], bt[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(at) < len(bt):
		return -1
	case len(at) > len(bt):
		return 1
	default:
		return 0
	}
}

// numTokenOrZero parses a release-core token numerically, treating a missing
// (empty) segment as 0 so "1.0" and "1.0.0" compare equal.
func numTokenOrZero(s string) (uint64, bool) {
	if s == "" {
		return 0, true
	}
	return parseNum(s)
}

func parseNum(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isNumericToken(s string) bool {
	_, ok := parseNum(s)
	return ok
}
