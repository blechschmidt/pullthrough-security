package depfirewall

import (
	"strconv"
	"strings"
)

// version is a parsed, comparable representation of a semantic-version-ish
// version string. It models the numeric release core (major.minor.patch and any
// further numeric segments) and an optional dot-separated pre-release suffix.
// Build metadata (after '+') is parsed away and ignored for ordering, per SemVer.
//
// The parser is deliberately tolerant: it accepts a leading "v"/"V" (Go modules,
// some npm tags), a missing minor/patch (treated as zero), and PEP 440-ish
// spellings (1.0.0rc1 / 1.0.0.dev1) approximated by folding a trailing
// non-numeric segment into the pre-release. It is sufficient for the firewall's
// membership and range tests against real lockfile-resolved versions; it is not
// a complete SemVer or PEP 440 implementation.
type version struct {
	nums  []uint64
	pre   []string
	valid bool
}

// parseVersion parses a version string into a comparable version. An empty or
// un-parseable string yields valid=false; callers treat that as "cannot
// evaluate" and fail safe.
func parseVersion(s string) version {
	s = strings.TrimSpace(s)
	if s == "" {
		return version{}
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Strip build metadata.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}

	tokens := strings.Split(s, ".")
	// Fold a trailing non-numeric token (the "1.0.0.rc1" dotted spelling) into the
	// pre-release suffix so the numeric core compares cleanly.
	for len(tokens) > 0 {
		last := tokens[len(tokens)-1]
		if _, ok := parseUint(last); ok {
			break
		}
		// A token like "1rc1" with an embedded boundary: split the numeric prefix.
		if num, suffix, ok := splitNumericPrefix(last); ok {
			tokens[len(tokens)-1] = num
			if pre == "" {
				pre = suffix
			} else {
				pre = suffix + "." + pre
			}
			break
		}
		if pre == "" {
			pre = last
		} else {
			pre = last + "." + pre
		}
		tokens = tokens[:len(tokens)-1]
	}

	nums := make([]uint64, 0, len(tokens))
	for _, t := range tokens {
		n, ok := parseUint(t)
		if !ok {
			return version{}
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return version{}
	}
	var preParts []string
	if pre != "" {
		preParts = strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' })
	}
	return version{nums: nums, pre: preParts, valid: true}
}

// splitNumericPrefix splits a token such as "1rc1" into its leading numeric run
// ("1") and the remainder ("rc1"). It returns ok=false when the token does not
// start with a digit.
func splitNumericPrefix(t string) (num, rest string, ok bool) {
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	return t[:i], t[i:], true
}

// num returns the i-th numeric segment of the release core, treating a missing
// segment as zero so 1.2 and 1.2.0 compare equal.
func (v version) num(i int) uint64 {
	if i < len(v.nums) {
		return v.nums[i]
	}
	return 0
}

// compareVer orders two parsed versions, returning -1, 0, or 1. A version with a
// pre-release suffix has lower precedence than the same release core without one
// (1.0.0-rc1 < 1.0.0), per SemVer §11.
func compareVer(a, b version) int {
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		switch {
		case a.num(i) < b.num(i):
			return -1
		case a.num(i) > b.num(i):
			return 1
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	default:
		return comparePre(a.pre, b.pre)
	}
}

// comparePre orders two pre-release identifier lists per SemVer §11: numeric
// identifiers compare numerically and rank below alphanumerics, alphanumerics
// compare lexically, and a longer list wins when all preceding fields are equal.
func comparePre(a, b []string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		an, aok := parseUint(a[i])
		bn, bok := parseUint(b[i])
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
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func parseUint(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// normalizeVersion canonicalizes a version for exact-match comparison: trims
// surrounding space and a single leading "v", and lower-cases the result. It is
// intentionally light — exact pin/deny matching compares the published spelling,
// only smoothing differences that are never semantically meaningful.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		v = v[1:]
	}
	return strings.ToLower(v)
}
