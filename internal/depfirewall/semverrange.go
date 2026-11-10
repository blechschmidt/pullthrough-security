package depfirewall

import (
	"fmt"
	"strings"
)

// op is a version comparison operator used by a single range comparator.
type op uint8

const (
	opGTE op = iota // >=
	opGT            // >
	opLTE           // <=
	opLT            // <
	opEQ            // = (exact)
)

// comparator is one primitive constraint, e.g. ">=1.2.0".
type comparator struct {
	op  op
	ver version
}

// satisfied reports whether v meets this comparator.
func (c comparator) satisfied(v version) bool {
	cmp := compareVer(v, c.ver)
	switch c.op {
	case opGTE:
		return cmp >= 0
	case opGT:
		return cmp > 0
	case opLTE:
		return cmp <= 0
	case opLT:
		return cmp < 0
	case opEQ:
		return cmp == 0
	}
	return false
}

// rangeSet is a disjunction (OR) of conjunctions (AND) of comparators, matching
// the npm/cargo range grammar: comma- or "||"-separated alternatives, each a
// space-separated set of comparators all of which must hold.
type rangeSet struct {
	groups [][]comparator
	raw    string
}

// String returns the original range expression for diagnostics.
func (rs rangeSet) String() string { return rs.raw }

// satisfies reports whether v lies within the range. An invalid (un-parseable)
// candidate version never satisfies a range — the firewall fails safe.
func (rs rangeSet) satisfies(v version) bool {
	if !v.valid {
		return false
	}
	for _, group := range rs.groups {
		all := true
		for _, c := range group {
			if !c.satisfied(v) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// parseRange parses a semver range expression into a rangeSet. It supports the
// common cross-ecosystem forms used in lockfiles and policy:
//
//   - / x / latest        match anything
//     1.2.3                  exact
//     =1.2.3                 exact
//     >=1.2.0 <2.0.0         space-separated AND of comparators
//     >=1.2.0, <2.0.0        comma-separated AND (Cargo style)
//     1.2.x / 1.x / 1.*      wildcard ranges
//     ^1.2.3                 caret range (compatible-with)
//     ~1.2.3 / ~1.2          tilde range (approximately-equivalent)
//     1.2.3 - 2.3.4          hyphen (inclusive) range
//     a || b                 OR of two ranges
//
// It returns an error for a malformed expression so a bad rule is rejected at
// configuration time rather than silently admitting or blocking everything.
func parseRange(expr string) (rangeSet, error) {
	raw := strings.TrimSpace(expr)
	if raw == "" {
		return rangeSet{}, fmt.Errorf("empty version range")
	}
	rs := rangeSet{raw: raw}
	for _, alt := range strings.Split(raw, "||") {
		group, err := parseRangeGroup(alt)
		if err != nil {
			return rangeSet{}, err
		}
		rs.groups = append(rs.groups, group)
	}
	if len(rs.groups) == 0 {
		return rangeSet{}, fmt.Errorf("version range %q has no comparators", raw)
	}
	return rs, nil
}

// parseRangeGroup parses one AND-group (one alternative of an OR range).
func parseRangeGroup(s string) ([]comparator, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty range alternative")
	}
	// Hyphen range: "1.2.3 - 2.3.4". Detect a bare " - " separator.
	if lo, hi, ok := splitHyphenRange(s); ok {
		lov := parseVersion(lo)
		hiv := parseVersion(hi)
		if !lov.valid || !hiv.valid {
			return nil, fmt.Errorf("invalid hyphen range %q", s)
		}
		return []comparator{{op: opGTE, ver: lov}, {op: opLTE, ver: hiv}}, nil
	}

	// Normalize comma separators (Cargo / requirements style) to spaces.
	s = strings.ReplaceAll(s, ",", " ")
	fields := strings.Fields(s)
	var out []comparator
	for _, f := range fields {
		cmps, err := parseComparator(f)
		if err != nil {
			return nil, err
		}
		out = append(out, cmps...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("range alternative %q has no comparators", s)
	}
	return out, nil
}

// splitHyphenRange splits "lo - hi" on a standalone hyphen surrounded by spaces.
func splitHyphenRange(s string) (lo, hi string, ok bool) {
	idx := strings.Index(s, " - ")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+3:]), true
}

// parseComparator parses a single token into one or more primitive comparators.
// Operator-prefixed tokens (>=, >, <=, <, =) yield one comparator; caret/tilde/
// wildcard tokens expand into a lower- and upper-bound pair.
func parseComparator(tok string) ([]comparator, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil, fmt.Errorf("empty comparator")
	}
	switch tok {
	case "*", "x", "X", "latest", "any":
		// Match anything: a tautological >= 0.
		return []comparator{{op: opGTE, ver: version{nums: []uint64{0}, valid: true}}}, nil
	}

	switch {
	case strings.HasPrefix(tok, ">="):
		return single(opGTE, tok[2:])
	case strings.HasPrefix(tok, "<="):
		return single(opLTE, tok[2:])
	case strings.HasPrefix(tok, ">"):
		return single(opGT, tok[1:])
	case strings.HasPrefix(tok, "<"):
		return single(opLT, tok[1:])
	case strings.HasPrefix(tok, "="):
		return single(opEQ, tok[1:])
	case strings.HasPrefix(tok, "^"):
		return caretRange(tok[1:])
	case strings.HasPrefix(tok, "~"):
		return tildeRange(tok[1:])
	}

	if strings.ContainsAny(tok, "xX*") {
		return wildcardRange(tok)
	}
	// Bare version: exact match.
	v := parseVersion(tok)
	if !v.valid {
		return nil, fmt.Errorf("invalid version %q in range", tok)
	}
	return []comparator{{op: opEQ, ver: v}}, nil
}

func single(o op, raw string) ([]comparator, error) {
	v := parseVersion(raw)
	if !v.valid {
		return nil, fmt.Errorf("invalid version %q in range comparator", raw)
	}
	return []comparator{{op: o, ver: v}}, nil
}

// parseCoreParts parses the numeric segments of a (possibly partial) version
// like "1", "1.2", or "1.2.3" into major/minor/patch with explicit presence
// flags, ignoring any pre-release suffix.
func parseCoreParts(raw string) (maj, min, pat uint64, haveMin, havePat bool, ok bool) {
	v := parseVersion(raw)
	if !v.valid {
		return 0, 0, 0, false, false, false
	}
	maj = v.num(0)
	min = v.num(1)
	pat = v.num(2)
	haveMin = len(v.nums) >= 2
	havePat = len(v.nums) >= 3
	return maj, min, pat, haveMin, havePat, true
}

// caretRange expands "^X.Y.Z" into its compatible-with bounds: the upper bound
// is the next version that changes the left-most non-zero segment.
func caretRange(raw string) ([]comparator, error) {
	maj, min, pat, haveMin, havePat, ok := parseCoreParts(raw)
	if !ok {
		return nil, fmt.Errorf("invalid caret range ^%s", raw)
	}
	lower := version{nums: []uint64{maj, min, pat}, valid: true}
	var upper version
	switch {
	case maj > 0 || !haveMin:
		upper = version{nums: []uint64{maj + 1, 0, 0}, valid: true}
	case min > 0 || !havePat:
		upper = version{nums: []uint64{maj, min + 1, 0}, valid: true}
	default:
		upper = version{nums: []uint64{maj, min, pat + 1}, valid: true}
	}
	return []comparator{{op: opGTE, ver: lower}, {op: opLT, ver: upper}}, nil
}

// tildeRange expands "~X.Y.Z" / "~X.Y" / "~X" into approximately-equivalent
// bounds: allow patch-level (or, for "~X", minor-level) changes.
func tildeRange(raw string) ([]comparator, error) {
	maj, min, pat, haveMin, _, ok := parseCoreParts(raw)
	if !ok {
		return nil, fmt.Errorf("invalid tilde range ~%s", raw)
	}
	lower := version{nums: []uint64{maj, min, pat}, valid: true}
	var upper version
	if haveMin {
		upper = version{nums: []uint64{maj, min + 1, 0}, valid: true}
	} else {
		upper = version{nums: []uint64{maj + 1, 0, 0}, valid: true}
	}
	return []comparator{{op: opGTE, ver: lower}, {op: opLT, ver: upper}}, nil
}

// wildcardRange expands "1.2.x" / "1.x" / "1.*" into a bounded range.
func wildcardRange(tok string) ([]comparator, error) {
	parts := strings.Split(tok, ".")
	// Find the first wildcard segment; everything before it is fixed.
	var fixed []uint64
	for _, p := range parts {
		if p == "x" || p == "X" || p == "*" || p == "" {
			break
		}
		n, ok := parseUint(p)
		if !ok {
			return nil, fmt.Errorf("invalid wildcard range %q", tok)
		}
		fixed = append(fixed, n)
	}
	switch len(fixed) {
	case 0:
		// "*"-only: match anything.
		return []comparator{{op: opGTE, ver: version{nums: []uint64{0}, valid: true}}}, nil
	case 1:
		lower := version{nums: []uint64{fixed[0], 0, 0}, valid: true}
		upper := version{nums: []uint64{fixed[0] + 1, 0, 0}, valid: true}
		return []comparator{{op: opGTE, ver: lower}, {op: opLT, ver: upper}}, nil
	default:
		lower := version{nums: []uint64{fixed[0], fixed[1], 0}, valid: true}
		upper := version{nums: []uint64{fixed[0], fixed[1] + 1, 0}, valid: true}
		return []comparator{{op: opGTE, ver: lower}, {op: opLT, ver: upper}}, nil
	}
}
