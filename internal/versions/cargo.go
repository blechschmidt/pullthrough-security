package versions

import (
	"strconv"
	"strings"
)

// cargo follows the semver crate (1.0: src/parse.rs, src/eval.rs,
// src/impls.rs), which Cargo resolves Cargo.toml requirements with:
//
//   - A version is exactly MAJOR.MINOR.PATCH[-PRE][+BUILD]: no "v", no
//     surrounding space, no leading zeros (build metadata excepted). Versions
//     order by major, minor, patch, pre-release (SemVer 2.0), then build
//     metadata as a tie-break, as the crate's derived Ord does.
//   - A requirement is comma-separated comparators, all of which must match
//     (at most 32, the crate's limit). A bare version is a caret requirement;
//     "*", "1.*", "1.2.*" (or x/X) are wildcards; "^", "~", "=", ">", ">=",
//     "<", "<=" take partial versions ("^1", "~1.2", ">=1.2").
//   - A pre-release matches only when some comparator has a pre-release and
//     the same MAJOR.MINOR.PATCH (the crate's matches_req).
//
// Deviations: numbers are int64 where the crate takes u64 (larger ones are an
// error), and an empty expression — what a dependency without a version key
// declares — is ErrNoConstraint where the crate reports an empty input.
type cargoScheme struct{}

// cargoMaxComparators is the crate's MAX_COMPARATORS.
const cargoMaxComparators = 32

func (cargoScheme) Name() string { return "cargo" }

type cargoVersion struct {
	raw string
	v   semver
}

func (v *cargoVersion) String() string   { return v.raw }
func (v *cargoVersion) Prerelease() bool { return len(v.v.pre) > 0 }
func (v *cargoVersion) Release() []int64 { return []int64{v.v.major, v.v.minor, v.v.patch} }
func (v *cargoVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "cargo"
}

func (cargoScheme) own(v Version) (*cargoVersion, bool) {
	if x, ok := v.(*cargoVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseCargoVersion(v.String())
	return x, err == nil
}

// Parse is semver::Version::parse.
func (cargoScheme) Parse(s string) (Version, error) {
	v, err := parseCargoVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func parseCargoVersion(s string) (*cargoVersion, error) {
	if err := checkLength("cargo", "version", s); err != nil {
		return nil, err
	}
	if s == "" {
		return nil, errorf("cargo", s, "empty")
	}
	core, err := parseStrictSemver(s, maxInt64)
	if err != "" {
		return nil, errorf("cargo", s, "%s", err)
	}
	return &cargoVersion{raw: s, v: core}, nil
}

func (s cargoScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	if c := x.v.compare(&y.v); c != 0 {
		return c
	}
	return compareCargoBuild(x.v.build, y.v.build)
}

// compareCargoBuild is the crate's BuildMetadata order: identifiers one by
// one, numeric ones by value then by length (0 < 00 < 1 < 01), below
// alphanumeric ones, which compare in ASCII order; no metadata ranks lowest.
func compareCargoBuild(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, bn := allDigits(a[i]), allDigits(b[i])
		switch {
		case an && bn:
			if c := cmpDigits(a[i], b[i]); c != 0 {
				return c
			}
			if c := cmpInt64(int64(len(a[i])), int64(len(b[i]))); c != 0 {
				return c
			}
		case an:
			return -1
		case bn:
			return 1
		default:
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		}
	}
	return cmpInt64(int64(len(a)), int64(len(b)))
}

// cargoOp is a comparator's operator.
type cargoOp uint8

const (
	cargoExact cargoOp = iota
	cargoGreater
	cargoGreaterEq
	cargoLess
	cargoLessEq
	cargoTilde
	cargoCaret
	cargoWildcard
)

// cargoComparator is the crate's Comparator: minor and patch may be absent.
type cargoComparator struct {
	op                 cargoOp
	major, minor       int64
	patch              int64
	hasMinor, hasPatch bool
	pre                []string
}

// cargoReq is a VersionReq. No comparators is "*".
type cargoReq struct {
	raw  string
	cmps []cargoComparator
}

func (r *cargoReq) String() string { return r.raw }

// Allows is VersionReq::matches.
func (r *cargoReq) Allows(v Version) bool {
	x, ok := cargoScheme{}.own(v)
	if !ok {
		return false
	}
	for i := range r.cmps {
		if !r.cmps[i].matches(&x.v) {
			return false
		}
	}
	if len(x.v.pre) == 0 {
		return true
	}
	// A pre-release is allowed only by a comparator with a pre-release of
	// the same MAJOR.MINOR.PATCH.
	for i := range r.cmps {
		c := &r.cmps[i]
		if c.major == x.v.major && c.hasMinor && c.minor == x.v.minor &&
			c.hasPatch && c.patch == x.v.patch && len(c.pre) > 0 {
			return true
		}
	}
	return false
}

// matches is the crate's matches_impl.
func (c *cargoComparator) matches(v *semver) bool {
	switch c.op {
	case cargoExact, cargoWildcard:
		return c.matchesExact(v)
	case cargoGreater:
		return c.matchesGreater(v)
	case cargoGreaterEq:
		return c.matchesExact(v) || c.matchesGreater(v)
	case cargoLess:
		return c.matchesLess(v)
	case cargoLessEq:
		return c.matchesExact(v) || c.matchesLess(v)
	case cargoTilde:
		return c.matchesTilde(v)
	case cargoCaret:
		return c.matchesCaret(v)
	}
	return false
}

func (c *cargoComparator) matchesExact(v *semver) bool {
	if v.major != c.major || (c.hasMinor && v.minor != c.minor) || (c.hasPatch && v.patch != c.patch) {
		return false
	}
	return comparePre(v.pre, c.pre) == 0
}

func (c *cargoComparator) matchesGreater(v *semver) bool {
	if v.major != c.major {
		return v.major > c.major
	}
	if !c.hasMinor {
		return false
	}
	if v.minor != c.minor {
		return v.minor > c.minor
	}
	if !c.hasPatch {
		return false
	}
	if v.patch != c.patch {
		return v.patch > c.patch
	}
	return comparePre(v.pre, c.pre) > 0
}

func (c *cargoComparator) matchesLess(v *semver) bool {
	if v.major != c.major {
		return v.major < c.major
	}
	if !c.hasMinor {
		return false
	}
	if v.minor != c.minor {
		return v.minor < c.minor
	}
	if !c.hasPatch {
		return false
	}
	if v.patch != c.patch {
		return v.patch < c.patch
	}
	return comparePre(v.pre, c.pre) < 0
}

func (c *cargoComparator) matchesTilde(v *semver) bool {
	if v.major != c.major || (c.hasMinor && v.minor != c.minor) {
		return false
	}
	if c.hasPatch && v.patch != c.patch {
		return v.patch > c.patch
	}
	return comparePre(v.pre, c.pre) >= 0
}

func (c *cargoComparator) matchesCaret(v *semver) bool {
	if v.major != c.major {
		return false
	}
	if !c.hasMinor {
		return true
	}
	if !c.hasPatch {
		if c.major > 0 {
			return v.minor >= c.minor
		}
		return v.minor == c.minor
	}
	switch {
	case c.major > 0:
		if v.minor != c.minor {
			return v.minor > c.minor
		}
		if v.patch != c.patch {
			return v.patch > c.patch
		}
	case c.minor > 0:
		if v.minor != c.minor {
			return false
		}
		if v.patch != c.patch {
			return v.patch > c.patch
		}
	default:
		if v.minor != c.minor || v.patch != c.patch {
			return false
		}
	}
	return comparePre(v.pre, c.pre) >= 0
}

// ParseConstraint is VersionReq::parse.
func (cargoScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("cargo", "requirement", expr); err != nil {
		return nil, err
	}
	text := strings.TrimLeft(expr, " ")
	if strings.TrimRight(text, " ") == "" {
		return nil, noConstraint("cargo", expr, "empty")
	}
	req := &cargoReq{raw: strings.TrimSpace(expr)}
	if w := cargoWildcardPrefix(text); w != "" {
		rest := strings.TrimLeft(text[1:], " ")
		switch {
		case rest == "":
			return req, nil
		case rest[0] == ',':
			return nil, errorf("cargo", expr, "wildcard req (%s) must be the only comparator in the version req", w)
		default:
			return nil, errorf("cargo", expr, "unexpected character after wildcard in version req")
		}
	}
	for {
		c, rest, err := parseCargoComparator(text)
		if err != "" {
			return nil, errorf("cargo", expr, "%s", err)
		}
		req.cmps = append(req.cmps, c)
		if rest == "" {
			return req, nil
		}
		if rest[0] != ',' {
			return nil, errorf("cargo", expr, "expected comma after a comparator, found %s", strconv.Quote(rest[:1]))
		}
		if len(req.cmps) == cargoMaxComparators {
			return nil, errorf("cargo", expr, "excessive number of version comparators")
		}
		text = strings.TrimLeft(rest[1:], " ")
	}
}

// cargoWildcardPrefix returns "*", "x" or "X" when text starts with one.
func cargoWildcardPrefix(text string) string {
	if text != "" && (text[0] == '*' || text[0] == 'x' || text[0] == 'X') {
		return text[:1]
	}
	return ""
}

// parseCargoComparator is the crate's comparator(): an operator (caret when
// none), spaces, a partial version with wildcards for minor and patch, a
// pre-release and build metadata only after a patch, trailing spaces. It
// returns the comparator and the rest of the text.
func parseCargoComparator(text string) (cargoComparator, string, string) {
	var c cargoComparator
	op, rest, defaultOp := cargoReadOp(text)
	c.op = op
	rest = strings.TrimLeft(rest, " ")
	var err string
	i := 0
	if c.major, i, err = readNumber(rest, 0, maxInt64); err != "" {
		return c, "", "major version: " + err
	}
	wildcard := false
	if i < len(rest) && rest[i] == '.' {
		i++
		if w := cargoWildcardPrefix(rest[i:]); w != "" {
			wildcard = true
			if defaultOp {
				c.op = cargoWildcard
			}
			i++
		} else {
			if c.minor, i, err = readNumber(rest, i, maxInt64); err != "" {
				return c, "", "minor version: " + err
			}
			c.hasMinor = true
		}
	}
	if i < len(rest) && rest[i] == '.' {
		i++
		switch {
		case cargoWildcardPrefix(rest[i:]) != "":
			if defaultOp {
				c.op = cargoWildcard
			}
			i++
		case wildcard:
			return c, "", "unexpected character after wildcard in version req"
		default:
			if c.patch, i, err = readNumber(rest, i, maxInt64); err != "" {
				return c, "", "patch version: " + err
			}
			c.hasPatch = true
		}
	}
	if c.hasPatch && i < len(rest) && rest[i] == '-' {
		if c.pre, i, err = readIdentifiers(rest, i+1, true); err != "" {
			return c, "", "pre-release: " + err
		}
	}
	if c.hasPatch && i < len(rest) && rest[i] == '+' {
		if _, i, err = readIdentifiers(rest, i+1, false); err != "" {
			return c, "", "build metadata: " + err
		}
	}
	return c, strings.TrimLeft(rest[i:], " "), ""
}

// cargoReadOp is the crate's op(): the operator and whether none was given.
func cargoReadOp(text string) (cargoOp, string, bool) {
	switch {
	case strings.HasPrefix(text, "="):
		return cargoExact, text[1:], false
	case strings.HasPrefix(text, ">="):
		return cargoGreaterEq, text[2:], false
	case strings.HasPrefix(text, ">"):
		return cargoGreater, text[1:], false
	case strings.HasPrefix(text, "<="):
		return cargoLessEq, text[2:], false
	case strings.HasPrefix(text, "<"):
		return cargoLess, text[1:], false
	case strings.HasPrefix(text, "~"):
		return cargoTilde, text[1:], false
	case strings.HasPrefix(text, "^"):
		return cargoCaret, text[1:], false
	}
	return cargoCaret, text, true
}
