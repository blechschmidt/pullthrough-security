package versions

import (
	"strconv"
	"strings"
)

// rubygems follows RubyGems (lib/rubygems/version.rb, requirement.rb, and
// Gem::Dependency#match?):
//
//   - A version matches Gem::Version's VERSION_PATTERN; "-" stands for
//     ".pre.". It is split into numeric and alphabetic segments; any letter
//     makes it a pre-release. Versions order as Gem::Version#<=> on the
//     canonical segments (trailing zeros dropped: 1.0 == 1; zeros before a
//     pre-release dropped: 1.0.a == 1.a), a string segment below a number.
//   - A requirement is comma-separated conditions ("=", "!=", ">", "<",
//     ">=", "<=", "~>", a bare version meaning "="), all of which must hold —
//     how Gemfile.lock writes a dependency's requirements. "~> 2.2" is
//     ">= 2.2, < 3", "~> 2.2.0" is ">= 2.2.0, < 2.3" (Gem::Version#bump).
//   - A pre-release is allowed only when a condition names one, the rule
//     Gem::Dependency#match? applies when gems are resolved
//     (Gem::Requirement#satisfied_by? alone has no such rule).
//
// Deviations: numbers are int64 where Ruby's are unbounded, and an empty
// expression — a gem listed without a requirement — is Gem::Requirement's
// default, ">= 0", though Gem::Requirement.parse refuses an empty string.
type rubygemsScheme struct{}

func (rubygemsScheme) Name() string { return "rubygems" }

// gemSegment is a numeric or an alphabetic version segment.
type gemSegment struct {
	num bool
	n   int64
	s   string
}

type gemVersion struct {
	raw        string
	version    string // stripped, with "-" replaced by ".pre."
	segments   []gemSegment
	canonical  []gemSegment
	prerelease bool
}

func (v *gemVersion) String() string   { return v.raw }
func (v *gemVersion) Prerelease() bool { return v.prerelease }
func (v *gemVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "rubygems"
}

// Release returns the leading numeric segments.
func (v *gemVersion) Release() []int64 {
	var out []int64
	for _, s := range v.segments {
		if !s.num {
			break
		}
		out = append(out, s.n)
	}
	return pad3(out)
}

func (rubygemsScheme) own(v Version) (*gemVersion, bool) {
	if x, ok := v.(*gemVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseGemVersion(v.String())
	return x, err == nil
}

// Parse is Gem::Version.new.
func (rubygemsScheme) Parse(s string) (Version, error) {
	v, err := parseGemVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// trimRuby trims what Ruby's \s matches: space, \t, \n, \v, \f, \r.
func trimRuby(s string) string { return strings.Trim(s, " \t\n\v\f\r") }

func parseGemVersion(s string) (*gemVersion, error) {
	if err := checkLength("rubygems", "version", s); err != nil {
		return nil, err
	}
	v, err := newGemVersion(trimRuby(s))
	if err != "" {
		return nil, errorf("rubygems", s, "%s", err)
	}
	v.raw = s
	return v, nil
}

// newGemVersion is Gem::Version#initialize on a trimmed version: an empty one
// is "0".
func newGemVersion(t string) (*gemVersion, string) {
	if t == "" {
		t = "0"
	}
	if !gemPattern(t) {
		return nil, "malformed version number string"
	}
	v := &gemVersion{version: strings.ReplaceAll(t, "-", ".pre.")}
	for i := 0; i < len(v.version); i++ {
		if isLetter(v.version[i]) {
			v.prerelease = true
			break
		}
	}
	var err string
	if v.segments, err = gemPartition(v.version); err != "" {
		return nil, err
	}
	if v.canonical, err = gemPartition(gemCanonical(v.version, v.prerelease)); err != "" {
		return nil, err
	}
	return v, ""
}

// gemPattern is VERSION_PATTERN, anchored:
// [0-9]+(?>\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?
func gemPattern(t string) bool {
	i := 0
	for i < len(t) && isDigit(t[i]) {
		i++
	}
	if i == 0 {
		return false
	}
	for i+1 < len(t) && t[i] == '.' && isAlnum(t[i+1]) {
		i++
		for i < len(t) && isAlnum(t[i]) {
			i++
		}
	}
	if i < len(t) && t[i] == '-' {
		for {
			i++
			j := i
			for j < len(t) && (isAlnum(t[j]) || t[j] == '-') {
				j++
			}
			if j == i {
				return false
			}
			i = j
			if i < len(t) && t[i] == '.' {
				continue
			}
			break
		}
	}
	return i == len(t)
}

// gemPartition is partition_segments: runs of digits (numbers) and of letters
// (strings), everything else skipped.
func gemPartition(ver string) ([]gemSegment, string) {
	var out []gemSegment
	for i := 0; i < len(ver); {
		j := i
		switch {
		case isDigit(ver[i]):
			for j < len(ver) && isDigit(ver[j]) {
				j++
			}
			n, ok := parseDigits(strings.TrimLeft(ver[i:j], "0"), maxInt64)
			if !ok && strings.TrimLeft(ver[i:j], "0") != "" {
				return nil, "a number is larger than " + strconv.FormatInt(maxInt64, 10)
			}
			out = append(out, gemSegment{num: true, n: n})
		case isLetter(ver[i]):
			for j < len(ver) && isLetter(ver[j]) {
				j++
			}
			out = append(out, gemSegment{s: ver[i:j]})
		default:
			j++
		}
		i = j
	}
	return out, ""
}

// gemCanonical is the text canonical_segments partitions: trailing zeros
// after a letter or dot dropped (/(?<=[a-zA-Z.])[.0]+\z/), and for a
// pre-release the zeros and dots that lead up to its first letter
// (/(?<=\.|\A)[0.]+(?=[a-zA-Z])/).
func gemCanonical(ver string, prerelease bool) string {
	s := len(ver)
	for s > 0 && (ver[s-1] == '.' || ver[s-1] == '0') {
		s--
	}
	if s < len(ver) {
		switch {
		case s > 0 && isLetter(ver[s-1]):
			ver = ver[:s]
		default:
			// The match must start right after a dot inside the run.
			if d := strings.IndexByte(ver[s:], '.'); d >= 0 && s+d+1 < len(ver) {
				ver = ver[:s+d+1]
			}
		}
	}
	if !prerelease {
		return ver
	}
	for p := 0; p < len(ver); p++ {
		if (p > 0 && ver[p-1] != '.') || (ver[p] != '0' && ver[p] != '.') {
			continue
		}
		e := p
		for e < len(ver) && (ver[e] == '0' || ver[e] == '.') {
			e++
		}
		if e < len(ver) && isLetter(ver[e]) {
			return ver[:p] + ver[e:]
		}
		// Every later start inside this run ends where it does: skip it.
		p = e
	}
	return ver
}

func (s rubygemsScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return compareGem(x, y)
}

// compareGem is Gem::Version#<=>.
func compareGem(a, b *gemVersion) int {
	if a.version == b.version {
		return 0
	}
	l, r := a.canonical, b.canonical
	i := 0
	for ; i < len(l) && i < len(r); i++ {
		x, y := l[i], r[i]
		switch {
		case x.num && y.num:
			if c := cmpInt64(x.n, y.n); c != 0 {
				return c
			}
		case !x.num && !y.num:
			if c := strings.Compare(x.s, y.s); c != 0 {
				return c
			}
		case !x.num:
			return -1
		default:
			return 1
		}
	}
	// The longer side decides by its rest: a string makes it the lower
	// (a pre-release of the shorter), a non-zero number the higher.
	for ; i < len(r); i++ {
		if !r[i].num {
			return 1
		}
		if r[i].n != 0 {
			return -1
		}
	}
	for ; i < len(l); i++ {
		if !l[i].num {
			return -1
		}
		if l[i].n != 0 {
			return 1
		}
	}
	return 0
}

// gemRequirement is one condition.
type gemRequirement struct {
	op   string
	v    *gemVersion
	bump *gemVersion // for "~>": Gem::Version#bump of v
}

// gemRequirements is a Gem::Requirement.
type gemRequirements struct {
	raw  string
	reqs []gemRequirement
}

func (r *gemRequirements) String() string { return r.raw }

// Allows is Gem::Dependency#match?: the pre-release rule, then
// Gem::Requirement#satisfied_by?.
func (r *gemRequirements) Allows(v Version) bool {
	x, ok := rubygemsScheme{}.own(v)
	if !ok {
		return false
	}
	if x.prerelease {
		named := false
		for _, q := range r.reqs {
			named = named || q.v.prerelease
		}
		if !named {
			return false
		}
	}
	for _, q := range r.reqs {
		if !q.satisfied(x) {
			return false
		}
	}
	return true
}

// satisfied is the condition's entry of Gem::Requirement::OPS.
func (q *gemRequirement) satisfied(v *gemVersion) bool {
	c := compareGem(v, q.v)
	switch q.op {
	case "=":
		return c == 0
	case "!=":
		return c != 0
	case ">":
		return c > 0
	case "<":
		return c < 0
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case "~>":
		return c >= 0 && compareGem(v.release(), q.bump) < 0
	}
	return false
}

// release is Gem::Version#release: a pre-release without its string
// segments (and what follows the first of them).
func (v *gemVersion) release() *gemVersion {
	if !v.prerelease {
		return v
	}
	segs := gemDropStrings(v.segments)
	r, err := newGemVersion(gemJoin(segs))
	if err != "" {
		return v
	}
	return r
}

// gemDropStrings pops segments off the end until none is a string ("pop
// while segments.any? String"): everything from the first string on goes.
func gemDropStrings(segs []gemSegment) []gemSegment {
	for i, s := range segs {
		if !s.num {
			return segs[:i]
		}
	}
	return segs
}

func gemJoin(segs []gemSegment) string {
	parts := make([]string, len(segs))
	for i, s := range segs {
		if s.num {
			parts[i] = strconv.FormatInt(s.n, 10)
		} else {
			parts[i] = s.s
		}
	}
	return strings.Join(parts, ".")
}

// gemBump is Gem::Version#bump: string segments popped, then the last
// segment if more than one remains, then the new last one incremented.
func gemBump(v *gemVersion) (*gemVersion, string) {
	segs := append([]gemSegment(nil), gemDropStrings(v.segments)...)
	if len(segs) > 1 {
		segs = segs[:len(segs)-1]
	}
	last := &segs[len(segs)-1]
	if last.n == maxInt64 {
		return nil, "a number is too large to bump"
	}
	last.n++
	b, err := newGemVersion(gemJoin(segs))
	if err != "" {
		return nil, err
	}
	return b, ""
}

// ParseConstraint reads comma-separated conditions, each as
// Gem::Requirement.parse reads one.
func (rubygemsScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("rubygems", "requirement", expr); err != nil {
		return nil, err
	}
	r := &gemRequirements{raw: trimRuby(expr)}
	if r.raw == "" {
		zero, _ := newGemVersion("0")
		r.reqs = []gemRequirement{{op: ">=", v: zero}}
		return r, nil
	}
	for _, part := range strings.Split(expr, ",") {
		if len(r.reqs) == MaxTerms {
			return nil, errorf("rubygems", expr, "more than %d conditions", MaxTerms)
		}
		q, err := parseGemRequirement(part)
		if err != "" {
			return nil, errorf("rubygems", expr, "%s", err)
		}
		r.reqs = append(r.reqs, q)
	}
	return r, nil
}

// parseGemRequirement is Gem::Requirement.parse:
// \A\s*(=|!=|>|<|>=|<=|~>)?\s*(VERSION_PATTERN)\s*\z, "=" by default.
func parseGemRequirement(part string) (gemRequirement, string) {
	t := trimRuby(part)
	q := gemRequirement{op: "="}
	for _, op := range []string{"!=", ">=", "<=", "~>", "=", ">", "<"} {
		if strings.HasPrefix(t, op) {
			q.op, t = op, trimRuby(t[len(op):])
			break
		}
	}
	if t == "" {
		return q, "illformed requirement " + quote(part)
	}
	v, err := newGemVersion(t)
	if err != "" {
		return q, "illformed requirement " + quote(part) + ": " + err
	}
	v.raw = t
	q.v = v
	if q.op == "~>" {
		if q.bump, err = gemBump(v); err != "" {
			return q, err
		}
	}
	return q, ""
}
