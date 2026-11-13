package versions

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrNoConstraint (wrapped) is what ParseConstraint returns for an expression
// that is valid where it was found but declares no version constraint the
// scheme can evaluate: a git, file, URL or workspace dependency, an npm
// dist-tag, a Maven soft requirement, a Go module version.
var ErrNoConstraint = errors.New("versions: the expression declares no version constraint")

// MaxInputLength bounds the length in bytes of a version or a constraint
// expression. Real ones are a few dozen bytes; longer input is refused before
// it is read.
const MaxInputLength = 1024

// MaxTerms bounds the comparators, specifiers, alternatives or ranges of one
// constraint expression.
const MaxTerms = 64

// Version is a parsed version of one scheme.
type Version interface {
	// String returns the text as given.
	String() string
	// Prerelease reports a pre-release: npm, Cargo and Go "-x", PEP 440
	// a/b/rc/dev, a NuGet release label, a Maven alpha, beta, milestone, rc or
	// snapshot qualifier, a letter in a RubyGems version.
	Prerelease() bool
	// Release returns the leading numeric release components (major, minor,
	// patch, ...): at least three, missing ones 0.
	Release() []int64
}

// Constraint is a parsed version constraint.
type Constraint interface {
	// Allows reports whether the constraint admits v. A version of another
	// scheme is judged by what the constraint's scheme makes of its text; a
	// nil or unreadable version is never allowed.
	Allows(v Version) bool
	// String returns the expression as given (trimmed), or a description for
	// a constraint built by this package.
	String() string
}

// Scheme is one ecosystem's version semantics.
type Scheme interface {
	// Name returns the upstream type the scheme belongs to ("npm", "pip", ...).
	Name() string
	// Parse reads a version as the ecosystem's registry lists it.
	Parse(s string) (Version, error)
	// Compare orders two versions of this scheme: -1, 0, +1. It is a total
	// order. A version of another scheme is compared by what this scheme
	// makes of its text; one this scheme cannot read sorts before every
	// version it can, and all such compare equal.
	Compare(a, b Version) int
	// ParseConstraint reads a constraint as the ecosystem's manifests spell
	// it. ErrNoConstraint (wrapped) means the expression is valid but declares
	// no version constraint the scheme can evaluate.
	ParseConstraint(expr string) (Constraint, error)
}

// schemes is every scheme, keyed by upstream type.
var schemes = map[string]Scheme{
	"npm":      npmScheme{},
	"cargo":    cargoScheme{},
	"pip":      pep440Scheme{},
	"go":       goScheme{},
	"nuget":    nugetScheme{},
	"maven":    mavenScheme{},
	"rubygems": rubygemsScheme{},
}

// For returns the scheme of an upstream type ("npm", "cargo", "pip", "go",
// "nuget", "maven", "rubygems"); ok is false for every other type.
func For(upstreamType string) (Scheme, bool) {
	s, ok := schemes[upstreamType]
	return s, ok
}

// Supported returns the upstream types For knows, sorted.
func Supported() []string {
	out := make([]string, 0, len(schemes))
	for name := range schemes {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Sort orders vs ascending under s. It is stable: versions the scheme
// considers equal (npm "1.0.0" and "1.0.0+build") keep their order.
func Sort(s Scheme, vs []Version) {
	sort.SliceStable(vs, func(i, j int) bool { return s.Compare(vs[i], vs[j]) < 0 })
}

// Level classifies an update.
type Level int

const (
	// LevelNone: the same version, or an older one.
	LevelNone Level = iota
	// LevelPatch: a newer version the scheme's convention calls a fix.
	LevelPatch
	// LevelMinor: a newer version within the same major version.
	LevelMinor
	// LevelMajor: a newer version the convention calls incompatible.
	LevelMajor
)

// String returns "none", "patch", "minor" or "major".
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelPatch:
		return "patch"
	case LevelMinor:
		return "minor"
	case LevelMajor:
		return "major"
	}
	return "level(" + strconv.Itoa(int(l)) + ")"
}

// Bump classifies the update from→to under the scheme's compatibility
// convention:
//
//   - npm and cargo: caret semantics, as "^from" reads in both. The left-most
//     non-zero of major, minor and patch is the breaking component: 0.2.3→0.3.0
//     is Major, 0.2.3→0.2.4 Patch, 0.0.3→0.0.4 Major.
//   - go: the major number, which is the module path's: v0.1→v0.2 is Minor,
//     v1→v2 Major.
//   - pip, nuget, maven, rubygems: plain components. The major differs: Major;
//     the minor differs: Minor; else Patch.
//
// It returns LevelNone when to is not newer than from (to <= from).
func Bump(s Scheme, from, to Version) Level {
	if s == nil {
		return LevelNone
	}
	f, fok := ownVersion(s, from)
	t, tok := ownVersion(s, to)
	if !fok || !tok || s.Compare(t, f) <= 0 {
		return LevelNone
	}
	fr, tr := pad3(f.Release()), pad3(t.Release())
	switch s.Name() {
	case "npm", "cargo":
		return caretLevel(fr, tr)
	case "pip":
		// A new epoch (PEP 440's way to change a versioning scheme) restarts
		// the numbering: whatever the numbers say, the change is a major one.
		if fp, ok := f.(*pep440Version); ok {
			if tp, ok := t.(*pep440Version); ok && fp.epoch != tp.epoch {
				return LevelMajor
			}
		}
	}
	return plainLevel(fr, tr)
}

// caretLevel classifies a newer version by caret compatibility: ^f admits
// every version whose components up to and including f's left-most non-zero
// one equal f's (^0.0.0 admits only 0.0.0 itself, so all three count then).
func caretLevel(f, t []int64) Level {
	breaking := 2
	for i := 0; i < 3; i++ {
		if f[i] != 0 {
			breaking = i
			break
		}
	}
	for i := 0; i <= breaking; i++ {
		if f[i] != t[i] {
			return LevelMajor
		}
	}
	if breaking == 0 && f[1] != t[1] {
		return LevelMinor
	}
	return LevelPatch
}

// plainLevel classifies a newer version by its first differing component.
func plainLevel(f, t []int64) Level {
	switch {
	case f[0] != t[0]:
		return LevelMajor
	case f[1] != t[1]:
		return LevelMinor
	}
	return LevelPatch
}

// Within reports whether to is newer than from by no more than maxLevel:
// LevelMinor is "same major", LevelPatch "patch only", LevelNone admits
// nothing.
func Within(s Scheme, from, to Version, maxLevel Level) bool {
	l := Bump(s, from, to)
	return l != LevelNone && l <= maxLevel
}

// SameMajor returns the constraint "the major version of v and not older than
// v": what Go's minimal version selection may move to within one module path.
// v1.2.3 gives >=v1.2.3 <v2.0.0, v0.4.1 gives >=v0.4.1 <v1.0.0, and
// v2.0.0+incompatible keeps major 2 and +incompatible (a v2 module path has no
// +incompatible versions, a path without /v2 nothing but). For the other
// schemes it is the same rule on Release()[0].
func SameMajor(s Scheme, v Version) Constraint {
	c := &sameMajor{s: s, v: v}
	if s == nil || v == nil {
		return c
	}
	own, ok := ownVersion(s, v)
	if !ok {
		return c
	}
	c.v, c.ok = own, true
	c.major = own.Release()[0]
	if g, isGo := own.(*goVersion); isGo {
		c.incompatible = g.incompatible()
	}
	return c
}

type sameMajor struct {
	s            Scheme
	v            Version
	ok           bool
	major        int64
	incompatible bool
}

func (c *sameMajor) Allows(w Version) bool {
	if !c.ok || w == nil {
		return false
	}
	own, ok := ownVersion(c.s, w)
	if !ok || own.Release()[0] != c.major || c.s.Compare(own, c.v) < 0 {
		return false
	}
	if g, isGo := own.(*goVersion); isGo && g.incompatible() != c.incompatible {
		return false
	}
	return true
}

func (c *sameMajor) String() string {
	if !c.ok {
		return "<no version>"
	}
	if _, isGo := c.v.(*goVersion); isGo {
		next := fmt.Sprintf("v%d.0.0", c.major+1)
		if c.incompatible {
			next += "+incompatible"
		}
		return ">=" + c.v.String() + " <" + next
	}
	return fmt.Sprintf(">=%s <%d (same major)", c.v.String(), c.major+1)
}

// Intersect returns the constraint that allows what every one of cs allows.
// Nil entries are ignored; with none left it allows every version.
func Intersect(cs ...Constraint) Constraint {
	out := make(intersection, 0, len(cs))
	for _, c := range cs {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// All is Intersect: the constraint every one of cs must allow. All() allows
// every version.
func All(cs ...Constraint) Constraint { return Intersect(cs...) }

type intersection []Constraint

func (in intersection) Allows(v Version) bool {
	if v == nil {
		return false
	}
	for _, c := range in {
		if !c.Allows(v) {
			return false
		}
	}
	return true
}

func (in intersection) String() string {
	if len(in) == 0 {
		return "*"
	}
	parts := make([]string, len(in))
	for i, c := range in {
		parts[i] = "(" + c.String() + ")"
	}
	return strings.Join(parts, " && ")
}

// schemeVersion is implemented by every version type of this package: it names
// the scheme the version was parsed by, or "" for a nil pointer.
type schemeVersion interface {
	scheme() string
}

// ownVersion returns v as a version of s: v itself when s parsed it, else
// what s makes of v's text. A nil version, also a nil pointer of this
// package's version types, is no version.
func ownVersion(s Scheme, v Version) (Version, bool) {
	if v == nil || s == nil {
		return nil, false
	}
	if sv, ok := v.(schemeVersion); ok {
		switch sv.scheme() {
		case "":
			return nil, false
		case s.Name():
			return v, true
		}
	}
	p, err := s.Parse(v.String())
	if err != nil {
		return nil, false
	}
	return p, true
}

// pad3 returns r with at least three components, missing ones 0.
func pad3(r []int64) []int64 {
	if len(r) >= 3 {
		return r
	}
	out := make([]int64, 3)
	copy(out, r)
	return out
}

// compareInvalid orders the outcome of reading two versions: one that could
// not be read sorts before one that could, and two that could not are equal.
// done is false when both were read and the caller must compare them.
func compareInvalid(aok, bok bool) (c int, done bool) {
	switch {
	case aok && bok:
		return 0, false
	case !aok && !bok:
		return 0, true
	case !aok:
		return -1, true
	}
	return 1, true
}

// checkLength refuses input longer than MaxInputLength.
func checkLength(scheme, what, s string) error {
	if len(s) > MaxInputLength {
		return fmt.Errorf("versions: %s: %s of %d bytes is longer than %d", scheme, what, len(s), MaxInputLength)
	}
	return nil
}

// errorf returns a parse error naming the scheme and (a bounded quote of) the
// input.
func errorf(scheme, input, format string, args ...any) error {
	return fmt.Errorf("versions: %s: %s: %s", scheme, quote(input), fmt.Sprintf(format, args...))
}

// noConstraint returns ErrNoConstraint wrapped with the scheme, the input and
// what the input is instead.
func noConstraint(scheme, input, what string) error {
	return fmt.Errorf("versions: %s: %s is %s: %w", scheme, quote(input), what, ErrNoConstraint)
}

// quote returns s quoted for an error message, cut to 80 bytes: the input is
// untrusted and may be long.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		return strconv.Quote(s[:max]) + "..."
	}
	return strconv.Quote(s)
}

// cmpInt64 orders two integers.
func cmpInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cmpDigits orders two strings of ASCII digits by numeric value, without
// converting them (pre-release identifiers may exceed any integer type).
// Leading zeros are ignored.
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// allDigits reports whether s is a non-empty string of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseDigits converts a non-empty string of ASCII digits to an int64 no
// larger than max; ok is false when it is larger (or not digits).
func parseDigits(s string, max int64) (int64, bool) {
	if !allDigits(s) {
		return 0, false
	}
	var n int64
	for i := 0; i < len(s); i++ {
		d := int64(s[i] - '0')
		if n > (max-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

// maxInt64 is the largest number a component may hold.
const maxInt64 = int64(^uint64(0) >> 1)

// isAlnum reports an ASCII letter or digit.
func isAlnum(c byte) bool {
	return isDigit(c) || isLetter(c)
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// lowerASCII lowercases the ASCII letters of s.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}
