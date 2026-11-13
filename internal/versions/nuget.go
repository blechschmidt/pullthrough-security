package versions

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// nuget follows NuGet.Versioning (NuGetVersionFactory, VersionComparer,
// VersionRangeFactory, FloatRange, VersionRange.IsBetter):
//
//   - A version has one to four numeric parts (1.0 == 1.0.0 == 1.0.0.0),
//     each at most int32, a release label of dot-separated identifiers
//     compared case-insensitively (numeric ones numerically, below the
//     others), and metadata after "+" that does not order.
//   - A range is a bare version (a minimum, inclusive: "1.0" is >= 1.0), an
//     interval ("[1.0,2.0)", "(1.0,)", "(,1.0]", "[1.0]") or a floating
//     version ("1.*", "1.2.*", "*", "1.0.0-*", "1.0.*-*", "*-*"), also as an
//     interval's minimum.
//   - A pre-release is allowed only when a bound of the range is one or the
//     range floats over pre-releases (IsBetter's rule).
//   - A floating range allows what its float covers, from its minimum:
//     "1.*" is >= 1.0.0 and < 2.0.0, stable only. NuGet's VersionRange says
//     only ">= 1.0.0" for "1.*"; resolution then prefers the highest version
//     the float covers (FloatRange.Satisfies) and reaches beyond it only when
//     nothing inside exists. A dependency that already resolved inside the
//     float can only move within it, so an update is held to the float.
//
// Deviation: an empty expression (a reference without a version) is
// ErrNoConstraint where NuGet reports an invalid range.
type nugetScheme struct{}

// nugetMaxPart is int.MaxValue, the largest version part NuGet parses.
const nugetMaxPart = 1<<31 - 1

func (nugetScheme) Name() string { return "nuget" }

type nugetVersion struct {
	raw    string
	parts  [4]int64 // major, minor, patch, revision
	labels []string
}

func (v *nugetVersion) String() string   { return v.raw }
func (v *nugetVersion) Prerelease() bool { return len(v.labels) > 0 }
func (v *nugetVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "nuget"
}

// Release returns major, minor and patch, and the revision when it is set.
func (v *nugetVersion) Release() []int64 {
	if v.parts[3] != 0 {
		return []int64{v.parts[0], v.parts[1], v.parts[2], v.parts[3]}
	}
	return []int64{v.parts[0], v.parts[1], v.parts[2]}
}

// release is the joined release label (NuGetVersion.Release).
func (v *nugetVersion) release() string { return strings.Join(v.labels, ".") }

func (nugetScheme) own(v Version) (*nugetVersion, bool) {
	if x, ok := v.(*nugetVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseNuGetVersion(v.String())
	return x, err == nil
}

// Parse is NuGetVersion.TryParse.
func (nugetScheme) Parse(s string) (Version, error) {
	v, err := parseNuGetVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func trimCS(s string) string { return strings.TrimFunc(s, unicode.IsSpace) }

func parseNuGetVersion(s string) (*nugetVersion, error) {
	if err := checkLength("nuget", "version", s); err != nil {
		return nil, err
	}
	v, err := scanNuGetVersion(trimCS(s))
	if err != "" {
		return nil, errorf("nuget", s, "%s", err)
	}
	v.raw = s
	return v, nil
}

// scanNuGetVersion reads a trimmed version: ParseSections splits it at the
// first "-" or "+" (and the labels at the next "+"), the numeric part has one
// to four parts, labels are [0-9A-Za-z-] without leading zeros on numeric
// ones, metadata identifiers [0-9A-Za-z-].
func scanNuGetVersion(s string) (*nugetVersion, string) {
	numeric, rest := s, ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		numeric, rest = s[:i], s[i:]
	}
	v := &nugetVersion{}
	if !nugetNumbers(numeric, &v.parts) {
		return nil, "not one to four numbers no larger than int32"
	}
	if strings.HasPrefix(rest, "-") {
		label := rest[1:]
		if i := strings.IndexByte(label, '+'); i >= 0 {
			label, rest = label[:i], label[i:]
		} else {
			rest = ""
		}
		for _, l := range strings.Split(label, ".") {
			if !nugetValidPart(l, false) {
				return nil, "an invalid release label"
			}
			v.labels = append(v.labels, l)
		}
	}
	if strings.HasPrefix(rest, "+") {
		for _, m := range strings.Split(rest[1:], ".") {
			if !nugetValidPart(m, true) {
				return nil, "invalid metadata"
			}
		}
		rest = ""
	}
	if rest != "" {
		return nil, "unexpected " + strconv.Quote(rest[:1])
	}
	return v, ""
}

// nugetNumbers is TryGetNormalizedVersion: one to four dot-separated
// numbers, each at most int32, whitespace allowed around each.
func nugetNumbers(str string, parts *[4]int64) bool {
	if strings.TrimFunc(str, unicode.IsSpace) == "" {
		return false
	}
	pos := 0
	for i := range parts {
		var ok bool
		if pos, parts[i], ok = nugetSection(str, pos); !ok {
			return false
		}
	}
	return pos == len(str)
}

// nugetSection is TryGetNormalizedVersion's ParseSection: an empty section
// at the end is 0; otherwise whitespace, digits, whitespace, and a "." that
// must not end the string. It returns the index after the section.
func nugetSection(str string, start int) (int, int64, bool) {
	if start == len(str) {
		return start, 0, true
	}
	end := nugetSkipSpace(str, start)
	if end == len(str) || !isDigit(str[end]) {
		return end, 0, false
	}
	var n int64
	for end < len(str) && isDigit(str[end]) {
		n = n*10 + int64(str[end]-'0')
		if n > nugetMaxPart {
			return end, 0, false
		}
		end++
	}
	end = nugetSkipSpace(str, end)
	switch {
	case end == len(str):
		return end, n, true
	case str[end] != '.' || end+1 == len(str):
		return end, 0, false
	}
	return end + 1, n, true
}

// nugetSkipSpace returns the index of the first non-whitespace rune at or
// after i (char.IsWhiteSpace).
func nugetSkipSpace(str string, i int) int {
	for i < len(str) {
		r, size := utf8.DecodeRuneInString(str[i:])
		if !unicode.IsSpace(r) {
			break
		}
		i += size
	}
	return i
}

// nugetValidPart is IsValidPart: non-empty, [0-9A-Za-z-], and — for labels —
// no leading zero on an all-digit identifier.
func nugetValidPart(s string, allowLeadingZeros bool) bool {
	if s == "" {
		return false
	}
	if !allowLeadingZeros && len(s) > 1 && s[0] == '0' && allDigits(s[1:]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isAlnum(s[i]) && s[i] != '-' {
			return false
		}
	}
	return true
}

func (s nugetScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return compareNuGet(x, y)
}

// compareNuGet is VersionComparer.Default: the four numbers, then a version
// without labels above one with, then the labels.
func compareNuGet(a, b *nugetVersion) int {
	for i := range a.parts {
		if c := cmpInt64(a.parts[i], b.parts[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.labels) == 0 && len(b.labels) == 0:
		return 0
	case len(a.labels) == 0:
		return 1
	case len(b.labels) == 0:
		return -1
	}
	for i := 0; i < len(a.labels) && i < len(b.labels); i++ {
		if c := compareNuGetLabel(a.labels[i], b.labels[i]); c != 0 {
			return c
		}
	}
	return cmpInt64(int64(len(a.labels)), int64(len(b.labels)))
}

// compareNuGetLabel is CompareRelease: labels int.TryParse accepts (an
// optional "-" and digits within int32) compare as numbers and below the
// others, which compare ordinally ignoring case.
func compareNuGetLabel(a, b string) int {
	an, aok := nugetLabelNumber(a)
	bn, bok := nugetLabelNumber(b)
	switch {
	case aok && bok:
		return cmpInt64(an, bn)
	case aok:
		return -1
	case bok:
		return 1
	}
	return strings.Compare(lowerASCII(a), lowerASCII(b))
}

func nugetLabelNumber(s string) (int64, bool) {
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	limit := int64(nugetMaxPart)
	if neg {
		limit++
	}
	n, ok := parseDigits(s, limit)
	if neg {
		n = -n
	}
	return n, ok
}

// nugetFloat is a FloatRange's behaviour.
type nugetFloat uint8

const (
	floatNone nugetFloat = iota
	floatPrerelease
	floatRevision
	floatPatch
	floatMinor
	floatMajor
	floatAbsoluteLatest
	floatPrereleaseRevision
	floatPrereleasePatch
	floatPrereleaseMinor
	floatPrereleaseMajor
)

// includesPrerelease is FloatRange.IncludePrerelease.
func (f nugetFloat) includesPrerelease() bool {
	switch f {
	case floatPrerelease, floatAbsoluteLatest, floatPrereleaseRevision,
		floatPrereleasePatch, floatPrereleaseMinor, floatPrereleaseMajor:
		return true
	}
	return false
}

// nugetRange is a VersionRange with its FloatRange.
type nugetRange struct {
	raw           string
	min, max      *nugetVersion
	minIncl       bool
	maxIncl       bool
	float         nugetFloat
	floating      bool // a FloatRange was parsed (it may float nothing)
	releasePrefix string
}

func (r *nugetRange) String() string { return r.raw }

// Allows is VersionRange.Satisfies, IsBetter's pre-release rule and, for a
// floating range, FloatRange.Satisfies.
func (r *nugetRange) Allows(v Version) bool {
	x, ok := nugetScheme{}.own(v)
	if !ok || !r.satisfies(x) {
		return false
	}
	hasPrereleaseBounds := (r.min != nil && r.min.Prerelease()) || (r.max != nil && r.max.Prerelease())
	if x.Prerelease() && !hasPrereleaseBounds && !(r.floating && r.float.includesPrerelease()) {
		return false
	}
	if r.floating && r.float != floatNone {
		return r.floatSatisfies(x)
	}
	return true
}

// satisfies is VersionRangeBase.Satisfies: the bounds alone.
func (r *nugetRange) satisfies(v *nugetVersion) bool {
	if r.min != nil {
		c := compareNuGet(r.min, v)
		if c > 0 || (c == 0 && !r.minIncl) {
			return false
		}
	}
	if r.max != nil {
		c := compareNuGet(r.max, v)
		if c < 0 || (c == 0 && !r.maxIncl) {
			return false
		}
	}
	return true
}

// floatSatisfies is FloatRange.Satisfies.
func (r *nugetRange) floatSatisfies(v *nugetVersion) bool {
	m := r.min
	labelOK := !v.Prerelease() || strings.HasPrefix(lowerASCII(v.release()), lowerASCII(r.releasePrefix))
	switch r.float {
	case floatAbsoluteLatest:
		return true
	case floatMajor:
		return !v.Prerelease()
	case floatPrereleaseRevision:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && m.parts[2] == v.parts[2] && labelOK
	case floatPrereleasePatch:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && labelOK
	case floatPrereleaseMinor:
		return m.parts[0] == v.parts[0] && labelOK
	case floatPrereleaseMajor:
		return labelOK
	case floatPrerelease:
		return m.parts == v.parts && labelOK
	case floatRevision:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && m.parts[2] == v.parts[2] && !v.Prerelease()
	case floatPatch:
		return m.parts[0] == v.parts[0] && m.parts[1] == v.parts[1] && !v.Prerelease()
	case floatMinor:
		return m.parts[0] == v.parts[0] && !v.Prerelease()
	}
	return false
}

// ParseConstraint is VersionRange.TryParse with floating versions allowed.
func (nugetScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("nuget", "range", expr); err != nil {
		return nil, err
	}
	t := trimCS(expr)
	if t == "" {
		return nil, noConstraint("nuget", expr, "empty")
	}
	r, err := parseNuGetRange(t)
	if err != "" {
		return nil, errorf("nuget", expr, "%s", err)
	}
	r.raw = t
	return r, nil
}

func parseNuGetRange(t string) (*nugetRange, string) {
	r := &nugetRange{}
	if t == "*" {
		r.min, r.minIncl = &nugetVersion{}, true
		r.floating, r.float = true, floatMajor
		return r, ""
	}
	var minText, maxText string
	hasMax := false
	switch t[0] {
	case '[', '(':
		r.minIncl = t[0] == '['
		switch t[len(t)-1] {
		case ']':
			r.maxIncl = true
		case ')':
		default:
			return nil, "an interval must end with \"]\" or \")\""
		}
		if len(t) < 2 {
			return nil, "an empty interval"
		}
		parts := strings.Split(t[1:len(t)-1], ",")
		switch {
		case len(parts) > 2:
			return nil, "an interval has at most two bounds"
		case len(parts) == 2 && parts[0] == "" && parts[1] == "", len(parts) == 1 && parts[0] == "":
			return nil, "an interval names no bound"
		case len(parts) == 1 && !(r.minIncl && r.maxIncl):
			return nil, "a single version must be enclosed in []"
		}
		minText, maxText, hasMax = parts[0], parts[0], true
		if len(parts) == 2 {
			maxText = parts[1]
		}
	default:
		r.minIncl = true
		minText = t
	}
	if strings.TrimFunc(minText, unicode.IsSpace) != "" {
		if strings.Contains(minText, "*") {
			if err := r.parseFloat(minText); err != "" {
				return nil, err
			}
		} else {
			v, err := scanNuGetVersion(trimCS(minText))
			if err != "" {
				return nil, "minimum: " + err
			}
			r.min = v
		}
	}
	if hasMax && strings.TrimFunc(maxText, unicode.IsSpace) != "" {
		v, err := scanNuGetVersion(trimCS(maxText))
		if err != "" {
			return nil, "maximum: " + err
		}
		r.max = v
	}
	if r.min != nil && r.max != nil {
		c := compareNuGet(r.min, r.max)
		if c > 0 || (c == 0 && r.minIncl != r.maxIncl) {
			return nil, "the minimum is above the maximum"
		}
	}
	return r, ""
}

// parseFloat is FloatRange.TryParse on a range's minimum: it sets the
// minimum version, the float behaviour and the release prefix.
func (r *nugetRange) parseFloat(s string) string {
	first, last := strings.IndexByte(s, '*'), strings.LastIndexByte(s, '*')
	hasPlus := strings.IndexByte(s, '+') >= 0
	var actual string
	prefixSet := false
	switch {
	case len(s) == 1 && first == 0:
		r.float, actual = floatMajor, "0.0"
	case s == "*-*":
		r.float, actual, prefixSet = floatAbsoluteLatest, "0.0.0-0", true
	case first != last && !hasPlus:
		// Two stars: "<stable>*-<prefix>*", the first right before the
		// first "-", the second at the end.
		dash := strings.IndexByte(s, '-')
		if dash == -1 || last != len(s)-1 || first != dash-1 {
			return "an invalid floating version"
		}
		stable := s[:dash-1] + "0"
		switch strings.Count(stable, ".") + 1 {
		case 1:
			r.float = floatPrereleaseMajor
		case 2:
			r.float = floatPrereleaseMinor
		case 3:
			r.float = floatPrereleasePatch
		case 4:
			r.float = floatPrereleaseRevision
		}
		release := s[dash+1:]
		r.releasePrefix, prefixSet = release[:len(release)-1], true
		part := r.releasePrefix
		if part == "" || strings.HasSuffix(part, ".") {
			part += "0"
		}
		actual = stable + "-" + part
	case last == len(s)-1 && !hasPlus:
		actual = s[:len(s)-1]
		if strings.IndexByte(s, '-') == -1 {
			actual += "0"
			switch strings.Count(actual, ".") + 1 {
			case 2:
				r.float = floatMinor
			case 3:
				r.float = floatPatch
			case 4:
				r.float = floatRevision
			}
		} else {
			r.float = floatPrerelease
			if strings.IndexByte(s, '-') == strings.LastIndexByte(s, '-') {
				r.releasePrefix, prefixSet = actual[strings.LastIndexByte(s, '-')+1:], true
				switch {
				case r.releasePrefix == "" || strings.HasSuffix(actual, "."):
					actual += "0"
				case strings.HasSuffix(actual, "-"):
					actual += "-"
				}
			}
		}
	default:
		return "an invalid floating version"
	}
	v, err := scanNuGetVersion(trimCS(actual))
	if err != "" {
		return "an invalid floating version: " + err
	}
	if !prefixSet && v.Prerelease() {
		// The FloatRange constructor's default: the minimum's own label.
		r.releasePrefix = v.release()
	}
	r.min, r.floating = v, true
	return ""
}
