package versions

import (
	"strconv"
	"strings"
)

// maven follows maven-artifact (Maven 3.9: ComparableVersion, VersionRange,
// Restriction):
//
//   - A version is any string. It orders as ComparableVersion: it is split
//     into items at ".", "-" and every change between digits and letters;
//     numbers compare numerically; qualifiers rank alpha (a) < beta (b) <
//     milestone (m) < rc = cr < snapshot < "" = final = ga = release < sp <
//     every other qualifier (lexically); trailing zero and release items
//     vanish (1 == 1.0 == 1.0.0, 1-ga == 1). Prerelease reports an alpha,
//     beta, milestone, rc or snapshot qualifier.
//   - A constraint is one or more ranges ("[1.0,2.0)", "(,1.0]", "[1.2]",
//     "[1.0,)", "(,1.0],[1.2,)"), a union. A version is in a range by
//     ComparableVersion alone: Maven ranges have no pre-release rule, so
//     [1.0,2.0) contains 2.0-alpha-1 (it orders below 2.0); callers apply
//     their own policy with Prerelease. A bare version ("1.0") is Maven's
//     soft requirement — a recommendation, not a constraint — and is
//     ErrNoConstraint, as are LATEST and RELEASE.
//
// Deviations: a version must consist of ASCII letters, digits, ".", "-", "_"
// and "+" (Maven takes any string; "${...}" properties are the caller's to
// resolve), its numbers must fit an int64, and it must have a shape on which
// ComparableVersion is a total order (see wellOrdered: Maven's order has
// cycles such as 1-alpha < 1 < 1.final.1 < 1-alpha, so versions like
// 1.final.1, 1-0.alpha, 1.0.0-alpha.beta.1 or v1.0 are refused); a bound
// holding a "," is refused where Maven reads "2.0,3.0" as one odd version, an
// empty bound ("[]") where Maven reads an empty version; the expression is
// trimmed first, as Maven's POM reader trims a version element. Maven itself resolves
// dependency ranges with maven-resolver's GenericVersionScheme, whose order
// agrees with ComparableVersion's on ordinary versions but not on every odd
// one.
type mavenScheme struct{}

func (mavenScheme) Name() string { return "maven" }

type mavenVersion struct {
	raw   string
	items *mvnItem
}

func (v *mavenVersion) String() string { return v.raw }
func (v *mavenVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "maven"
}

// Prerelease reports a qualifier ranked below a release: alpha, beta,
// milestone, rc (cr) or snapshot, anywhere in the version.
func (v *mavenVersion) Prerelease() bool { return v.items.hasPrereleaseQualifier() }

// Release returns the leading numbers of the version, as ComparableVersion
// reads them (trailing zeros normalized away, then padded back to three).
func (v *mavenVersion) Release() []int64 {
	var out []int64
	for _, it := range v.items.list {
		if it.kind != mvnNumber {
			break
		}
		out = append(out, it.value())
	}
	return pad3(out)
}

func (mavenScheme) own(v Version) (*mavenVersion, bool) {
	if x, ok := v.(*mavenVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseMavenVersion(v.String())
	return x, err == nil
}

// Parse is new ComparableVersion(s), for the versions maven-metadata.xml
// lists.
func (mavenScheme) Parse(s string) (Version, error) {
	v, err := parseMavenVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func parseMavenVersion(s string) (*mavenVersion, error) {
	if err := checkLength("maven", "version", s); err != nil {
		return nil, err
	}
	if s == "" {
		return nil, errorf("maven", s, "empty")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isAlnum(c) && c != '.' && c != '-' && c != '_' && c != '+' {
			return nil, errorf("maven", s, "unexpected %s", strconv.Quote(s[i:i+1]))
		}
	}
	items, err := parseComparableVersion(s)
	if err != "" {
		return nil, errorf("maven", s, "%s", err)
	}
	if !items.wellOrdered(true) {
		return nil, errorf("maven", s, "a version of this shape is not totally ordered by ComparableVersion (a qualifier inside a list, a leading letter, or a list where a separator or null item starts one)")
	}
	return &mavenVersion{raw: s, items: items}, nil
}

// wellOrdered reports whether a normalized item list has the shape on which
// ComparableVersion is a total order: the top list starts with a number,
// every other list starts with a number or a qualifier, a qualifier appears
// nowhere else, and no list starts with a list.
//
// ComparableVersion ranks, at one position, a number above a list above a
// qualifier, while each compares differently with the end of a shorter
// version: 1-alpha < 1 < 1.final.1 < 1-alpha, a cycle Maven itself has. The
// cycle needs a qualifier and a list at the same position. Lists only ever
// sit at the end of their parent, so with the rule above a qualifier (first
// item of a sub-list) can only meet a number, and a list (last item, never
// first) only a number or a list; normalization has removed null items
// before a list, so a number before one is never zero. Ordinary versions —
// 1.0, 1.0-SNAPSHOT, 2.0.0-M1, 31.1-jre, 7.1.0.Final-redhat-1,
// 2.0.0.v20100429, 1.0.0-alpha.1 — all have this shape.
func (it *mvnItem) wellOrdered(top bool) bool {
	for i, c := range it.list {
		switch c.kind {
		case mvnString:
			if top || i > 0 {
				return false
			}
		case mvnList:
			if i == 0 || !c.wellOrdered(false) {
				return false
			}
		}
	}
	return true
}

func (s mavenScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return x.items.compare(y.items)
}

// mvnKind is the kind of a ComparableVersion item.
type mvnKind uint8

const (
	mvnNumber mvnKind = iota // IntItem, LongItem or BigIntegerItem
	mvnString                // StringItem
	mvnList                  // ListItem
)

// mvnItem is one ComparableVersion item.
type mvnItem struct {
	kind mvnKind
	// digits is a number's text as ComparableVersion keeps it: leading zeros
	// stripped, except that an all-zero run is kept whole.
	digits string
	// width is the Java type a number becomes — 0 int (up to 9 digits), 1
	// long (up to 18), 2 BigInteger — which ComparableVersion compares
	// before the values.
	width int
	// str is a qualifier after its aliases (a1 is alpha, cr is rc, ga is "").
	str  string
	list []*mvnItem
}

// mvnQualifiers is StringItem.QUALIFIERS, lowest first; "" is the release.
var mvnQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

// mvnReleaseIndex is String.valueOf(QUALIFIERS.indexOf("")).
const mvnReleaseIndex = "5"

// comparableQualifier is StringItem.comparableQualifier: a known qualifier's
// index, or "7-" and the qualifier, compared as strings.
func comparableQualifier(q string) string {
	for i, k := range mvnQualifiers {
		if k == q {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mvnQualifiers)) + "-" + q
}

func newMvnString(value string, followedByDigit bool) *mvnItem {
	if followedByDigit && len(value) == 1 {
		switch value {
		case "a":
			value = "alpha"
		case "b":
			value = "beta"
		case "m":
			value = "milestone"
		}
	}
	switch value {
	case "ga", "final", "release":
		value = ""
	case "cr":
		value = "rc"
	}
	return &mvnItem{kind: mvnString, str: value}
}

// newMvnNumber is parseItem for digits: leading zeros are stripped (an
// all-zero run stays as it is), and the length picks the Java type.
func newMvnNumber(buf string) (*mvnItem, string) {
	if buf == "" {
		buf = "0"
	}
	if t := strings.TrimLeft(buf, "0"); t != "" {
		buf = t
		if _, ok := parseDigits(t, maxInt64); !ok {
			return nil, "a number is larger than " + strconv.FormatInt(maxInt64, 10)
		}
	}
	width := 0
	switch {
	case len(buf) > 18:
		width = 2
	case len(buf) > 9:
		width = 1
	}
	return &mvnItem{kind: mvnNumber, digits: buf, width: width}, ""
}

// value is a number item's value; parsing has checked that it fits.
func (it *mvnItem) value() int64 {
	n, _ := parseDigits(strings.TrimLeft(it.digits, "0"), maxInt64)
	return n
}

func (it *mvnItem) isNull() bool {
	switch it.kind {
	case mvnNumber:
		return strings.TrimLeft(it.digits, "0") == ""
	case mvnString:
		return comparableQualifier(it.str) == mvnReleaseIndex
	}
	return len(it.list) == 0
}

// normalize is ListItem.normalize: null items (0, "", an empty list) are
// removed from the end, skipping over non-empty lists.
func (it *mvnItem) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		last := it.list[i]
		if last.isNull() {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.kind != mvnList {
			break
		}
	}
}

func (it *mvnItem) hasPrereleaseQualifier() bool {
	for _, c := range it.list {
		switch c.kind {
		case mvnString:
			if q := comparableQualifier(c.str); q < mvnReleaseIndex && len(q) == 1 {
				return true
			}
		case mvnList:
			if c.hasPrereleaseQualifier() {
				return true
			}
		}
	}
	return false
}

// parseComparableVersion is ComparableVersion.parseVersion.
func parseComparableVersion(version string) (*mvnItem, string) {
	items := &mvnItem{kind: mvnList}
	v := lowerASCII(version)
	list := items
	stack := []*mvnItem{list}
	push := func() {
		l := &mvnItem{kind: mvnList}
		list.list = append(list.list, l)
		list = l
		stack = append(stack, l)
	}
	add := func(isDigit bool, buf string) string {
		if isDigit {
			n, err := newMvnNumber(buf)
			if err != "" {
				return err
			}
			list.list = append(list.list, n)
			return ""
		}
		list.list = append(list.list, newMvnString(buf, false))
		return ""
	}
	digit := false
	start := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-':
			if i == start {
				list.list = append(list.list, &mvnItem{kind: mvnNumber, digits: "0"})
			} else if err := add(digit, v[start:i]); err != "" {
				return nil, err
			}
			start = i + 1
			if c == '-' {
				push()
			}
		case isDigit(c):
			if !digit && i > start {
				// 1.0.0.X1 < 1.0.0-X2: treat .X as -X for any string
				// qualifier X.
				if len(list.list) > 0 {
					push()
				}
				list.list = append(list.list, newMvnString(v[start:i], true))
				start = i
				push()
			}
			digit = true
		default:
			if digit && i > start {
				if err := add(true, v[start:i]); err != "" {
					return nil, err
				}
				start = i
				push()
			}
			digit = false
		}
	}
	if len(v) > start {
		if !digit && len(list.list) > 0 {
			push()
		}
		if err := add(digit, v[start:]); err != "" {
			return nil, err
		}
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return items, ""
}

// compare is Item.compareTo; b may be nil (Java's null: compare with
// nothing).
func (it *mvnItem) compare(b *mvnItem) int {
	switch it.kind {
	case mvnNumber:
		if b == nil {
			if it.isNull() {
				return 0
			}
			return 1
		}
		switch b.kind {
		case mvnNumber:
			if it.width != b.width {
				return cmpInt64(int64(it.width), int64(b.width))
			}
			return cmpDigits(it.digits, b.digits)
		default:
			return 1 // 1.1 > 1-sp, 1.1 > 1-1
		}
	case mvnString:
		if b == nil {
			// 1-rc < 1, 1-ga > 1
			return strings.Compare(comparableQualifier(it.str), mvnReleaseIndex)
		}
		switch b.kind {
		case mvnString:
			return strings.Compare(comparableQualifier(it.str), comparableQualifier(b.str))
		default:
			return -1 // 1.any < 1.1, 1.any < 1-1
		}
	}
	if b == nil {
		for _, c := range it.list {
			if r := c.compare(nil); r != 0 {
				return r
			}
		}
		return 0
	}
	switch b.kind {
	case mvnNumber:
		return -1 // 1-1 < 1.0.x
	case mvnString:
		return 1 // 1-1 > 1-sp
	}
	for i := 0; i < len(it.list) || i < len(b.list); i++ {
		var l, r *mvnItem
		if i < len(it.list) {
			l = it.list[i]
		}
		if i < len(b.list) {
			r = b.list[i]
		}
		var c int
		switch {
		case l == nil && r == nil:
		case l == nil:
			c = -r.compare(nil)
		default:
			c = l.compare(r)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// mavenRestriction is a Restriction: bounds may be absent.
type mavenRestriction struct {
	lower, upper         *mavenVersion
	lowerIncl, upperIncl bool
}

// contains is Restriction.containsVersion.
func (r *mavenRestriction) contains(v *mavenVersion) bool {
	if r.lower != nil {
		c := r.lower.items.compare(v.items)
		if c > 0 || (c == 0 && !r.lowerIncl) {
			return false
		}
	}
	if r.upper != nil {
		c := r.upper.items.compare(v.items)
		if c < 0 || (c == 0 && !r.upperIncl) {
			return false
		}
	}
	return true
}

// mavenRange is a VersionRange with restrictions (a union).
type mavenRange struct {
	raw          string
	restrictions []mavenRestriction
}

func (r *mavenRange) String() string { return r.raw }

// Allows is VersionRange.containsVersion.
func (r *mavenRange) Allows(v Version) bool {
	x, ok := mavenScheme{}.own(v)
	if !ok {
		return false
	}
	for i := range r.restrictions {
		if r.restrictions[i].contains(x) {
			return true
		}
	}
	return false
}

// trimJava is String.trim: it removes every character up to U+0020.
func trimJava(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return r <= ' ' })
}

// ParseConstraint is VersionRange.createFromVersionSpec.
func (mavenScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("maven", "version range", expr); err != nil {
		return nil, err
	}
	process := trimJava(expr)
	r := &mavenRange{raw: process}
	var upper *mavenVersion
	for strings.HasPrefix(process, "[") || strings.HasPrefix(process, "(") {
		if len(r.restrictions) == MaxTerms {
			return nil, errorf("maven", expr, "more than %d ranges", MaxTerms)
		}
		i1, i2 := strings.IndexByte(process, ')'), strings.IndexByte(process, ']')
		index := i2
		if (i2 < 0 || i1 < i2) && i1 >= 0 {
			index = i1
		}
		if index < 0 {
			return nil, errorf("maven", expr, "unbounded range")
		}
		res, err := parseMavenRestriction(process[:index+1])
		if err != "" {
			return nil, errorf("maven", expr, "%s", err)
		}
		if upper != nil && (res.lower == nil || res.lower.items.compare(upper.items) < 0) {
			return nil, errorf("maven", expr, "ranges overlap")
		}
		r.restrictions = append(r.restrictions, res)
		upper = res.upper
		process = trimJava(process[index+1:])
		if strings.HasPrefix(process, ",") {
			process = trimJava(process[1:])
		}
	}
	if process != "" {
		if len(r.restrictions) > 0 {
			return nil, errorf("maven", expr, "only fully-qualified sets allowed in multiple set scenario")
		}
		if strings.Contains(process, "${") {
			return nil, errorf("maven", expr, "an unresolved property")
		}
		return nil, noConstraint("maven", expr, "a soft requirement (a recommended version, not a range)")
	}
	if len(r.restrictions) == 0 {
		return nil, noConstraint("maven", expr, "empty")
	}
	return r, nil
}

// parseMavenRestriction is VersionRange.parseRestriction for "[a,b)" and
// the like.
func parseMavenRestriction(spec string) (mavenRestriction, string) {
	r := mavenRestriction{lowerIncl: spec[0] == '[', upperIncl: spec[len(spec)-1] == ']'}
	process := trimJava(spec[1 : len(spec)-1])
	i := strings.IndexByte(process, ',')
	if i < 0 {
		if !r.lowerIncl || !r.upperIncl {
			return r, "a single version must be surrounded by []"
		}
		v, err := parseMavenVersion(process)
		if err != nil {
			return r, "bound: " + err.Error()
		}
		r.lower, r.upper = v, v
		return r, ""
	}
	lowerText, upperText := trimJava(process[:i]), trimJava(process[i+1:])
	if strings.IndexByte(upperText, ',') >= 0 {
		return r, "a range has at most two bounds"
	}
	var err error
	if lowerText != "" {
		if r.lower, err = parseMavenVersion(lowerText); err != nil {
			return r, "lower bound: " + err.Error()
		}
	}
	if upperText != "" {
		if r.upper, err = parseMavenVersion(upperText); err != nil {
			return r, "upper bound: " + err.Error()
		}
	}
	if r.lower != nil && r.upper != nil {
		c := r.upper.items.compare(r.lower.items)
		if c < 0 || (c == 0 && (!r.lowerIncl || !r.upperIncl)) {
			return r, "range defies version ordering"
		}
	}
	return r, ""
}
