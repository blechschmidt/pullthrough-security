package versions

import (
	"strconv"
	"strings"
	"unicode"
)

// pip follows PEP 440 as the packaging library (24.0: version.py,
// specifiers.py, utils.py) implements it, which pip vendors:
//
//   - A version is [N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local], read the way
//     packaging's VERSION_PATTERN reads it: a leading "v", any case, the
//     alternative spellings (alpha, beta, c, pre, preview, rev, r, "-N" for a
//     post-release) and separators (".", "-", "_"), implicit numbers.
//   - Versions order as packaging's _cmpkey: epoch, release without trailing
//     zeros (1.0 == 1.0.0), then dev < pre < final < post (1.0.dev0 <
//     1.0a0), and a local version after its public version, segment-wise
//     with numbers above strings.
//   - A constraint is a specifier set: comma-separated specifiers ("~=",
//     "==", "!=", "<=", ">=", "<", ">", "===", with "==1.2.*" and "!=1.2.*"
//     prefix matches), all of which must hold, with Specifier's exclusive
//     ordered comparisons (<V excludes pre-releases of V, >V post-releases and
//     local versions of V). ParseConstraint takes the specifiers only: the
//     caller strips the name, extras and markers.
//   - Pre-releases follow SpecifierSet.contains with prereleases unspecified:
//     one is allowed only when a specifier of the set (==, >=, <=, ~= or ===)
//     names a pre-release, and an empty set allows none.
//
// Packaging's own helpers are ported as they are, including where they
// misread odd input (a "~=v1.2" specifier never matches in packaging 24.0, and
// does not here). Deviation: only ASCII is read (packaging's case-insensitive
// expressions also match some non-ASCII letters), and numbers are int64.
type pep440Scheme struct{}

func (pep440Scheme) Name() string { return "pip" }

// pep440Local is one segment of a local version label.
type pep440Local struct {
	num bool
	n   int64
	s   string
}

type pep440Version struct {
	raw      string
	epoch    int64
	release  []int64
	hasPre   bool
	preL     string // "a", "b" or "rc"
	preN     int64
	hasPost  bool
	postN    int64
	hasDev   bool
	devN     int64
	hasLocal bool
	local    []pep440Local
}

func (v *pep440Version) String() string { return v.raw }

// Prerelease is packaging's is_prerelease: a pre-release or a dev release.
func (v *pep440Version) Prerelease() bool { return v.hasPre || v.hasDev }

func (v *pep440Version) Release() []int64 {
	return pad3(append([]int64(nil), v.release...))
}

func (v *pep440Version) scheme() string {
	if v == nil {
		return ""
	}
	return "pip"
}

func (pep440Scheme) own(v Version) (*pep440Version, bool) {
	if x, ok := v.(*pep440Version); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parsePEP440(v.String())
	return x, err == nil
}

// Parse is packaging.version.Version.
func (pep440Scheme) Parse(s string) (Version, error) {
	v, err := parsePEP440(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// isPySpace is Python's str.isspace, what \s matches in packaging's
// expressions: Unicode whitespace and the ASCII separators 0x1c-0x1f.
func isPySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

func trimPy(s string) string { return strings.TrimFunc(s, isPySpace) }

func parsePEP440(s string) (*pep440Version, error) {
	if err := checkLength("pip", "version", s); err != nil {
		return nil, err
	}
	v, err := scanPEP440(trimPy(s))
	if err != "" {
		return nil, errorf("pip", s, "%s", err)
	}
	v.raw = s
	return v, nil
}

// pep440Scanner reads a version left to right the way VERSION_PATTERN
// matches it. Every optional part of the pattern either matches where the
// scanner is or is skipped; no later part can make an earlier choice wrong,
// so no backtracking is needed.
type pep440Scanner struct {
	s string // lowercased
	i int
}

func (p *pep440Scanner) sep() bool {
	return p.i < len(p.s) && (p.s[p.i] == '.' || p.s[p.i] == '-' || p.s[p.i] == '_')
}

// word matches one of words at the scanner, in order.
func (p *pep440Scanner) word(words ...string) string {
	for _, w := range words {
		if strings.HasPrefix(p.s[p.i:], w) {
			p.i += len(w)
			return w
		}
	}
	return ""
}

// digits reads a run of ASCII digits.
func (p *pep440Scanner) digits() string {
	j := p.i
	for j < len(p.s) && isDigit(p.s[j]) {
		j++
	}
	d := p.s[p.i:j]
	p.i = j
	return d
}

// letterPart reads [-_.]?(letter)[-_.]?(N)?, returning the letter and the
// number text ("" when implicit); ok is false (and nothing is consumed) when
// no letter matches.
func (p *pep440Scanner) letterPart(letters ...string) (string, string, bool) {
	start := p.i
	if p.sep() {
		p.i++
	}
	l := p.word(letters...)
	if l == "" {
		p.i = start
		return "", "", false
	}
	if p.sep() && p.i+1 < len(p.s) && isDigit(p.s[p.i+1]) {
		p.i++
	} else if p.sep() {
		// A separator with no number after it still belongs to this part
		// ("1.0a." is 1.0a0).
		p.i++
		return l, "", true
	}
	return l, p.digits(), true
}

// pep440Num converts a number of a version, refusing one beyond int64.
func pep440Num(d string) (int64, string) {
	if d == "" {
		return 0, ""
	}
	n, ok := parseDigits(d, maxInt64)
	if !ok {
		return 0, "a number is larger than " + strconv.FormatInt(maxInt64, 10)
	}
	return n, ""
}

// scanPEP440 reads a (trimmed) version.
func scanPEP440(text string) (*pep440Version, string) {
	for i := 0; i < len(text); i++ {
		if text[i] >= 0x80 {
			return nil, "not ASCII"
		}
	}
	p := &pep440Scanner{s: lowerASCII(text)}
	v := &pep440Version{}
	var err string
	if p.i < len(p.s) && p.s[p.i] == 'v' {
		p.i++
	}
	first := p.digits()
	if first == "" {
		return nil, "a release number is missing"
	}
	if p.i < len(p.s) && p.s[p.i] == '!' {
		p.i++
		if v.epoch, err = pep440Num(first); err != "" {
			return nil, err
		}
		if first = p.digits(); first == "" {
			return nil, "a release number is missing after the epoch"
		}
	}
	for d := first; ; {
		n, err := pep440Num(d)
		if err != "" {
			return nil, err
		}
		v.release = append(v.release, n)
		if p.i+1 < len(p.s) && p.s[p.i] == '.' && isDigit(p.s[p.i+1]) {
			p.i++
			d = p.digits()
			continue
		}
		break
	}
	if l, n, ok := p.letterPart("alpha", "a", "beta", "b", "preview", "pre", "c", "rc"); ok {
		v.hasPre = true
		v.preL = map[string]string{"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}[l]
		if v.preN, err = pep440Num(n); err != "" {
			return nil, err
		}
	}
	if p.i+1 < len(p.s) && p.s[p.i] == '-' && isDigit(p.s[p.i+1]) {
		p.i++
		v.hasPost = true
		if v.postN, err = pep440Num(p.digits()); err != "" {
			return nil, err
		}
	} else if _, n, ok := p.letterPart("post", "rev", "r"); ok {
		v.hasPost = true
		if v.postN, err = pep440Num(n); err != "" {
			return nil, err
		}
	}
	if _, n, ok := p.letterPart("dev"); ok {
		v.hasDev = true
		if v.devN, err = pep440Num(n); err != "" {
			return nil, err
		}
	}
	if p.i < len(p.s) && p.s[p.i] == '+' {
		p.i++
		if v.local, err = scanPEP440Local(p); err != "" {
			return nil, err
		}
		v.hasLocal = true
	}
	if p.i != len(p.s) {
		return nil, "unexpected " + strconv.Quote(text[p.i:p.i+1])
	}
	return v, ""
}

// scanPEP440Local reads [a-z0-9]+([-_.][a-z0-9]+)*: segments, numeric ones as
// numbers (_parse_local_version).
func scanPEP440Local(p *pep440Scanner) ([]pep440Local, string) {
	var out []pep440Local
	for {
		j := p.i
		for j < len(p.s) && isAlnum(p.s[j]) {
			j++
		}
		seg := p.s[p.i:j]
		if seg == "" {
			return nil, "a local version segment is empty"
		}
		p.i = j
		if allDigits(seg) {
			n, err := pep440Num(seg)
			if err != "" {
				return nil, err
			}
			out = append(out, pep440Local{num: true, n: n})
		} else {
			out = append(out, pep440Local{s: seg})
		}
		if p.sep() && p.i+1 < len(p.s) && isAlnum(p.s[p.i+1]) {
			p.i++
			continue
		}
		return out, ""
	}
}

// normalized is packaging's str(Version): the canonical spelling.
func (v *pep440Version) normalized() string {
	var b strings.Builder
	b.WriteString(v.public())
	if v.hasLocal {
		b.WriteByte('+')
		b.WriteString(v.localText())
	}
	return b.String()
}

func (v *pep440Version) localText() string {
	parts := make([]string, len(v.local))
	for i, l := range v.local {
		if l.num {
			parts[i] = strconv.FormatInt(l.n, 10)
		} else {
			parts[i] = l.s
		}
	}
	return strings.Join(parts, ".")
}

// public is packaging's Version.public: the normalized version without its
// local label.
func (v *pep440Version) public() string {
	var b strings.Builder
	b.WriteString(v.baseVersion())
	if v.hasPre {
		b.WriteString(v.preL)
		b.WriteString(strconv.FormatInt(v.preN, 10))
	}
	if v.hasPost {
		b.WriteString(".post")
		b.WriteString(strconv.FormatInt(v.postN, 10))
	}
	if v.hasDev {
		b.WriteString(".dev")
		b.WriteString(strconv.FormatInt(v.devN, 10))
	}
	return b.String()
}

// baseVersion is packaging's Version.base_version: epoch and release.
func (v *pep440Version) baseVersion() string {
	var b strings.Builder
	if v.epoch != 0 {
		b.WriteString(strconv.FormatInt(v.epoch, 10))
		b.WriteByte('!')
	}
	for i, n := range v.release {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatInt(n, 10))
	}
	return b.String()
}

// withoutLocal is Version(v.public).
func (v *pep440Version) withoutLocal() *pep440Version {
	w := *v
	w.hasLocal, w.local = false, nil
	return &w
}

// base is Version(v.base_version).
func (v *pep440Version) base() *pep440Version {
	return &pep440Version{epoch: v.epoch, release: v.release}
}

func (s pep440Scheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return comparePEP440(x, y)
}

// comparePEP440 orders by packaging's _cmpkey.
func comparePEP440(a, b *pep440Version) int {
	if c := cmpInt64(a.epoch, b.epoch); c != 0 {
		return c
	}
	// Trailing zeros of the release do not count: compare as if padded.
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		var x, y int64
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := cmpInt64(x, y); c != 0 {
			return c
		}
	}
	if c := cmpInt64(a.preRank(), b.preRank()); c != 0 {
		return c
	}
	if a.hasPre && b.hasPre {
		if c := strings.Compare(a.preL, b.preL); c != 0 {
			return c
		}
		if c := cmpInt64(a.preN, b.preN); c != 0 {
			return c
		}
	}
	// No post-release sorts before any; no dev release after any.
	if c := cmpOptional(a.hasPost, a.postN, b.hasPost, b.postN, false); c != 0 {
		return c
	}
	if c := cmpOptional(a.hasDev, a.devN, b.hasDev, b.devN, true); c != 0 {
		return c
	}
	return compareLocal(a, b)
}

// preRank places the pre-release key: a dev release of a final version
// (1.0.dev0) sorts below every pre-release, a final or post-release above.
func (v *pep440Version) preRank() int64 {
	switch {
	case !v.hasPre && !v.hasPost && v.hasDev:
		return -1
	case !v.hasPre:
		return 1
	}
	return 0
}

// cmpOptional orders two optional numbers; absentHigh says whether a missing
// one sorts above (dev) or below (post) every present one.
func cmpOptional(aHas bool, a int64, bHas bool, b int64, absentHigh bool) int {
	switch {
	case aHas && bHas:
		return cmpInt64(a, b)
	case !aHas && !bHas:
		return 0
	case !aHas && absentHigh, aHas && !absentHigh:
		// a is the absent one and absence ranks high, or a is the present
		// one and absence ranks low.
		return 1
	}
	return -1
}

// compareLocal orders local labels: none sorts first; then segment by
// segment, strings below numbers, strings lexically, numbers numerically; a
// label that is a prefix of the other sorts first.
func compareLocal(a, b *pep440Version) int {
	switch {
	case !a.hasLocal && !b.hasLocal:
		return 0
	case !a.hasLocal:
		return -1
	case !b.hasLocal:
		return 1
	}
	for i := 0; i < len(a.local) && i < len(b.local); i++ {
		x, y := a.local[i], b.local[i]
		switch {
		case x.num && y.num:
			if c := cmpInt64(x.n, y.n); c != 0 {
				return c
			}
		case x.num:
			return 1
		case y.num:
			return -1
		default:
			if c := strings.Compare(x.s, y.s); c != 0 {
				return c
			}
		}
	}
	return cmpInt64(int64(len(a.local)), int64(len(b.local)))
}

// pep440Spec is one Specifier.
type pep440Spec struct {
	op       string
	version  string // the version text as written (stripped)
	parsed   *pep440Version
	wildcard bool // "==" or "!=" with ".*"
}

// pep440Set is a SpecifierSet.
type pep440Set struct {
	raw   string
	specs []pep440Spec
}

func (s *pep440Set) String() string { return s.raw }

// ParseConstraint is packaging.specifiers.SpecifierSet: comma-separated
// specifiers, empty items skipped. The empty set is valid and allows every
// final release.
func (pep440Scheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("pip", "specifier set", expr); err != nil {
		return nil, err
	}
	set := &pep440Set{raw: trimPy(expr)}
	for _, item := range strings.Split(expr, ",") {
		item = trimPy(item)
		if item == "" {
			continue
		}
		if len(set.specs) == MaxTerms {
			return nil, errorf("pip", expr, "more than %d specifiers", MaxTerms)
		}
		spec, err := parsePEP440Spec(item)
		if err != "" {
			return nil, errorf("pip", expr, "invalid specifier %s: %s", quote(item), err)
		}
		set.specs = append(set.specs, spec)
	}
	return set, nil
}

// parsePEP440Spec reads one specifier the way Specifier's expression does:
// which version forms each operator takes differs.
func parsePEP440Spec(item string) (pep440Spec, string) {
	var sp pep440Spec
	for _, op := range []string{"===", "~=", "==", "!=", "<=", ">=", "<", ">"} {
		if strings.HasPrefix(item, op) {
			sp.op = op
			break
		}
	}
	if sp.op == "" {
		return sp, "an operator is missing"
	}
	rest := trimPy(item[len(sp.op):])
	if sp.op == "===" {
		// Arbitrary equality: anything but whitespace, ";" and ")".
		if strings.IndexFunc(rest, func(r rune) bool { return isPySpace(r) || r == ';' || r == ')' }) >= 0 {
			return sp, "an arbitrary version cannot contain whitespace, \";\" or \")\""
		}
		// packaging asks Version(text).is_prerelease of every "==="
		// specifier when a set is evaluated, which raises for text that is no
		// PEP 440 version: pip cannot evaluate such a set at all.
		v, err := scanPEP440(rest)
		if err != "" {
			return sp, "packaging cannot evaluate an arbitrary equality with a version that is not PEP 440"
		}
		sp.version, sp.parsed = rest, v
		return sp, ""
	}
	sp.version = rest
	if (sp.op == "==" || sp.op == "!=") && strings.HasSuffix(rest, ".*") {
		v, err := scanPEP440(rest[:len(rest)-2])
		if err != "" {
			return sp, err
		}
		if v.hasPre || v.hasPost || v.hasDev || v.hasLocal {
			return sp, "a prefix match takes a release only"
		}
		sp.parsed, sp.wildcard = v, true
		return sp, ""
	}
	v, err := scanPEP440(rest)
	if err != "" {
		return sp, err
	}
	switch {
	case v.hasLocal && sp.op != "==" && sp.op != "!=":
		return sp, "a local version is allowed with == and != only"
	case sp.op == "~=" && len(v.release) < 2:
		return sp, "~= needs at least two release segments"
	}
	sp.parsed = v
	return sp, ""
}

// prereleases is Specifier.prereleases: an inclusive operator naming a
// pre-release lets the set allow pre-releases.
func (sp *pep440Spec) prereleases() bool {
	switch sp.op {
	case "==", ">=", "<=", "~=", "===":
		return sp.parsed.Prerelease()
	}
	return false
}

// Allows is SpecifierSet.contains with prereleases unspecified.
func (s *pep440Set) Allows(v Version) bool {
	x, ok := pep440Scheme{}.own(v)
	if !ok {
		return false
	}
	prereleases := false
	for i := range s.specs {
		if s.specs[i].prereleases() {
			prereleases = true
			break
		}
	}
	if !prereleases && x.Prerelease() {
		return false
	}
	for i := range s.specs {
		if !s.specs[i].contains(x) {
			return false
		}
	}
	return true
}

// contains is the specifier's operator (the set has decided pre-releases).
func (sp *pep440Spec) contains(v *pep440Version) bool {
	switch sp.op {
	case "~=":
		return pep440Compatible(v, sp)
	case "==":
		return pep440Equal(v, sp)
	case "!=":
		return !pep440Equal(v, sp)
	case "<=":
		return comparePEP440(v.withoutLocal(), sp.parsed) <= 0
	case ">=":
		return comparePEP440(v.withoutLocal(), sp.parsed) >= 0
	case "<":
		return pep440Less(v, sp.parsed)
	case ">":
		return pep440Greater(v, sp.parsed)
	case "===":
		return strings.EqualFold(v.normalized(), sp.version)
	}
	return false
}

// pep440Compatible is _compare_compatible: ~=V is >=V and ==P.* where P is V
// without its suffix segments and its last release segment.
func pep440Compatible(v *pep440Version, sp *pep440Spec) bool {
	if comparePEP440(v.withoutLocal(), sp.parsed) < 0 {
		return false
	}
	var prefix []string
	for _, seg := range pep440VersionSplit(sp.version) {
		if pep440IsSuffix(seg) {
			break
		}
		prefix = append(prefix, seg)
	}
	if len(prefix) > 0 {
		prefix = prefix[:len(prefix)-1]
	}
	if len(prefix) == 0 {
		return false
	}
	joined := prefix[0] + "!" + strings.Join(prefix[1:], ".")
	return pep440PrefixMatch(v, joined)
}

// pep440Equal is _compare_equal: a prefix match for ".*", else equality, with
// the candidate's local label ignored unless the specifier has one.
func pep440Equal(v *pep440Version, sp *pep440Spec) bool {
	if sp.wildcard {
		return pep440PrefixMatch(v, sp.version[:len(sp.version)-2])
	}
	if !sp.parsed.hasLocal {
		v = v.withoutLocal()
	}
	return comparePEP440(v, sp.parsed) == 0
}

// pep440PrefixMatch is the ".*" branch of _compare_equal: both sides are
// canonicalized and split into segments, the candidate is padded with zeros
// to the specifier's release length and cut to its length, and the segments
// must be equal.
func pep440PrefixMatch(v *pep440Version, spec string) bool {
	split := pep440VersionSplit(pep440Canonicalize(spec))
	cand := pep440VersionSplit(v.public())
	padded := pep440Pad(cand, split)
	if len(padded) < len(split) {
		return false
	}
	padded = padded[:len(split)]
	for i := range split {
		if padded[i] != split[i] {
			return false
		}
	}
	return true
}

// pep440Less is _compare_less_than: <V does not admit a pre-release of V
// unless V is one.
func pep440Less(v, spec *pep440Version) bool {
	if comparePEP440(v, spec) >= 0 {
		return false
	}
	if !spec.Prerelease() && v.Prerelease() && comparePEP440(v.base(), spec.base()) == 0 {
		return false
	}
	return true
}

// pep440Greater is _compare_greater_than: >V does not admit a post-release
// of V unless V is one, nor a local version of V.
func pep440Greater(v, spec *pep440Version) bool {
	if comparePEP440(v, spec) <= 0 {
		return false
	}
	if !spec.hasPost && v.hasPost && comparePEP440(v.base(), spec.base()) == 0 {
		return false
	}
	if v.hasLocal && comparePEP440(v.base(), spec.base()) == 0 {
		return false
	}
	return true
}

// pep440Canonicalize is canonicalize_version(strip_trailing_zero=False): the
// normalized form, or the text unchanged when it is no version.
func pep440Canonicalize(s string) string {
	v, err := scanPEP440(trimPy(s))
	if err != "" {
		return s
	}
	return v.normalized()
}

// pep440VersionSplit is _version_split: the epoch ("0" when absent), then the
// dot-separated items, an item like "1rc1" split into "1" and "rc1".
func pep440VersionSplit(s string) []string {
	epoch, rest := "0", s
	if i := strings.LastIndexByte(s, '!'); i >= 0 {
		epoch, rest = s[:i], s[i+1:]
		if epoch == "" {
			epoch = "0"
		}
	}
	out := []string{epoch}
	for _, item := range strings.Split(rest, ".") {
		if n, suffix, ok := pep440SplitPrefix(item); ok {
			out = append(out, n, suffix)
		} else {
			out = append(out, item)
		}
	}
	return out
}

// pep440SplitPrefix is _prefix_regex, ^([0-9]+)((?:a|b|c|rc)[0-9]+)$.
func pep440SplitPrefix(item string) (string, string, bool) {
	i := 0
	for i < len(item) && isDigit(item[i]) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	rest := item[i:]
	for _, l := range []string{"rc", "a", "b", "c"} {
		if strings.HasPrefix(rest, l) && allDigits(rest[len(l):]) {
			return item[:i], rest, true
		}
	}
	return "", "", false
}

// pep440IsSuffix is the negation of _is_not_suffix.
func pep440IsSuffix(seg string) bool {
	for _, p := range []string{"dev", "a", "b", "rc", "post"} {
		if strings.HasPrefix(seg, p) {
			return true
		}
	}
	return false
}

// pep440Pad is _pad_version for the left side: zeros inserted after its
// leading digit segments up to the right side's count of them.
func pep440Pad(left, right []string) []string {
	ln, rn := pep440LeadingDigits(left), pep440LeadingDigits(right)
	if rn <= ln {
		return left
	}
	out := make([]string, 0, len(left)+rn-ln)
	out = append(out, left[:ln]...)
	for i := ln; i < rn; i++ {
		out = append(out, "0")
	}
	return append(out, left[ln:]...)
}

func pep440LeadingDigits(segs []string) int {
	n := 0
	for n < len(segs) && allDigits(segs[n]) {
		n++
	}
	return n
}
