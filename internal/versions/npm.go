package versions

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// npm follows node-semver v7 (classes/semver.js, classes/range.js,
// classes/comparator.js) as npm evaluates a package.json range, in strict
// mode with includePrerelease off:
//
//   - A version is MAJOR.MINOR.PATCH[-PRE][+BUILD] with numbers no larger
//     than Number.MAX_SAFE_INTEGER and at most 256 characters; a leading "v"
//     or "=" is tolerated the way semver.clean strips it. Build metadata does
//     not order.
//   - A range is "||"-separated alternatives of space-separated comparators.
//     Each comparator desugars as node-semver's parseComparator does — caret,
//     tilde, X-ranges and partial versions, hyphen ranges — into primitive
//     comparators (<, <=, >, >=, =), and a version satisfies an alternative
//     when it satisfies every comparator of it and, if it is a pre-release,
//     some comparator names a pre-release of the same MAJOR.MINOR.PATCH.
//
// Deliberate deviations, all refusals of input node-semver accepts only by
// accident of its regular expressions: a comparator that is nothing but build
// metadata ("+build", which node-semver erases into "any version") and a "*"
// outside an X-range position ("1.2.3*", whose star node-semver deletes) are
// errors here. Where node-semver 7.7 and 7.8 read a range differently (7.8
// refuses "1.x.3" and "x.1", which 7.7 read as "1.x" and "*"), the range is
// refused.
type npmScheme struct{}

// npmMaxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER, the largest
// version number node-semver accepts.
const npmMaxSafeInteger = 1<<53 - 1

// npmMaxLength is node-semver's MAX_LENGTH for a version string.
const npmMaxLength = 256

func (npmScheme) Name() string { return "npm" }

type npmVersion struct {
	raw string
	v   semver
}

func (v *npmVersion) String() string   { return v.raw }
func (v *npmVersion) Prerelease() bool { return len(v.v.pre) > 0 }
func (v *npmVersion) Release() []int64 { return []int64{v.v.major, v.v.minor, v.v.patch} }
func (v *npmVersion) scheme() string {
	if v == nil {
		return ""
	}
	return "npm"
}

func (s npmScheme) own(v Version) (*npmVersion, bool) {
	if x, ok := v.(*npmVersion); ok {
		return x, x != nil
	}
	if v == nil {
		return nil, false
	}
	x, err := parseNpmVersion(v.String())
	return x, err == nil
}

// Parse reads a version the way semver.clean does: surrounding whitespace and
// leading "=" and "v" characters are dropped, the rest must be a strict
// SemVer version.
func (npmScheme) Parse(s string) (Version, error) {
	v, err := parseNpmVersion(s)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func parseNpmVersion(s string) (*npmVersion, error) {
	if err := checkLength("npm", "version", s); err != nil {
		return nil, err
	}
	// semver.clean: trim, drop leading "=" and "v" characters; then the
	// SemVer constructor (at most 256 characters) trims again and reads an
	// optional "v" and the version.
	t := strings.TrimLeft(trimJS(s), "=v")
	if len(t) > npmMaxLength {
		return nil, errorf("npm", s, "longer than %d characters", npmMaxLength)
	}
	t = strings.TrimPrefix(trimJS(t), "v")
	core, err := parseStrictSemver(t, npmMaxSafeInteger)
	if err != "" {
		return nil, errorf("npm", s, "%s", err)
	}
	return &npmVersion{raw: s, v: core}, nil
}

// parseStrictSemver reads MAJOR.MINOR.PATCH[-PRE][+BUILD] exactly, as
// node-semver's FULL expression and the semver crate's Version::parse both
// require.
func parseStrictSemver(s string, max int64) (semver, string) {
	var v semver
	var err string
	i := 0
	for n, part := range []*int64{&v.major, &v.minor, &v.patch} {
		if *part, i, err = readNumber(s, i, max); err != "" {
			return v, err
		}
		if n < 2 {
			if i >= len(s) || s[i] != '.' {
				return v, "not MAJOR.MINOR.PATCH"
			}
			i++
		}
	}
	if i < len(s) && s[i] == '-' {
		if v.pre, i, err = readIdentifiers(s, i+1, true); err != "" {
			return v, "pre-release: " + err
		}
	}
	if i < len(s) && s[i] == '+' {
		if v.build, i, err = readIdentifiers(s, i+1, false); err != "" {
			return v, "build metadata: " + err
		}
	}
	if i != len(s) {
		return v, "unexpected " + strconv.Quote(s[i:i+1])
	}
	return v, ""
}

func (s npmScheme) Compare(a, b Version) int {
	x, aok := s.own(a)
	y, bok := s.own(b)
	if c, done := compareInvalid(aok, bok); done {
		return c
	}
	return x.v.compare(&y.v)
}

// ParseConstraint reads a package.json dependency spec. A spec that is no
// registry range — a git, file, link, URL, workspace or tarball spec, a dist
// tag — is ErrNoConstraint; an "npm:<name>@<range>" alias is its range.
func (npmScheme) ParseConstraint(expr string) (Constraint, error) {
	if err := checkLength("npm", "range", expr); err != nil {
		return nil, err
	}
	spec := trimJS(expr)
	if strings.HasPrefix(spec, "npm:") {
		return parseNpmAlias(expr, spec[len("npm:"):])
	}
	if what := npmNonRegistry(spec); what != "" {
		return nil, noConstraint("npm", expr, what)
	}
	r, err := parseNpmRange(spec)
	if err == nil {
		r.raw = spec
		return r, nil
	}
	if npmDistTag(spec) {
		return nil, noConstraint("npm", expr, "a dist-tag")
	}
	return nil, err
}

// parseNpmAlias reads the target of an "npm:" alias the way
// npm-package-arg splits it: the name ends at the first "@" after its first
// byte (a scope's "@" is the first byte), and a missing range is "*".
func parseNpmAlias(expr, target string) (Constraint, error) {
	at := -1
	if len(target) > 1 {
		if i := strings.IndexByte(target[1:], '@'); i >= 0 {
			at = i + 1
		}
	}
	name, rng := target, "*"
	if at > 0 {
		name, rng = target[:at], strings.TrimSpace(target[at+1:])
		if rng == "" {
			rng = "*"
		}
	}
	if name == "" || strings.ContainsAny(name, " :") {
		return nil, errorf("npm", expr, "not an alias of a registry package")
	}
	if npmNonRegistry(rng) != "" {
		return nil, errorf("npm", expr, "an alias must name a registry range")
	}
	r, err := parseNpmRange(rng)
	if err == nil {
		r.raw = trimJS(expr)
		return r, nil
	}
	if npmDistTag(rng) {
		return nil, noConstraint("npm", expr, "an alias of a dist-tag")
	}
	return nil, err
}

// npmProtocols are the package.json spec prefixes of dependencies that do not
// come from the registry: npm-package-arg's git, file, directory and remote
// types, and the protocols of yarn and pnpm workspaces.
var npmProtocols = []string{
	"file:", "link:", "git+", "git:", "git@", "github:", "gitlab:", "bitbucket:",
	"gist:", "http:", "https:", "workspace:", "portal:", "patch:", "exec:",
	"catalog:", "jsr:",
}

// npmNonRegistry names what a spec is when it is no registry range, or
// returns "". A range never contains a slash, a backslash or a colon, so
// anything with one is a URL, a path or a hosted-git shortcut ("user/repo").
func npmNonRegistry(spec string) string {
	lower := lowerASCII(spec)
	for _, p := range npmProtocols {
		if strings.HasPrefix(lower, p) {
			return "a " + strings.TrimRight(p, ":+@") + " spec"
		}
	}
	switch {
	case strings.HasSuffix(lower, ".tgz"), strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tar"):
		return "a tarball"
	case strings.HasPrefix(spec, "."), strings.HasPrefix(spec, "~/"), strings.ContainsAny(spec, `/\`):
		return "a path or git repository"
	}
	return ""
}

// npmDistTag reports a spec npm would read as a dist-tag ("latest", "next",
// "beta"): npm-package-arg's tag rule (no valid range, only characters
// encodeURIComponent leaves alone), narrowed to tags that start with a letter
// and do not read as a version — node-semver's loose mode, which npm uses to
// tell ranges from tags, accepts "v1.2.3beta" as a version, and a tag must not
// swallow it.
func npmDistTag(spec string) bool {
	if spec == "" || !isLetter(spec[0]) {
		return false
	}
	if c := spec[0] | 0x20; (c == 'v' || c == 'x') && (len(spec) == 1 || !isLetter(spec[1])) {
		return false
	}
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if !isAlnum(c) && strings.IndexByte("-_.!~*'()", c) < 0 {
			return false
		}
	}
	return true
}

// npmOp is a primitive comparator's operator.
type npmOp uint8

const (
	npmAny npmOp = iota // node-semver's ANY: the empty comparator
	npmEQ
	npmLT
	npmLE
	npmGT
	npmGE
)

var npmOpText = [...]string{npmAny: "", npmEQ: "", npmLT: "<", npmLE: "<=", npmGT: ">", npmGE: ">="}

// npmComparator is a primitive comparator after desugaring.
type npmComparator struct {
	op npmOp
	v  semver
}

func (c *npmComparator) test(v *semver) bool {
	if c.op == npmAny {
		return true
	}
	cmp := v.compare(&c.v)
	switch c.op {
	case npmEQ:
		return cmp == 0
	case npmLT:
		return cmp < 0
	case npmLE:
		return cmp <= 0
	case npmGT:
		return cmp > 0
	case npmGE:
		return cmp >= 0
	}
	return false
}

// value is node-semver's Comparator.value: the operator and the version.
func (c *npmComparator) value() string {
	if c.op == npmAny {
		return ""
	}
	return npmOpText[c.op] + formatSemver(&c.v)
}

// npmRange is a parsed range: alternatives of comparator sets.
type npmRange struct {
	raw  string
	sets [][]npmComparator
}

func (r *npmRange) String() string { return r.raw }

// Allows is node-semver's Range.test.
func (r *npmRange) Allows(v Version) bool {
	x, ok := npmScheme{}.own(v)
	if !ok {
		return false
	}
	for _, set := range r.sets {
		if npmTestSet(set, &x.v) {
			return true
		}
	}
	return false
}

// npmTestSet is node-semver's testSet: every comparator holds, and a
// pre-release is admitted only by a comparator that names a pre-release of
// the same MAJOR.MINOR.PATCH (^1.2.3-pr.1 admits 1.2.3-pr.2, never
// 1.2.4-alpha).
func npmTestSet(set []npmComparator, v *semver) bool {
	for i := range set {
		if !set[i].test(v) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for i := range set {
		c := &set[i]
		if c.op != npmAny && len(c.v.pre) > 0 && c.v.samePatch(v) {
			return true
		}
	}
	return false
}

// desugared is node-semver's Range.range: the comparator sets as they test,
// with node-semver's simplifications (a null set alone, duplicates and
// redundant "any" comparators removed), joined by "||". It exists so tests
// can hold the desugaring to node-semver's output.
func (r *npmRange) desugared() string {
	sets := make([][]npmComparator, 0, len(r.sets))
	for _, set := range r.sets {
		sets = append(sets, npmSimplifySet(set))
	}
	if len(sets) > 1 {
		first := sets[0]
		kept := sets[:0:0]
		for _, set := range sets {
			if !npmIsNullSet(set[0]) {
				kept = append(kept, set)
			}
		}
		switch {
		case len(kept) == 0:
			sets = [][]npmComparator{first}
		case len(kept) > 1:
			sets = kept
			for _, set := range kept {
				if len(set) == 1 && set[0].op == npmAny {
					sets = [][]npmComparator{set}
					break
				}
			}
		default:
			sets = kept
		}
	}
	parts := make([]string, len(sets))
	for i, set := range sets {
		comps := make([]string, len(set))
		for j := range set {
			comps[j] = set[j].value()
		}
		parts[i] = strings.Join(comps, " ")
	}
	return strings.Join(parts, "||")
}

// npmSimplifySet applies parseRange's rangeMap: ">=0.0.0" is "any", a null
// set ("<0.0.0-0") replaces the whole set, comparators are unique by value
// (first position kept), and "any" goes when anything else is left.
func npmSimplifySet(set []npmComparator) []npmComparator {
	var out []npmComparator
	seen := map[string]int{}
	for _, c := range set {
		if c.op == npmGE && len(c.v.pre) == 0 && c.v.major == 0 && c.v.minor == 0 && c.v.patch == 0 {
			c = npmComparator{op: npmAny}
		}
		if npmIsNullSet(c) {
			return []npmComparator{c}
		}
		if i, dup := seen[c.value()]; dup {
			out[i] = c
			continue
		}
		seen[c.value()] = len(out)
		out = append(out, c)
	}
	if len(out) > 1 {
		if i, ok := seen[""]; ok {
			out = append(out[:i], out[i+1:]...)
		}
	}
	return out
}

func npmIsNullSet(c npmComparator) bool {
	return c.op == npmLT && c.v.major == 0 && c.v.minor == 0 && c.v.patch == 0 &&
		len(c.v.pre) == 1 && c.v.pre[0] == "0"
}

// parseNpmRange is node-semver's Range constructor (strict, without
// includePrerelease) for a spec already known to be a range candidate.
func parseNpmRange(spec string) (*npmRange, error) {
	raw := collapseJSSpace(spec)
	alts := strings.Split(raw, "||")
	if len(alts) > MaxTerms {
		return nil, errorf("npm", spec, "more than %d alternatives", MaxTerms)
	}
	r := &npmRange{raw: spec}
	terms := 0
	for _, alt := range alts {
		alt = strings.Trim(alt, " ")
		terms += strings.Count(alt, " ") + 1
		if terms > MaxTerms {
			return nil, errorf("npm", spec, "more than %d comparators", MaxTerms)
		}
		set, err := parseNpmSet(alt)
		if err != "" {
			return nil, errorf("npm", spec, "%s", err)
		}
		r.sets = append(r.sets, set)
	}
	return r, nil
}

// parseNpmSet reads one alternative: a hyphen range, or comparators.
func parseNpmSet(alt string) ([]npmComparator, string) {
	if alt == "" {
		return []npmComparator{{op: npmAny}}, ""
	}
	if i := strings.Index(alt, " - "); i >= 0 {
		from, ferr := parseNpmPartial(alt[:i])
		to, terr := parseNpmPartial(alt[i+3:])
		if ferr == "" && terr == "" {
			return npmHyphen(from, to)
		}
		// node-semver's hyphen expression does not match: the "-" is then a
		// comparator of its own, which is invalid.
		return nil, "invalid comparator \"-\""
	}
	var set []npmComparator
	for _, word := range npmMergeOperators(strings.Split(alt, " ")) {
		comps, err := parseNpmComparator(word)
		if err != "" {
			return nil, err
		}
		set = append(set, comps...)
	}
	return set, ""
}

// npmMergeOperators joins an operator to the version that follows it after a
// space, in the order node-semver's comparator, tilde and caret "trim" passes
// do: "> 1.2" is ">1.2", "~> 1.2" is "~1.2", "^ 1.2" is "^1.2".
func npmMergeOperators(words []string) []string {
	words = npmMergePass(words, func(w, next string) (string, bool) {
		switch w {
		case "<", ">", "<=", ">=", "=":
			if npmStartsPartial(next) {
				return w + next, true
			}
		}
		return "", false
	})
	words = npmMergePass(words, func(w, next string) (string, bool) {
		if w == "~" || w == "~>" {
			return "~" + next, true
		}
		return "", false
	})
	return npmMergePass(words, func(w, next string) (string, bool) {
		if w == "^" {
			return "^" + next, true
		}
		return "", false
	})
}

func npmMergePass(words []string, merge func(w, next string) (string, bool)) []string {
	out := make([]string, 0, len(words))
	for i := 0; i < len(words); i++ {
		if i+1 < len(words) {
			if m, ok := merge(words[i], words[i+1]); ok {
				out = append(out, m)
				i++
				continue
			}
		}
		out = append(out, words[i])
	}
	return out
}

// npmStartsPartial reports whether a word starts a version or X-range after
// any "v" and "=" prefix: what node-semver's comparator trim needs to see
// after an operator.
func npmStartsPartial(w string) bool {
	w = strings.TrimLeft(w, "v=")
	return w != "" && (isDigit(w[0]) || w[0] == 'x' || w[0] == 'X' || w[0] == '*')
}

// npmPartial is a version as an X-range spells it: each of major, minor and
// patch is digits, "x", "X", "*", or absent ("").
type npmPartial struct {
	prefix          string
	major, minor    string
	patch           string
	pre             []string
	majorN, minorN  int64
	patchN          int64
	full, wildcards bool
}

func npmIsX(id string) bool { return id == "" || id == "x" || id == "X" || id == "*" }

// parseNpmPartial reads node-semver's XRANGEPLAIN: a "v"/"=" prefix, then
// one to three components, then — after a third — a pre-release and build
// metadata.
func parseNpmPartial(s string) (npmPartial, string) {
	var p npmPartial
	i := 0
	for i < len(s) && (s[i] == 'v' || s[i] == '=') {
		i++
	}
	p.prefix = s[:i]
	ids := []*string{&p.major, &p.minor, &p.patch}
	for n := 0; n < 3; n++ {
		j := i
		switch {
		case j < len(s) && (s[j] == 'x' || s[j] == 'X' || s[j] == '*'):
			j++
		case j < len(s) && isDigit(s[j]):
			for j < len(s) && isDigit(s[j]) {
				j++
			}
			if s[i] == '0' && j-i > 1 {
				return p, "a number has a leading zero"
			}
		default:
			return p, "a version is missing or malformed"
		}
		*ids[n] = s[i:j]
		i = j
		if n < 2 && i < len(s) && s[i] == '.' {
			i++
			continue
		}
		break
	}
	var err string
	if p.patch != "" {
		if i < len(s) && s[i] == '-' {
			if p.pre, i, err = readIdentifiers(s, i+1, true); err != "" {
				return p, "pre-release: " + err
			}
			for _, id := range p.pre {
				if !npmBoundedPreIdent(id) {
					return p, "a pre-release identifier is too long"
				}
			}
		}
		if i < len(s) && s[i] == '+' {
			var build []string
			if build, i, err = readIdentifiers(s, i+1, false); err != "" {
				return p, "build metadata: " + err
			}
			for _, id := range build {
				if len(id) > npmMaxBuildIdent {
					return p, "a build identifier is too long"
				}
			}
		}
	}
	if i != len(s) {
		return p, "unexpected " + strconv.Quote(s[i:i+1])
	}
	for _, id := range []struct {
		text string
		n    *int64
	}{{p.major, &p.majorN}, {p.minor, &p.minorN}, {p.patch, &p.patchN}} {
		if npmIsX(id.text) {
			p.wildcards = true
			continue
		}
		// node-semver checks a number only where a comparator uses it
		// ("^x.9007199254740992" is "*"): a larger one is kept as one past
		// the limit, which npmCmp refuses when it builds a comparator.
		v, ok := parseDigits(id.text, npmMaxSafeInteger)
		if !ok {
			v = npmMaxSafeInteger + 1
		}
		*id.n = v
	}
	p.full = !p.wildcards
	return p, ""
}

// npmCmp builds a primitive comparator, refusing a version node-semver could
// not construct (a number above MAX_SAFE_INTEGER, a string over 256
// characters).
func npmCmp(op npmOp, major, minor, patch int64, pre []string) (npmComparator, string) {
	c := npmComparator{op: op, v: semver{major: major, minor: minor, patch: patch, pre: pre}}
	if major > npmMaxSafeInteger || minor > npmMaxSafeInteger || patch > npmMaxSafeInteger {
		return c, "a bound is larger than Number.MAX_SAFE_INTEGER"
	}
	if len(formatSemver(&c.v)) > npmMaxLength {
		return c, "a version is longer than 256 characters"
	}
	return c, ""
}

// npmMaxBuildIdent is the longest build identifier node-semver's
// length-bounded expressions match (MAX_SAFE_BUILD_LENGTH).
const npmMaxBuildIdent = npmMaxLength - 6

// npmBoundedPreIdent reports whether a pre-release identifier fits
// node-semver's length-bounded expressions: a numeric one at most 257 digits,
// an alphanumeric one at most 256 leading digits, a letter or hyphen, and
// npmMaxBuildIdent more characters.
func npmBoundedPreIdent(id string) bool {
	if allDigits(id) {
		return len(id) <= npmMaxLength+1
	}
	lead := 0
	for lead < len(id) && isDigit(id[lead]) {
		lead++
	}
	return lead <= npmMaxLength && len(id)-lead-1 <= npmMaxBuildIdent
}

// npmZeroPre is the "-0" pre-release node-semver puts on an exclusive upper
// bound so that no pre-release of the bound itself passes.
var npmZeroPre = []string{"0"}

// npmBuild collects comparators and the first error.
type npmBuild struct {
	out []npmComparator
	err string
}

func (b *npmBuild) add(op npmOp, major, minor, patch int64, pre []string) {
	if b.err != "" {
		return
	}
	c, err := npmCmp(op, major, minor, patch, pre)
	if err != "" {
		b.err = err
		return
	}
	b.out = append(b.out, c)
}

func (b *npmBuild) done() ([]npmComparator, string) {
	if b.err != "" {
		return nil, b.err
	}
	if len(b.out) == 0 {
		return []npmComparator{{op: npmAny}}, ""
	}
	return b.out, ""
}

// npmHyphen is node-semver's hyphenReplace: "1.2.3 - 2.3.4" is
// ">=1.2.3 <=2.3.4", and a partial upper bound excludes what follows it
// ("1.2.3 - 2.3" is ">=1.2.3 <2.4.0-0").
func npmHyphen(from, to npmPartial) ([]npmComparator, string) {
	var b npmBuild
	switch {
	case npmIsX(from.major):
	case npmIsX(from.minor):
		b.add(npmGE, from.majorN, 0, 0, nil)
	case npmIsX(from.patch):
		b.add(npmGE, from.majorN, from.minorN, 0, nil)
	default:
		// node-semver keeps the text as written here (">=" + from), which
		// its comparator only reads with no prefix or a single "v".
		if from.prefix != "" && from.prefix != "v" {
			return nil, "invalid comparator \">=" + from.prefix + "\""
		}
		b.add(npmGE, from.majorN, from.minorN, from.patchN, from.pre)
	}
	switch {
	case npmIsX(to.major):
	case npmIsX(to.minor):
		b.add(npmLT, to.majorN+1, 0, 0, npmZeroPre)
	case npmIsX(to.patch):
		b.add(npmLT, to.majorN, to.minorN+1, 0, npmZeroPre)
	case len(to.pre) > 0:
		b.add(npmLE, to.majorN, to.minorN, to.patchN, to.pre)
	default:
		if to.prefix != "" && to.prefix != "v" {
			return nil, "invalid comparator \"<=" + to.prefix + "\""
		}
		b.add(npmLE, to.majorN, to.minorN, to.patchN, nil)
	}
	return b.done()
}

// parseNpmComparator desugars one comparator word as parseComparator does:
// build metadata is dropped, then caret, tilde and X-range forms are
// replaced by primitive comparators.
func parseNpmComparator(word string) ([]npmComparator, string) {
	w, stripped := npmStripBuild(word)
	if stripped && w == "" {
		return nil, "a comparator is nothing but build metadata"
	}
	switch {
	case w == "":
		return []npmComparator{{op: npmAny}}, ""
	case w[0] == '^':
		p, err := parseNpmPartial(w[1:])
		if err != "" {
			return nil, "invalid caret range " + strconv.Quote(word) + ": " + err
		}
		return npmCaret(p)
	case w[0] == '~':
		rest := strings.TrimPrefix(w[1:], ">")
		p, err := parseNpmPartial(rest)
		if err != "" {
			return nil, "invalid tilde range " + strconv.Quote(word) + ": " + err
		}
		return npmTilde(p)
	}
	op, rest := npmReadGTLT(w)
	p, err := parseNpmPartial(rest)
	if err != "" {
		return nil, "invalid comparator " + strconv.Quote(word) + ": " + err
	}
	return npmXRange(op, p, word)
}

// npmStripBuild removes the first build-metadata run ("+" and identifiers)
// from a comparator, as parseComparator's BUILD replacement does wherever it
// occurs.
func npmStripBuild(w string) (string, bool) {
	for i := 0; i+1 < len(w); i++ {
		if w[i] != '+' || !(isAlnum(w[i+1]) || w[i+1] == '-') {
			continue
		}
		// An identifier is at most npmMaxBuildIdent characters in
		// node-semver's (length-bounded) expression; the match ends there.
		j := i + 1
		for {
			start := j
			for j < len(w) && j-start < npmMaxBuildIdent && (isAlnum(w[j]) || w[j] == '-') {
				j++
			}
			if j-start < npmMaxBuildIdent && j+1 < len(w) && w[j] == '.' && (isAlnum(w[j+1]) || w[j+1] == '-') {
				j++
				continue
			}
			break
		}
		return w[:i] + w[j:], true
	}
	return w, false
}

// npmReadGTLT reads node-semver's GTLT operator: "<", ">", "<=", ">=", "="
// or none.
func npmReadGTLT(w string) (string, string) {
	for _, op := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(w, op) {
			return op, w[len(op):]
		}
	}
	return "", w
}

// npmCaret is node-semver's replaceCaret: changes that do not modify the
// left-most non-zero of major, minor and patch.
func npmCaret(p npmPartial) ([]npmComparator, string) {
	var b npmBuild
	M, m, pt := p.majorN, p.minorN, p.patchN
	switch {
	case npmIsX(p.major):
	case npmIsX(p.minor):
		b.add(npmGE, M, 0, 0, nil)
		b.add(npmLT, M+1, 0, 0, npmZeroPre)
	case npmIsX(p.patch):
		b.add(npmGE, M, m, 0, nil)
		if M == 0 {
			b.add(npmLT, M, m+1, 0, npmZeroPre)
		} else {
			b.add(npmLT, M+1, 0, 0, npmZeroPre)
		}
	default:
		b.add(npmGE, M, m, pt, p.pre)
		switch {
		case M == 0 && m == 0:
			b.add(npmLT, M, m, pt+1, npmZeroPre)
		case M == 0:
			b.add(npmLT, M, m+1, 0, npmZeroPre)
		default:
			b.add(npmLT, M+1, 0, 0, npmZeroPre)
		}
	}
	return b.done()
}

// npmTilde is node-semver's replaceTilde: patch-level changes when a minor
// version is given, minor-level changes when not.
func npmTilde(p npmPartial) ([]npmComparator, string) {
	var b npmBuild
	M, m, pt := p.majorN, p.minorN, p.patchN
	switch {
	case npmIsX(p.major):
	case npmIsX(p.minor):
		b.add(npmGE, M, 0, 0, nil)
		b.add(npmLT, M+1, 0, 0, npmZeroPre)
	case npmIsX(p.patch):
		b.add(npmGE, M, m, 0, nil)
		b.add(npmLT, M, m+1, 0, npmZeroPre)
	default:
		b.add(npmGE, M, m, pt, p.pre)
		b.add(npmLT, M, m+1, 0, npmZeroPre)
	}
	return b.done()
}

// npmXRange is node-semver's replaceXRange for a comparator with an optional
// GTLT operator; a full version without wildcards is a primitive comparator.
func npmXRange(gtlt string, p npmPartial, word string) ([]npmComparator, string) {
	var b npmBuild
	M, m := p.majorN, p.minorN
	xM, xm := npmIsX(p.major), npmIsX(p.major) || npmIsX(p.minor)
	if p.full {
		// The comparator is read as written: GTLT, an optional "v", the
		// version (Comparator's COMPARATOR expression).
		if p.prefix != "" && p.prefix != "v" {
			return nil, "invalid comparator " + strconv.Quote(word)
		}
		op := map[string]npmOp{"": npmEQ, "=": npmEQ, "<": npmLT, "<=": npmLE, ">": npmGT, ">=": npmGE}[gtlt]
		b.add(op, p.majorN, p.minorN, p.patchN, p.pre)
		return b.done()
	}
	// A wildcard followed by a number ("x.1", "1.x.3") is refused, as
	// node-semver 7.8 refuses it; 7.7 read it as the wildcard alone.
	if (xM && !npmIsX(p.minor)) || (npmIsX(p.minor) && p.patch != "" && !npmIsX(p.patch)) {
		return nil, "invalid comparator " + strconv.Quote(word) + ": a number after a wildcard"
	}
	if gtlt == "=" {
		gtlt = ""
	}
	switch {
	case xM:
		if gtlt == ">" || gtlt == "<" {
			b.add(npmLT, 0, 0, 0, npmZeroPre) // nothing is allowed
		}
		// Otherwise nothing is forbidden: "*".
	case gtlt != "":
		pm, pp := m, int64(0)
		if xm {
			pm = 0
		}
		op := gtlt
		switch op {
		case ">":
			op = ">="
			if xm {
				M, pm, pp = M+1, 0, 0
			} else {
				pm, pp = pm+1, 0
			}
		case "<=":
			op = "<"
			if xm {
				M++
			} else {
				pm++
			}
		}
		var pre []string
		if op == "<" {
			pre = npmZeroPre
		}
		b.add(map[string]npmOp{"<": npmLT, ">=": npmGE}[op], M, pm, pp, pre)
	case xm:
		b.add(npmGE, M, 0, 0, nil)
		b.add(npmLT, M+1, 0, 0, npmZeroPre)
	default:
		b.add(npmGE, M, m, 0, nil)
		b.add(npmLT, M, m+1, 0, npmZeroPre)
	}
	return b.done()
}

// isJSSpace reports what JavaScript's \s and String.prototype.trim treat as
// whitespace: Unicode White_Space and the byte-order mark, but not U+0085.
func isJSSpace(r rune) bool {
	return r == '\ufeff' || (r != '\u0085' && unicode.IsSpace(r))
}

// trimJS is String.prototype.trim.
func trimJS(s string) string {
	return strings.TrimFunc(s, isJSSpace)
}

// collapseJSSpace is node-semver's first step on a range: trim, then replace
// every run of whitespace by one space.
func collapseJSSpace(s string) string {
	s = trimJS(s)
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if isJSSpace(r) {
			if !inSpace {
				b.WriteByte(' ')
			}
			inSpace = true
		} else {
			b.WriteString(s[i : i+size])
			inSpace = false
		}
		i += size
	}
	return b.String()
}
