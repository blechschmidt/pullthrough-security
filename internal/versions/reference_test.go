package versions

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The reference corpora in testdata/ were produced by the real tools
// (node-semver 7.7 and 7.8, the semver crate 1.0, packaging 24.0, x/mod
// semver, NuGet.Versioning 6.9, maven-artifact 3.9, RubyGems 3.6) from the
// strings of each tool's own test suite plus the tricky cases of this
// package's tests; testdata/reference/gen.sh regenerates them byte for byte.
//
//   - <scheme>-versions.tsv: a version (JSON-quoted) and its rank in the
//     tool's order, equal versions sharing a rank; -1 when the tool refuses
//     it. (go: a third column, 1 for a pseudo-version; maven: a matrix of
//     direct comparisons instead of a rank, see TestMavenReference.)
//   - <scheme>-constraints.tsv (npm-ranges.tsv): a first line
//     "# [universe]" (the versions every constraint was evaluated against),
//     then per constraint its text; "ok", "invalid", "differs" (two releases
//     disagree), "raises" (the tool cannot evaluate it) or "soft" (Maven's
//     soft requirement); a scheme-specific detail; and one 0/1 per universe
//     version: whether the tool allows it.
//
// The tests below hold the schemes to those results: validity, order,
// allowed versions — and for npm the desugared form, node-semver's
// Range.range. Every difference is listed, with its reason, as a deviation.

// refVersion is a line of a versions corpus.
type refVersion struct {
	text string
	rank int
}

// refConstraint is a line of a constraints corpus.
type refConstraint struct {
	text string
	ok   bool
	// differs marks a constraint two releases of the tool read differently
	// (npm: node-semver 7.7 and 7.8), or one the tool parses but cannot
	// evaluate (pip: "raises"): it must be refused.
	differs bool
	// soft marks an expression the tool reads as no constraint (Maven's
	// soft requirement): it must be ErrNoConstraint.
	soft   bool
	detail string
	bits   string
}

func refPath(name string) string { return filepath.Join("testdata", name) }

func readRefVersions(t *testing.T, name string) []refVersion {
	t.Helper()
	var out []refVersion
	for _, f := range readTSV(t, name) {
		if len(f) != 2 {
			t.Fatalf("%s: malformed line %q", name, f)
		}
		rank, err := strconv.Atoi(f[1])
		if err != nil {
			t.Fatalf("%s: rank %q", name, f[1])
		}
		out = append(out, refVersion{text: unquoteJSON(t, f[0]), rank: rank})
	}
	return out
}

func readRefConstraints(t *testing.T, name string) ([]string, []refConstraint) {
	t.Helper()
	raw, err := os.ReadFile(refPath(name))
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(raw), "\n")
	var universe []string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(header, "# ")), &universe); err != nil {
		t.Fatalf("%s: universe: %v", name, err)
	}
	var out []refConstraint
	for _, f := range readTSV(t, name) {
		if len(f) != 4 {
			t.Fatalf("%s: malformed line %q", name, f)
		}
		c := refConstraint{text: unquoteJSON(t, f[0]), ok: f[1] == "ok", differs: f[1] == "differs" || f[1] == "raises", soft: f[1] == "soft", bits: f[3]}
		if f[2] != "" {
			c.detail = unquoteJSON(t, f[2])
		}
		if c.ok && len(c.bits) != len(universe) {
			t.Fatalf("%s: %q has %d results for %d versions", name, c.text, len(c.bits), len(universe))
		}
		out = append(out, c)
	}
	return universe, out
}

func readTSV(t *testing.T, name string) [][]string {
	t.Helper()
	f, err := os.Open(refPath(name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, "\t"))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func unquoteJSON(t *testing.T, s string) string {
	t.Helper()
	var out string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("unquote %s: %v", s, err)
	}
	return out
}

// checkRefVersions holds Parse and Compare to a versions corpus: the same
// versions are refused, and every pair of accepted ones orders as the tool
// orders them.
func checkRefVersions(t *testing.T, s Scheme, name string, deviations map[string]string) {
	t.Helper()
	refs := readRefVersions(t, name)
	var parsed []Version
	var ranks []int
	for _, r := range refs {
		v, err := s.Parse(r.text)
		if _, known := deviations[r.text]; known {
			continue
		}
		switch {
		case r.rank < 0 && err == nil:
			t.Errorf("%s: Parse(%q) = %v, the tool refuses it", s.Name(), r.text, v)
		case r.rank >= 0 && err != nil:
			t.Errorf("%s: Parse(%q): %v, the tool accepts it", s.Name(), r.text, err)
		case err == nil:
			parsed = append(parsed, v)
			ranks = append(ranks, r.rank)
		}
	}
	if len(parsed) < 10 {
		t.Fatalf("%s: only %d versions to order", name, len(parsed))
	}
	bad := 0
	for i := range parsed {
		for j := range parsed {
			want := cmpInt64(int64(ranks[i]), int64(ranks[j]))
			if got := s.Compare(parsed[i], parsed[j]); got != want && bad < 20 {
				bad++
				t.Errorf("%s: Compare(%q, %q) = %d, the tool says %d", s.Name(), parsed[i], parsed[j], got, want)
			}
		}
	}
}

// checkRefConstraints holds ParseConstraint and Allows to a constraints
// corpus. A constraint the tool refuses must be refused; one it accepts must
// be accepted — unless listed in deviations, the documented refusals — and
// allow exactly what the tool allows. detail, when set, checks the
// scheme-specific column.
func checkRefConstraints(t *testing.T, s Scheme, name string, deviations, versionDeviations map[string]string, detail func(t *testing.T, c Constraint, want string)) {
	t.Helper()
	universe, rows := readRefConstraints(t, name)
	versions := make([]Version, len(universe))
	for i, text := range universe {
		v, err := s.Parse(text)
		if _, known := versionDeviations[text]; err != nil && !known {
			t.Fatalf("%s: universe version %q: %v", name, text, err)
		}
		versions[i] = v // nil for a version deviation: not checked
	}
	accepted, refused := 0, 0
	for _, r := range rows {
		c, err := s.ParseConstraint(r.text)
		why, deviation := deviations[r.text]
		switch {
		case r.soft && deviation:
			continue
		case r.soft:
			if !errors.Is(err, ErrNoConstraint) && !strings.Contains(r.text, "${") {
				t.Errorf("%s: ParseConstraint(%q) = %v, %v; the tool reads no constraint", s.Name(), r.text, c, err)
			}
			continue
		case r.differs && err == nil:
			t.Errorf("%s: ParseConstraint(%q) accepted what releases of the tool read differently (%s)", s.Name(), r.text, c)
			continue
		case !r.ok && err == nil && deviation:
			continue
		case !r.ok && err == nil:
			t.Errorf("%s: ParseConstraint(%q) accepted what the tool refuses (%s)", s.Name(), r.text, c)
			continue
		case !r.ok:
			refused++
			continue
		case err != nil && deviation:
			continue
		case err != nil:
			t.Errorf("%s: ParseConstraint(%q): %v; the tool accepts it", s.Name(), r.text, err)
			continue
		case deviation:
			t.Errorf("%s: %q is listed as a deviation (%s) but is accepted", s.Name(), r.text, why)
		}
		accepted++
		if detail != nil {
			detail(t, c, r.detail)
		}
		for i, v := range versions {
			if v == nil {
				continue
			}
			want := r.bits[i] == '1'
			if got := c.Allows(v); got != want {
				t.Errorf("%s: %q Allows(%q) = %v, the tool says %v", s.Name(), r.text, v, got, want)
			}
		}
	}
	for text := range deviations {
		found := false
		for _, r := range rows {
			found = found || r.text == text
		}
		if !found {
			t.Errorf("%s: deviation %q is not in the corpus", name, text)
		}
	}
	if accepted < 20 || refused < 5 {
		t.Fatalf("%s: %d accepted and %d refused constraints is too thin a corpus", name, accepted, refused)
	}
}

// npmDeviations are ranges node-semver accepts that this package refuses on
// purpose (see npmScheme): each only by an accident of node-semver's regular
// expressions.
var npmDeviations = map[string]string{
	">= 1 +build < 2": "a comparator that is nothing but build metadata, which node-semver erases",
	"+1.2.3":          "a range that is nothing but build metadata, which node-semver reads as any version",
	"1.2.3*":          "a star after a version, which node-semver's star replacement deletes",
}

func TestNpmReference(t *testing.T) {
	s, _ := For("npm")
	checkRefVersions(t, s, "npm-versions.tsv", nil)
	checkRefConstraints(t, s, "npm-ranges.tsv", npmDeviations, nil, func(t *testing.T, c Constraint, want string) {
		r, ok := c.(*npmRange)
		if !ok {
			t.Errorf("npm: %q parsed as %T", c, c)
			return
		}
		if got := r.desugared(); got != want {
			t.Errorf("npm: %q desugars to %q, node-semver to %q", c, got, want)
		}
	})
}

// cargoVersionDeviations are versions the semver crate accepts and this
// package refuses: numbers beyond int64 (the crate's are u64).
var cargoVersionDeviations = map[string]string{
	"9223372036854775808.0.0": "a number beyond int64",
}

var cargoDeviations = map[string]string{
	"9223372036854775808.0.0": "a number beyond int64",
	"^18446744073709551615":   "a number beyond int64",
}

func TestCargoReference(t *testing.T) {
	s, _ := For("cargo")
	checkRefVersions(t, s, "cargo-versions.tsv", cargoVersionDeviations)
	checkRefConstraints(t, s, "cargo-constraints.tsv", cargoDeviations, cargoVersionDeviations, nil)
}

// pipVersionDeviations are versions packaging accepts and this package
// refuses: numbers beyond int64 (Python's integers are unbounded).
var pipVersionDeviations = map[string]string{
	"9223372036854775808":         "a number beyond int64",
	"1.0+9223372036854775808":     "a number beyond int64",
	"1.0.post9223372036854775808": "a number beyond int64",
}

func TestPipReference(t *testing.T) {
	s, _ := For("pip")
	checkRefVersions(t, s, "pip-versions.tsv", pipVersionDeviations)
	checkRefConstraints(t, s, "pip-constraints.tsv", nil, pipVersionDeviations, nil)
}

// goVersionDeviations are versions x/mod/semver accepts and this package
// refuses: numbers beyond int64 (x/mod compares digit strings).
var goVersionDeviations = map[string]string{
	"v9223372036854775808.0.0": "a number beyond int64",
}

// TestGoReference holds the go scheme to golang.org/x/mod/semver (the copy
// vendored in GOROOT): validity, order, and module.IsPseudoVersion. The
// versions corpus has a third column, 1 for a pseudo-version.
func TestGoReference(t *testing.T) {
	s, _ := For("go")
	var parsed []Version
	var ranks []int
	for _, f := range readTSV(t, "go-versions.tsv") {
		text := unquoteJSON(t, f[0])
		rank, _ := strconv.Atoi(f[1])
		v, err := s.Parse(text)
		if _, known := goVersionDeviations[text]; known {
			continue
		}
		switch {
		case rank < 0 && err == nil:
			t.Errorf("go: Parse(%q) accepted what x/mod refuses", text)
		case rank >= 0 && err != nil:
			t.Errorf("go: Parse(%q): %v", text, err)
		case err == nil:
			parsed = append(parsed, v)
			ranks = append(ranks, rank)
			if got, want := IsPseudoVersion(v), f[2] == "1"; got != want {
				t.Errorf("go: IsPseudoVersion(%q) = %v, module.IsPseudoVersion says %v", text, got, want)
			}
		}
	}
	for i := range parsed {
		for j := range parsed {
			if got, want := s.Compare(parsed[i], parsed[j]), cmpInt64(int64(ranks[i]), int64(ranks[j])); got != want {
				t.Errorf("go: Compare(%q, %q) = %d, x/mod says %d", parsed[i], parsed[j], got, want)
			}
		}
	}
	if len(parsed) < 50 {
		t.Fatalf("only %d versions", len(parsed))
	}
}

func TestNuGetReference(t *testing.T) {
	s, _ := For("nuget")
	checkRefVersions(t, s, "nuget-versions.tsv", nil)
	checkRefConstraints(t, s, "nuget-constraints.tsv", nil, nil, nil)
}

// mavenRefused are the corpus versions maven-artifact orders and this
// package refuses, each for a documented reason: a character outside
// [A-Za-z0-9._+-] (Maven takes any string), a number beyond int64, or a shape
// on which ComparableVersion is no total order (see mvnItem.wellOrdered).
func mavenRefused(text string) string {
	for i := 0; i < len(text); i++ {
		if c := text[i]; !isAlnum(c) && strings.IndexByte("._+-", c) < 0 {
			return "a character outside [A-Za-z0-9._+-]"
		}
	}
	switch {
	case text == "9223372036854775808", text == "12345678901234567890.1H.5-beta":
		return "a number beyond int64"
	case text != "" && isLetter(text[0]) && !releaseAlias[lowerASCII(text)]:
		// "RELEASE" alone normalizes to nothing (it equals "0").
		return "starts with a letter: not totally ordered"
	case mavenShapeRefused[text]:
		return "not totally ordered"
	}
	return ""
}

var releaseAlias = map[string]bool{"ga": true, "final": true, "release": true}

// mavenShapeRefused lists, as reviewed, the corpus versions starting with a
// digit that are refused for their shape: a list where a null item starts
// one (1-0.alpha is [1, [[alpha]]]), a qualifier inside a list
// (1.0.BUILD-SNAPSHOT is [1, 0, build, [snapshot]]).
var mavenShapeRefused = map[string]bool{
	"1-0.alpha":          true,
	"1-0.beta":           true,
	"1.0.BUILD-SNAPSHOT": true,
}

// TestMavenReference holds the maven scheme to maven-artifact 3.9. The
// versions corpus is a matrix of ComparableVersion's direct comparisons (it
// cannot be a sorted list: Maven's order has cycles), the constraints corpus
// VersionRange.containsVersion, with "soft" for a bare version.
func TestMavenReference(t *testing.T) {
	s, _ := For("maven")
	raw, err := os.ReadFile(refPath("maven-versions.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(raw), "\n")
	var matrix []string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(header, "# ")), &matrix); err != nil {
		t.Fatal(err)
	}
	parsed := make([]Version, len(matrix))
	for i, text := range matrix {
		v, err := s.Parse(text)
		why := mavenRefused(text)
		switch {
		case err != nil && why == "":
			t.Errorf("maven: Parse(%q): %v; maven-artifact orders it", text, err)
		case err == nil && why != "":
			t.Errorf("maven: Parse(%q) accepted, but it is listed as refused (%s)", text, why)
		}
		parsed[i] = v
	}
	compared := 0
	for _, f := range readTSV(t, "maven-versions.tsv") {
		text := unquoteJSON(t, f[0])
		v, err := s.Parse(text)
		if err != nil {
			if mavenRefused(text) == "" {
				t.Errorf("maven: Parse(%q): %v", text, err)
			}
			continue
		}
		for j, w := range parsed {
			if w == nil {
				continue
			}
			want := map[byte]int{'<': -1, '=': 0, '>': 1}[f[1][j]]
			if got := s.Compare(v, w); got != want {
				t.Errorf("maven: Compare(%q, %q) = %d, ComparableVersion says %d", text, w, got, want)
			}
			compared++
		}
	}
	if compared < 10000 {
		t.Fatalf("only %d comparisons", compared)
	}
	deviations := map[string]string{
		" [1.0,2.0) ":   "trimmed, as Maven's POM reader trims a version; VersionRange alone reads a soft version",
		"[1.0,2.0,3.0]": "a bound with a comma, which Maven reads as the odd version \"2.0,3.0\"",
		"[]":            "an empty bound, which Maven reads as an empty version",
		"[${a},${b})":   "unresolved properties",
	}
	versionDeviations := map[string]string{}
	for _, text := range matrix {
		if why := mavenRefused(text); why != "" {
			versionDeviations[text] = why
		}
	}
	checkRefConstraints(t, s, "maven-constraints.tsv", deviations, versionDeviations, nil)
}

// rubygemsVersionDeviations are versions RubyGems accepts and this package
// refuses: numbers beyond int64 (Ruby's integers are unbounded).
var rubygemsVersionDeviations = map[string]string{
	"9223372036854775808": "a number beyond int64",
}

// rubygemsDeviations: a blank requirement is the default (">= 0") here, as
// an empty one is for RubyGems (Gem::Requirement.new with no conditions),
// where Gem::Requirement.parse refuses blank text; and "~>" whose bump
// leaves int64.
var rubygemsDeviations = map[string]string{
	" ":                      "blank: the default requirement",
	"  ":                     "blank: the default requirement",
	"   ":                    "blank: the default requirement",
	"~> 9223372036854775807": "a bump beyond int64",
}

func TestRubyGemsReference(t *testing.T) {
	s, _ := For("rubygems")
	checkRefVersions(t, s, "rubygems-versions.tsv", rubygemsVersionDeviations)
	checkRefConstraints(t, s, "rubygems-constraints.tsv", rubygemsDeviations, rubygemsVersionDeviations, nil)
}
