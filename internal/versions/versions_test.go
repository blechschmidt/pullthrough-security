package versions

import (
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func TestFor(t *testing.T) {
	for _, name := range []string{"npm", "cargo", "pip", "go", "nuget", "maven", "rubygems"} {
		s, ok := For(name)
		if !ok || s.Name() != name {
			t.Errorf("For(%q) = %v, %v", name, s, ok)
		}
	}
	for _, name := range []string{"", "docker", "composer", "pypi", "NPM", "git"} {
		if s, ok := For(name); ok {
			t.Errorf("For(%q) = %v", name, s)
		}
	}
	if got := strings.Join(Supported(), ","); got != "cargo,go,maven,npm,nuget,pip,rubygems" {
		t.Errorf("Supported() = %s", got)
	}
}

func TestLevelString(t *testing.T) {
	for l, want := range map[Level]string{LevelNone: "none", LevelPatch: "patch", LevelMinor: "minor", LevelMajor: "major", Level(9): "level(9)"} {
		if got := l.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", int(l), got, want)
		}
	}
}

func TestBump(t *testing.T) {
	for _, tc := range []struct {
		scheme, from, to string
		want             Level
	}{
		// Caret semantics: the left-most non-zero component breaks.
		{"npm", "1.2.3", "1.2.4", LevelPatch},
		{"npm", "1.2.3", "1.3.0", LevelMinor},
		{"npm", "1.2.3", "2.0.0", LevelMajor},
		{"npm", "0.2.3", "0.2.4", LevelPatch},
		{"npm", "0.2.3", "0.3.0", LevelMajor},
		{"npm", "0.0.3", "0.0.4", LevelMajor},
		{"npm", "0.0.0", "0.0.1", LevelMajor},
		{"npm", "1.2.3-beta", "1.2.3", LevelPatch},
		{"npm", "1.2.3", "1.2.3", LevelNone},
		{"npm", "1.2.3", "1.2.3+build", LevelNone},
		{"npm", "1.2.3", "1.2.2", LevelNone},
		{"npm", "1.2.3", "1.2.4-0", LevelPatch},
		{"cargo", "0.2.3", "0.3.0", LevelMajor},
		{"cargo", "0.2.3", "0.2.4", LevelPatch},
		{"cargo", "0.0.3", "0.0.4", LevelMajor},
		{"cargo", "1.2.3", "1.4.0", LevelMinor},
		// Go: the major number, the module path's.
		{"go", "v0.1.0", "v0.2.0", LevelMinor},
		{"go", "v1.2.3", "v1.2.4", LevelPatch},
		{"go", "v1.2.3", "v2.0.0", LevelMajor},
		{"go", "v2.0.0+incompatible", "v2.1.0+incompatible", LevelMinor},
		{"go", "v1.2.3", "v1.2.4-0.20210101000000-abcdef123456", LevelPatch},
		// Plain components.
		{"pip", "0.2.3", "0.3.0", LevelMinor},
		{"pip", "1.0", "1.0.1", LevelPatch},
		{"pip", "1.0", "1.0.post1", LevelPatch},
		{"pip", "1.0rc1", "1.0", LevelPatch},
		{"pip", "1.9", "2.0", LevelMajor},
		{"pip", "1.0", "1!1.0", LevelMajor},
		{"pip", "1.0", "1.0.0", LevelNone},
		{"nuget", "1.0", "1.0.0.1", LevelPatch},
		{"nuget", "1.2.3", "1.3", LevelMinor},
		{"nuget", "1.0", "2.0.0-beta", LevelMajor},
		{"maven", "1.0-SNAPSHOT", "1.0", LevelPatch},
		{"maven", "1.9", "2.0-alpha-1", LevelMajor},
		{"maven", "1.0", "1.1", LevelMinor},
		{"maven", "1.0", "1.0.0", LevelNone},
		{"rubygems", "1.0", "1.1", LevelMinor},
		{"rubygems", "2.2", "3.0", LevelMajor},
		{"rubygems", "1.0.0.rc1", "1.0.0", LevelPatch},
	} {
		s := mustScheme(t, tc.scheme)
		if got := Bump(s, mustParse(t, s, tc.from), mustParse(t, s, tc.to)); got != tc.want {
			t.Errorf("%s: Bump(%s, %s) = %s, want %s", tc.scheme, tc.from, tc.to, got, tc.want)
		}
	}
}

func TestWithin(t *testing.T) {
	npm := mustScheme(t, "npm")
	v := func(s string) Version { return mustParse(t, npm, s) }
	for _, tc := range []struct {
		from, to string
		max      Level
		want     bool
	}{
		{"1.2.3", "1.9.0", LevelMinor, true},
		{"1.2.3", "2.0.0", LevelMinor, false},
		{"1.2.3", "2.0.0", LevelMajor, true},
		{"1.2.3", "1.2.4", LevelPatch, true},
		{"1.2.3", "1.3.0", LevelPatch, false},
		{"0.2.3", "0.2.9", LevelPatch, true},
		{"0.2.3", "0.3.0", LevelMinor, false},
		{"1.2.3", "1.2.3", LevelMajor, false},
		{"1.2.3", "1.2.2", LevelMajor, false},
		{"1.2.3", "1.2.4", LevelNone, false},
	} {
		if got := Within(npm, v(tc.from), v(tc.to), tc.max); got != tc.want {
			t.Errorf("Within(%s, %s, %s) = %v", tc.from, tc.to, tc.max, got)
		}
	}
}

func TestSameMajorOtherSchemes(t *testing.T) {
	for _, tc := range []struct {
		scheme, v       string
		allowed, denied []string
	}{
		{"npm", "1.2.3", []string{"1.2.3", "1.9.0"}, []string{"1.2.2", "2.0.0"}},
		{"pip", "2.0", []string{"2.0", "2.9", "2.0.post1"}, []string{"1.9", "3.0"}},
		{"maven", "1.0-SNAPSHOT", []string{"1.0-SNAPSHOT", "1.0", "1.9"}, []string{"1.0-alpha", "2.0"}},
	} {
		s := mustScheme(t, tc.scheme)
		c := SameMajor(s, mustParse(t, s, tc.v))
		for _, v := range tc.allowed {
			if !c.Allows(mustParse(t, s, v)) {
				t.Errorf("%s: %s does not allow %s", tc.scheme, c, v)
			}
		}
		for _, v := range tc.denied {
			if c.Allows(mustParse(t, s, v)) {
				t.Errorf("%s: %s allows %s", tc.scheme, c, v)
			}
		}
	}
	npm := mustScheme(t, "npm")
	if got := SameMajor(npm, mustParse(t, npm, "1.2.3")).String(); got != ">=1.2.3 <2 (same major)" {
		t.Errorf("String() = %q", got)
	}
	if c := SameMajor(npm, nil); c.Allows(mustParse(t, npm, "1.0.0")) || c.String() == "" {
		t.Errorf("SameMajor(nil) = %s allows a version", c)
	}
}

func TestIntersect(t *testing.T) {
	npm := mustScheme(t, "npm")
	caret, _ := npm.ParseConstraint("^1.2.3")
	below, _ := npm.ParseConstraint("<1.5.0")
	c := Intersect(caret, nil, below)
	for v, want := range map[string]bool{"1.2.3": true, "1.4.9": true, "1.5.0": false, "1.2.2": false} {
		if got := c.Allows(mustParse(t, npm, v)); got != want {
			t.Errorf("%s Allows(%s) = %v", c, v, got)
		}
	}
	if c.String() != "(^1.2.3) && (<1.5.0)" {
		t.Errorf("String() = %q", c.String())
	}
	same := SameMajor(npm, mustParse(t, npm, "1.2.3"))
	if !All(caret, same).Allows(mustParse(t, npm, "1.9.0")) || All(caret, same).Allows(mustParse(t, npm, "1.2.2")) {
		t.Error("All(caret, same major) is wrong")
	}
	for _, all := range []Constraint{Intersect(), All(), Intersect(nil)} {
		if !all.Allows(mustParse(t, npm, "1.0.0")) || all.String() != "*" {
			t.Errorf("%s does not allow everything", all)
		}
		if all.Allows(nil) {
			t.Error("the empty intersection allows a nil version")
		}
	}
}

// TestTotalOrder holds every scheme's Compare to a total order on the valid
// versions of its reference corpus: shuffled and sorted, the result is
// ascending; Compare is reflexive, antisymmetric and transitive on every
// triple; and Sort keeps equal versions in their order.
func TestTotalOrder(t *testing.T) {
	for _, tc := range []struct{ scheme, file string }{
		{"npm", "npm-versions.tsv"}, {"cargo", "cargo-versions.tsv"}, {"pip", "pip-versions.tsv"},
		{"nuget", "nuget-versions.tsv"}, {"rubygems", "rubygems-versions.tsv"},
		{"go", "go-versions.tsv"}, {"maven", "maven-versions.tsv"},
	} {
		s := mustScheme(t, tc.scheme)
		var vs []Version
		for _, f := range readTSV(t, tc.file) {
			if v, err := s.Parse(unquoteJSON(t, f[0])); err == nil {
				vs = append(vs, v)
			}
		}
		rng := rand.New(rand.NewSource(1))
		rng.Shuffle(len(vs), func(i, j int) { vs[i], vs[j] = vs[j], vs[i] })
		if len(vs) > 150 {
			vs = vs[:150]
		}
		n := len(vs)
		cmp := make([][]int, n)
		for i := range vs {
			cmp[i] = make([]int, n)
			for j := range vs {
				cmp[i][j] = s.Compare(vs[i], vs[j])
			}
		}
		bad := 0
		for i := 0; i < n && bad < 5; i++ {
			if cmp[i][i] != 0 {
				t.Errorf("%s: Compare(%s, %s) = %d", tc.scheme, vs[i], vs[i], cmp[i][i])
				bad++
			}
			for j := 0; j < n; j++ {
				if cmp[i][j] != -cmp[j][i] {
					t.Errorf("%s: Compare(%s, %s) = %d but Compare(%s, %s) = %d", tc.scheme, vs[i], vs[j], cmp[i][j], vs[j], vs[i], cmp[j][i])
					bad++
				}
				if cmp[i][j] > 0 {
					continue
				}
				for k := 0; k < n; k++ {
					if cmp[j][k] <= 0 && cmp[i][k] > 0 {
						t.Errorf("%s: %s <= %s <= %s but %s > %s", tc.scheme, vs[i], vs[j], vs[k], vs[i], vs[k])
						bad++
					}
				}
			}
		}
		sorted := append([]Version(nil), vs...)
		Sort(s, sorted)
		for i := 1; i < len(sorted); i++ {
			if s.Compare(sorted[i-1], sorted[i]) > 0 {
				t.Errorf("%s: sorted %s before %s", tc.scheme, sorted[i-1], sorted[i])
			}
		}
		if n < 50 {
			t.Errorf("%s: only %d versions to order", tc.scheme, n)
		}
	}
	// Stable: equal versions keep their order.
	npm := mustScheme(t, "npm")
	vs := []Version{mustParse(t, npm, "2.0.0"), mustParse(t, npm, "1.0.0+b"), mustParse(t, npm, "1.0.0"), mustParse(t, npm, "1.0.0+a")}
	Sort(npm, vs)
	if got := vs[0].String() + " " + vs[1].String() + " " + vs[2].String() + " " + vs[3].String(); got != "1.0.0+b 1.0.0 1.0.0+a 2.0.0" {
		t.Errorf("Sort = %s", got)
	}
}

// foreignVersion is a Version of no scheme of this package.
type foreignVersion string

func (f foreignVersion) String() string   { return string(f) }
func (f foreignVersion) Prerelease() bool { return false }
func (f foreignVersion) Release() []int64 { return []int64{9, 9, 9} }

// A version of another scheme, a foreign implementation or nil is judged by
// its text, or as no version; nothing panics.
func TestForeignAndNilVersions(t *testing.T) {
	npm, cargo := mustScheme(t, "npm"), mustScheme(t, "cargo")
	c, _ := cargo.ParseConstraint("^1.2")
	if !c.Allows(mustParse(t, npm, "1.5.0")) || !c.Allows(foreignVersion("1.2.0")) || c.Allows(foreignVersion("v1.2.0")) {
		t.Error("a cargo requirement misjudges versions of other origins")
	}
	if cargo.Compare(foreignVersion("1.0.0"), mustParse(t, cargo, "1.0.0")) != 0 {
		t.Error("a foreign version is not read by its text")
	}
	for _, s := range []Scheme{npm, cargo, mustScheme(t, "pip"), mustScheme(t, "go"), mustScheme(t, "nuget"), mustScheme(t, "maven"), mustScheme(t, "rubygems")} {
		var typedNil Version
		switch s.Name() {
		case "npm":
			typedNil = (*npmVersion)(nil)
		case "cargo":
			typedNil = (*cargoVersion)(nil)
		case "pip":
			typedNil = (*pep440Version)(nil)
		case "go":
			typedNil = (*goVersion)(nil)
		case "nuget":
			typedNil = (*nugetVersion)(nil)
		case "maven":
			typedNil = (*mavenVersion)(nil)
		case "rubygems":
			typedNil = (*gemVersion)(nil)
		}
		valid := map[string]string{"npm": "1.0.0", "cargo": "1.0.0", "pip": "1.0", "go": "v1.0.0", "nuget": "1.0", "maven": "1.0", "rubygems": "1.0"}[s.Name()]
		v := mustParse(t, s, valid)
		for _, bad := range []Version{nil, typedNil, foreignVersion("not a version")} {
			if s.Compare(bad, v) != -1 || s.Compare(v, bad) != 1 || s.Compare(bad, bad) != 0 {
				t.Errorf("%s: an unreadable version does not sort first", s.Name())
			}
			if Bump(s, bad, v) != LevelNone || Bump(s, v, bad) != LevelNone || Within(s, bad, v, LevelMajor) {
				t.Errorf("%s: Bump with an unreadable version", s.Name())
			}
			if SameMajor(s, bad).Allows(v) || SameMajor(s, v).Allows(bad) {
				t.Errorf("%s: SameMajor with an unreadable version", s.Name())
			}
			any, err := s.ParseConstraint(map[string]string{"npm": "*", "cargo": "*", "pip": ">=0", "go": ">=v0.0.0", "nuget": "0.0", "maven": "[0,)", "rubygems": ">= 0"}[s.Name()])
			if err != nil {
				t.Fatal(err)
			}
			if any.Allows(bad) || !any.Allows(v) {
				t.Errorf("%s: %s and an unreadable version", s.Name(), any)
			}
		}
	}
	if Bump(nil, nil, nil) != LevelNone {
		t.Error("Bump(nil)")
	}
}

// Untrusted input is bounded: long input, too many terms and numbers beyond
// int64 are errors.
func TestBounds(t *testing.T) {
	long := strings.Repeat("1", MaxInputLength+1)
	for _, name := range Supported() {
		s := mustScheme(t, name)
		if _, err := s.Parse(long); err == nil {
			t.Errorf("%s: Parse accepted %d bytes", name, len(long))
		}
		if _, err := s.ParseConstraint(long); err == nil || errors.Is(err, ErrNoConstraint) {
			t.Errorf("%s: ParseConstraint accepted %d bytes: %v", name, len(long), err)
		}
	}
	for name, exprs := range map[string][]string{
		"npm":      {strings.Repeat(">=1.0.0 ", MaxTerms+1), strings.Repeat("1.0.0||", MaxTerms+1)},
		"cargo":    {strings.Repeat(">=1.0.0, ", 32) + ">=1.0.0"},
		"pip":      {strings.Repeat(">=1.0,", MaxTerms+1)},
		"maven":    {strings.Repeat("[1.0],", MaxTerms+1)},
		"rubygems": {strings.Repeat(">= 1.0,", MaxTerms) + ">= 1.0"},
	} {
		for _, e := range exprs {
			if _, err := mustScheme(t, name).ParseConstraint(e); err == nil {
				t.Errorf("%s: %d bytes of terms accepted", name, len(e))
			}
		}
	}
	// At the limit they are read.
	for name, e := range map[string]string{
		"npm":      strings.TrimSpace(strings.Repeat(">=1.0.0 ", MaxTerms)),
		"cargo":    strings.Repeat(">=1.0.0, ", 31) + ">=1.0.0",
		"pip":      strings.Repeat(">=1.0,", MaxTerms),
		"rubygems": strings.Repeat(">= 1.0,", MaxTerms-1) + ">= 1.0",
	} {
		if _, err := mustScheme(t, name).ParseConstraint(e); err != nil {
			t.Errorf("%s: at the limit: %v", name, err)
		}
	}
	huge := "99999999999999999999"
	for name, texts := range map[string][]string{
		"npm":      {huge + ".0.0", "9007199254740992.0.0"},
		"cargo":    {huge + ".0.0", "1." + huge + ".0"},
		"pip":      {huge, "1.0.post" + huge, "1.0+" + huge, huge + "!1.0"},
		"go":       {"v" + huge + ".0.0"},
		"nuget":    {huge + ".0", "2147483648.0"},
		"maven":    {huge, "1.0-" + huge},
		"rubygems": {huge, "1." + huge},
	} {
		checkInvalidVersions(t, name, texts...)
	}
	for name, exprs := range map[string][]string{
		"npm":      {"^" + huge, ">=" + huge + ".0.0"},
		"cargo":    {"^" + huge, ">=1." + huge},
		"pip":      {">=" + huge, "==1.0.post" + huge},
		"go":       {">=v" + huge + ".0.0"},
		"nuget":    {"[" + huge + ",)", huge + ".*"},
		"maven":    {"[" + huge + ",)"},
		"rubygems": {"~> " + huge, "~> 9223372036854775807"},
	} {
		checkInvalidConstraints(t, name, exprs...)
	}
}
