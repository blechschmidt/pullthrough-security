//go:build fuzz
// +build fuzz

// Fuzz targets for the version schemes. Versions and constraints come from
// repositories and registries, so each scheme's Parse and ParseConstraint
// read untrusted input inside the proxy. For three fuzzed strings, as
// versions and as constraints, the properties are:
//
//   - nothing panics, and parsing is deterministic;
//   - a parsed version keeps its text and has at least three release
//     components;
//   - Compare is reflexive, antisymmetric and transitive on the parsed
//     versions — a total order — and Bump agrees with it;
//   - a parsed constraint evaluates every version the same way twice.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzNpm ./internal/versions/
package versions

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fuzzMaxInput bounds an input: the schemes refuse anything longer than
// MaxInputLength, and longer inputs only slow each run down.
const fuzzMaxInput = 4 * MaxInputLength

// fuzzSeeds returns the first column of a reference corpus.
func fuzzSeeds(f *testing.F, names ...string) []string {
	var out []string
	for _, name := range names {
		file, err := os.Open(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			field, _, _ := strings.Cut(line, "\t")
			var s string
			if json.Unmarshal([]byte(field), &s) == nil {
				out = append(out, s)
			}
		}
		file.Close()
	}
	return out
}

// addSeeds seeds a target with triples from the given strings.
func addSeeds(f *testing.F, seeds []string) {
	for i := 0; i+2 < len(seeds); i += 3 {
		f.Add(seeds[i], seeds[i+1], seeds[i+2])
	}
}

func fuzzScheme(t *testing.T, name string, inputs ...string) {
	for _, in := range inputs {
		if len(in) > fuzzMaxInput {
			return
		}
	}
	s, ok := For(name)
	if !ok {
		t.Fatalf("no scheme %q", name)
	}
	var vs []Version
	for _, in := range inputs {
		v, err := s.Parse(in)
		again, err2 := s.Parse(in)
		if (err == nil) != (err2 == nil) {
			t.Fatalf("Parse(%q) is not deterministic: %v, %v", in, err, err2)
		}
		if err != nil {
			continue
		}
		if v.String() != in {
			t.Fatalf("Parse(%q).String() = %q", in, v.String())
		}
		if len(v.Release()) < 3 {
			t.Fatalf("Parse(%q).Release() = %v", in, v.Release())
		}
		if c := s.Compare(v, again); c != 0 {
			t.Fatalf("Compare(%q, itself) = %d", in, c)
		}
		v.Prerelease()
		vs = append(vs, v)
	}
	for _, a := range vs {
		for _, b := range vs {
			ab, ba := s.Compare(a, b), s.Compare(b, a)
			if ab < -1 || ab > 1 || ab != -ba {
				t.Fatalf("Compare(%q, %q) = %d, Compare(%q, %q) = %d", a, b, ab, b, a, ba)
			}
			if bumped := Bump(s, a, b) != LevelNone; bumped != (ba > 0) {
				t.Fatalf("Bump(%q, %q) = %s, Compare(%q, %q) = %d", a, b, Bump(s, a, b), b, a, ba)
			}
			for _, c := range vs {
				if ab <= 0 && s.Compare(b, c) <= 0 && s.Compare(a, c) > 0 {
					t.Fatalf("not transitive: %q <= %q <= %q but %q > %q", a, b, c, a, c)
				}
			}
		}
	}
	for _, in := range inputs {
		c, err := s.ParseConstraint(in)
		_, err2 := s.ParseConstraint(in)
		if (err == nil) != (err2 == nil) || errors.Is(err, ErrNoConstraint) != errors.Is(err2, ErrNoConstraint) {
			t.Fatalf("ParseConstraint(%q) is not deterministic: %v, %v", in, err, err2)
		}
		if err != nil {
			continue
		}
		_ = c.String()
		for _, v := range vs {
			if c.Allows(v) != c.Allows(v) {
				t.Fatalf("%q Allows(%q) is not deterministic", in, v)
			}
		}
		_ = Intersect(c, SameMajor(s, nil)).Allows(nil)
	}
	for _, v := range vs {
		_ = SameMajor(s, v).Allows(v)
	}
}

func FuzzNpm(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "npm-versions.tsv", "npm-ranges.tsv"))
	f.Add("^1.2.3", "1.2.3 - 2.3", ">=1.2.3-alpha <2")
	f.Add("npm:@scope/pkg@~1.2.0", "git+https://github.com/a/b.git", "latest")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "npm", a, b, c) })
}

func FuzzCargo(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "cargo-versions.tsv", "cargo-constraints.tsv"))
	f.Add("^0.0.3", ">=1.2.3-alpha, <2", "1.2.3+build.01")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "cargo", a, b, c) })
}

func FuzzPip(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "pip-versions.tsv", "pip-constraints.tsv"))
	f.Add("~=1.4.5", "==1.1.*,!=1.1.3", "1!1.0a1.post2.dev3+local.7")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "pip", a, b, c) })
}

func FuzzGo(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "go-versions.tsv"))
	f.Add("v0.0.0-20210101000000-abcdef123456", "v2.0.0+incompatible", ">=v1.2.3")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "go", a, b, c) })
}

func FuzzNuGet(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "nuget-versions.tsv", "nuget-constraints.tsv"))
	f.Add("[1.0,2.0)", "1.0.*-beta*", "1.0.0.1-Beta.2+meta")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "nuget", a, b, c) })
}

func FuzzMaven(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "maven-versions.tsv", "maven-constraints.tsv"))
	f.Add("1-alpha", "1.final.1", "(,1.0],[1.2,)")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "maven", a, b, c) })
}

func FuzzRubyGems(f *testing.F) {
	addSeeds(f, fuzzSeeds(f, "rubygems-versions.tsv", "rubygems-constraints.tsv"))
	f.Add("~> 2.2.0", "1.0.0.pre.rc.1", ">= 1.0.a, != 1.1")
	f.Fuzz(func(t *testing.T, a, b, c string) { fuzzScheme(t, "rubygems", a, b, c) })
}
