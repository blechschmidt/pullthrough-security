//go:build fuzz
// +build fuzz

// Fuzz targets for the homebrew feed's parsers (Task 190): a formula's JSON
// document, the "platforms" option, and the paths of homebrew-core. None of
// them may panic; what they accept must stay bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHomebrewFormula$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends/homebrew"
)

func FuzzHomebrewFormula(f *testing.F) {
	entries, _ := os.ReadDir(filepath.Join("testdata", "feeds", "homebrew"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "formula-") {
			if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "homebrew", e.Name())); err == nil {
				f.Add(data)
			}
		}
	}
	for _, s := range []string{``, `[]`, `{"name":"x"}`, `{"name":"x","versions":{"stable":null}}`, `{"name":"x","versions":{"stable":"1/2"},"bottle":{"stable":{"files":{"a":{"url":""},"B":{"url":"u"}}}}}`,
		`{"name":"x","versions":{},"bottle":{"stable":{"files":[]}}}`, `{"name":"x","versions":{"stable":"1"},"disabled":"yes"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fm, err := homebrewParseFormula(data)
		if err != nil {
			return
		}
		if fm.name == "" || len(fm.bottles) > homebrewMaxBottles {
			t.Fatalf("%+v", fm)
		}
		if fm.version != "" && (!cleanName(fm.version) || strings.Contains(fm.version, "/")) {
			t.Fatalf("version %q", fm.version)
		}
		if !sort.SliceIsSorted(fm.bottles, func(i, j int) bool { return fm.bottles[i].tag < fm.bottles[j].tag }) {
			t.Fatalf("bottles out of order")
		}
		for _, b := range fm.bottles {
			if !homebrewValidTag(b.tag) || b.url == "" {
				t.Fatalf("bottle %+v", b)
			}
		}
	})
}

func FuzzHomebrewPlatforms(f *testing.F) {
	for _, s := range []string{"", "arm64_sequoia", "arm64_sequoia, x86_64_linux", "all", ",", "macOS", "a,,b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := homebrewParsePlatforms(s)
		if err != nil {
			return
		}
		for tag := range p {
			if !homebrewValidTag(tag) {
				t.Fatalf("%q kept tag %q", s, tag)
			}
		}
	})
}

func FuzzHomebrewCoordinate(f *testing.F) {
	for _, s := range []string{"Formula/j/jq.rb", "Formula/jq.rb", "Formula/lib/libxml++.rb", "Formula/o/openssl@3.rb", "Formula/j/x/y.rb",
		"Formula//jq.rb", "Formula/j/.rb", "Formula/j/../x.rb", "Aliases/jq", ""} {
		f.Add(s, uint8(gitAdded))
		f.Add(s, uint8(gitDeleted))
	}
	f.Fuzz(func(t *testing.T, p string, change uint8) {
		_ = homebrewArea(p)
		c, ok := homebrewCoordinate(p, gitChange(change%4))
		if !ok {
			return
		}
		if _, ok := homebrew.FormulaDocumentPath(c.Name); !ok || !cleanName(c.Name) || c.Version != "" {
			t.Fatalf("%q gave %+v", p, c)
		}
	})
}
