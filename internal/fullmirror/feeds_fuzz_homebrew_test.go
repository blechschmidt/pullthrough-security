//go:build fuzz
// +build fuzz

// Fuzz targets for the homebrew feed's parsers (Task 190): a formula's JSON
// document, the "platforms" option, and the paths of homebrew-core — and the
// formula index of index mode (Task 191). None of them may panic; what they
// accept must stay bounded and well formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHomebrewFormula$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"bytes"
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

func FuzzHomebrewIndex(f *testing.F) {
	if data, err := os.ReadFile(filepath.Join("testdata", "feeds", "homebrew", "formula-index.json")); err == nil {
		f.Add(data)
	}
	for _, s := range []string{``, `[]`, `{}`, `[{"name":"x"}]`, `[1,null,"s",[],{"name":"x","versions":"1"}]`, `[{"name":"x","versions":{"stable":"1/2"},"revision":"r"}]`,
		`[{"name":"x","versions":{"stable":"1"},"tap_git_head":"` + strings.Repeat("a", 40) + `","bottle":{"stable":{"rebuild":1,"files":{"all":{"url":"https://ghcr.io/v2/homebrew/core/x/blobs/sha256:` + strings.Repeat("a", 64) + `"},"B":{"url":"u"}}}}}]`,
		`[{"name":"x"}`, `[{"name":"x"}]]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		n := 0
		head, err := homebrewParseIndex(bytes.NewReader(data), func(e homebrewIndexEntry) error {
			n++
			if _, ok := homebrew.FormulaDocumentPath(e.name); !ok || !homebrewValidName(e.name) {
				t.Fatalf("entry name %q", e.name)
			}
			if e.version != "" && (!cleanName(e.version) || strings.Contains(e.version, "/")) {
				t.Fatalf("version %q", e.version)
			}
			if len(e.bottles) > homebrewMaxBottles || !sort.SliceIsSorted(e.bottles, func(i, j int) bool { return e.bottles[i].tag < e.bottles[j].tag }) {
				t.Fatalf("bottles %v", e.bottles)
			}
			for _, b := range e.bottles {
				if !homebrewValidTag(b.tag) || b.url == "" {
					t.Fatalf("bottle %+v", b)
				}
			}
			recs := homebrewIndexRecords(e, nil, "")
			if len(recs) > len(e.bottles) || (len(recs) > 0 && (e.disabled || e.version == "")) {
				t.Fatalf("%d records of %+v", len(recs), e)
			}
			for _, r := range recs {
				if !r.valid() || r.Name != e.name || r.Version != e.version || !strings.HasPrefix(r.Path, "/bottle/") {
					t.Fatalf("record %+v of %+v", r, e)
				}
			}
			return nil
		})
		if err != nil && !IsPermanent(err) {
			t.Fatalf("a malformed index is not a permanent error: %v", err)
		}
		if head != "" && !homebrewValidCommit(head) {
			t.Fatalf("head %q", head)
		}
		if n > len(data)/10+1 {
			t.Fatalf("%d formulae from %d bytes", n, len(data))
		}
	})
}
