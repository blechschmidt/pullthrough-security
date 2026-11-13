//go:build fuzz
// +build fuzz

// Fuzz target for the maintenance updater's own readers of untrusted input
// (Task 182): registry packuments it trims for the sandbox, lock files whose
// registry base it restores, ignore-list entries, and the commit objects of a
// remote branch it decides are its own.
//
//	go test -tags fuzz -run='^$' -fuzz=FuzzUpdaterInputs ./internal/repos/
package repos

import (
	"context"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/versions"
)

// commitObjects answers CommitObject with fuzzed bytes.
type commitObjects struct {
	BranchSource
	raw []byte
}

func (c commitObjects) CommitObject(context.Context, Repo, string) ([]byte, error) { return c.raw, nil }

func FuzzUpdaterInputs(f *testing.F) {
	f.Add([]byte(`{"versions":{"1.0.0":{},"2.0.0":{}},"dist-tags":{"latest":"2.0.0"}}`), "npm/left-pad@^1",
		[]byte("tree a\nparent b\ncommitter x <pullthrough@localhost> 1 +0000\n\nUpdate\n\nPullthrough-Run: 20261113t000000.000z-0a0b0c0d\n"))
	f.Add([]byte(`{"packages":{"":{},"node_modules/a":{"resolved":"https://r/a/-/a-1.tgz"}}}`), "*/x*", []byte(""))
	f.Fuzz(func(t *testing.T, doc []byte, ignore string, commit []byte) {
		sch, _ := versions.For("npm")
		_, _ = filterPackument(doc, sch, "1.0.1", map[string]bool{"1.1.0": true})
		_ = restoreNPMResolved(doc, "npm", doc)
		if r, err := parseIgnore(ignore); err == nil {
			if r.name == "" || r.typ == "" {
				t.Fatalf("a rule without a name or type from %q", ignore)
			}
			v, _ := sch.Parse("1.0.0")
			_, _ = ignoreList{r}.version(sch, "npm", "x", v)
		}
		s := &Service{opts: Options{Branches: commitObjects{raw: commit}}}
		s.cfg = s.cfg.withDefaults()
		_ = s.ownCommit(context.Background(), Repo{Name: "r"}, "0000000000000000000000000000000000000000")
		_ = oneLine(string(commit))
		_ = mdCode(ignore)
	})
}
