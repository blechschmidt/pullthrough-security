//go:build fuzz
// +build fuzz

// Fuzz targets for the GitHub Actions `uses:` parser (Task 115, mirroring the
// Task 30 harness).
//
// The parser consumes workflow / composite-action YAML that originates from an
// untrusted upstream Git repository. It must never panic, must bound its work,
// and must terminate on hostile input (enormous lines, embedded NULs, truncated
// files, pathological quoting). The targets assert only "does not panic / does
// terminate" plus a couple of cheap internal invariants; correctness is covered
// by the deterministic unit tests.
package actionpin

import (
	"strings"
	"testing"
)

func FuzzParseContent(f *testing.F) {
	f.Add("steps:\n  - uses: actions/checkout@v4\n")
	f.Add("  uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n")
	f.Add("uses: ./local\nuses: docker://alpine:3.18\n")
	f.Add("uses:\nuses: \nuses: '\n")
	f.Add("- uses: \"org/repo/.github/workflows/ci.yml@main\"\n")
	f.Add("")
	f.Add(strings.Repeat("uses: a/b@c\n", 10000))
	f.Fuzz(func(t *testing.T, content string) {
		refs := ParseContent(content)
		if len(refs) > maxReferences {
			t.Fatalf("ParseContent returned %d refs, exceeds bound %d", len(refs), maxReferences)
		}
		for i := range refs {
			r := refs[i]
			if len(r.Raw) > maxRawLen {
				t.Fatalf("reference Raw length %d exceeds bound %d", len(r.Raw), maxRawLen)
			}
			_ = r.pinningOf()
		}
	})
}

func FuzzClassify(f *testing.F) {
	f.Add("actions/checkout@v4")
	f.Add("docker://ghcr.io/x/y@sha256:deadbeef")
	f.Add("./a/b")
	f.Add("@@@@")
	f.Add("a/b/c/d/e@")
	f.Fuzz(func(t *testing.T, raw string) {
		ref := Classify(raw)
		if len(ref.Raw) > maxRawLen {
			t.Fatalf("Classify Raw length %d exceeds bound %d", len(ref.Raw), maxRawLen)
		}
		_ = ref.pinningOf()
	})
}

func FuzzParseUsesValue(f *testing.F) {
	f.Add("  uses: actions/checkout@v4 # comment")
	f.Add("\t- uses:\t'x'")
	f.Add("uses::::")
	f.Fuzz(func(t *testing.T, line string) {
		v, ok := ParseUsesValue(line)
		if ok && len(v) > maxRawLen {
			t.Fatalf("value length %d exceeds bound %d", len(v), maxRawLen)
		}
	})
}
