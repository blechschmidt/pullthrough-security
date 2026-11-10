//go:build fuzz
// +build fuzz

// Fuzz target for the SARIF findings-aggregation layer (Task 42, harness from
// Task 30).
//
// The `pullthrough findings sarif` CLI decodes a JSON admission-input document
// (or array) supplied by a caller, normalizes it (FromInput), and renders SARIF
// (SARIFFromDocuments). Although the input is operator-supplied rather than
// upstream-untrusted, the decode→normalize→render pipeline must never panic on
// adversarial JSON, and the rendered log must always be structurally valid SARIF
// (every result references a defined rule by a valid in-range index and carries a
// valid level). This target asserts both invariants.
//
// Build-tag gated (`fuzz`) to match the project convention, so the default
// `go test ./...` stays fast. Run with:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzFindingsSARIF ./internal/findings/
package findings

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

var fuzzSeeds = []string{
	`{}`,
	`[]`,
	`{"artifact":{"name":"a","version":"1"}}`,
	`{"artifact":{"name":"a"},"vuln":{"scanned":true,"findings":[{"id":"CVE-1","severity":"critical","package":"a"}]}}`,
	`{"artifact":{"name":"a"},"secret":{"scanned":true,"findings":[{"ruleId":"r","severity":"high","file":"f"}]}}`,
	`[{"artifact":{"name":"a","version":"1"}},{"artifact":{"name":"b"},"nameguard":{"scanned":true,"findings":[{"kind":"typosquat","name":"b","similar":"c"}]}}]`,
	`{"artifact":{"name":"a"},"license":{"evaluated":true,"code":"denied","findings":[{"component":"x","outcome":"denied","license":"GPL-3.0"}]}}`,
	`{"artifact":{"name":"a"},"signature":{"checked":true,"error":"boom"}}`,
	`{"artifact":{"name":"a"},"provenance":{"found":false}}`,
	`not json`,
	`{"artifact":`,
}

func FuzzFindingsSARIF(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Mirror the CLI decode: tolerate a single object or an array.
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			return
		}
		var inputs []policyengine.Input
		if trimmed[0] == '[' {
			if err := json.Unmarshal(data, &inputs); err != nil {
				return // malformed JSON is a normal rejection, not a crash
			}
		} else {
			var one policyengine.Input
			if err := json.Unmarshal(data, &one); err != nil {
				return
			}
			inputs = []policyengine.Input{one}
		}

		docs := make([]Document, 0, len(inputs))
		for _, in := range inputs {
			docs = append(docs, FromInput(in, Options{}))
		}
		log := SARIFFromDocuments(docs, SARIFOptions{ToolVersion: "fuzz"})

		// Invariant 1: the rendered log re-marshals without error.
		if _, err := json.Marshal(log); err != nil {
			t.Fatalf("rendered SARIF failed to marshal: %v", err)
		}
		// Invariant 2: structural SARIF validity.
		for _, run := range log.Runs {
			n := len(run.Tool.Driver.Rules)
			for _, res := range run.Results {
				if res.RuleIndex < 0 || res.RuleIndex >= n {
					t.Fatalf("result ruleIndex %d out of range [0,%d) for rule %q", res.RuleIndex, n, res.RuleID)
				}
				if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
					t.Fatalf("result ruleIndex %d points at rule %q, not %q", res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
				}
				switch res.Level {
				case "error", "warning", "note", "none":
				default:
					t.Fatalf("invalid result level %q", res.Level)
				}
				if len(res.Locations) == 0 {
					t.Fatalf("result for rule %q has no locations", res.RuleID)
				}
			}
		}
	})
}
