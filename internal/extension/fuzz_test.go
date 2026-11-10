//go:build fuzz
// +build fuzz

// Fuzz targets for the extension host ABI serialization (Task 59, harness from
// Task 30).
//
// Two surfaces consume bytes the host did not author:
//
//   - The host MARSHALS a HostInput into a module's memory each invocation. A
//     malformed or adversarial signal document (which can originate from an
//     untrusted upstream registry's metadata, by the time it reaches the
//     accumulator) must round-trip through unmarshal→MarshalHostInput without
//     panicking, and the result must always be valid JSON the module can decode.
//
//   - The host PARSES a Verdict out of a module's memory. The module is
//     operator-supplied but untrusted code; ParseVerdict must never panic on
//     arbitrary bytes and must always either return a valid, bounded verdict or a
//     clean error — never an out-of-bounds verdict that escapes into the audit
//     log, response headers, or notifications.
//
// Build-tag gated (`fuzz`) to match the project convention. Run with, e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseVerdict ./internal/extension/
package extension

import (
	"encoding/json"
	"testing"
)

var hostInputSeeds = []string{
	`{}`,
	`{"abiVersion":1,"signals":{"artifact":{"name":"a","version":"1"}}}`,
	`{"signals":{"artifact":{"ecosystem":"npm","name":"left-pad"},"vuln":{"scanned":true,"criticalCount":2}}}`,
	`{"signals":{"tenant":"team-a","artifact":{"name":"x"}},"risk":{"score":80,"band":"critical"}}`,
	`{"signals":{"artifact":{"name":"\u0000\uffff weird"}}}`,
	`not json`,
	`{"signals":`,
	`{"risk":{"score":-5,"band":""}}`,
}

func FuzzHostInputRoundTrip(f *testing.F) {
	for _, s := range hostInputSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var in HostInput
		// Arbitrary bytes that do not decode are simply skipped — we only fuzz the
		// serialization of values that did decode.
		if err := json.Unmarshal(data, &in); err != nil {
			return
		}
		out, err := MarshalHostInput("fuzz-module", in)
		if err != nil {
			t.Fatalf("MarshalHostInput must not fail on a decoded input: %v", err)
		}
		// The host's own document must always be valid JSON and carry the stamped
		// ABI version, so a module can always decode it.
		var back HostInput
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("re-marshaled host input is not valid JSON: %v", err)
		}
		if back.ABIVersion != ABIVersion {
			t.Fatalf("ABI version not stamped: %d", back.ABIVersion)
		}
		if back.Module != "fuzz-module" {
			t.Fatalf("module name not stamped: %q", back.Module)
		}
	})
}

var verdictSeeds = []string{
	`{"decision":"allow"}`,
	`{"decision":"warn","reason":"x"}`,
	`{"decision":"block","annotations":{"a":"b"}}`,
	`{"decision":"nuke"}`,
	`{}`,
	`{"decision":"allow","extra":1}`,
	`{"decision":"allow","annotations":{"k":"` + "veryverylong" + `"}}`,
	`{`,
	``,
	`null`,
	`[]`,
}

func FuzzParseVerdict(f *testing.F) {
	for _, s := range verdictSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ParseVerdict(data)
		if err != nil {
			return // a clean rejection is the expected outcome for most inputs
		}
		// A successfully parsed verdict must satisfy every ABI invariant.
		if !v.Decision.Valid() {
			t.Fatalf("parsed verdict has an invalid decision %q", v.Decision)
		}
		if len(v.Reason) > maxReasonBytes {
			t.Fatalf("parsed reason exceeds bound: %d", len(v.Reason))
		}
		if len(v.Annotations) > maxAnnotations {
			t.Fatalf("parsed annotations exceed bound: %d", len(v.Annotations))
		}
		for k, val := range v.Annotations {
			if len(k) > maxAnnotationKey || len(val) > maxAnnotationByte {
				t.Fatalf("parsed annotation %q exceeds bound", k)
			}
		}
	})
}
