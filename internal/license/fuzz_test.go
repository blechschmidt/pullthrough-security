//go:build fuzz
// +build fuzz

// Fuzz targets for the SPDX license-expression parser (Task 30).
//
// SPDX expressions reach the proxy from untrusted upstream SBOMs (the license
// field of a CycloneDX component, a .nuspec <license>, an npm "license" string,
// etc.), so ParseExpression is an adversarial-input parser: it must never panic,
// must not recurse without bound, and must round-trip whatever it accepts.
//
// Build-tag gated (`fuzz`) to match the integration-test convention, so the
// default `go test ./...` stays fast. Run with:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseExpression ./internal/license/
package license

import (
	"strings"
	"testing"
)

// spdxSeeds are real-world and known-malformed SPDX expressions.
var spdxSeeds = []string{
	// Well-formed, real-world expressions.
	"MIT",
	"Apache-2.0",
	"Apache-2.0+",
	"GPL-2.0-or-later",
	"GPL-2.0-only WITH Classpath-exception-2.0",
	"(MIT OR Apache-2.0)",
	"MIT AND Apache-2.0",
	"(MIT OR Apache-2.0) AND BSD-3-Clause",
	"LGPL-2.1-only OR (MIT AND BSD-3-Clause)",
	"GPL-3.0-or-later WITH GCC-exception-3.1",
	"LicenseRef-Proprietary",
	"DocumentRef-spdx-tool:LicenseRef-1",
	"CC-BY-4.0",
	"0BSD",
	"NOASSERTION",
	// Whitespace / case variants.
	"  MIT  ",
	"mit or apache-2.0",
	"MIT and APACHE-2.0",
	"MIT wItH Classpath-exception-2.0",
	// Malformed / adversarial.
	"",
	" ",
	"(",
	")",
	"()",
	"(MIT",
	"MIT)",
	"MIT OR",
	"OR MIT",
	"MIT AND AND MIT",
	"WITH",
	"MIT WITH",
	"(MIT OR Apache-2.0) WITH Foo",
	"MIT @ Apache-2.0",
	"+",
	"++",
	"-",
	"MIT WITH WITH Foo",
	strings.Repeat("(", 100) + "MIT" + strings.Repeat(")", 100),
	strings.Repeat("(", 5000) + "MIT" + strings.Repeat(")", 5000),
	strings.Repeat("MIT OR ", 1000) + "MIT",
	strings.Repeat("A", 100000),
}

func FuzzParseExpression(f *testing.F) {
	for _, s := range spdxSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		expr, err := ParseExpression(s)
		if err != nil {
			// On error the returned Expression must be the zero value and safe to use.
			if !expr.IsZero() {
				t.Fatalf("error result is not zero-valued: %q -> %#v", s, expr)
			}
			_ = expr.String()
			_ = expr.Licenses()
			return
		}

		// A successful parse must round-trip: re-parsing the canonical rendering
		// must succeed and render identically (parser/printer are consistent).
		rendered := expr.String()
		expr2, err2 := ParseExpression(rendered)
		if err2 != nil {
			t.Fatalf("re-parse of canonical form %q (from %q) failed: %v", rendered, s, err2)
		}
		if got := expr2.String(); got != rendered {
			t.Fatalf("render not idempotent: %q -> %q -> %q", s, rendered, got)
		}

		// Licenses() must be safe and self-consistent.
		for _, id := range expr.Licenses() {
			if id == "" {
				t.Fatalf("empty license id extracted from %q", s)
			}
		}
	})
}
