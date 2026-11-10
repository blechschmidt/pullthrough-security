//go:build fuzz
// +build fuzz

// Fuzz targets for the SPIFFE/SVID parsers (Task 58, Task 30).
//
// Both inputs are fully attacker-controlled: a SPIFFE ID is read from a client
// certificate's SAN URI (a peer the proxy is in the process of authenticating),
// and a SPIFFE trust bundle may be supplied as an externally produced JSON
// document. Neither parser may panic; ParseID must additionally round-trip any
// id it accepts.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseID ./internal/spiffe/
package spiffe

import (
	"strings"
	"testing"
)

func FuzzParseID(f *testing.F) {
	seeds := []string{
		"spiffe://example.org/ns/prod/sa/web",
		"spiffe://example.org",
		"spiffe://example.org/",
		"SPIFFE://Example.ORG/ns/a",
		"https://example.org/x",
		"spiffe://example.org:8443/x",
		"spiffe://user@example.org/x",
		"spiffe:///ns/a",
		"spiffe://example.org/ns/a?q=1#f",
		"",
		"spiffe://" + strings.Repeat("a", 300),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := ParseID(s)
		if err != nil {
			return
		}
		// An accepted id must have a non-empty trust domain and round-trip through
		// String -> ParseID to a stable value.
		if id.TrustDomain == "" {
			t.Fatalf("accepted id %q has empty trust domain", s)
		}
		round := id.String()
		id2, err2 := ParseID(round)
		if err2 != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", round, s, err2)
		}
		if id2.String() != round {
			t.Fatalf("id did not round-trip: %q -> %q -> %q", s, round, id2.String())
		}
		_ = id.Selectors() // must not panic on any accepted path
	})
}

func FuzzParseTrustBundle(f *testing.F) {
	seeds := []string{
		`{"keys":[{"use":"x509-svid","x5c":["bm90LWEtY2VydA=="]}]}`,
		`{"trust_domains":{"a.example":{"keys":[]}}}`,
		`{"spiffe_sequence":1,"keys":[]}`,
		"-----BEGIN CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END CERTIFICATE-----\n",
		"not a bundle at all",
		"{",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Exercise every format selector; none may panic regardless of input.
		for _, format := range []BundleFormat{FormatAuto, FormatPEM, FormatSPIFFE} {
			_, _ = ParseTrustBundle([]byte(s), format, "example.org")
		}
	})
}
