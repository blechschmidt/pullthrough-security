//go:build fuzz
// +build fuzz

// Fuzz target for the digest-normalization parser (Task 68, Task 30).
//
// The reproducible-build verification gate compares a rebuilt artifact's digest
// against the upstream-served artifact's digest. Both digest strings arrive from
// outside the gate's control — the upstream registry's content-address and a
// pluggable (potentially third-party) builder's output — in a variety of
// spellings. parseDigest/NormalizeDigest must never panic and must be stable
// (idempotent) on any input, so a hostile or malformed digest can neither crash
// the gate nor make a mismatch look reproducible.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzNormalizeDigest ./internal/rebuildverify/
package rebuildverify

import "testing"

func FuzzNormalizeDigest(f *testing.F) {
	seeds := []string{
		"sha256:" + repeat("a", 64),
		"sha512:" + repeat("F", 128),
		repeat("0", 64),
		"  sha1:" + repeat("a", 40) + "  ",
		"\"sha256:" + repeat("b", 64) + "\"",
		"sha256:",
		"sha256:zzzz",
		"::::",
		"sha256:" + repeat("a", 63),
		"custom:" + repeat("a", 10),
		"multihash:1220" + repeat("a", 64),
		"",
		"not a digest",
		"sha256:AABBCCDD",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, ok := NormalizeDigest(s)
		if !ok {
			if got != "" {
				t.Fatalf("NormalizeDigest(%q) returned ok=false but non-empty %q", s, got)
			}
			return
		}
		// A successful normalization must itself be a valid, stable digest:
		// re-normalizing the canonical form must be a no-op (idempotence).
		again, ok2 := NormalizeDigest(got)
		if !ok2 {
			t.Fatalf("NormalizeDigest(%q)=%q did not re-parse", s, got)
		}
		if again != got {
			t.Fatalf("NormalizeDigest not idempotent: %q -> %q -> %q", s, got, again)
		}
		// A parsed digest must compare equal to itself.
		d, _ := parseDigest(s)
		if !d.Equal(d) {
			t.Fatalf("parseDigest(%q) not self-equal", s)
		}
	})
}
