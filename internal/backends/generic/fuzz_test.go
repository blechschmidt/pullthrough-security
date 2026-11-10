package generic

import (
	"strings"
	"testing"
)

// FuzzParseChecksumSidecar exercises the sidecar parser over arbitrary upstream
// bytes. It must never panic and must only report ok for a well-formed digest of
// the algorithm's length; whenever it reports ok the returned token must itself
// re-parse to the same value (idempotent) and be exactly that many lowercase hex
// characters.
func FuzzParseChecksumSidecar(f *testing.F) {
	f.Add(strings.Repeat("a", 64), "sha256")
	f.Add("sha256:"+strings.Repeat("0", 64), "sha256")
	f.Add(strings.Repeat("A", 128)+"  file.tar.gz\n", "sha512")
	f.Add(strings.Repeat("f", 40), "sha1")
	f.Add("", "sha256")
	f.Add("not a digest", "sha256")
	f.Fuzz(func(t *testing.T, s, algo string) {
		got, ok := parseChecksumSidecar([]byte(s), algo)
		if !ok {
			return
		}
		want := digestHexLen(algo)
		if want == 0 {
			t.Fatalf("parseChecksumSidecar reported ok for unknown algorithm %q", algo)
		}
		if len(got) != want || !isHex(got) || got != strings.ToLower(got) {
			t.Fatalf("parseChecksumSidecar(%q,%q) returned malformed digest %q", s, algo, got)
		}
		again, ok2 := parseChecksumSidecar([]byte(got), algo)
		if !ok2 || again != got {
			t.Fatalf("parse not idempotent for %q: (%q,%v)", got, again, ok2)
		}
	})
}

// FuzzSidecarURL exercises the sidecar-URL derivation over arbitrary artifact
// URLs and suffixes. It must never panic; a derived URL must be parseable and
// must carry no query (a sidecar is a plain file).
func FuzzSidecarURL(f *testing.F) {
	f.Add("https://u.example/pkg/foo-1.0.tar.gz", ".sha256", false)
	f.Add("https://u.example/pkg/foo-1.0.tar.gz?token=x", ".sha256", true)
	f.Add("://bad", ".sha256", false)
	f.Fuzz(func(t *testing.T, raw, suffix string, replace bool) {
		v := &VerifyConfig{SidecarSuffix: suffix, SidecarReplacesExtension: replace}
		got, ok := sidecarURL(raw, v)
		if !ok {
			return
		}
		if strings.Contains(got, "?") {
			t.Fatalf("sidecarURL(%q) retained a query: %q", raw, got)
		}
	})
}
