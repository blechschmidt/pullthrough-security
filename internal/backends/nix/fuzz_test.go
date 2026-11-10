//go:build fuzz
// +build fuzz

// Fuzz targets for the Nix binary-cache pull-through parsers (Task 30, Task 140).
//
// A malicious or compromised upstream binary cache controls the narinfo body and
// (via the client) the request path. Both are parsed on the pull path before any
// content is cached or served, so the parsers must never panic, must not allocate
// without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/nix/
package nix

import (
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	fh := strings.Repeat("a", 52)
	sh := strings.Repeat("a", 32)
	seeds := []string{
		"/nix-cache-info",
		"/" + sh + ".narinfo",
		"/nar/" + fh + ".nar.xz",
		"/nar/" + fh + ".nar",
		"/nar/" + sh + ".nar.zst",
		"/nar/../../etc/passwd",
		"/" + strings.Repeat("e", 32) + ".narinfo",
		"", "/", "////", "/nar//",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		_ = res.cacheable()
		_ = res.kindLabel()
		if res.verifiable() {
			if len(res.fileHash) != nixBase32Len(sha256Bytes) || !isNixBase32(res.fileHash) {
				t.Fatalf("verifiable resource with non-sha256 content hash: %q -> %q", path, res.fileHash)
			}
		}
		if res.storeHash != "" && (len(res.storeHash) != storeHashLen || !isNixBase32(res.storeHash)) {
			t.Fatalf("accepted invalid store hash %q for %q", res.storeHash, path)
		}
	})
}

func FuzzParseNarInfo(f *testing.F) {
	f.Add([]byte("StorePath: /nix/store/" + strings.Repeat("b", 32) + "-x\nURL: nar/abc.nar.xz\nNarHash: sha256:1xyz\nNarSize: 10\nReferences: a-b\nSig: k:AAAA\n"))
	f.Add([]byte("StorePath: /nix/store/x\nURL: nar/y.nar\n"))
	f.Add([]byte("NarSize: not-a-number\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))

	f.Fuzz(func(t *testing.T, body []byte) {
		ni, err := parseNarInfo(body)
		if err != nil {
			return
		}
		// A successful parse guarantees the required fields, and none of the
		// downstream operations may panic on attacker-controlled input.
		if ni.StorePath == "" || ni.URL == "" {
			t.Fatalf("successful parse with empty required field: %+v", ni)
		}
		_, _ = ni.fingerprint()
		ni.rewriteURL("nar/rewritten.nar.xz")
		if got := ni.reemit(); !strings.Contains(got, "URL: nar/rewritten.nar.xz") {
			t.Fatalf("rewrite not reflected in reemit:\n%s", got)
		}
	})
}
