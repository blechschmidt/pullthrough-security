//go:build fuzz
// +build fuzz

// Fuzz targets for the Homebrew pull-through parsers (Task 30, Task 158).
//
// A malicious or compromised upstream controls the formula JSON body and (via
// the client) the request path. Both are parsed on the pull path before any
// content is cached or served, so the parsers must never panic, must not
// allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/homebrew/
package homebrew

import (
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	digest := strings.Repeat("a", 64)
	seeds := []string{
		"/api/formula.json",
		"/api/formula/wget.json",
		"/api/formula/openssl@3.json",
		"/api/cask.json",
		"/api/formula.jws.json",
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:" + digest,
		"/bottle/wget/1.21.4/v2/homebrew/core/wget/blobs/sha256:short",
		"/bottle/wget", "/bottle//", "/api/../etc/passwd",
		"", "/", "////",
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
		_ = res.rewrites()
		if res.isBottle() {
			if len(res.digest) != sha256HexLen || !isHex(res.digest) {
				t.Fatalf("bottle resource with non-sha256 digest: %q -> %q", path, res.digest)
			}
			if res.repo == "" || res.name == "" || res.version == "" {
				t.Fatalf("bottle resource with empty field: %q -> %+v", path, res)
			}
			if !strings.HasPrefix(res.blobPath, "v2/") {
				t.Fatalf("bottle blobPath not an OCI path: %q -> %q", path, res.blobPath)
			}
		}
	})
}

func FuzzRewriteBottleURLs(f *testing.F) {
	digest := strings.Repeat("c", 64)
	f.Add([]byte(`{"name":"wget","versions":{"stable":"1.0"},"bottle":{"stable":{"files":{"x":{"url":"https://ghcr.io/v2/homebrew/core/wget/blobs/sha256:` + digest + `","sha256":"` + digest + `"}}}}}`))
	f.Add([]byte(`[{"name":"a","versions":{"stable":"1"}},{"name":"b"}]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, body []byte) {
		out, n := rewriteBottleURLs(body, "https://proxy.example/v1/homebrew", "ghcr.io")
		if n < 0 {
			t.Fatalf("negative rewrite count")
		}
		// A document that was not rewritten must be returned byte-for-byte.
		if n == 0 && string(out) != string(body) {
			t.Fatalf("no-op rewrite altered the body")
		}
	})
}
