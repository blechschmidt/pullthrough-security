//go:build fuzz
// +build fuzz

// Fuzz targets for the Julia pull-through parsers (Task 30, Task 129).
//
// A malicious or compromised upstream Pkg Server controls the tarball body and
// (via the client) the request path. Both are parsed on the pull path before any
// content is cached or served, so the parsers must never panic, must not allocate
// without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/julia/
package julia

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/registries",
		"/registry/23338594-aafe-5451-b93e-139f81909106/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc",
		"/package/7876af07-990d-54b4-ab0e-23690620f79a/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc",
		"/artifact/46e44e869b4d90b96bd8ed1fdcf32244fddfb6cc",
		"/artifact/" + strings.Repeat("a", 64),
		"/package/../../etc/passwd/" + strings.Repeat("a", 40),
		"/registry//",
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
		if res.verifiable() {
			if len(res.hash) != gitTreeSHA1HexLen {
				t.Fatalf("verifiable resource with non-sha1 hash: %q -> %q", path, res.hash)
			}
			if !isLowerHexString(res.hash) {
				t.Fatalf("verifiable resource with non-hex hash: %q", res.hash)
			}
		}
		if res.uuid != "" && !validUUID(res.uuid) {
			t.Fatalf("accepted invalid uuid %q for %q", res.uuid, path)
		}
	})
}

func FuzzGitTreeHashGzip(f *testing.F) {
	// Seed with a well-formed gzipped tar and some near-misses.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	_ = tw.WriteHeader(&tar.Header{Name: "a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("abc"))
	_ = tw.Close()
	_ = zw.Close()
	f.Add(buf.Bytes())
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip magic, truncated
	f.Add([]byte("not gzip"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, body []byte) {
		h, err := gitTreeHashGzip(bytes.NewReader(body))
		if err != nil {
			return
		}
		// A successful parse must yield a 40-char lowercase-hex git-tree-sha1.
		if len(h) != gitTreeSHA1HexLen || !isLowerHexString(h) {
			t.Fatalf("gitTreeHashGzip returned malformed hash %q", h)
		}
	})
}
