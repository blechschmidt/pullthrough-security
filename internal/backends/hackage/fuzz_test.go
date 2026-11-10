//go:build fuzz
// +build fuzz

// Fuzz targets for the Hackage pull-through parsers (Task 30, Task 155).
//
// A malicious or compromised upstream repository controls the request path and
// the package.json TUF target metadata the proxy reads to recover an sdist's
// declared SHA-256. Both are parsed on the pull path before any content is
// cached or served, so the parsers must never panic, must not allocate without
// bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/hackage/
package hackage

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/01-index.tar.gz",
		"/root.json",
		"/package/text-2.1/text-2.1.tar.gz",
		"/package/aeson-pretty-0.8.10/aeson-pretty-0.8.10.tar.gz",
		"/package/text-2.1.tar.gz",
		"/package/text-2.1/text.cabal",
		"/package/text-2.1/package.json",
		"/package/text-2.1/../../etc/passwd",
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
		_ = res.coordinateName()
		if res.verifiableFile() {
			if res.filename == "" || res.name == "" || res.version == "" {
				t.Fatalf("verifiable sdist with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParsePkgID(f *testing.F) {
	for _, s := range []string{"text-2.1", "aeson-pretty-0.8.10", "HUnit-1.6.2.0", "text", "-2.1", "foo-bar"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		name, version, ok := parsePkgID(id)
		if !ok {
			return
		}
		if !validPackageName(name) || !validVersion(version) {
			t.Fatalf("parsePkgID accepted an invalid split: %q -> %q/%q", id, name, version)
		}
	})
}

func FuzzParseTargetSHA256(f *testing.F) {
	f.Add([]byte(`{"signed":{"targets":{"r/package/text-2.1.tar.gz":{"hashes":{"sha256":"abcd"},"length":3}}}}`))
	f.Add([]byte(`{"signed":{"targets":{}}}`))
	f.Add([]byte("not json"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, body []byte) {
		if h, ok := parseTargetSHA256(body, "text-2.1.tar.gz"); ok {
			if len(h) != sha256HexLen || !isHex(h) {
				t.Fatalf("parseTargetSHA256 accepted a non-sha256 digest: %q", h)
			}
		}
	})
}
