//go:build fuzz
// +build fuzz

// Fuzz targets for the CRAN pull-through parsers (Task 30, Task 113).
//
// A malicious or compromised upstream repository controls the PACKAGES index
// body and (via the client) the request path. Both are parsed on the pull path
// before any content is cached or served, so the parsers must never panic, must
// not allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/cran/
package cran

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/src/contrib/PACKAGES",
		"/src/contrib/jsonlite_1.8.8.tar.gz",
		"/bin/windows/contrib/4.3/Rcpp_1.0.12.zip",
		"/bin/macosx/big-sur-arm64/contrib/4.3/Rcpp_1.0.12.tgz",
		"/src/contrib/Archive/jsonlite/jsonlite_1.8.7.tar.gz",
		"/src/contrib/../../etc/passwd.tar.gz",
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
			if res.filename == "" {
				t.Fatalf("verifiable package with empty filename: %q", path)
			}
			if res.name == "" || res.version == "" {
				t.Fatalf("package with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParsePackages(f *testing.F) {
	seeds := []string{
		"Package: jsonlite\nVersion: 1.8.8\nMD5sum: 0123456789abcdef0123456789abcdef\n",
		"Package: p\nVersion: 1.0\nMD5sum: tooshort\n",
		"garbage without fields\n",
		"Package: p\n Version: continued\n",
		"",
		"   \n\t  ",
		"::::\n\n::::",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		idx, err := ParsePackages(body)
		if err != nil {
			return
		}
		// Every recorded digest must be a valid 32-char hex MD5, and lookups must be
		// safe for arbitrary keys.
		for stem, d := range idx.md5 {
			if len(d) != md5HexLen || !isHex(d) {
				t.Fatalf("index accepted invalid digest %q for %q", d, stem)
			}
		}
		_, _ = idx.md5For("jsonlite_1.8.8")
		_, _ = idx.md5For("")
	})
}
