//go:build fuzz
// +build fuzz

// Fuzz targets for the Conda pull-through parsers (Task 30, Task 113).
//
// A malicious or compromised upstream channel controls the repodata.json body
// and (via the client) the request path. Both are parsed on the pull path
// before any content is cached or served, so the parsers must never panic, must
// not allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/conda/
package conda

import (
	"strings"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/noarch/repodata.json",
		"/linux-64/numpy-1.26.0-py312h0_0.conda",
		"/osx-arm64/python-dateutil-2.9.0-pyhd8ed1ab_0.tar.bz2",
		"/channeldata.json",
		"/conda-forge/linux-64/zlib-1.3.1-h0_0.conda",
		"/linux-64/../../etc/passwd.conda",
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
		// Invariants for an accepted path: the predicates must be callable without
		// panicking, and a verifiable package must carry a non-empty filename and
		// decoded coordinate.
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.verifiableFile() {
			if res.filename == "" {
				t.Fatalf("verifiable package with empty filename: %q", path)
			}
			if res.name == "" || res.version == "" || res.build == "" {
				t.Fatalf("package with incomplete coordinate: %q -> %+v", path, res)
			}
			if res.subdir == "" {
				t.Fatalf("package with empty subdir: %q", path)
			}
		}
	})
}

func FuzzRepodataChecksum(f *testing.F) {
	seeds := []string{
		`{"packages":{"a-1-0.tar.bz2":{"sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		`{"packages.conda":{"a-1-0.conda":{"md5":"` + strings.Repeat("b", 32) + `"}}}`,
		`{"info":{"subdir":"linux-64"},"packages":{}}`,
		`{`,
		`not json`,
		``,
		`{"packages":"notanobject"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), "a-1-0.conda")
	}
	f.Fuzz(func(t *testing.T, body []byte, want string) {
		sha, md5hex, found, err := repodataChecksum(strings.NewReader(string(body)), want)
		if err != nil {
			return
		}
		if !found {
			return
		}
		// A found entry must yield at least one well-formed digest.
		if sha == "" && md5hex == "" {
			t.Fatalf("found entry with no digests for %q", want)
		}
		if sha != "" && (len(sha) != sha256HexLen || !isHex(sha)) {
			t.Fatalf("invalid sha256 %q", sha)
		}
		if md5hex != "" && (len(md5hex) != md5HexLen || !isHex(md5hex)) {
			t.Fatalf("invalid md5 %q", md5hex)
		}
	})
}
