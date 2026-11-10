//go:build fuzz
// +build fuzz

// Fuzz targets for the Composer pull-through parsers (Task 30, Task 45).
//
// A malicious or compromised Packagist mirror controls packages.json and the v2
// metadata documents (the source of the dist download URL and the verification
// shasum) and, via the client, the request path. All are parsed on the pull path
// before any content is cached or served, so the parsers must never panic, must
// not allocate without bound, and must fail closed on malformed input. The
// minified-delta expansion is a particular focus: a hostile document must not be
// able to drive unbounded growth or a panic through the "__unset" sentinel.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzParseMetadata ./internal/backends/composer/
package composer

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/packages.json",
		"/p2/symfony/console.json",
		"/p2/symfony/console~dev.json",
		"/p/monolog/monolog.json",
		"/dist/symfony/console/abc123.zip",
		"/dist/../../etc/passwd.zip",
		"",
		"/",
		"////",
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
		if res.verifiableArtifact() && (res.vendor == "" || res.pkg == "" || res.reference == "") {
			t.Fatalf("verifiable dist with empty coordinate/reference: %q", path)
		}
	})
}

func FuzzParseMetadata(f *testing.F) {
	seeds := []string{
		metadataFixture,
		minifiedFixture,
		`{"packages":{}}`,
		`{"minified":"composer/2.0","packages":{"a/b":[{"version":"1.0.0"},{"version":"__unset"}]}}`,
		`{"minified":"composer/2.0","packages":{"a/b":[]}}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		md, err := ParseMetadata(data)
		if err != nil {
			return
		}
		for _, versions := range md.Packages {
			for _, v := range versions {
				// A version that carries a non-empty dist reference must be findable
				// by it (FindByReference is how the backend recovers the download URL
				// and shasum for a dist request).
				if v.Dist.Reference != "" {
					if _, found := md.FindByReference(v.Dist.Reference); !found {
						t.Fatalf("version with reference %q not findable", v.Dist.Reference)
					}
				}
				// A reported checksum must be a well-formed SHA-1 hex digest.
				if cs, ok := v.Checksum(); ok && len(cs.hex) != distShasumHexLen {
					t.Fatalf("checksum of wrong length: %q", cs.hex)
				}
			}
		}
	})
}

func FuzzParseRoot(f *testing.F) {
	seeds := []string{
		`{"metadata-url":"/p2/%package%.json"}`,
		`{"packages":{},"providers-url":"/p/%package%$%hash%.json"}`,
		`{}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRoot(data)
	})
}
