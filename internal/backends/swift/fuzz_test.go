//go:build fuzz
// +build fuzz

// Fuzz targets for the Swift Package Registry pull-through parsers (Task 30,
// Task 104).
//
// A malicious or compromised upstream registry controls the release-metadata
// JSON body and (via the client) the request path. Both are parsed on the pull
// path before any content is cached or served, so the parsers must never panic,
// must not allocate without bound, and must fail closed on malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/swift/
package swift

import "testing"

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/mona/LinkedList",
		"/mona/LinkedList/1.1.1",
		"/mona/LinkedList/1.1.1/Package.swift",
		"/mona/LinkedList/1.1.1/Package@swift-5.3.swift",
		"/mona/LinkedList/1.1.1.zip",
		"/identifiers",
		"/mona/LinkedList/1.1.1/../../../etc/passwd",
		"",
		"/",
		"////",
		"/-bad/name",
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
		// panicking, and an archive must carry a non-empty version.
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		if res.isArchive() && res.version == "" {
			t.Fatalf("archive with empty version: %q", path)
		}
		if res.kind == kindManifest && res.manifestName == "" {
			t.Fatalf("manifest with empty filename: %q", path)
		}
	})
}

func FuzzParseReleaseMetadata(f *testing.F) {
	seeds := []string{
		`{"resources":[{"name":"source-archive","checksum":"` +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}]}`,
		`{"resources":[],"metadata":{"repositoryURLs":["https://example.com/x"]}}`,
		`not json`,
		``,
		`{`,
		`{"resources":null}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		rm, err := parseReleaseMetadata(body)
		if err != nil {
			return
		}
		// Any checksum the parser accepts must be a valid lowercase hex SHA-256.
		if hex, ok := rm.sourceArchiveChecksum(); ok {
			if len(hex) != sha256HexLen || !isHex(hex) {
				t.Fatalf("accepted invalid checksum %q", hex)
			}
		}
		_ = rm.repositoryURL()
	})
}
