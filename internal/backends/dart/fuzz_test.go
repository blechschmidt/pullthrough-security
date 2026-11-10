//go:build fuzz
// +build fuzz

// Fuzz targets for the Dart/pub pull-through parsers (Task 30, Task 104).
//
// A malicious or compromised upstream repository controls the list-versions
// JSON body and (via the client) the request path. Both are parsed on the pull
// path before any content is cached or served, so the parsers must never panic,
// must not allocate without bound, and must fail closed on malformed input. The
// archive_url rewrite, in particular, is applied to an attacker-controlled
// document and must never panic or emit a non-JSON result.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/dart/
package dart

import (
	"encoding/json"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/api/packages/path",
		"/api/packages/path/advisories",
		"/api/archives/path-1.2.3.tar.gz",
		"/api/archives/my_pkg-2.0.0-beta.1.tar.gz",
		"/api/packages/a/../../etc/passwd",
		"",
		"/",
		"////",
		"/api/archives/-1.0.0.tar.gz",
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
		if res.isArchive() && (res.name == "" || res.version == "") {
			t.Fatalf("archive with empty name/version: %q", path)
		}
	})
}

func FuzzParseVersionList(f *testing.F) {
	seeds := []string{
		`{"name":"path","latest":{"version":"1.0.0","archive_url":"https://x/a.tar.gz","archive_sha256":"` +
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"},"versions":[]}`,
		`{"versions":[{"version":"1.0.0","pubspec":{"repository":"https://x"}}]}`,
		`not json`,
		``,
		`{`,
		`{"versions":null,"latest":null}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		vl, err := parseVersionList(body)
		if err != nil {
			return
		}
		if e, ok := vl.archiveFor("1.0.0"); ok {
			_ = e.repository()
			if hex, ok := normalizeDigest(e.ArchiveSha256); ok {
				if len(hex) != sha256HexLen || !isHex(hex) {
					t.Fatalf("accepted invalid checksum %q", hex)
				}
			}
		}
	})
}

func FuzzRewriteArchiveURLs(f *testing.F) {
	seeds := []string{
		`{"name":"p","latest":{"version":"1.0.0","archive_url":"https://u/a.tar.gz"},"versions":[{"version":"1.0.0","archive_url":"https://u/a.tar.gz","pubspec":{"a":1}}]}`,
		`{"versions":"notarray"}`,
		`{"latest":42}`,
		`{}`,
		`[]`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		out, err := rewriteArchiveURLs(body, func(version string) string {
			return "https://proxy/v1/pub/api/archives/p-" + version + ".tar.gz"
		})
		if err != nil {
			// On a parse failure the original bytes are returned unchanged.
			return
		}
		// A successful rewrite must always yield valid JSON.
		if !json.Valid(out) {
			t.Fatalf("rewrite produced invalid JSON for input %q", body)
		}
	})
}
