//go:build fuzz
// +build fuzz

// Fuzz targets for the Docker/OCI Registry v2 request parsers (Task 30, Task 5).
//
// The proxy routes every registry request by parsing the v2 API path and, for
// digest-addressed resources, parsing and verifying the content digest. Both
// inputs are fully attacker-controlled (a client requests an arbitrary path; an
// upstream or client supplies an arbitrary digest string), so the parsers must
// never panic and must classify safely.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzParseReference ./internal/backends/docker/
package docker

import (
	"strings"
	"testing"
)

func FuzzParseReference(f *testing.F) {
	seeds := []string{
		"/v2/",
		"/v2",
		"/v2/library/nginx/manifests/latest",
		"/v2/library/nginx/manifests/sha256:" + strings.Repeat("a", 64),
		"/v2/library/nginx/blobs/sha256:" + strings.Repeat("b", 64),
		"/v2/library/nginx/tags/list",
		"/v2/a/b/c/d/manifests/v1.2.3",
		"/v2/library/nginx/blobs/uploads/abc-123",
		"/v2/x/manifests/",
		"/v2//manifests/latest",
		"/v2/x/manifests/a/b",
		"/not/v2",
		"",
		"/",
		"/v2/x/manifests/" + strings.Repeat("t", 10000),
		"/v2/" + strings.Repeat("a/", 5000) + "manifests/latest",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		ref, ok := parseReference(path)
		if !ok {
			return
		}
		// scope() must not panic and must be consistent with the parsed name.
		scope := ref.scope()
		switch ref.kind {
		case refManifest, refBlob:
			if ref.name == "" || ref.reference == "" {
				t.Fatalf("manifest/blob ref missing name or reference: %q -> %#v", path, ref)
			}
			if strings.Contains(ref.reference, "/") {
				t.Fatalf("reference segment contains '/': %q -> %q", path, ref.reference)
			}
			// isDigest must agree with the digest validator.
			if ref.isDigest != IsDigest(ref.reference) {
				t.Fatalf("isDigest disagrees with IsDigest for %q", ref.reference)
			}
		}
		if ref.name != "" && scope == "" {
			t.Fatalf("named ref produced empty scope: %#v", ref)
		}
	})
}

func FuzzParseDigest(f *testing.F) {
	seeds := []string{
		"sha256:" + strings.Repeat("a", 64),
		"sha512:" + strings.Repeat("f", 128),
		"sha256:" + strings.Repeat("A", 64), // uppercase hex
		"sha256:short",
		"sha256:",
		"md5:" + strings.Repeat("a", 32),
		"sha256",
		":",
		"",
		"sha256:" + strings.Repeat("g", 64), // non-hex chars
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		strings.Repeat("a", 100000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDigest(s)
		if err != nil {
			if IsDigest(s) {
				t.Fatalf("ParseDigest errored but IsDigest reports valid: %q", s)
			}
			return
		}
		// A parsed digest must round-trip and be usable.
		if d.String() != s {
			t.Fatalf("digest did not round-trip: %q -> %q", s, d.String())
		}
		if !IsDigest(s) {
			t.Fatalf("ParseDigest succeeded but IsDigest reports invalid: %q", s)
		}
		// newHash must return a usable hasher for the recognized algorithm.
		if h := d.newHash(); h == nil {
			t.Fatalf("nil hash for digest %q", s)
		}
	})
}
