package swift

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about each
// registry endpoint. The archive and the manifest are what SwiftPM builds and
// runs; the release list, a release's metadata and the identifier lookup are
// documents.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRegistry(t), nil)

	cases := []struct {
		name     string
		path     string
		query    url.Values
		class    backends.ArtifactClass
		filename string // what Resolved.ArtifactFilename reports
	}{
		{"source archive", "/mona/LinkedList/1.1.1.zip", nil, backends.ArtifactPayload, "1.1.1.zip"},
		{"pre-release source archive", "/mona/Linked-List/2.0.0-beta.1.zip", nil, backends.ArtifactPayload, "2.0.0-beta.1.zip"},
		{"package manifest", "/mona/LinkedList/1.1.1/Package.swift", nil, backends.ArtifactPayload, "Package.swift"},
		{
			"package manifest selected by query", "/mona/LinkedList/1.1.1/Package.swift",
			url.Values{"swift-version": {"5.3"}}, backends.ArtifactPayload, "Package.swift",
		},
		{"tools-version manifest", "/mona/LinkedList/1.1.1/Package@swift-5.3.swift", nil, backends.ArtifactPayload, "Package@swift-5.3.swift"},

		{"release list", "/mona/LinkedList", nil, backends.ArtifactMetadata, "LinkedList"},
		{"release metadata", "/mona/LinkedList/1.1.1", nil, backends.ArtifactMetadata, "1.1.1"},
		{"release metadata with the json extension", "/mona/LinkedList/1.1.1.json", nil, backends.ArtifactMetadata, "1.1.1.json"},
		{"pre-release metadata", "/mona/LinkedList/2.0.0-beta.1", nil, backends.ArtifactMetadata, "2.0.0-beta.1"},
		{"release metadata with build identifiers", "/mona/LinkedList/1.0.0+build.5", nil, backends.ArtifactMetadata, "1.0.0+build.5"},
		{
			"identifier lookup", "/identifiers",
			url.Values{"url": {"https://github.com/mona/LinkedList"}}, backends.ArtifactMetadata, "identifiers",
		},

		// classify takes any third segment that does not end in ".zip" for a
		// release. One that is not positively a version may still be answered with
		// the archive (a case-insensitive registry, ";param" stripping), so it is
		// not called metadata.
		{"archive suffix in upper case", "/mona/LinkedList/1.1.1.ZIP", nil, backends.ArtifactUnclassified, "1.1.1.ZIP"},
		{"archive suffix in mixed case", "/mona/LinkedList/1.1.1.Zip", nil, backends.ArtifactUnclassified, "1.1.1.Zip"},
		{"archive with a path parameter", "/mona/LinkedList/1.1.1.zip;a=b", nil, backends.ArtifactUnclassified, "1.1.1.zip;a=b"},
		{"archive with a trailing space", "/mona/LinkedList/1.1.1.zip ", nil, backends.ArtifactUnclassified, "1.1.1.zip "},
		{"archive with the json extension", "/mona/LinkedList/1.1.1.zip.json", nil, backends.ArtifactUnclassified, "1.1.1.zip.json"},
		{"well-formed version spelling the archive suffix", "/mona/LinkedList/1.0.0-rc.ZIP", nil, backends.ArtifactUnclassified, "1.0.0-rc.ZIP"},
		{"not a version", "/mona/LinkedList/latest", nil, backends.ArtifactUnclassified, "latest"},
		{"two-component version", "/mona/LinkedList/1.1", nil, backends.ArtifactUnclassified, "1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := tc.query
			if query == nil {
				query = url.Values{}
			}
			resolved, err := b.Resolve(context.Background(), &backends.Request{
				Method: http.MethodGet, Path: tc.path, Query: query, Header: http.Header{},
			})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.path, err)
			}
			got := resolved.Artifact
			if got.Class != tc.class {
				t.Errorf("Resolve(%q) class = %s, want %s", tc.path, got.Class, tc.class)
			}
			// A manifest is one Swift source file; the source archive is an archive.
			wantKind := backends.ArtifactKind("")
			if got.Class == backends.ArtifactPayload && strings.HasSuffix(tc.path, ".swift") {
				wantKind = backends.KindFile
			}
			if got.Kind != wantKind {
				t.Errorf("Resolve(%q) kind = %q, want %q", tc.path, got.Kind, wantKind)
			}
			// Every Swift registry resource is fetched from a URL that ends in its
			// own name, so no explicit file name is needed.
			if got.Filename != "" {
				t.Errorf("Resolve(%q) filename = %q, want none", tc.path, got.Filename)
			}
			if name := resolved.ArtifactFilename(); name != tc.filename {
				t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", tc.path, name, tc.filename)
			}
		})
	}
}

func TestIsReleaseVersion(t *testing.T) {
	for _, v := range []string{
		"0.0.0", "1.1.1", "10.20.30", "1.1.1.json",
		"2.0.0-beta.1", "1.0.0-alpha", "1.0.0-0.3.7", "1.0.0-x-y-z.1",
		"1.0.0+build.5", "1.0.0-rc.1+exp.sha.5114f85", "1.0.0-rc.1.json",
	} {
		if !isReleaseVersion(v) {
			t.Errorf("isReleaseVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{
		"", "1", "1.1", "1.1.1.1", "v1.1.1", "latest", "1.1.x",
		"1.1.1.ZIP", "1.1.1.Zip", "1.1.1.zip", "1.1.1.zip.json", "1.0.0-rc.ZIP", "1.0.0+build.zip",
		"1.1.1.zip;a=b", "1.1.1;a=b", "1.1.1.zip ", "1.1.1 ", "1.1.1%2ezip", "1.1.1\\..\\x",
		"1.0.0-", "1.0.0+", "1.0.0-rc..1", "1.1.1.JSON",
	} {
		if isReleaseVersion(v) {
			t.Errorf("isReleaseVersion(%q) = true, want false", v)
		}
	}
}
