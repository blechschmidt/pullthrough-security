package dart

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about each
// pub endpoint: the archive is the package a client unpacks, the list-versions
// and advisories documents are metadata. An archive's upstream URL is the
// list-versions document it is located through, so the classification must name
// the archive file itself.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRepo(t), nil)

	cases := []struct {
		name         string
		path         string
		class        backends.ArtifactClass
		filename     string // Artifact.Filename
		servedAs     string // what Resolved.ArtifactFilename reports
		upstreamTail string // how Resolved.UpstreamURL ends
	}{
		{
			"archive", "/api/archives/path-1.2.3.tar.gz",
			backends.ArtifactPayload, "path-1.2.3.tar.gz", "path-1.2.3.tar.gz", "/api/packages/path",
		},
		{
			"pre-release archive", "/api/archives/my_pkg-2.0.0-beta.1.tar.gz",
			backends.ArtifactPayload, "my_pkg-2.0.0-beta.1.tar.gz", "my_pkg-2.0.0-beta.1.tar.gz", "/api/packages/my_pkg",
		},
		{
			"archive with build metadata", "/api/archives/path-1.2.3+4.tar.gz",
			backends.ArtifactPayload, "path-1.2.3+4.tar.gz", "path-1.2.3+4.tar.gz", "/api/packages/path",
		},
		{
			"list versions", "/api/packages/path",
			backends.ArtifactMetadata, "", "path", "/api/packages/path",
		},
		{
			"list versions with a trailing slash", "/api/packages/path/",
			backends.ArtifactMetadata, "", "path", "/api/packages/path/",
		},
		{
			"advisories", "/api/packages/path/advisories",
			backends.ArtifactMetadata, "", "advisories", "/api/packages/path/advisories",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := b.Resolve(context.Background(), &backends.Request{
				Method: http.MethodGet, Path: tc.path, Query: url.Values{}, Header: http.Header{},
			})
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.path, err)
			}
			got := resolved.Artifact
			if got.Class != tc.class {
				t.Errorf("Resolve(%q) class = %s, want %s", tc.path, got.Class, tc.class)
			}
			if got.Kind != "" {
				t.Errorf("Resolve(%q) kind = %q, want none", tc.path, got.Kind)
			}
			if got.Filename != tc.filename {
				t.Errorf("Resolve(%q) filename = %q, want %q", tc.path, got.Filename, tc.filename)
			}
			if name := resolved.ArtifactFilename(); name != tc.servedAs {
				t.Errorf("Resolve(%q).ArtifactFilename() = %q, want %q", tc.path, name, tc.servedAs)
			}
			if !strings.HasSuffix(resolved.UpstreamURL, tc.upstreamTail) {
				t.Errorf("Resolve(%q) upstream URL = %q, want it to end in %q", tc.path, resolved.UpstreamURL, tc.upstreamTail)
			}
		})
	}
}
