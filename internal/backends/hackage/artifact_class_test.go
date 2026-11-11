package hackage

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the Hackage layout names. Only the sdist tarball is a payload;
// the package index, the TUF documents, a package's target metadata, its .cabal
// description and its landing page are metadata. The index is itself a
// ".tar.gz", so the class is stated per kind and never inferred from a suffix.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: the sdist tarball, in both spellings of its path.
		{"/package/text-2.1/text-2.1.tar.gz", backends.ArtifactPayload, true},
		{"/package/aeson-pretty-0.8.10/aeson-pretty-0.8.10.tar.gz", backends.ArtifactPayload, true},
		{"/package/HUnit-1.6.2.0/HUnit-1.6.2.0.tar.gz", backends.ArtifactPayload, true},
		{"/package/text-2.1.tar.gz", backends.ArtifactPayload, true},

		// Metadata: the incremental package index.
		{"/01-index.tar.gz", backends.ArtifactMetadata, false},
		{"/01-index.tar", backends.ArtifactMetadata, false},

		// Metadata: the TUF security documents.
		{"/root.json", backends.ArtifactMetadata, false},
		{"/snapshot.json", backends.ArtifactMetadata, false},
		{"/timestamp.json", backends.ArtifactMetadata, false},
		{"/mirrors.json", backends.ArtifactMetadata, false},

		// Metadata: per-package documents.
		{"/package/text-2.1/package.json", backends.ArtifactMetadata, false},
		{"/package/text-2.1/text.cabal", backends.ArtifactMetadata, false},
		{"/package/aeson-pretty-0.8.10/aeson-pretty.cabal", backends.ArtifactMetadata, false},
		{"/package/text-2.1", backends.ArtifactMetadata, false},
		{"/package/text", backends.ArtifactMetadata, false},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}})
		if err != nil {
			t.Errorf("Resolve(%q): %v", c.path, err)
			continue
		}
		if res.Artifact.Class != c.want {
			t.Errorf("Resolve(%q).Artifact.Class = %s, want %s", c.path, res.Artifact.Class, c.want)
		}
		if res.Cacheable != c.cacheable {
			t.Errorf("Resolve(%q).Cacheable = %v, want %v", c.path, res.Cacheable, c.cacheable)
		}
		// Every Hackage resource is fetched from a URL that ends in its own file
		// name, so no explicit name is stated. The one refinement is the package
		// index, which is metadata in the form of a tar archive.
		wantKind := backends.ArtifactKind("")
		if strings.HasPrefix(c.path, "/01-index.tar") {
			wantKind = backends.KindIndexArchive
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want kind %q and no file name", c.path, res.Artifact, wantKind)
		}
	}
}
