package nix

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every binary-cache resource. A NAR — whatever its compression, and whether or
// not its content address is one the backend can verify — is the payload; the
// narinfo and the nix-cache-info descriptor are metadata.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeCache(t), nil, nil)

	fh := strings.Repeat("a", 52) // valid-length nix base-32 (sha256)
	sh := strings.Repeat("a", 32) // valid store hash

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: NAR archives.
		{"/nar/" + fh + ".nar.xz", backends.ArtifactPayload, true},
		{"/nar/" + fh + ".nar.zst", backends.ArtifactPayload, true},
		{"/nar/" + fh + ".nar.bz2", backends.ArtifactPayload, true},
		{"/nar/" + fh + ".nar", backends.ArtifactPayload, true},
		// A content address the backend cannot verify is no less a payload.
		{"/nar/" + sh + ".nar.xz", backends.ArtifactPayload, true},

		// Metadata: the narinfo and the cache descriptor.
		{"/" + sh + ".narinfo", backends.ArtifactMetadata, false},
		{"/nix-cache-info", backends.ArtifactMetadata, false},
	}
	for _, c := range cases {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: c.path, Query: url.Values{}, Header: http.Header{}})
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
		// Every binary-cache resource is fetched from a URL that ends in its own
		// file name, so no explicit name (and no payload refinement) is stated.
		if res.Artifact.Filename != "" || res.Artifact.Kind != "" {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}
