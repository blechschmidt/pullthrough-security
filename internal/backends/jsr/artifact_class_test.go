package jsr

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every resource the JSR layout names. A module file is source a runtime
// executes — a payload; the package and version metadata documents are
// metadata. The two are separated by position in the path, so a module file
// that merely carries a metadata document's name must stay a payload.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, newFakeRemote(t), nil)

	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: module files of a published version, at any depth.
		{"/@luca/flag/1.0.1/main.ts", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8/mod.ts", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8/posix/join.ts", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8/deno.json", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8-rc.1/mod.ts", backends.ArtifactPayload, true},
		// A module file named like a metadata document is still a module file.
		{"/@std/path/1.0.8/meta.json", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8/1.0.8_meta.json", backends.ArtifactPayload, true},
		{"/@std/path/1.0.8/sub/meta.json", backends.ArtifactPayload, true},

		// Metadata: the package and version documents directly below the package.
		{"/@luca/flag/meta.json", backends.ArtifactMetadata, false},
		{"/@std/path/meta.json", backends.ArtifactMetadata, false},
		{"/@std/path/1.0.8_meta.json", backends.ArtifactMetadata, false},
		{"/@std/path/1.0.8-rc.1_meta.json", backends.ArtifactMetadata, false},
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
		// Every JSR resource is fetched from a URL that ends in its own file
		// name, so no explicit name (and no payload refinement) is stated.
		// JSR serves module files one by one: every payload is a single file.
		wantKind := backends.ArtifactKind("")
		if res.Artifact.Class == backends.ArtifactPayload {
			wantKind = backends.KindFile
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want only a class", c.path, res.Artifact)
		}
	}
}
