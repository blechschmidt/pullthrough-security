package julia

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// TestResolveArtifactClass pins what Resolve tells the content gates about
// every Pkg Server resource. Package and artifact tarballs are payloads; the
// /registries listing and a registry tarball (an index of TOML files) are
// metadata. All three tarballs are cached and verified alike, so the class is
// asserted next to the cacheability it must not be inferred from.
func TestResolveArtifactClass(t *testing.T) {
	b := newTestBackend(t, doerFunc(func(context.Context, upstream.Request) (*upstream.Response, error) {
		t.Fatal("Resolve must not perform I/O")
		return nil, nil
	}), &Metrics{})

	sha3Hash := strings.Repeat("a", sha3TreeHexLen)
	cases := []struct {
		path      string
		want      backends.ArtifactClass
		cacheable bool
	}{
		// Payloads: package source and artifact tarballs.
		{"/package/" + exampleUUID + "/" + sampleTreeSHA, backends.ArtifactPayload, true},
		{"/artifact/" + sampleTreeSHA, backends.ArtifactPayload, true},
		// A reserved-length (unverifiable) tree hash is no less a payload.
		{"/package/" + exampleUUID + "/" + sha3Hash, backends.ArtifactPayload, true},
		{"/artifact/" + sha3Hash, backends.ArtifactPayload, true},

		// Metadata: the registries listing and a registry's index tarball.
		{"/registries", backends.ArtifactMetadata, false},
		{"/registry/" + generalUUID + "/" + sampleTreeSHA, backends.ArtifactMetadata, true},
		{"/registry/" + generalUUID + "/" + sha3Hash, backends.ArtifactMetadata, true},
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
		// A Pkg Server resource has no file name (its URL ends in the tree hash),
		// so none is stated and the format is left to the bytes. The one
		// refinement is a registry, which is metadata in the form of a tarball.
		wantKind := backends.ArtifactKind("")
		if strings.HasPrefix(c.path, "/registry/") {
			wantKind = backends.KindIndexArchive
		}
		if res.Artifact.Filename != "" || res.Artifact.Kind != wantKind {
			t.Errorf("Resolve(%q).Artifact = %+v, want kind %q and no file name", c.path, res.Artifact, wantKind)
		}
	}
}
