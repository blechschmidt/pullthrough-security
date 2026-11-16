package ansible

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// ArtifactPathCoordinate reads a path exactly as Resolve does: for every
// collection artifact Resolve caches it returns the coordinate Resolve
// attaches, and it refuses every path Resolve serves live.
func TestArtifactPathCoordinateIsWhatResolveReads(t *testing.T) {
	b, err := New(Options{Name: "galaxy", UpstreamURL: "https://galaxy.ansible.com", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, collection, version string }{
		{"/api/v3/plugin/ansible/content/published/collections/artifacts/community-general-14.0.1.tar.gz", "community.general", "14.0.1"},
		{"/api/v3/plugin/ansible/content/published/collections/artifacts/fjacquet-ppdm-0.3.0.tar.gz", "fjacquet.ppdm", "0.3.0"},
		{"/api/v3/plugin/ansible/content/rh-certified/collections/artifacts/epfl_si-secrets-0.1.1.tar.gz", "epfl_si.secrets", "0.1.1"},
		{"/api/v3/plugin/ansible/content/published/collections/artifacts/acme-tools-1.0.0-beta.1+b2.tar.gz", "acme.tools", "1.0.0-beta.1+b2"},
	} {
		c, v, ok := ArtifactPathCoordinate(tc.path)
		if !ok || c != tc.collection || v != tc.version {
			t.Errorf("%s: %q %q %v, want %q %q", tc.path, c, v, ok, tc.collection, tc.version)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: tc.path, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if !res.Cacheable || res.Coordinate.Name != c || res.Coordinate.Version != v {
			t.Errorf("%s: Resolve gives %+v (cacheable %v), ArtifactPathCoordinate %q %q", tc.path, res.Coordinate, res.Cacheable, c, v)
		}
		if !ValidRelease(c, v) {
			t.Errorf("ValidRelease(%q, %q) = false", c, v)
		}
	}
	for _, p := range []string{
		"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/",
		"/api/v3/plugin/ansible/content/published/collections/index/community/general/versions/14.0.1/",
		"/api/v3/plugin/ansible/content/published/collections/artifacts/Community-General-1.0.0.tar.gz",
		"/api/v3/plugin/ansible/content/published/collections/artifacts/community-general.tar.gz",
		"/api/v3/plugin/ansible/content/published/collections/artifacts/../community-general-1.0.0.tar.gz",
		"/download/community-general-1.0.0.tar.gz",
	} {
		if c, v, ok := ArtifactPathCoordinate(p); ok {
			t.Errorf("%s: read as artifact %q %q", p, c, v)
			continue
		}
		if res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}}); err == nil && res.Cacheable {
			t.Errorf("%s: ArtifactPathCoordinate refuses a path Resolve caches", p)
		}
	}
}

func TestValidCollectionAndRelease(t *testing.T) {
	for name, want := range map[string]bool{
		"community.general": true, "epfl_si.secrets": true, "a10.acos_axapi": true,
		"Community.general": false, "community-general": false, "community": false, "community.": false,
		".general": false, "community.gen.eral": false, "community/general": false, "": false,
	} {
		if got := ValidCollection(name); got != want {
			t.Errorf("ValidCollection(%q) = %v, want %v", name, got, want)
		}
	}
	for _, tc := range []struct {
		collection, version string
		want                bool
	}{
		{"community.general", "14.0.1", true},
		{"community.general", "1.0.0-rc.1", true},
		{"community.general", "", false},
		{"community.general", "1.0/0", false},
		{"community.general", "1 0", false},
		{"community.general", "..", false},
		{"Community.general", "1.0.0", false},
	} {
		if got := ValidRelease(tc.collection, tc.version); got != tc.want {
			t.Errorf("ValidRelease(%q, %q) = %v, want %v", tc.collection, tc.version, got, tc.want)
		}
	}
}
