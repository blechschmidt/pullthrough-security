package rubygems

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// GemPathCoordinate reads a path exactly as Resolve does: the coordinate it
// returns is the one Resolve attaches, for every gem path Resolve caches, and
// it refuses every path that is not a gem download.
func TestGemPathCoordinateIsWhatResolveReads(t *testing.T) {
	b, err := New(Options{Name: "rubygems", UpstreamURL: "https://rubygems.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, name, version string }{
		{"/gems/rack-test-2.3.0.gem", "rack-test", "2.3.0"},
		{"/gems/oximg-0.11.0-aarch64-linux-gnu.gem", "oximg", "0.11.0-aarch64-linux-gnu"},
		{"/gems/--1.gem", "-", "1"},
		{"/gems/-A-0.0.0.gem", "-A", "0.0.0"},
		{"/gems/rails-7.0.4.1.gem", "rails", "7.0.4.1"},
		// A name with "-" before a digit is split there: the backend reads the
		// file as another gem's.
		{"/gems/3scale-3scale_ws_api-0.1.gem", "3scale", "3scale_ws_api-0.1"},
	} {
		name, version, ok := GemPathCoordinate(tc.path)
		if !ok || name != tc.name || version != tc.version {
			t.Errorf("%s: %q %q %v, want %q %q", tc.path, name, version, ok, tc.name, tc.version)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: tc.path, Query: url.Values{}})
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if !res.Cacheable || res.Coordinate.Name != name || res.Coordinate.Version != version {
			t.Errorf("%s: Resolve gives %+v (cacheable %v), GemPathCoordinate %q %q", tc.path, res.Coordinate, res.Cacheable, name, version)
		}
	}
	for _, p := range []string{"/info/rack-test", "/versions", "/gems/rack-test.gem", "/gems/../rack-1.0.gem", "/quick/Marshal.4.8/rack-1.0.gemspec.rz", "/gems/a/b-1.0.gem"} {
		if name, version, ok := GemPathCoordinate(p); ok {
			t.Errorf("%s: read as gem %q %q", p, name, version)
		}
	}
}
