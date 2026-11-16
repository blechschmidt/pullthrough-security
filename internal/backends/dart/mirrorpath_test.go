package dart

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// ArchivePathCoordinate reads a path exactly as Resolve does: for every
// archive Resolve caches it returns the coordinate Resolve attaches, and it
// refuses every other path.
func TestArchivePathCoordinateIsWhatResolveReads(t *testing.T) {
	b, err := New(Options{Name: "pub", UpstreamURL: "https://pub.dev", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, name, version string }{
		{"/api/archives/open_at_login-0.0.2.tar.gz", "open_at_login", "0.0.2"},
		{"/api/archives/zepben_protobuf-1.10.0-beta.1.tar.gz", "zepben_protobuf", "1.10.0-beta.1"},
		{"/api/archives/http-1.2.0+1.tar.gz", "http", "1.2.0+1"},
	} {
		n, v, ok := ArchivePathCoordinate(tc.path)
		if !ok || n != tc.name || v != tc.version {
			t.Errorf("%s: %q %q %v, want %q %q", tc.path, n, v, ok, tc.name, tc.version)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: tc.path, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		if !res.Cacheable || res.Coordinate.Name != n || res.Coordinate.Version != v {
			t.Errorf("%s: Resolve gives %+v (cacheable %v), ArchivePathCoordinate %q %q", tc.path, res.Coordinate, res.Cacheable, n, v)
		}
	}
	for _, p := range []string{
		"/api/packages/open_at_login", "/api/packages/open_at_login/advisories", "/api/archives/open_at_login.tar.gz",
		"/api/archives/Autolinker-0.1.0.tar.gz", "/api/archives/open_at_login-0.0.2.zip", "/api/archives/x/open_at_login-0.0.2.tar.gz",
		"/packages/open_at_login/versions/0.0.2.tar.gz",
	} {
		if n, v, ok := ArchivePathCoordinate(p); ok {
			t.Errorf("%s: read as archive %q %q", p, n, v)
			continue
		}
		if res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}}); err == nil && res.Cacheable {
			t.Errorf("%s: ArchivePathCoordinate refuses a path Resolve caches", p)
		}
	}
	for name, want := range map[string]bool{"open_at_login": true, "_private": true, "a1": true, "Autolinker": false, "1a": false, "a-b": false, "": false} {
		if got := ValidPackageName(name); got != want {
			t.Errorf("ValidPackageName(%q) = %v, want %v", name, got, want)
		}
	}
}
