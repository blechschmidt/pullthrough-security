package cran

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// SourcePackagePath names a path the backend resolves to the package version
// it was built for, and nothing the backend would read as another.
func TestSourcePackagePathRoundTrips(t *testing.T) {
	b, err := New(Options{Name: "cran", UpstreamURL: "https://cloud.r-project.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ dir, name, version, want string }{
		{"", "jsonlite", "1.8.8", "/src/contrib/jsonlite_1.8.8.tar.gz"},
		{"", "data.table", "1.16.4", "/src/contrib/data.table_1.16.4.tar.gz"},
		{"", "boot", "1.3-32", "/src/contrib/boot_1.3-32.tar.gz"},
		{"4.7.0/Recommended", "boot", "1.3-32", "/src/contrib/4.7.0/Recommended/boot_1.3-32.tar.gz"},
		{"/sub/", "pkg", "0.1", "/src/contrib/sub/pkg_0.1.tar.gz"},
	} {
		p, ok := SourcePackagePath(tc.dir, tc.name, tc.version)
		if !ok || p != tc.want {
			t.Errorf("%+v: %q %v", tc, p, ok)
			continue
		}
		dec, _ := url.PathUnescape(p)
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !res.Cacheable || res.Coordinate.Name != tc.name || res.Coordinate.Version != tc.version {
			t.Errorf("%s resolves to %+v", p, res.Coordinate)
		}
	}
	for _, tc := range []struct{ dir, name, version string }{
		{"", "a_b", "1.0"},      // the name would end at the underscore
		{"", "pkg", "1.0/../x"}, // a separator in the version
		{"", "", "1.0"},         // no name
		{"", "pkg", ""},         // no version
		{"..", "pkg", "1.0"},    // a dot segment
		{"a//b", "pkg", "1.0"},  // an empty segment
		{"", "pkg", "1.0 beta"}, // a space
		{"", "pkg", "1.0%2F2"},  // an escape
		{"x\\y", "pkg", "1.0"},  // a backslash
		{"", "pkg", "1.0\n"},    // a control character
	} {
		if p, ok := SourcePackagePath(tc.dir, tc.name, tc.version); ok {
			t.Errorf("%+v accepted as %q", tc, p)
		}
	}
}
