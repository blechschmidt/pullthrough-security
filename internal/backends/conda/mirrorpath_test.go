package conda

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// PackagePath names a path the backend resolves to the package it was built
// for, and nothing the backend would not serve as one.
func TestPackagePathRoundTrips(t *testing.T) {
	b, err := New(Options{Name: "conda-forge", UpstreamURL: "https://conda.anaconda.org/conda-forge", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ subdir, file, name, version string }{
		{"noarch", "requests-2.32.3-pyhd8ed1ab_1.conda", "requests", "2.32.3"},
		{"linux-64", "numpy-1.26.4-py312heda63a1_0.tar.bz2", "numpy", "1.26.4"},
		{"win-arm64", "7zip-26.02-h11ae69d_0.conda", "7zip", "26.02"},
		{"osx-arm64", "python_abi-3.12-8_cp312.conda", "python_abi", "3.12"},
		{"linux-aarch64", "libgcc-ng-14.2.0-h69a702a_2.conda", "libgcc-ng", "14.2.0"},
		{"noarch", "pkg-1!2.0+local-0.conda", "pkg", "1!2.0+local"},
	} {
		p, name, version, ok := PackagePath(tc.subdir, tc.file)
		if !ok || name != tc.name || version != tc.version {
			t.Errorf("%s/%s: %q %q %q %v", tc.subdir, tc.file, p, name, version, ok)
			continue
		}
		dec, err := url.PathUnescape(p)
		if err != nil || dec != "/"+tc.subdir+"/"+tc.file {
			t.Errorf("%s decodes to %q (%v)", p, dec, err)
			continue
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !res.Cacheable || res.Coordinate.Name != tc.name || res.Coordinate.Version != tc.version || res.Metadata[MetaSubdir] != tc.subdir {
			t.Errorf("%s resolves to %+v %v", p, res.Coordinate, res.Metadata)
		}
	}
	for _, tc := range []struct{ subdir, file string }{
		{"noarch", "requests-2.32.3.conda"},
		{"noarch", "requests-2.32.3-0.whl"},
		{"noarch", "repodata.json"},
		{"plan9-64", "x-1-0.conda"},
		{"noarch", "../x-1-0.conda"},
		{"noarch", "a/b-1-0.conda"},
		{"no/arch", "x-1-0.conda"},
		{"", "x-1-0.conda"},
		{"noarch", "x-1-0 .conda"},
		{"noarch", "x-1-0%2F.conda"},
		{"noarch", "-1-0.conda"},
	} {
		if p, _, _, ok := PackagePath(tc.subdir, tc.file); ok {
			t.Errorf("%s/%s accepted as %q", tc.subdir, tc.file, p)
		}
	}
	for s, want := range map[string]bool{"noarch": true, "linux-64": true, "osx-arm64": true, "emscripten-wasm32": true, "zos-z": true, "linux": false, "plan9-64": false, "linux-": false, "noarch/": false, "": false} {
		if IsSubdir(s) != want {
			t.Errorf("IsSubdir(%q) = %v", s, !want)
		}
	}
}
