package puppet

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// ReleaseFileCoordinate reads a path exactly as Resolve does: for every
// release tarball Resolve caches it returns the coordinate Resolve attaches,
// and it refuses every path Resolve serves live.
func TestReleaseFileCoordinateIsWhatResolveReads(t *testing.T) {
	b, err := New(Options{Name: "forge", UpstreamURL: "https://forgeapi.puppet.com", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1")})
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(p string) *backends.Resolved {
		t.Helper()
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return res
	}
	for _, tc := range []struct{ path, module, version string }{
		{"/v3/files/puppetlabs-stdlib-9.6.0.tar.gz", "puppetlabs-stdlib", "9.6.0"},
		{"/v3/files/treydock-yum_cron-10.0.0.tar.gz", "treydock-yum_cron", "10.0.0"},
		{"/v3/files/030-git-0.2.6.tar.gz", "030-git", "0.2.6"},
		{"/v3/files/acme-mod-1.0.0-rc.1+build.5.tar.gz", "acme-mod", "1.0.0-rc.1+build.5"},
		// Owners and names hold no "-": the first two split the slug, and the
		// rest is the version, as the backend reads it.
		{"/v3/files/puppetlabs-std-lib-1.0.0.tar.gz", "puppetlabs-std", "lib-1.0.0"},
	} {
		m, v, ok := ReleaseFileCoordinate(tc.path)
		if !ok || m != tc.module || v != tc.version {
			t.Errorf("%s: %q %q %v, want %q %q", tc.path, m, v, ok, tc.module, tc.version)
		}
		res := resolve(tc.path)
		if !res.Cacheable || res.Coordinate.Name != m || res.Coordinate.Version != v {
			t.Errorf("%s: Resolve gives %+v (cacheable %v), ReleaseFileCoordinate %q %q", tc.path, res.Coordinate, res.Cacheable, m, v)
		}
		if !ValidRelease(m, v) {
			t.Errorf("ValidRelease(%q, %q) = false", m, v)
		}
	}
	for _, p := range []string{
		"/v3/modules/puppetlabs-stdlib", "/v3/releases/puppetlabs-stdlib-9.6.0", "/v3/files/puppetlabs-stdlib.tar.gz",
		"/v3/files/Slashbunny-phpfpm-0.1.9.tar.gz", "/v3/files/../x-y-1.tar.gz",
		"/v3/files/a/puppetlabs-stdlib-9.6.0.tar.gz.sig", "/v3/files/puppetlabs-stdlib-9.6.0.zip",
	} {
		if m, v, ok := ReleaseFileCoordinate(p); ok {
			t.Errorf("%s: read as release %q %q", p, m, v)
			continue
		}
		if res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}}); err == nil && res.Cacheable {
			t.Errorf("%s: ReleaseFileCoordinate refuses a path Resolve caches", p)
		}
	}
}

func TestValidModuleAndRelease(t *testing.T) {
	for slug, want := range map[string]bool{
		"puppetlabs-stdlib": true, "030-git": true, "treydock-yum_cron": true,
		"Slashbunny-phpfpm": false, "puppetlabs-Stdlib": false, "puppetlabs/stdlib": false, "puppetlabs": false,
		"puppetlabs-": false, "-stdlib": false, "puppetlabs-std-lib": false, "puppetlabs-1lib": false, "": false,
	} {
		if got := ValidModule(slug); got != want {
			t.Errorf("ValidModule(%q) = %v, want %v", slug, got, want)
		}
	}
	for _, tc := range []struct {
		module, version string
		want            bool
	}{
		{"puppetlabs-stdlib", "9.6.0", true},
		{"puppetlabs-stdlib", "1.0.0-rc1", true},
		{"puppetlabs-stdlib", "", false},
		{"puppetlabs-stdlib", "1.0/0", false},
		{"puppetlabs-stdlib", "1.0.0 ", false},
		{"puppetlabs-stdlib", "..", false},
		{"Slashbunny-phpfpm", "0.1.9", false},
	} {
		if got := ValidRelease(tc.module, tc.version); got != tc.want {
			t.Errorf("ValidRelease(%q, %q) = %v, want %v", tc.module, tc.version, got, tc.want)
		}
	}
}
