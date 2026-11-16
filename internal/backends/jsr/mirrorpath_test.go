package jsr

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func mirrorPathTestBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(Options{Name: "jsr-test", UpstreamURL: "https://jsr.io", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mirrorPathResolve(t *testing.T, b *Backend, p string) *backends.Resolved {
	t.Helper()
	dec, err := url.PathUnescape(p)
	if err != nil {
		t.Fatalf("%s does not decode: %v", p, err)
	}
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return res
}

// A module file path, decoded as the server decodes a request, resolves to
// the cacheable module file of the package and version at exactly the
// manifest's key; the two metadata documents resolve as such and are not
// cached.
func TestModuleFilePathRoundTrips(t *testing.T) {
	b := mirrorPathTestBackend(t)
	for _, tc := range []struct{ file, want string }{
		{"/mod.ts", "/@std/path/1.1.6/mod.ts"},
		{"/_common/assert_path.ts", "/@std/path/1.1.6/_common/assert_path.ts"},
		{"/posix/mod.ts", "/@std/path/1.1.6/posix/mod.ts"},
		{"/routes/[id]/(group)/page.tsx", "/@std/path/1.1.6/routes/%5Bid%5D/%28group%29/page.tsx"},
		{"/x@1.0/$mod+{a}~.ts", "/@std/path/1.1.6/x@1.0/$mod+%7Ba%7D~.ts"},
		{"/a b.ts", "/@std/path/1.1.6/a%20b.ts"},
		{"/50%25.ts", "/@std/path/1.1.6/50%2525.ts"},
		{"/q?.ts", "/@std/path/1.1.6/q%3F.ts"},
		{"/meta.json", "/@std/path/1.1.6/meta.json"},
	} {
		p, ok := ModuleFilePath("std", "path", "1.1.6", tc.file)
		if !ok || p != tc.want {
			t.Errorf("ModuleFilePath(%q) = %q, %v; want %q", tc.file, p, ok, tc.want)
			continue
		}
		res := mirrorPathResolve(t, b, p)
		if !res.Cacheable || res.Coordinate.Name != "@std/path" || res.Coordinate.Version != "1.1.6" || res.Metadata[metaFilePath] != tc.file {
			t.Errorf("%s resolves to %+v, file %q (cacheable %v)", p, res.Coordinate, res.Metadata[metaFilePath], res.Cacheable)
		}
	}
	for _, file := range []string{"", "/", "mod.ts", "//mod.ts", "/a//b.ts", "/a/", "/./a.ts", "/../a.ts", "/a/../b.ts", "/a\x00.ts", "/a\nb.ts", "/a\x7f.ts"} {
		if p, ok := ModuleFilePath("std", "path", "1.1.6", file); ok {
			t.Errorf("ModuleFilePath(%q) = %q, want a refusal", file, p)
		}
	}
	for _, tc := range []struct{ scope, name, version string }{
		{"Std", "path", "1.0.0"}, {"std", "Path", "1.0.0"}, {"std", "path", "1/0"}, {"std", "path", ""}, {"", "path", "1.0.0"},
		{"std", "", "1.0.0"}, {"st d", "path", "1.0.0"}, {"std", "path", "1.0.0_x"},
	} {
		if p, ok := ModuleFilePath(tc.scope, tc.name, tc.version, "/mod.ts"); ok {
			t.Errorf("ModuleFilePath(%+v) = %q, want a refusal", tc, p)
		}
	}
}

func TestMetaPathsRoundTrip(t *testing.T) {
	b := mirrorPathTestBackend(t)
	p, ok := PackageMetaPath("luca", "flag")
	if !ok || p != "/@luca/flag/meta.json" {
		t.Fatalf("PackageMetaPath = %q, %v", p, ok)
	}
	if res := mirrorPathResolve(t, b, p); res.Cacheable || res.Coordinate.Name != "@luca/flag" || res.Metadata[metaKind] != "package-meta" {
		t.Errorf("%s resolves to %+v (%s)", p, res.Coordinate, res.Metadata[metaKind])
	}
	p, ok = VersionMetaPath("std", "fmt", "1.0.0-rc.1")
	if !ok || p != "/@std/fmt/1.0.0-rc.1_meta.json" {
		t.Fatalf("VersionMetaPath = %q, %v", p, ok)
	}
	if res := mirrorPathResolve(t, b, p); res.Cacheable || res.Coordinate.Version != "1.0.0-rc.1" || res.Metadata[metaKind] != "version-meta" {
		t.Errorf("%s resolves to %+v (%s)", p, res.Coordinate, res.Metadata[metaKind])
	}
	for _, bad := range [][2]string{{"Luca", "flag"}, {"luca", "fl/ag"}, {"luca", ""}, {"", "flag"}, {"lu ca", "flag"}} {
		if p, ok := PackageMetaPath(bad[0], bad[1]); ok {
			t.Errorf("PackageMetaPath(%q, %q) = %q", bad[0], bad[1], p)
		}
	}
	for _, v := range []string{"", "1/0", "1.0.0_x", ".."} {
		if p, ok := VersionMetaPath("std", "fmt", v); ok {
			t.Errorf("VersionMetaPath(%q) = %q", v, p)
		}
	}
}
