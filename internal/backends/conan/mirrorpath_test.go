package conan

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The exported path builders round-trip through the backend's own Resolve:
// each path decodes to the resource the builder names, with the reference's
// coordinate and revisions, and only what sits beneath a pinned revision is
// cacheable.
func TestMirrorPathsRoundTripThroughResolve(t *testing.T) {
	b, err := New(Options{Name: "cc", UpstreamURL: "https://center2.conan.io", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	const (
		rrev = "cac0f6daea041b0ccf42934163defb20"
		pid  = "c81087b06d1a5beef0ad711fc32d45f7a425a8f3"
		prev = "d3a7706ae25c74b78bafbb0b63cb5dcf"
	)
	resolve := func(p string, ok bool) *backends.Resolved {
		t.Helper()
		if !ok {
			t.Fatalf("refused")
		}
		dec, err := url.PathUnescape(p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if res.Coordinate.Name != "zlib" || res.Coordinate.Version != "1.3.1" || res.Metadata[MetaReference] != "zlib/1.3.1" {
			t.Errorf("%s: coordinate %+v reference %q", p, res.Coordinate, res.Metadata[MetaReference])
		}
		return res
	}
	must := func(p string, ok bool) string {
		t.Helper()
		if !ok {
			t.Fatalf("a builder refused a valid reference")
		}
		return p
	}
	for _, tc := range []struct {
		path      string
		want      string
		kind      string
		cacheable bool
	}{
		{must(RecipeLatestPath("zlib", "1.3.1")), "/v2/conans/zlib/1.3.1/_/_/latest", "recipe-latest", false},
		{must(RecipeFilesPath("zlib", "1.3.1", rrev)), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/files", "recipe-files", true},
		{must(RecipeFilePath("zlib", "1.3.1", rrev, "conan_export.tgz")), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/files/conan_export.tgz", "recipe-file", true},
		{must(PackageSearchPath("zlib", "1.3.1", rrev)), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/search", "search", false},
		{must(PackageLatestPath("zlib", "1.3.1", rrev, pid)), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/packages/" + pid + "/latest", "package-latest", false},
		{must(PackageFilesPath("zlib", "1.3.1", rrev, pid, prev)), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/packages/" + pid + "/revisions/" + prev + "/files", "package-files", true},
		{must(PackageFilePath("zlib", "1.3.1", rrev, pid, prev, "conan_package.tgz")), "/v2/conans/zlib/1.3.1/_/_/revisions/" + rrev + "/packages/" + pid + "/revisions/" + prev + "/files/conan_package.tgz", "package-file", true},
	} {
		if tc.path != tc.want {
			t.Errorf("path %s, want %s", tc.path, tc.want)
		}
		res := resolve(tc.path, true)
		if res.Metadata[metaKind] != tc.kind || res.Cacheable != tc.cacheable {
			t.Errorf("%s: kind %s cacheable %v", tc.path, res.Metadata[metaKind], res.Cacheable)
		}
	}
	if p := RecipeSearchPath(); p != "/v2/conans/search" {
		t.Errorf("search path %s", p)
	} else if res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{"q": {"zlib/*"}}, Header: http.Header{}}); err != nil || res.Metadata[metaKind] != "search" {
		t.Errorf("search: %v %v", res, err)
	}
	// A name the URL must escape stays one segment.
	if p, ok := RecipeLatestPath("lib+x", "1.0"); !ok || p != "/v2/conans/lib+x/1.0/_/_/latest" {
		t.Errorf("plus: %s %v", p, ok)
	}
	if p, ok := RecipeFilePath("zlib", "1.3.1", rrev, "a b#c"); !ok || p != "/v2/conans/zlib/1.3.1/_/_/revisions/"+rrev+"/files/a%20b%23c" {
		t.Errorf("escaped file: %s %v", p, ok)
	}

	for name, ok := range map[string]bool{
		"name slash":    first(RecipeLatestPath("a/b", "1.0")),
		"name empty":    first(RecipeLatestPath("", "1.0")),
		"version dots":  first(RecipeLatestPath("zlib", "..")),
		"rrev slash":    first(RecipeFilesPath("zlib", "1.0", "a/b")),
		"rrev empty":    first(RecipeFilesPath("zlib", "1.0", "")),
		"file nested":   first(RecipeFilePath("zlib", "1.0", rrev, "metadata/logs/x")),
		"file empty":    first(RecipeFilePath("zlib", "1.0", rrev, "")),
		"file dot":      first(RecipeFilePath("zlib", "1.0", rrev, ".")),
		"pid slash":     first(PackageLatestPath("zlib", "1.0", rrev, "a/b")),
		"prev empty":    first(PackageFilesPath("zlib", "1.0", rrev, pid, "")),
		"pkg file back": first(PackageFilePath("zlib", "1.0", rrev, pid, prev, `a\b`)),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func first(_ string, ok bool) bool { return ok }
