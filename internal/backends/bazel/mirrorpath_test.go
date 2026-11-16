package bazel

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The exported path builders round-trip through the backend's own Resolve:
// the path decodes to the resource the builder names, with the module
// coordinate, and the per-version files are the cacheable ones.
func TestMirrorPathsRoundTripThroughResolve(t *testing.T) {
	b, err := New(Options{Name: "bcr", UpstreamURL: "https://bcr.bazel.build", PublicBaseURL: "https://proxy.example/v1/bcr",
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		kind      string
		cacheable bool
		version   string
	}
	check := func(p string, ok bool, w want) {
		t.Helper()
		if !ok {
			t.Fatalf("%s: refused", p)
		}
		dec, err := url.PathUnescape(p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if res.Metadata[metaKind] != w.kind || res.Cacheable != w.cacheable || res.Coordinate.Name != "zlib" || res.Coordinate.Version != w.version {
			t.Errorf("%s: kind %s cacheable %v coordinate %+v, want %+v", p, res.Metadata[metaKind], res.Cacheable, res.Coordinate, w)
		}
	}
	p, ok := MetadataPath("zlib")
	check(p, ok, want{"metadata", false, ""})
	if p != "/modules/zlib/metadata.json" {
		t.Errorf("metadata path %s", p)
	}
	p, ok = ModuleFilePath("zlib", "1.3.1.bcr.5")
	check(p, ok, want{"module-bazel", true, "1.3.1.bcr.5"})
	p, ok = SourcePath("zlib", "1.3.1")
	check(p, ok, want{"source", false, "1.3.1"})
	p, ok = PatchPath("zlib", "1.3.1", "add_build_file.patch")
	check(p, ok, want{"patch", true, "1.3.1"})
	if p != "/modules/zlib/1.3.1/patches/add_build_file.patch" {
		t.Errorf("patch path %s", p)
	}
	// A patch name the layout allows but a URL must escape.
	p, ok = PatchPath("zlib", "1.3.1", "fix #1 50%.patch")
	check(p, ok, want{"patch", true, "1.3.1"})
	if p != "/modules/zlib/1.3.1/patches/fix%20%231%2050%25.patch" {
		t.Errorf("escaped patch path %s", p)
	}
	p, ok = OverlayPath("zlib", "1.3.1", "lib/defs.h")
	check(p, ok, want{"overlay", true, "1.3.1"})
	if p != "/modules/zlib/1.3.1/overlay/lib/defs.h" {
		t.Errorf("overlay path %s", p)
	}

	// What the layout cannot carry is refused.
	for name, ok := range map[string]bool{
		"name upper":      first(MetadataPath("Zlib")),
		"name dot dot":    first(MetadataPath("..")),
		"name slash":      first(MetadataPath("a/b")),
		"name empty":      first(MetadataPath("")),
		"version slash":   first(ModuleFilePath("zlib", "1.0/x")),
		"version space":   first(SourcePath("zlib", "1 0")),
		"version empty":   first(ModuleFilePath("zlib", "")),
		"patch suffix":    first(PatchPath("zlib", "1.0", "x.txt")),
		"patch nested":    first(PatchPath("zlib", "1.0", "a/b.patch")),
		"patch backslash": first(PatchPath("zlib", "1.0", `a\b.patch`)),
		"overlay up":      first(OverlayPath("zlib", "1.0", "../x")),
		"overlay empty":   first(OverlayPath("zlib", "1.0", "a//b")),
		"overlay rooted":  first(OverlayPath("zlib", "1.0", "/a")),
		"overlay space":   first(OverlayPath("zlib", "1.0", "a b")),
		"overlay none":    first(OverlayPath("zlib", "1.0", "")),
	} {
		if ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func first(_ string, ok bool) bool { return ok }
