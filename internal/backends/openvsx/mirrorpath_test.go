package openvsx

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// VsixPath builds the paths open-vsx.org writes into its documents (as
// recorded on 2026-11-16), and they round-trip through Resolve: an archive,
// cached and verified, of the extension and version.
func TestVsixPathRoundTripsThroughResolve(t *testing.T) {
	b, err := New(Options{Name: "ovsx", UpstreamURL: "https://open-vsx.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ns, ext, platform, version, want string }{
		{"rust-lang", "rust-analyzer", "linux-x64", "0.4.3120", "/api/rust-lang/rust-analyzer/linux-x64/0.4.3120/file/rust-lang.rust-analyzer-0.4.3120@linux-x64.vsix"},
		{"rust-lang", "rust-analyzer", Universal, "0.4.3120", "/api/rust-lang/rust-analyzer/0.4.3120/file/rust-lang.rust-analyzer-0.4.3120.vsix"},
		{"redhat", "vscode-yaml", Universal, "2.1.2026111208", "/api/redhat/vscode-yaml/2.1.2026111208/file/redhat.vscode-yaml-2.1.2026111208.vsix"},
		{"golang", "Go", "darwin-arm64", "0.47.1", "/api/golang/Go/darwin-arm64/0.47.1/file/golang.Go-0.47.1@darwin-arm64.vsix"},
		{"a_b", "c+d$e~f", "web", "1.0.0-rc.1+build.5", "/api/a_b/c+d$e~f/web/1.0.0-rc.1+build.5/file/a_b.c+d$e~f-1.0.0-rc.1+build.5@web.vsix"},
	} {
		p, ok := VsixPath(tc.ns, tc.ext, tc.platform, tc.version)
		if !ok || p != tc.want {
			t.Errorf("%s.%s %s %s: %q %v", tc.ns, tc.ext, tc.platform, tc.version, p, ok)
			continue
		}
		if url.PathEscape(strings.TrimPrefix(p, "/")) != strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "%2F") {
			t.Errorf("%s needs escaping", p)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil || !res.Cacheable || res.Metadata[metaVerify] != "1" || res.Artifact != backends.Payload() ||
			res.Coordinate.Name != tc.ns+"."+tc.ext || res.Coordinate.Version != tc.version {
			t.Errorf("%s: %+v %v", p, res, err)
		}
		ext, version, ok := VsixCoordinate(p)
		if !ok || ext != tc.ns+"."+tc.ext || version != tc.version {
			t.Errorf("%s reads back as %q %q %v", p, ext, version, ok)
		}
	}
	for _, tc := range []struct{ ns, ext, platform, version string }{
		{"file", "x", Universal, "1.0.0"}, // the backend reads the namespace as the file marker
		{"x", "file", "linux-x64", "1.0.0"},
		{"a.b", "c", Universal, "1.0.0"},
		{"", "c", Universal, "1.0.0"},
		{"-", "c", Universal, "1.0.0"},
		{strings.Repeat("a", 256), "c", Universal, "1.0.0"},
		{"a", "c d", Universal, "1.0.0"},
		{"a", "c", Universal, "1.0"},
		{"a", "c", Universal, "latest"},
		{"a", "c", Universal, "01.0.0"},
		{"a", "c", Universal, "1.0.0/../x"},
		{"a", "c", "macos", "1.0.0"},
		{"a", "c", "", "1.0.0"},
	} {
		if p, ok := VsixPath(tc.ns, tc.ext, tc.platform, tc.version); ok {
			t.Errorf("%+v built %s", tc, p)
		}
	}
	for _, p := range []string{"/api/a/b/1.0.0/file/a.b-1.0.0.sha256", "/api/a/b", "/api/a/b/file/x.vsix", "/vscode/gallery/x.vsix", "/sitemap.xml"} {
		if ext, v, ok := VsixCoordinate(p); ok {
			t.Errorf("%s read as an archive of %s %s", p, ext, v)
		}
	}
	if !IsTargetPlatform("alpine-arm64") || IsTargetPlatform("Linux-x64") || len(TargetPlatforms()) != 12 {
		t.Errorf("target platforms: %v", TargetPlatforms())
	}
}
