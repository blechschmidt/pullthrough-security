package hackage

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestSdistPathRoundTripsThroughClassifyAndResolve(t *testing.T) {
	b, err := New(Options{Name: "hackage", UpstreamURL: "https://hackage.haskell.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, version, want string }{
		{"base64", "1.0", "/package/base64-1.0.tar.gz"},
		{"time-manager", "0.4.2", "/package/time-manager-0.4.2.tar.gz"},
		{"aeson-pretty", "0.8.10", "/package/aeson-pretty-0.8.10.tar.gz"},
		{"HUnit", "1.6.2.0", "/package/HUnit-1.6.2.0.tar.gz"},
		{"seihou-okf-extension", "0.16.0.1", "/package/seihou-okf-extension-0.16.0.1.tar.gz"},
		{"3d-graphics-examples", "0.0.0.2", "/package/3d-graphics-examples-0.0.0.2.tar.gz"},
	} {
		p, ok := SdistPath(c.name, c.version)
		if !ok || p != c.want {
			t.Errorf("SdistPath(%q, %q) = %q, %v; want %q", c.name, c.version, p, ok, c.want)
			continue
		}
		r, ok := classify(p)
		if !ok || r.kind != kindSdist || r.name != c.name || r.version != c.version {
			t.Errorf("classify(%q) = %+v, %v", p, r, ok)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("Resolve(%q): %v", p, err)
		}
		if !res.Cacheable || res.Coordinate.Name != c.name || res.Coordinate.Version != c.version || res.Metadata[metaVerify] != "1" {
			t.Errorf("Resolve(%q): cacheable %v, coordinate %+v, verify %q", p, res.Cacheable, res.Coordinate, res.Metadata[metaVerify])
		}
	}
	for _, c := range []struct{ name, version string }{
		{"", "1.0"}, {"text", ""}, {"../etc", "1.0"}, {"a/b", "1.0"}, {"text", "1.0-beta"},
		{"text", "1..0"}, {"text", "v1.0"}, {"123", "1.0"}, {"te xt", "1.0"}, {"text", "1.0/../x"},
	} {
		if p, ok := SdistPath(c.name, c.version); ok {
			t.Errorf("SdistPath(%q, %q) = %q, want refused", c.name, c.version, p)
		}
	}
}
