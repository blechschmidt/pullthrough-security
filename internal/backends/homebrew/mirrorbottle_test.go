package homebrew

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// BottlePath is exactly the rewrite the backend applies to a formula document
// it serves (rewriteBottleURLs), relative to the mount, and the path
// round-trips through Resolve: a cached bottle of the formula's version.
func TestBottlePathIsTheDocumentsRewrite(t *testing.T) {
	digest := func(c string) string { return strings.Repeat(c, 64) }
	doc := `[{"name":"openssl@3","versions":{"stable":"3.5.9"},"bottle":{"stable":{"files":{
		"arm64_sequoia":{"url":"https://ghcr.io/v2/homebrew/core/openssl/3/blobs/sha256:` + digest("a") + `","sha256":"` + digest("a") + `"},
		"x86_64_linux":{"url":"https://ghcr.io/v2/homebrew/core/openssl/3/blobs/sha256:` + digest("b") + `","sha256":"` + digest("b") + `"}}}}},
	{"name":"libxml++","versions":{"stable":" 2.42.4 "},"bottle":{"stable":{"files":{
		"all":{"url":"https://ghcr.io/v2/homebrew/core/libxmlxx/blobs/sha256:` + digest("c") + `","sha256":"` + digest("c") + `"},
		"sonoma":{"url":"https://bottles.example.org/v2/homebrew/core/libxmlxx/blobs/sha256:` + digest("d") + `","sha256":"` + digest("d") + `"}}}}}]`
	rewritten, n := rewriteBottleURLs([]byte(doc), "/v1/brew", "ghcr.io")
	if n != 3 {
		t.Fatalf("the backend rewrote %d URLs", n)
	}
	docs, ok := decodeFormulae([]byte(doc))
	if !ok {
		t.Fatal("the document does not decode")
	}
	b, err := New(Options{Name: "brew", UpstreamURL: "https://formulae.brew.sh", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test"), Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	built := 0
	for _, d := range docs {
		for tag, f := range d.Bottle.Stable.Files {
			p, ok := BottlePath("", f.URL, d.Name, d.Versions.Stable)
			if strings.Contains(f.URL, "bottles.example.org") {
				if ok || !strings.Contains(string(rewritten), f.URL) {
					t.Errorf("%s %s: a bottle on another host built %q; the backend leaves it", d.Name, tag, p)
				}
				continue
			}
			if !ok || !strings.Contains(string(rewritten), `"url":"/v1/brew`+p+`"`) {
				t.Errorf("%s %s: %q (%v) is not what the backend rewrote", d.Name, tag, p, ok)
				continue
			}
			built++
			res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
			if err != nil || !res.Cacheable || res.Artifact != backends.Payload() ||
				res.Coordinate.Name != d.Name || res.Coordinate.Version != strings.TrimSpace(d.Versions.Stable) {
				t.Errorf("%s: %+v %v", p, res, err)
			}
		}
	}
	if built != 3 {
		t.Errorf("%d paths built", built)
	}

	// Another bottle registry (the setting bottleRegistryUrl).
	own := "https://bottles.internal.example:8443/v2/homebrew/core/jq/blobs/sha256:" + digest("e")
	if p, ok := BottlePath("https://bottles.internal.example:8443/", own, "jq", "1.8.2"); !ok || p != "/bottle/jq/1.8.2/v2/homebrew/core/jq/blobs/sha256:"+digest("e") {
		t.Errorf("another registry: %q %v", p, ok)
	}
	if p, ok := BottlePath("https://bottles.internal.example:8443", "https://ghcr.io/v2/homebrew/core/jq/blobs/sha256:"+digest("e"), "jq", "1.8.2"); ok {
		t.Errorf("a ghcr.io bottle built %q for another registry", p)
	}
	// What the backend does not rewrite, or would not serve as the
	// formula's bottle.
	ghcr := "https://ghcr.io/v2/homebrew/core/jq/blobs/sha256:" + digest("f")
	for _, tc := range []struct{ registry, url, name, version string }{
		{"", ghcr, "jq", ""},
		{"", ghcr, "", "1.0"},
		{"", ghcr, "a/b", "1.0"},
		{"", ghcr, "jq", "1/0"},
		{"", ghcr, "jq", ".."},
		{"", "https://ghcr.io/v2/homebrew/core/jq/manifests/1.8.2", "jq", "1.8.2"},
		{"", "https://ghcr.io/v2/homebrew/core/jq/blobs/sha256:xyz", "jq", "1.8.2"},
		{"", "ftp://ghcr.io/v2/homebrew/core/jq/blobs/sha256:" + digest("f"), "jq", "1.8.2"},
		{"ftp://ghcr.io", ghcr, "jq", "1.8.2"},
		{"", "::", "jq", "1.8.2"},
	} {
		if p, ok := BottlePath(tc.registry, tc.url, tc.name, tc.version); ok {
			t.Errorf("%+v built %q", tc, p)
		}
	}
}
