package homebrew

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// FormulaDocumentPath round-trips through the backend's own Resolve: the
// formula document, rewritten, with the formula's name as its coordinate.
func TestFormulaDocumentPathRoundTripsThroughResolve(t *testing.T) {
	b, err := New(Options{Name: "brew", UpstreamURL: "https://formulae.brew.sh", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"jq", "openssl@3", "libxml++", "c-ares", "python@3.13", "ca-certificates"} {
		p, ok := FormulaDocumentPath(name)
		if !ok || p != "/api/formula/"+name+".json" {
			t.Fatalf("%s: %q %v", name, p, ok)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if res.Metadata[metaKind] != "formula" || res.Metadata[metaRewrite] != "1" || res.Coordinate.Name != name || res.Artifact != backends.Metadata() || res.Cacheable {
			t.Errorf("%s: kind %s rewrite %q coordinate %+v artifact %+v cacheable %v", p, res.Metadata[metaKind], res.Metadata[metaRewrite], res.Coordinate, res.Artifact, res.Cacheable)
		}
	}
	for _, bad := range []string{"", "a/b", "..", "x.jws", "a b", "a%2f", "naïve", "a;b"} {
		if p, ok := FormulaDocumentPath(bad); ok {
			t.Errorf("%q accepted as %s", bad, p)
		}
	}
}
