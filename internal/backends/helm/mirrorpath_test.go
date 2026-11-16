package helm

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// ArchivePath names exactly the link the index rewrite hands a client, and
// that link resolves, through the backend's own classification, to the entry
// it was minted for.
func TestArchivePathIsTheRewrittenLink(t *testing.T) {
	type entry struct{ chart, version, location string }
	entries := []entry{
		{"nginx", "1.2.3", "https://charts.example.com/nginx-1.2.3.tgz"},
		{"relative", "2.0.0", "charts/relative-2.0.0.tgz"},
		{"renamed", "3.0.0", "https://github.com/o/r/releases/download/v3.0.0/chart.tgz"},
		{"queried", "4.0.0", "https://dl.example.com/get/queried-4.0.0.tgz?token=x#frag"},
		{"oci", "5.0.0", "oci://registry.example.com/charts/oci:5.0.0"},
		{"build", "1.0.0+meta.1", "https://charts.example.com/build-1.0.0%2Bmeta.1.tgz"},
		{"prov", "6.0.0", "https://charts.example.com/files/prov-6.0.0.tgz.prov"},
		{"nobase", "7.0.0", "https://charts.example.com"},
		{"spaced name", "8.0.0", "https://charts.example.com/spaced%20name-8.0.0.tgz"},
	}
	var doc strings.Builder
	doc.WriteString("apiVersion: v1\nentries:\n")
	for _, e := range entries {
		doc.WriteString("  " + e.chart + ":\n  - name: " + e.chart + "\n    version: " + e.version + "\n    urls:\n    - \"" + e.location + "\"\n")
	}
	scanned, source, err := scanIndexSource([]byte(doc.String()))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := scanned.rewrite(source, linker{})
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ParseIndex(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{Name: "charts", UpstreamURL: "https://charts.example.com", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got, ok := ArchivePath(e.chart, e.version, e.location)
		if !ok {
			t.Errorf("%s: no path", e.chart)
			continue
		}
		cv, found := idx.FindVersion(e.chart, e.version)
		if !found || len(cv.URLs) != 1 || "/"+cv.URLs[0] != got {
			t.Errorf("%s: ArchivePath %q, the rewritten index links %v", e.chart, got, cv.URLs)
		}
		dec, err := url.PathUnescape(got)
		if err != nil {
			t.Fatalf("%s: %v", got, err)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: dec, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Errorf("%s: %v", got, err)
			continue
		}
		if !res.Cacheable || res.Coordinate.Name != e.chart || res.Coordinate.Version != e.version || res.Metadata[metaIndexed] != "1" {
			t.Errorf("%s resolves to %+v (cacheable %v)", got, res.Coordinate, res.Cacheable)
		}
		// The location the backend fetches is the one the entry lists.
		r, ok := classify(dec)
		if !ok {
			t.Fatalf("%s does not classify", dec)
		}
		if locs := (&Index{Entries: map[string][]ChartVersion{e.chart: {{Name: e.chart, Version: e.version, URLs: []string{e.location}}}}}).locate(r.name, r.version, r.filename); len(locs) != 1 || locs[0].URL != e.location {
			t.Errorf("%s: the index lookup finds %v", got, locs)
		}
	}
	// What the rewrite cannot address, it does not hand out.
	for _, e := range []entry{{"", "1.0.0", "x.tgz"}, {"a/b", "1.0.0", "x.tgz"}, {"..", "1.0.0", "x.tgz"}, {"ok", "1/0", "x.tgz"}, {"ok", "1.0.0", "  "}, {"ok", "", "x.tgz"}} {
		if p, ok := ArchivePath(e.chart, e.version, e.location); ok {
			t.Errorf("%+v: %q", e, p)
		}
	}
}
