package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/openvsx"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The openvsx fixtures are open-vsx.org's responses of 2026-11-16: the
// sitemap trimmed to six of its 21,436 entries; the documents of
// redhat/vscode-yaml (built for every platform) and rust-lang/rust-analyzer
// (built per platform), their allVersions trimmed to a few versions and the
// downloads to three platforms; the first page of the search listing by time
// (search.json, trimmed to three extensions); the first pages of version
// listings (versions-*.json, trimmed to their first versions), the page at
// offset 1400 of rust-analyzer's linux-x64 listing, where its stable release
// sits, and the empty listing of a platform an extension is not built for.
// The documents are served as recorded, pointing at open-vsx.org; the tests
// run them through the real backend, which rewrites those URLs into the
// proxy, as the gated pipeline would. The listings are read from the
// registry directly, as the adapter reads them.

// openvsxFixtureDocs maps the API paths the documents answer.
var openvsxFixtureDocs = map[string]string{
	"/api/redhat/vscode-yaml":      "redhat.vscode-yaml.json",
	"/api/rust-lang/rust-analyzer": "rust-lang.rust-analyzer.json",
}

// openvsxUpstream answers the backend's requests to open-vsx.org from docs
// (404 for anything else, with open-vsx.org's body).
type openvsxUpstream map[string][]byte

func (u openvsxUpstream) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := u[req.URL.Path]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
		body = []byte(`{"deprecated":false,"downloadable":false,"error":"Extension not found"}`)
	}
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}, nil
}

// openvsxTestBackend is the real backend for upstream name, open-vsx.org
// answered from docs.
func openvsxTestBackend(t *testing.T, name string, docs openvsxUpstream) *openvsx.Backend {
	t.Helper()
	b, err := openvsx.New(openvsx.Options{Name: name, UpstreamURL: "https://open-vsx.org", PublicBaseURL: "https://proxy.example/v1/" + name,
		Client: upstream.NewWithHTTPClient(&http.Client{Transport: docs}, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// openvsxServed serves documents through the real backend — their URLs
// rewritten into the proxy — into a fake pipeline.
func openvsxServed(t *testing.T, name string, docs openvsxUpstream) *fakeReads {
	t.Helper()
	b := openvsxTestBackend(t, name, docs)
	reads := newFakeReads()
	for p := range docs {
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		fr, err := b.Fetch(context.Background(), res)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		body, err := io.ReadAll(fr.Content)
		fr.Content.Close()
		if err != nil {
			t.Fatal(err)
		}
		reads.set(p, body)
	}
	return reads
}

// openvsxDocs reads the recorded documents.
func openvsxDocs(t *testing.T) openvsxUpstream {
	t.Helper()
	docs := openvsxUpstream{}
	for p, file := range openvsxFixtureDocs {
		docs[p] = fixture(t, "openvsx", file)
	}
	return docs
}

// openvsxVersionEntry is one entry of a version listing.
type openvsxVersionEntry struct{ version, url string }

// openvsxListingEntries reads a recorded version listing's entries in their
// order.
func openvsxListingEntries(t *testing.T, file string) []openvsxVersionEntry {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(fixture(t, "openvsx", file)))
	var out []openvsxVersionEntry
	depth := 0
	inVersions := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' {
				depth++
			} else if v == '}' {
				depth--
				inVersions = false
			}
		case string:
			if depth == 1 && v == "versions" {
				inVersions = true
				continue
			}
			if inVersions && depth == 2 {
				var u string
				if err := dec.Decode(&u); err != nil {
					t.Fatal(err)
				}
				out = append(out, openvsxVersionEntry{v, u})
			}
		}
	}
}

// openvsxServeListing has the fixture server answer a version listing in
// pages of size, as openvsx-server pages it.
func openvsxServeListing(t *testing.T, srv *fixtureServer, path string, entries []openvsxVersionEntry, size int) {
	t.Helper()
	for off := 0; off == 0 || off < len(entries); off += size {
		end := off + size
		if end > len(entries) {
			end = len(entries)
		}
		var b bytes.Buffer
		fmt.Fprintf(&b, `{"offset":%d,"totalSize":%d,"versions":{`, off, len(entries))
		for i, e := range entries[off:end] {
			if i > 0 {
				b.WriteByte(',')
			}
			k, _ := json.Marshal(e.version)
			v, _ := json.Marshal(e.url)
			b.Write(k)
			b.WriteByte(':')
			b.Write(v)
		}
		b.WriteString("}}")
		srv.on("GET", fmt.Sprintf("%s?offset=%d", path, off)).reply(http.StatusOK, b.Bytes()).withHeader("Content-Type", "application/json")
	}
}

// openvsxSearchEntry is one extension of a search page made for a test.
type openvsxSearchEntry struct{ id, version, timestamp string }

// openvsxSearch is a page of the search listing holding entries, in the
// format of the recorded page.
func openvsxSearch(t *testing.T, entries ...openvsxSearchEntry) []byte {
	t.Helper()
	var page map[string]any
	if err := json.Unmarshal(fixture(t, "openvsx", "search.json"), &page); err != nil {
		t.Fatal(err)
	}
	template := page["extensions"].([]any)[0].(map[string]any)
	var exts []any
	for _, e := range entries {
		ns, name, _ := strings.Cut(e.id, ".")
		x := map[string]any{}
		for k, v := range template {
			x[k] = v
		}
		x["namespace"], x["name"], x["version"], x["timestamp"] = ns, name, e.version, e.timestamp
		x["url"] = "https://open-vsx.org/api/" + ns + "/" + name
		exts = append(exts, x)
	}
	page["extensions"], page["totalSize"] = exts, len(exts)
	if exts == nil {
		page["extensions"] = []any{}
	}
	out, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenVSXFeedLocation(t *testing.T) {
	sitemap := func(env Env) string {
		t.Helper()
		f, err := newOpenVSXFeed(env)
		if err != nil {
			t.Fatal(err)
		}
		return f.(*openvsxFeed).src.(*openvsxSource).url
	}
	for up, want := range map[string]string{
		"https://open-vsx.org":                 "https://open-vsx.org/sitemap.xml",
		"https://open-vsx.org/":                "https://open-vsx.org/sitemap.xml",
		"https://vsx.internal.example/openvsx": "https://vsx.internal.example/openvsx/sitemap.xml",
	} {
		if got := sitemap(Env{Upstream: "o", Type: "openvsx", URL: up}); got != want {
			t.Errorf("%s: %s, want %s", up, got, want)
		}
	}
	env := Env{Upstream: "o", Type: "openvsx", URL: "https://open-vsx.org", Options: map[string]string{"url": "https://mirror.example/vsx/sitemap.xml", "platforms": "linux-x64, darwin-arm64"}}
	if got := sitemap(env); got != "https://mirror.example/vsx/sitemap.xml" {
		t.Errorf("option url: %s", got)
	}
	f, _ := newOpenVSXFeed(env)
	if p := f.(*openvsxFeed).platforms; fmt.Sprint(p) != "map[darwin-arm64:true linux-x64:true]" {
		t.Errorf("platforms %v", p)
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "https://mirror.example/vsx"}, {"url": "https://mirror.example/sitemap.xml?x=1"},
		{"url": "ftp://mirror.example/sitemap.xml"}, {"platforms": "macos"}, {"platforms": "linux-x64,"}, {"platforms": "Linux-x64"}} {
		if err := Check(Env{Upstream: "o", Type: "openvsx", URL: "https://open-vsx.org", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// openvsxTestFeed is the feed of a fixture server, at the time *now says. The
// server answers the search listing with the recorded page unless a test
// says otherwise (later routes win).
func openvsxTestFeed(t *testing.T, srv *fixtureServer, now *time.Time) *openvsxFeed {
	t.Helper()
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, fixture(t, "openvsx", "search.json")).withHeader("Content-Type", "application/json")
	f := mustFeed(t, testEnv(t, "openvsx", srv.URL(), newFakeReads(), nil)).(*openvsxFeed)
	f.src.(*openvsxSource).now = func() time.Time { return *now }
	return f
}

func TestOpenVSXFollowsTheSitemap(t *testing.T) {
	srv := newFixtureServer(t)
	sitemap := fixture(t, "openvsx", "sitemap.xml")
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap).withHeader("Content-Type", "application/xml")
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	ctx := context.Background()
	b, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "openvsx", "bootstrap", viewBatch(t, b))

	// Five minutes later, the same sitemap and listing: nothing to report —
	// the extensions of the day are not looked at again.
	now = now.Add(5 * time.Minute)
	got, next := drainChanges(t, f, b.Next)
	if len(got) != 0 {
		t.Errorf("unchanged: %v", got)
	}
	// rust-analyzer publishes again the same day: its date stays as it was,
	// the listing shows it on top. Reported once; not again while the
	// listing shows it, nor once it drops out of the listing.
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, openvsxSearch(t,
		openvsxSearchEntry{"rust-lang.rust-analyzer", "0.4.3121", "2026-11-16T12:01:02.000003Z"},
		openvsxSearchEntry{"kanbanr.kanbanr", "1.0.0", "2026-11-16T07:28:26.067524Z"}))
	now = now.Add(5 * time.Minute)
	if got, next = drainChanges(t, f, next); fmt.Sprint(got) != "[rust-lang.rust-analyzer]" {
		t.Errorf("a second publication on a day: %v", got)
	}
	now = now.Add(5 * time.Minute)
	if got, next = drainChanges(t, f, next); len(got) != 0 {
		t.Errorf("still listed: %v", got)
	}
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, fixture(t, "openvsx", "search.json"))
	now = now.Add(5 * time.Minute)
	if got, next = drainChanges(t, f, next); len(got) != 0 {
		t.Errorf("out of the listing: %v", got)
	}

	// The sitemap changes: vscode-yaml published, ad-astra is gone, a new
	// extension appears; the gzip-encoded answer is read as well.
	edited := strings.Replace(string(sitemap), "<lastmod>2026-11-12</lastmod>", "<lastmod>2026-11-16</lastmod>", 1)
	edited = strings.Replace(edited, "  <url>\n    <loc>https://open-vsx.org/extension/ugi-dev/ad-astra</loc>\n    <lastmod>2026-02-27</lastmod>\n  </url>\n",
		"  <url>\n    <loc>https://open-vsx.org/extension/new-ns/new-ext</loc>\n    <lastmod>2026-11-16</lastmod>\n  </url>\n", 1)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(edited))
	_ = zw.Close()
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, gz.Bytes()).withHeader("Content-Encoding", "gzip").requireHeader("Accept-Encoding", "gzip")
	now = now.Add(time.Hour)
	ch, err := f.Changes(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "openvsx", "changes", viewBatch(t, ch))
}

// An openvsx-server in mirror mode dates every extension anew at every mirror
// run: its whole registry is not reported at every poll, nor once a day —
// only what its listing shows published, and what is new or gone.
func TestOpenVSXMirrorModeServer(t *testing.T) {
	const n = 300
	sitemap := func(day string, skip, extra int) []byte {
		var sb strings.Builder
		sb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n" + `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
		for i := 0; i < n+extra; i++ {
			if i == skip {
				continue
			}
			fmt.Fprintf(&sb, "  <url>\n    <loc>https://vsx.internal.example/extension/ns%d/ext%d</loc>\n    <lastmod>%s</lastmod>\n  </url>\n", i, i, day)
		}
		sb.WriteString("</urlset>\n")
		return []byte(sb.String())
	}
	srv := newFixtureServer(t)
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap("2026-11-16", -1, 0))
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, openvsxSearch(t))
	listed, cursor := drainBootstrap(t, f)
	if len(listed) != n {
		t.Fatalf("listed %d", len(listed))
	}
	for poll := 1; poll <= 3; poll++ {
		now = now.Add(5 * time.Minute)
		got, next := drainChanges(t, f, cursor)
		if len(got) != 0 {
			t.Errorf("poll %d (the sitemap unchanged): %d extensions reported", poll, len(got))
		}
		cursor = next
	}
	// The next day's mirror run dates them all anew.
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap("2026-11-17", -1, 0))
	now = time.Date(2026, 11, 17, 1, 0, 0, 0, time.UTC)
	got, cursor := drainChanges(t, f, cursor)
	if len(got) != 0 {
		t.Errorf("the mirror run dated %d extensions anew, and they were reported", len(got))
	}
	// A version the mirror published, an extension new and one gone are.
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, openvsxSearch(t, openvsxSearchEntry{"ns7.ext7", "2.0.0", "2026-11-17T00:30:00Z"}))
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap("2026-11-17", 9, 1))
	now = now.Add(time.Hour)
	got, _ = drainChanges(t, f, cursor)
	sort.Strings(got)
	if fmt.Sprint(got) != "[ns300.ext300 ns7.ext7 ns9.ext9 (deleted)]" {
		t.Errorf("changes %v", got)
	}
}

// A server that sends validators is asked conditionally; a 304 with nothing
// newer in the listing is no change, one with a same-day publication is.
func TestOpenVSXNotModified(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, fixture(t, "openvsx", "sitemap.xml")).withHeader("ETag", `"s1"`)
	srv.on("GET", "/sitemap.xml").requireHeader("If-None-Match", `"s1"`).reply(http.StatusNotModified, nil)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	_, cursor := drainBootstrap(t, f)
	now = now.Add(5 * time.Minute)
	got, next := drainChanges(t, f, cursor)
	if len(got) != 0 || next != cursor {
		t.Errorf("after a 304: %v (cursor moved: %v)", got, next != cursor)
	}
	srv.on("GET", "/api/-/search?offset=0").reply(http.StatusOK, openvsxSearch(t, openvsxSearchEntry{"zovo.zovo-flame-graph", "1.1.0", "2026-11-16T12:03:00Z"}))
	now = now.Add(5 * time.Minute)
	if got, next = drainChanges(t, f, next); fmt.Sprint(got) != "[zovo.zovo-flame-graph]" {
		t.Errorf("a same-day publication after a 304: %v", got)
	}
	now = now.Add(5 * time.Minute)
	if got, _ = drainChanges(t, f, next); len(got) != 0 {
		t.Errorf("again: %v", got)
	}
	if log := srv.requests(); len(log) != 8 || !strings.HasPrefix(log[0], "GET /api/-/search?") || log[1] != "GET /sitemap.xml" {
		t.Errorf("requests %v", log)
	}
}

// A listing that cannot be read costs that read's same-day publications only:
// the sitemap is followed, the mark stays.
func TestOpenVSXListingFailure(t *testing.T) {
	srv := newFixtureServer(t)
	sitemap := fixture(t, "openvsx", "sitemap.xml")
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	_, cursor := drainBootstrap(t, f)
	var c indexCursor
	var st openvsxState
	if err := json.Unmarshal([]byte(cursor), &c); err != nil || json.Unmarshal(c.State, &st) != nil || st.Mark == 0 {
		t.Fatalf("cursor %s", cursor)
	}
	day := "2026-10-21" // golang.Go's
	for _, fail := range []func(r *route){
		func(r *route) { r.reply(http.StatusInternalServerError, nil) },
		func(r *route) { r.reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "60") },
		func(r *route) { r.reply(http.StatusOK, []byte("<html>")) },
	} {
		fail(srv.on("GET", "/api/-/search?offset=0"))
		now = now.Add(24 * time.Hour)
		next := now.Format("2006-01-02")
		sitemap = []byte(strings.Replace(string(sitemap), "<lastmod>"+day+"</lastmod>", "<lastmod>"+next+"</lastmod>", 1))
		day = next
		srv.on("GET", "/sitemap.xml").reply(http.StatusOK, sitemap)
		got, after := drainChanges(t, f, cursor)
		var nc indexCursor
		var nst openvsxState
		if json.Unmarshal([]byte(after), &nc) != nil || json.Unmarshal(nc.State, &nst) != nil || nst.Mark != st.Mark {
			t.Errorf("the mark moved: %s", after)
		}
		if fmt.Sprint(got) != "[golang.Go]" {
			t.Errorf("the date of golang.Go moved: %v", got)
		}
		cursor = after
	}
}

func TestOpenVSXSitemapEntries(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://open-vsx.org/extension/ok/one</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>https://vsx.example/ui/extension/ok/two/</loc><lastmod>2026-11-16T09:30:00+02:00</lastmod></url>
  <url><loc>https://open-vsx.org/extension/ok/three</loc></url>
  <url><loc>https://open-vsx.org/extension/ok/four</loc><lastmod>sometime</lastmod></url>
  <url><loc>https://open-vsx.org/extension/ok/five</loc><lastmod>2026-11-17</lastmod></url>
  <url><loc>https://open-vsx.org/extension/bad.ns/x</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>https://open-vsx.org/namespace/ok/x</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>https://open-vsx.org/extension/ok</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>https://open-vsx.org/extension/ok/a%2Fb</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>https://open-vsx.org/extension/ok/sp ace</loc><lastmod>2026-01-02</lastmod></url>
  <url><loc>://broken</loc><lastmod>2026-01-02</lastmod></url>
  <url><lastmod>2026-01-02</lastmod></url>
  <other><loc>https://open-vsx.org/extension/ok/nested</loc></other>
  <url><loc>https://open-vsx.org/extension/ok/` + strings.Repeat("x", openvsxMaxField) + `</loc></url>
</urlset>`
	var recs []string
	err := openvsxParseSitemap(strings.NewReader(doc), func(e openvsxEntry) error {
		r := openvsxRecord(e.namespace+"."+e.name, e.lastmod, "", false, 0, false)
		recs = append(recs, fmt.Sprintf("%s %q", r.Name, r.Digest))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`ok.one "2026-01-02"`, `ok.two "2026-11-16T07:30:00Z"`, `ok.three ""`, `ok.four ""`, `ok.five "2026-11-17"`}
	if strings.Join(recs, "\n") != strings.Join(want, "\n") {
		t.Errorf("records:\n%s\nwant:\n%s", strings.Join(recs, "\n"), strings.Join(want, "\n"))
	}
	// A record's digest: its date, with the time of its newest version the
	// listing showed while the date stayed the same.
	for _, tc := range []struct {
		lastmod, old string
		hasOld       bool
		listed       int64
		redating     bool
		want         string
	}{
		{"2026-11-16", "", false, 0, false, "2026-11-16"},
		{"2026-11-16", "", false, 300, false, "2026-11-16/300"},
		{"2026-11-16", "2026-11-16/100", true, 0, false, "2026-11-16/100"},
		{"2026-11-16", "2026-11-16/100", true, 200, false, "2026-11-16/200"},
		{"2026-11-16", "2026-11-16/100", true, 50, false, "2026-11-16/100"},
		{"2026-11-16", "2026-11-15/100", true, 0, false, "2026-11-16"},
		{"2026-11-16", "2026-11-15/100", true, 0, true, "2026-11-15/100"},
		{"2026-11-16", "2026-11-15/100", true, 100, true, "2026-11-15/100"},
		{"2026-11-16", "2026-11-15/100", true, 200, true, "2026-11-16/200"},
		{"2026-11-16", "x/y", true, 0, false, "2026-11-16"},
		{"", "", true, 0, false, ""},
	} {
		if got := openvsxRecord("a.b", tc.lastmod, tc.old, tc.hasOld, tc.listed, tc.redating); got.Digest != tc.want || !got.valid() {
			t.Errorf("%+v: %q", tc, got.Digest)
		}
	}
	for name, bad := range map[string]string{
		"garbage":   "<html><body>rate limited",
		"index":     `<?xml version="1.0"?><sitemapindex><sitemap><loc>https://open-vsx.org/sitemap-1.xml</loc></sitemap></sitemapindex>`,
		"empty":     "",
		"json":      `{"urlset":[]}`,
		"unclosed":  `<urlset><url><loc>https://open-vsx.org/extension/a/b</loc>`,
		"deep":      "<urlset>" + strings.Repeat("<a>", openvsxMaxDepth) + strings.Repeat("</a>", openvsxMaxDepth) + "</urlset>",
		"big token": "<urlset><url><loc>" + strings.Repeat("x", openvsxMaxToken+1) + "</loc></url></urlset>",
		"entity":    `<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY a "aaaa">]><urlset><url><loc>&a;</loc></url></urlset>`,
	} {
		err := openvsxParseSitemap(strings.NewReader(bad), func(openvsxEntry) error { return nil })
		mustErr(t, err, true, false, "")
		if t.Failed() {
			t.Fatalf("%s", name)
		}
	}
	// A failing stream is the stream's error, retried: not a permanent one.
	err = openvsxParseSitemap(io.MultiReader(strings.NewReader("<urlset><url>"), openvsxFailingReader{}), func(openvsxEntry) error { return nil })
	if err == nil || IsPermanent(err) || !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("a failing stream: %v", err)
	}
}

// openvsxFailingReader fails as a dropped connection does.
type openvsxFailingReader struct{}

func (openvsxFailingReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("read: connection reset by peer")
}

// The listings' pages: entries without a valid name, time or version are
// skipped; the floor stops the search listing.
func TestOpenVSXListingPages(t *testing.T) {
	listed := map[string]int64{}
	newest, n, total, stop, err := openvsxReadSearchPage(fixture(t, "openvsx", "search.json"), 0, listed)
	if err != nil || n != 3 || total != 21442 || stop || len(listed) != 3 || newest != time.Date(2026, 11, 16, 7, 28, 26, 67524000, time.UTC).UnixMicro() {
		t.Errorf("the recorded page: %d %d %d %v %v %v", newest, n, total, stop, listed, err)
	}
	listed = map[string]int64{}
	page := `{"totalSize":9,"extensions":[{"namespace":"a","name":"b","timestamp":"2026-11-16T10:00:00Z"},{"namespace":"a.x","name":"b","timestamp":"2026-11-16T09:00:00Z"},` +
		`{"namespace":"a","name":"c","timestamp":"yesterday"},{"namespace":"a","name":"d","timestamp":"2026-11-16T08:00:00Z"},{"namespace":"a","name":"e","timestamp":"2026-11-16T07:00:00Z"}]}`
	floor := time.Date(2026, 11, 16, 8, 0, 0, 0, time.UTC).UnixMicro()
	if _, n, _, stop, err := openvsxReadSearchPage([]byte(page), floor, listed); err != nil || n != 5 || !stop || fmt.Sprint(listed) != fmt.Sprintf("map[a.b:%d]", floor+2*3600e6) {
		t.Errorf("a page down to the floor: %d %v %v %v", n, stop, listed, err)
	}
	for _, bad := range []string{"<html>", `[]`, `{"extensions":{}}`} {
		if _, _, _, _, err := openvsxReadSearchPage([]byte(bad), 0, map[string]int64{}); err == nil {
			t.Errorf("%s read as a search page", bad)
		}
	}
	vs, n, total, err := openvsxReadVersionPage(fixture(t, "openvsx", "versions-rust-lang.rust-analyzer-linux-x64.json"))
	if err != nil || n != 3 || total != 1624 || fmt.Sprint(vs) != "[0.4.3118 0.4.3119 0.4.3120]" {
		t.Errorf("the recorded version page: %v %d %d %v", vs, n, total, err)
	}
	vs, n, _, err = openvsxReadVersionPage([]byte(`{"totalSize":5,"versions":{"1.0.0":"u","latest":"u","1.0":"u","../1.0.0":"u","2.0.0-rc.1":"u"}}`))
	if err != nil || n != 5 || fmt.Sprint(vs) != "[1.0.0 2.0.0-rc.1]" {
		t.Errorf("versions %v %d %v", vs, n, err)
	}
	if _, _, _, err := openvsxReadVersionPage([]byte(`{"versions":[]}`)); err == nil {
		t.Errorf("a list read as a version page")
	}
}

// openvsxReleasesFeed is a feed reading the recorded documents through the
// real backend and the listings from a fixture server.
func openvsxReleasesFeed(t *testing.T, docs openvsxUpstream) (*openvsxFeed, *fixtureServer, *fakeReads, backends.Backend) {
	t.Helper()
	srv := newFixtureServer(t)
	env := testEnv(t, "openvsx", srv.URL(), nil, nil)
	reads := openvsxServed(t, env.Upstream, docs)
	env.Read = reads.read
	f := mustFeed(t, env).(*openvsxFeed)
	return f, srv, reads, openvsxTestBackend(t, env.Upstream, docs)
}

func TestOpenVSXReleases(t *testing.T) {
	docs := openvsxDocs(t)
	f, srv, reads, backend := openvsxReleasesFeed(t, docs)
	if served := reads.docs["/api/rust-lang/rust-analyzer"].body; !bytes.Contains(served, []byte(`"https://proxy.example/v1/openvsx-test/api/rust-lang/rust-analyzer/linux-x64/0.4.3120/file/rust-lang.rust-analyzer-0.4.3120@linux-x64.vsix"`)) {
		t.Fatalf("the document was not rewritten: %.300s", served)
	}
	f.versionPage = 3
	ctx := context.Background()

	// A universal extension: the universal listing alone, page by page —
	// a version the registry has no universal archive of is not listed.
	yaml := openvsxListingEntries(t, "versions-redhat.vscode-yaml-universal.json")
	openvsxServeListing(t, srv, "/api/redhat/vscode-yaml/universal/versions", yaml, 3)
	rels, err := f.Releases(ctx, "redhat.vscode-yaml")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "openvsx", "releases-redhat.vscode-yaml", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "redhat.vscode-yaml", r.Version })
	if len(rels) != len(yaml) {
		t.Errorf("%d releases of %d versions listed", len(rels), len(yaml))
	}

	// A platform extension: every platform's listing, down past the
	// pre-release line to the stable release.
	empty := openvsxListingEntries(t, "versions-empty.json")
	listings := map[string][]openvsxVersionEntry{
		"linux-x64": append(openvsxListingEntries(t, "versions-rust-lang.rust-analyzer-linux-x64.json"),
			openvsxListingEntries(t, "versions-rust-lang.rust-analyzer-linux-x64-offset1400.json")...),
		"universal":    openvsxListingEntries(t, "versions-rust-lang.rust-analyzer-universal.json"),
		"darwin-arm64": openvsxListingEntries(t, "versions-rust-lang.rust-analyzer-darwin-arm64.json"),
	}
	for _, p := range openvsx.TargetPlatforms() {
		entries, ok := listings[p]
		if !ok {
			entries = empty
		}
		openvsxServeListing(t, srv, "/api/rust-lang/rust-analyzer/"+p+"/versions", entries, 3)
	}
	before := len(srv.requests())
	rels, err = f.Releases(ctx, "rust-lang.rust-analyzer")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "openvsx", "releases-rust-lang.rust-analyzer", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "rust-lang.rust-analyzer", r.Version })
	if !hasVersion(rels, "0.3.3121") {
		t.Errorf("the stable release is not listed: %v", viewReleases(rels))
	}
	// A request per platform, and one more for linux-x64's second page.
	if n := len(srv.requests()) - before; n != 12+1 {
		t.Errorf("%d listing requests", n)
	}

	// The option platforms keeps those and universal.
	f.platforms, _ = openvsxParsePlatforms("darwin-arm64")
	before = len(srv.requests())
	rels, err = f.Releases(ctx, "rust-lang.rust-analyzer")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, r := range rels {
		for _, a := range r.Artifacts {
			paths = append(paths, a.Path[strings.LastIndex(a.Path, "/")+1:])
		}
	}
	if want := "[rust-lang.rust-analyzer-0.4.3118.vsix rust-lang.rust-analyzer-0.4.3119.vsix rust-lang.rust-analyzer-0.4.3119@darwin-arm64.vsix rust-lang.rust-analyzer-0.4.3120.vsix rust-lang.rust-analyzer-0.4.3120@darwin-arm64.vsix]"; fmt.Sprint(paths) != want {
		t.Errorf("platforms darwin-arm64: %v", paths)
	}
	if log := srv.requests()[before:]; len(log) != 2 || !strings.Contains(log[0], "/darwin-arm64/versions") && !strings.Contains(log[1], "/darwin-arm64/versions") {
		t.Errorf("listings read with the option: %v", log)
	}
}

// openvsxVariant is the recorded vscode-yaml document with edits, served
// through the backend as another extension's.
func openvsxVariant(t *testing.T, docs openvsxUpstream, ns, name string, edits ...string) {
	t.Helper()
	doc := string(fixture(t, "openvsx", "redhat.vscode-yaml.json"))
	doc = strings.ReplaceAll(doc, "/api/redhat/vscode-yaml/", "/api/"+ns+"/"+name+"/")
	doc = strings.ReplaceAll(doc, "/file/redhat.vscode-yaml-", "/file/"+ns+"."+name+"-")
	doc = strings.Replace(doc, `"name":"vscode-yaml"`, `"name":"`+name+`"`, 1)
	doc = strings.Replace(doc, `"namespace":"redhat"`, `"namespace":"`+ns+`"`, 1)
	for i := 0; i < len(edits); i += 2 {
		if !strings.Contains(doc, edits[i]) {
			t.Fatalf("%s.%s: the fixture has no %s", ns, name, edits[i])
		}
		doc = strings.ReplaceAll(doc, edits[i], edits[i+1])
	}
	docs["/api/"+ns+"/"+name] = []byte(doc)
}

func TestOpenVSXReleasesMalformedAndRefused(t *testing.T) {
	docs := openvsxDocs(t)
	// The registry names the newest archive otherwise than the builder: only
	// that archive is listed, and no listing is read. Not downloadable:
	// nothing is.
	openvsxVariant(t, docs, "acme", "legacy", "/file/acme.legacy-2.1.2026111208.vsix", "/file/legacy-upload.vsix")
	openvsxVariant(t, docs, "acme", "nodownload", `"downloadable":true`, `"downloadable":false`)
	openvsxVariant(t, docs, "acme", "other", `"name":"other"`, `"name":"else"`)
	openvsxVariant(t, docs, "acme", "shape", `"downloads":{`, `"downloads":["x"],"ignored":{`)
	openvsxVariant(t, docs, "acme", "plain")
	f, srv, reads, _ := openvsxReleasesFeed(t, docs)
	reads.set("/api/acme/garbage", []byte("<html>"))
	reads.setDoc("/api/acme/typosquat", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	reads.setDoc("/api/acme/held", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	ctx := context.Background()

	rels, err := f.Releases(ctx, "acme.legacy")
	if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 || !strings.HasSuffix(rels[0].Artifacts[0].Path, "/2.1.2026111208/file/legacy-upload.vsix") {
		t.Errorf("legacy: %+v %v", rels, err)
	}
	if rels, err := f.Releases(ctx, "acme.nodownload"); err != nil || len(rels) != 0 {
		t.Errorf("not downloadable: %+v %v", rels, err)
	}
	// A listing the registry does not have lists nothing more than the
	// newest version; one it cannot answer now is retried; one that is not
	// a listing is not.
	srv.on("GET", "/api/acme/plain/universal/versions?offset=0").reply(http.StatusNotFound, nil)
	if rels, err := f.Releases(ctx, "acme.plain"); err != nil || len(rels) != 1 || rels[0].Version != "2.1.2026111208" {
		t.Errorf("no listing: %+v %v", rels, err)
	}
	srv.on("GET", "/api/acme/plain/universal/versions?offset=0").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "60")
	if _, err := f.Releases(ctx, "acme.plain"); err == nil || IsPermanent(err) {
		t.Errorf("a listing unavailable: %v", err)
	}
	srv.on("GET", "/api/acme/plain/universal/versions?offset=0").reply(http.StatusOK, []byte(`<html>`))
	_, err = f.Releases(ctx, "acme.plain")
	mustErr(t, err, true, false, "version listing")
	// A listing without end is read to its bound.
	f.versionPage = 1
	srv.on("GET", "/api/acme/plain/universal/versions").reply(http.StatusOK, []byte(`{"offset":0,"totalSize":100000,"versions":{"1.0.0":"u"}}`))
	before := len(srv.requests())
	if _, err := f.Releases(ctx, "acme.plain"); err != nil {
		t.Fatal(err)
	}
	if n := len(srv.requests()) - before; n != openvsxVersionPages {
		t.Errorf("%d pages read", n)
	}

	for name, want := range map[string]string{
		"acme.other":     "is of",
		"acme.shape":     "downloads",
		"acme.garbage":   "/api/acme/garbage",
		"acme.nope":      "not found",
		"acme.typosquat": "nameguard",
		"nonamespace":    "not an Open VSX extension",
		"a.b.c":          "not an Open VSX extension",
		"../x.y":         "not an Open VSX extension",
		".x":             "not an Open VSX extension",
	} {
		_, err := f.Releases(ctx, name)
		mustErr(t, err, true, false, want)
		if t.Failed() {
			t.Fatalf("%s", name)
		}
	}
	_, err = f.Releases(ctx, "acme.held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
}

func TestOpenVSXCursorsAndAdapters(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, fixture(t, "openvsx", "sitemap.xml"))
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	_, cursor := drainBootstrap(t, f)
	for _, bad := range []string{"null", `{"format":"hex/1","snap":"` + strings.Repeat("a", 64) + `"}`, `{"format":"openvsx/1","snap":"x"}`} {
		_, err := f.Changes(context.Background(), bad)
		mustErr(t, err, false, true, "")
	}
	var c indexCursor
	if err := json.Unmarshal([]byte(cursor), &c); err != nil || c.Format != "openvsx/1" {
		t.Errorf("cursor %s (%v)", cursor, err)
	}
	// Bootstrap pages through the copy, and its last cursor follows it.
	f.page = 4
	listed, last := drainBootstrap(t, f)
	if fmt.Sprint(listed) != "[es6kr.claude-sessions golang.Go redhat.vscode-yaml rust-lang.rust-analyzer ugi-dev.ad-astra zovo.zovo-flame-graph]" {
		t.Errorf("listed %v", listed)
	}
	if err := decodeCursor(last, "openvsx/1", &c); err != nil || c.Listing {
		t.Errorf("final cursor %s (%v)", last, err)
	}
}

// A cursor's state the source cannot use means the sitemap is read in full
// and the listing from its top.
func TestOpenVSXStateItCannotUse(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/sitemap.xml").reply(http.StatusOK, fixture(t, "openvsx", "sitemap.xml")).withHeader("ETag", `"s1"`)
	srv.on("GET", "/sitemap.xml").requireHeader("If-None-Match", `"s1"`).reply(http.StatusNotModified, nil)
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	f := openvsxTestFeed(t, srv, &now)
	b, err := f.Bootstrap(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var c indexCursor
	if err := json.Unmarshal([]byte(b.Next), &c); err != nil {
		t.Fatal(err)
	}
	for _, st := range []string{`{"etag":"\"s1\"\nX-Injected: 1"}`, `[1]`, `{"etag":7}`, `{"mark":-5}`} {
		c.State = json.RawMessage(st)
		ch, err := f.Changes(context.Background(), encodeCursor(&c))
		if err != nil || len(ch.Items) != 0 || !strings.Contains(ch.Next, `"state":{"etag":"\"s1\""`) {
			t.Errorf("state %s: %+v %v", st, ch, err)
		}
	}
	var sitemaps int
	for _, r := range srv.requests() {
		if r == "GET /sitemap.xml" {
			sitemaps++
		}
	}
	if sitemaps != 5 {
		t.Errorf("%d sitemap requests: %v", sitemaps, srv.requests())
	}
}
