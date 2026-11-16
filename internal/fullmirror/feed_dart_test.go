package fullmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/dart"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestDartFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url    string
		opts   map[string]string
		want   string
		settle time.Duration
	}{
		{"https://pub.dev", nil, "https://pub.dev", dartDefaultSettle},
		{"https://pub.dartlang.org/", nil, "https://pub.dev", dartDefaultSettle},
		// A mirror of pub.dev, following pub.dev itself: the documents come
		// through the mirror, which may serve them late.
		{"https://pub.flutter-io.cn", map[string]string{"url": "https://pub.dev/"}, "https://pub.dev", dartIntermediarySettle},
		{"https://repo.example/artifactory/api/pub/pub-remote", map[string]string{"url": "https://pub.dev"}, "https://pub.dev", dartIntermediarySettle},
		// A site that serves pub.dev's feed and documents itself.
		{"https://pub.internal.example", map[string]string{"url": "https://pub.internal.example/"}, "https://pub.internal.example", dartDefaultSettle},
		{"https://pub.dev", map[string]string{"settle": "1h"}, "https://pub.dev", time.Hour},
	} {
		f, err := newDartFeed(Env{Upstream: "pub", Type: "dart", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		df := f.(*dartFeed)
		if got := df.src.feed.String(); got != tc.want {
			t.Errorf("%s: feed %s, want %s", tc.url, got, tc.want)
		}
		if df.src.settle != tc.settle {
			t.Errorf("%s: settle %s, want %s", tc.url, df.src.settle, tc.settle)
		}
		if df.src.listingSettle != dartListingSettle || df.src.namesPage != listingBatch || df.src.gapPages != dartGapPages || df.maxDocument != dartMaxDocument ||
			df.src.maxFeed != dartMaxFeed || df.src.maxListing != dartMaxListing || df.src.maxNames != dartMaxNames || df.src.maxDocument != dartMaxDocument {
			t.Errorf("%s: defaults %+v", tc.url, df.src)
		}
	}
	// The pub alias resolves to the same adapter.
	if err := Check(Env{Upstream: "pub", Type: "pub", URL: "https://pub.dev", Options: map[string]string{"settle": "0"}}); err != nil {
		t.Errorf("the pub alias: %v", err)
	}
	// A spec-only pub server has no listing: refused at load time, saying
	// what to set.
	err := Check(Env{Upstream: "unpub", Type: "dart", URL: "https://unpub.internal.example"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a pub server without a feed URL: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"settle": "a while"}, {"settle": "-1s"}, {"url": "file:///srv/pub"}, {"url": "https://u:p@pub.example"}} {
		if err := Check(Env{Upstream: "pub", Type: "dart", URL: "https://pub.dev", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// dartTestFeed builds the adapter against a fixture server standing in for
// pub.dev (given as the feed option url).
func dartTestFeed(t *testing.T) (*dartFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "dart", "https://pub.dev", reads, map[string]string{"url": srv.URL()})).(*dartFeed)
	return f, srv, reads
}

// dartGzip compresses a body as pub.dev serves its name list.
func dartGzip(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dartServeNames serves the name list as pub.dev does: gzip-compressed, and
// 406 to a client that does not accept gzip.
func dartServeNames(t *testing.T, srv *fixtureServer, body []byte) {
	t.Helper()
	srv.on("GET", "/api/package-names").reply(http.StatusNotAcceptable, []byte(`{"error":{"code":"NotAcceptable","message":"Client must accept gzip content."}}`))
	srv.on("GET", "/api/package-names").requireHeader("Accept-Encoding", "gzip").reply(200, dartGzip(t, body)).withHeader("Content-Encoding", "gzip")
}

// dartView is a batch as the dart golden files show it: its items sorted and
// whether more follows (the order of a listing batch and its cursor are the
// listing driver's).
type dartView struct {
	Items []string `json:"items"`
	More  bool     `json:"more"`
}

func dartViewOf(t *testing.T, b Batch) dartView {
	t.Helper()
	if err := validateBatch(b); err != nil {
		t.Fatalf("the engine would refuse the batch: %v", err)
	}
	items := names(b.Items)
	sort.Strings(items)
	for i := 1; i < len(items); i++ {
		if items[i] == items[i-1] {
			t.Errorf("%s reported twice in one batch", items[i])
		}
	}
	return dartView{Items: items, More: b.More}
}

func TestDartBootstrapListsEveryNameThenFollowsTheFeed(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	f.batch, f.src.namesPage = 4, 4
	// When the enumeration begins, the feed's newest version is
	// html_to_markdown_ffi_macos 1.3.0; its next is four hours older.
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed-before.atom"))
	dartServeNames(t, srv, fixture(t, "dart", "package-names.json"))
	ctx := context.Background()
	var views []dartView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, dartViewOf(t, b))
		cursor = b.Next
		if !b.More {
			break
		}
		if i > 10 {
			t.Fatal("the enumeration does not end")
		}
	}
	// The name list's legacy upper-case names are left out; the feed's
	// packages it misses are listed too.
	checkGolden(t, "dart", "bootstrap", views)
	var c listingCursor
	if err := decodeCursor(cursor, "dart/1", &c); err != nil || c.Listing || !c.Mark.Equal(time.Date(2026, 11, 16, 6, 6, 2, 2074000, time.UTC)) {
		t.Errorf("the final cursor %+v (%v): want a follow cursor marked at html_to_markdown_ffi_macos 1.3.0", c, err)
	}

	// Four versions were published since.
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	ch, err := f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "dart", "changes", dartViewOf(t, ch))
	for _, it := range ch.Items {
		if it.Version != "" {
			t.Errorf("%s: changes name packages alone", it)
		}
	}
	// A quiet poll reads the feed alone and reports nothing.
	before := len(srv.requests())
	quiet, err := f.Changes(ctx, ch.Next)
	if err != nil || len(quiet.Items) != 0 || quiet.More {
		t.Errorf("a quiet poll: %+v %v", quiet, err)
	}
	if n := len(srv.requests()) - before; n != 1 {
		t.Errorf("a quiet poll made %d requests", n)
	}
	if _, err := f.Bootstrap(ctx, ch.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

// When the feed does not reach back to the mark, the pass reads the live
// listing until a page ends before it.
func TestDartGapPassReadsTheListing(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	srv.on("GET", "/packages.json?page=1").reply(200, fixture(t, "dart", "packages-page1.json"))
	srv.on("GET", "/packages.json?page=2").reply(200, fixture(t, "dart", "packages-page2.json"))
	// The listing's last page (it names no next one), recorded at page 1914,
	// stands in for page 3.
	srv.on("GET", "/packages.json?page=3").reply(200, fixture(t, "dart", "packages-page1914.json"))
	for _, p := range []string{"html_to_markdown_ffi", "zepben_protobuf", "quart"} {
		srv.on("GET", "/api/packages/"+p).requireHeader("Accept", dartAccept).reply(200, fixture(t, "dart", "package-"+p+".json"))
	}
	// The mark is an hour older than the feed's oldest version.
	mark := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC), Seen: listingSeenAt(time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC), "old@1.0.0")})
	b, err := f.Changes(context.Background(), mark)
	if err != nil {
		t.Fatal(err)
	}
	// The packages of the feed, those of the listing's first two pages, and
	// those of the page that ends before the mark — but its last.
	checkGolden(t, "dart", "changes-gap", dartViewOf(t, b))
	if got := strings.Join(srv.requests(), "\n"); !strings.Contains(got, "/api/packages/quart") || strings.Contains(got, "page=4") {
		t.Errorf("requests:\n%s", got)
	}
	var c listingCursor
	if err := decodeCursor(b.Next, "dart/1", &c); err != nil || c.Pass || !c.Mark.Equal(time.Date(2026, 11, 16, 6, 10, 1, 303297000, time.UTC)) {
		t.Errorf("after the pass: %+v %v", c, err)
	}

	// A package gone between the listing and its document: the one before
	// it tells the time.
	srv.on("GET", "/api/packages/quart").reply(http.StatusNotFound, []byte(`{"error":{"code":"NotFound"}}`))
	srv.on("GET", "/api/packages/calendar_constants").reply(200, bytes.Replace(fixture(t, "dart", "package-quart.json"), []byte(`"name":"quart"`), []byte(`"name":"calendar_constants"`), 1))
	b, err = f.Changes(context.Background(), mark)
	if err != nil || dartViewOf(t, b).More {
		t.Fatalf("%+v %v", b, err)
	}
	if got := fmt.Sprint(dartViewOf(t, b).Items); !strings.Contains(got, "json_rpc") || !strings.Contains(got, "quart") || strings.Contains(got, "calendar_constants") {
		t.Errorf("with quart gone: %s", got)
	}

	// A pass longer than the bound starts over.
	f.src.gapPages = 2
	_, err = f.Changes(context.Background(), mark)
	mustErr(t, err, false, true, "enumerated again")
}

// A version younger than the settle period — its document may not list it
// yet — is reported by a later pass.
func TestDartHoldsBackUnsettledVersions(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	mark := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 6, 6, 2, 2074000, time.UTC), Seen: listingSeenAt(time.Date(2026, 11, 16, 6, 6, 2, 2074000, time.UTC), "html_to_markdown_ffi_macos@1.3.0")})
	// pub.dev's clock stands two minutes after the newest version.
	early := time.Date(2026, 11, 16, 6, 12, 1, 0, time.UTC).Format(http.TimeFormat)
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom")).withHeader("Date", early)
	b, err := f.Changes(context.Background(), mark)
	if err != nil || len(b.Items) != 0 {
		t.Fatalf("unsettled versions were reported: %v %v", names(b.Items), err)
	}
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	b, err = f.Changes(context.Background(), b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(dartViewOf(t, b).Items); got != "[bones_api html_to_markdown_ffi html_to_markdown_ffi_flutter open_at_login]" {
		t.Errorf("the settled versions: %s", got)
	}
	// A feed of nothing but unsettled versions: Bootstrap marks the start of
	// the settle period, after which they are reported once settled.
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom")).withHeader("Date", time.Date(2026, 11, 16, 2, 8, 0, 0, time.UTC).Format(http.TimeFormat))
	dartServeNames(t, srv, fixture(t, "dart", "package-names.json"))
	boot, err := f.Bootstrap(context.Background(), "")
	if err != nil || boot.More {
		t.Fatalf("Bootstrap: %+v %v", boot, err)
	}
	var c listingCursor
	if err := decodeCursor(boot.Next, "dart/1", &c); err != nil || !c.Mark.Equal(time.Date(2026, 11, 16, 2, 3, 0, 0, time.UTC)) || !boot.HeadTime.Equal(c.Mark) {
		t.Errorf("Bootstrap's mark: %+v %s %v", c, boot.HeadTime, err)
	}
}

// dartServed serves recorded package documents through the real dart
// backend — what the gated pipeline hands the adapter, archive_url rewritten
// to the backend's archive endpoint — into a fake pipeline.
func dartServed(t *testing.T, upstreamName string, docs map[string][]byte) *fakeReads {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	b, err := dart.New(dart.Options{Name: upstreamName, UpstreamURL: srv.URL, PublicBaseURL: "http://proxy.example/v1/" + upstreamName,
		Client: upstream.NewWithHTTPClient(srv.Client(), "test")})
	if err != nil {
		t.Fatal(err)
	}
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

// dartTestBackend is the backend the adapter's paths are checked against.
func dartTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := dart.New(dart.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "http://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDartReleasesComeFromTheRewrittenDocument(t *testing.T) {
	pkgs := []string{"open_at_login", "zepben_protobuf", "quart", "font_face_observer"}
	docs := map[string][]byte{}
	for _, p := range pkgs {
		docs["/api/packages/"+p] = fixture(t, "dart", "package-"+p+".json")
	}
	// A retracted version (none of the recorded packages has one).
	retracted := strings.Replace(string(fixture(t, "dart", "package-open_at_login.json")), `"name":"open_at_login"`, `"name":"retracted_pkg"`, 1)
	retracted = strings.Replace(retracted, `"version":"0.0.1",`, `"version":"0.0.1","retracted":true,`, 1)
	if !strings.Contains(retracted, `"retracted":true`) {
		t.Fatal("the fixture has no version 0.0.1")
	}
	docs["/api/packages/retracted_pkg"] = []byte(retracted)
	env := testEnv(t, "dart", "https://pub.dev", nil, nil)
	reads := dartServed(t, env.Upstream, docs)
	if served := reads.docs["/api/packages/quart"].body; !bytes.Contains(served, []byte(`"archive_url":"http://proxy.example/v1/dart-test/api/archives/quart-0.0.1+hotfix.m3.tar.gz"`)) {
		t.Fatalf("the document was not rewritten: %.400s", served)
	}
	env.Read = reads.read
	f := mustFeed(t, env).(*dartFeed)
	backend := dartTestBackend(t, env)
	ctx := context.Background()
	for _, p := range append(pkgs, "retracted_pkg") {
		rels, err := f.Releases(ctx, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		checkGolden(t, "dart", "releases-"+p, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return p, r.Version })
	}
	// A document the backend did not rewrite (archive_url still at pub.dev)
	// has its archives at the backend's endpoint all the same.
	reads.set("/api/packages/zepben_protobuf", fixture(t, "dart", "package-zepben_protobuf.json"))
	rels, err := f.Releases(ctx, "zepben_protobuf")
	if err != nil || len(rels) != 1 || rels[0].Artifacts[0].Path != "/api/archives/zepben_protobuf-1.10.0-beta.1.tar.gz" {
		t.Errorf("an unrewritten document: %+v %v", viewReleases(rels), err)
	}
	// An archive_url naming another package's archive is not this package's.
	reads.set("/api/packages/evil", []byte(`{"name":"evil","versions":[
		{"version":"1.0.0","archive_url":"http://proxy.example/v1/dart-test/api/archives/http-1.0.0.tar.gz","published":"2026-01-01T00:00:00Z"},
		{"version":"1.0.1","archive_url":"http://proxy.example/v1/dart-test/api/archives/evil-1.0.1.tar.gz","published":"2026-01-02T00:00:00Z"},
		{"version":"1.0.2 ","archive_url":"http://proxy.example/v1/dart-test/api/archives/evil-1.0.2.tar.gz"},
		{"version":"1.0.3","archive_url":"http://proxy.example/v1/dart-test/api/archives/evil-1.0.3.tar.gz","retracted":"yes"}]}`))
	rels, err = f.Releases(ctx, "evil")
	if err != nil || fmt.Sprint(len(rels)) != "2" || rels[0].Version != "1.0.1" || rels[1].Version != "1.0.3" || rels[1].Yanked {
		t.Errorf("evil: %+v %v", viewReleases(rels), err)
	}
}

func TestDartMalformedAndRefused(t *testing.T) {
	f, srv, reads := dartTestFeed(t)
	ctx := context.Background()
	mark := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
	for _, tc := range []struct{ body, want string }{
		{`{"packages":[]}`, "reading pub.dev's feed"},
		{`<feed><entry><title>v1.0.0 of a</title>`, "reading pub.dev's feed"},
		{`<?xml version="1.0"?><rss></rss>`, "reading pub.dev's feed"},
	} {
		srv.on("GET", "/feed.atom").reply(200, []byte(tc.body))
		_, err := f.Changes(ctx, mark)
		mustErr(t, err, true, false, tc.want)
	}
	srv.on("GET", "/feed.atom").reply(200, []byte(`<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"></feed>`))
	_, err := f.Changes(ctx, mark)
	mustErr(t, err, false, false, "lists no version")
	// One bad entry does not fail the feed: a title of another shape, a name
	// the backend does not serve, a version no path carries, a link to
	// another package, a time that does not read.
	entry := func(title, link, updated string) string {
		return fmt.Sprintf(`<entry><id>urn:uuid:x</id><title>%s</title><updated>%s</updated><content>c</content><link href="https://pub.dev/packages/%s" rel="alternate" title="%s"/></entry>`, title, updated, link, link)
	}
	srv.on("GET", "/feed.atom").reply(200, []byte(`<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom">`+strings.Join([]string{
		entry("v2.0.0 of acme_new", "acme_new", "2026-11-14T10:00:00.5Z"),
		entry("acme_shape 1.0.0", "acme_shape", "2026-11-14T09:59:00Z"),
		entry("v1.0.0 of Acme_upper", "Acme_upper", "2026-11-14T09:58:00Z"),
		entry("v1.0/0 of acme_mod", "acme_mod", "2026-11-14T09:57:00Z"),
		entry("v1.0.0 of acme_mod", "acme_other", "2026-11-14T09:56:00Z"),
		entry("v1.1.0 of acme_mod", "acme_mod", "yesterday"),
		entry("v1.0.0 of acme_old", "acme_old", "2026-10-01T10:00:00Z"),
	}, "")+`</feed>`))
	b, err := f.Changes(ctx, mark)
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme_new]" {
		t.Errorf("a feed with bad entries: %v %v", names(b.Items), err)
	}
	// A feed past its bound is refused, not cut.
	f.src.maxFeed = 64
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	_, err = f.Changes(ctx, mark)
	mustErr(t, err, true, false, "larger than the adapter reads")
	f.src.maxFeed = dartMaxFeed
	srv.on("GET", "/feed.atom").reply(http.StatusServiceUnavailable, nil).withHeader("Retry-After", "60")
	_, err = f.Changes(ctx, mark)
	if d, ok := RetryAfterOf(err); !ok || d != time.Minute {
		t.Errorf("a 503: %v", err)
	}

	// The listing: garbage, a wrong shape, URLs that name no package. (A pass
	// continued in a later call reads the feed again: the packages it names
	// are not the listing's to report.)
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	listing := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Pass: true,
		Token: dartToken{page: 1, upper: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)}.String()})
	for _, tc := range []struct{ body, want string }{
		{`<html>`, "reading pub.dev's listing"},
		{`{"next":null}`, "not a package listing"},
		{`{"packages":"x"}`, "reading pub.dev's listing"},
	} {
		srv.on("GET", "/packages.json?page=1").json(tc.body)
		_, err := f.Changes(ctx, listing)
		mustErr(t, err, true, false, tc.want)
	}
	srv.on("GET", "/packages.json?page=1").json(`{"packages":["https://pub.dev/packages/Upper.json","https://pub.dev/other/x.json","https://pub.dev/packages/ok_pkg","::","https://pub.dev/packages/old_pkg.json"],"next":null}`)
	srv.on("GET", "/api/packages/old_pkg").json(`{"name":"old_pkg","versions":[{"version":"1.0.0","published":"2020-01-01T00:00:00Z"}]}`)
	b, err = f.Changes(ctx, listing)
	if err != nil || len(b.Items) != 0 {
		t.Errorf("a listing of bad names and an old package: %v %v", names(b.Items), err)
	}
	// A page naming nothing the backend serves still leads to the next.
	srv.on("GET", "/packages.json?page=1").json(`{"packages":["https://pub.dev/packages/Upper.json"],"next":"https://pub.dev/packages.json?page=2"}`)
	srv.on("GET", "/packages.json?page=2").json(`{"packages":["https://pub.dev/packages/old_pkg.json"],"next":null}`)
	before := len(srv.requests())
	b, err = f.Changes(ctx, listing)
	if err != nil || len(b.Items) != 0 || !strings.Contains(strings.Join(srv.requests()[before:], "\n"), "page=2") {
		t.Errorf("a page of bad names: %v %v %v", names(b.Items), err, srv.requests()[before:])
	}
	for _, tok := range []string{"x", "p0@1", "p1@-5", "p1@abc", "p01@5", "p1@05", "p1", "p999999@1",
		// After the first page a token names the boundary with the page before.
		"p2@5", "p1@5@1@aaaaaaaa", "p2@5@0@aaaaaaaa", "p2@5@01@aaaaaaaa", "p2@5@1@short", "p2@5@1@aaaaaaaa.bbbbbbbb.cccccccc.dddddddd", "p2@5@1@aaaaaaa!", "p2@5@1@aaaaaaaa@x"} {
		_, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Pass: true, Token: tok}))
		mustErr(t, err, false, true, "")
	}
	// Boundaries kept in the cursor that are not ones.
	for _, gap := range []string{"", "x", "2.1.0", "1.1763276000.0:aaaaaaaa:bbbbbbbb", "401.1763276000.0:aaaaaaaa:bbbbbbbb", "2.0.0:aaaaaaaa:bbbbbbbb",
		"2.99999999999.0:aaaaaaaa:bbbbbbbb", "2.1763276000.-1:aaaaaaaa:bbbbbbbb", "2.1763276000.0::bbbbbbbb", "2.1763276000.0:aaaaaaaa:", "2.1763276000.0:aaaaaaaa:bbbbbbb",
		"2.1763276000.0:aaaaaaaa,bbbbbbbb,cccccccc,dddddddd:eeeeeeee", "02.1763276000.0:aaaaaaaa:bbbbbbbb", "2.1763276000.0:aaaaaaaa:bbbbbbbb:cccccccc"} {
		cursor := encodeCursor(&dartCursor{listingCursor: listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}, Gaps: []string{gap}})
		_, err := f.Changes(ctx, cursor)
		mustErr(t, err, false, true, "")
	}
	tooMany := make([]string, dartMaxGaps+1)
	for i := range tooMany {
		tooMany[i] = dartGap{Page: 2 + i%300, Since: 1763276000, Before: []string{"aaaaaaaa"}, After: []string{"bbbbbbbb"}}.String()
	}
	_, err = f.Changes(ctx, encodeCursor(&dartCursor{listingCursor: listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}, Gaps: tooMany}))
	mustErr(t, err, false, true, "page boundaries")

	// The name list: garbage, a wrong shape, too large.
	boot := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Listing: true})
	srv.on("GET", "/feed.atom").reply(200, fixture(t, "dart", "feed.atom"))
	for _, tc := range []struct{ body, want string }{
		{`not json`, "reading pub.dev's name list"},
		{`{"nextUrl":null}`, "not a name list"},
		{`{"packages":"a"}`, "reading pub.dev's name list"},
	} {
		dartServeNames(t, srv, []byte(tc.body))
		_, err := f.Bootstrap(ctx, boot)
		mustErr(t, err, true, false, tc.want)
	}
	f.src.maxNames = 32
	dartServeNames(t, srv, fixture(t, "dart", "package-names.json"))
	_, err = f.Bootstrap(ctx, boot)
	mustErr(t, err, true, false, "larger than the adapter reads")
	f.src.maxNames = dartMaxNames
	for _, tok := range []string{"x", "after:", "after:Upper", "before:a"} {
		_, err := f.Bootstrap(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Listing: true, Token: tok}))
		mustErr(t, err, false, true, "")
	}

	// Documents: garbage, a wrong shape, another package's, one pub.dev does
	// not have, names the backend does not serve, refusals of the pipeline.
	for name, tc := range map[string]struct{ body, want string }{
		"acme_garbage": {"<html>", "document of acme_garbage"},
		"acme_shape":   {`{"name":"acme_shape","versions":{"1.0.0":{}}}`, "document of acme_shape"},
		"acme_noname":  {`{"versions":[]}`, "not a package document"},
		"acme_another": {`{"name":"http","versions":[]}`, `describes "http"`},
	} {
		reads.set("/api/packages/"+name, []byte(tc.body))
		_, err := f.Releases(ctx, name)
		mustErr(t, err, true, false, tc.want)
	}
	_, err = f.Releases(ctx, "acme_missing")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"Autolinker", "a-b", "1abc", "a/b", "../x", ""} {
		_, err := f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a pub package name")
	}
	reads.setDoc("/api/packages/typo_squat", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo_squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/api/packages/held", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	f.maxDocument = 64
	reads.set("/api/packages/acme_big", fixture(t, "dart", "package-quart.json"))
	_, err = f.Releases(ctx, "acme_big")
	mustErr(t, err, true, false, "larger than the adapter reads")
}

// dartEntry is an entry of pub.dev's Atom feed.
func dartEntry(pkg, version, at string) string {
	return fmt.Sprintf(`<entry><id>urn:uuid:%[1]s-%[2]s</id><title>v%[2]s of %[1]s</title><updated>%[3]s</updated><content>c</content>`+
		`<link href="https://pub.dev/packages/%[1]s" rel="alternate" title="%[1]s"/></entry>`, pkg, version, at)
}

// dartFeedOf is pub.dev's Atom feed of entries.
func dartFeedOf(entries ...string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?><feed xmlns="http://www.w3.org/2005/Atom">` + strings.Join(entries, "") + `</feed>`)
}

// dartListingOf is a page of /packages.json listing names.
func dartListingOf(names []string, more bool) string {
	urls := make([]string, 0, len(names))
	for _, n := range names {
		urls = append(urls, fmt.Sprintf("%q", "https://pub.dev/packages/"+n+".json"))
	}
	next := "null"
	if more {
		next = `"https://pub.dev/packages.json?page=next"`
	}
	return `{"packages":[` + strings.Join(urls, ",") + `],"next":` + next + `}`
}

// dartDocOf is the document of a package with one version, published at.
func dartDocOf(name, at string) string {
	return fmt.Sprintf(`{"name":%q,"versions":[{"version":"1.0.0","published":%q}]}`, name, at)
}

// dartAt is a time of 2026-11-16 as pub.dev's Date header states it.
func dartAt(h, m int) string {
	return time.Date(2026, 11, 16, h, m, 0, 0, time.UTC).Format(http.TimeFormat)
}

// dartGapsOf reads the boundaries a cursor keeps.
func dartGapsOf(t *testing.T, cursor string) []dartGap {
	t.Helper()
	var c dartCursor
	if err := decodeCursor(cursor, "dart/1", &c); err != nil {
		t.Fatal(err)
	}
	gaps, err := dartParseGaps(c.Gaps, dartGapPages, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return gaps
}

// dartGapScenario serves the pass the review of Task 191 found to lose
// packages. pub.dev's instances list packages from copies they bring up to
// date every 15 minutes, and consecutive requests reach different ones
// (2026-11-16: five requests of page 1 within ten seconds returned three
// states). At 07:00 the feed reaches back to 05:00 and the mark lies at 01:00:
// the pass reads the listing. Its page 1 comes from an instance that has
// taken in new1..new3, its page 2 from one that has not — so pkg048..pkg050,
// published between the mark and the feed's oldest version, sit at no page
// either instance served. The scenario returns the stable packages in listing
// order.
func dartGapScenario(t *testing.T, f *dartFeed, srv *fixtureServer) []string {
	t.Helper()
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("new2", "1.0.0", "2026-11-16T06:40:00Z"),
		dartEntry("new3", "1.0.0", "2026-11-16T06:30:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 0))
	var stable []string
	for i := 1; i <= 150; i++ {
		stable = append(stable, fmt.Sprintf("pkg%03d", i))
	}
	fresh := append([]string{"new1", "new2", "new3"}, stable...)
	srv.on("GET", "/packages.json?page=1").json(dartListingOf(fresh[0:50], true)).withHeader("Date", dartAt(7, 0))
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(stable[50:100], true)).withHeader("Date", dartAt(7, 0))
	srv.on("GET", "/api/packages/pkg047").json(dartDocOf("pkg047", "2026-11-16T03:00:00Z"))
	srv.on("GET", "/api/packages/pkg100").json(dartDocOf("pkg100", "2026-11-16T00:30:00Z"))
	f.src.now = func() time.Time { return time.Date(2026, 11, 16, 7, 1, 0, 0, time.UTC) }
	return stable
}

// A boundary the pass cannot check — the page after it does not repeat the
// end of the page before — is kept in the cursor and looked at again once
// every instance lists at least what the two pages were read from; the
// packages between its sides are reported then.
func TestDartGapPassLooksAgainAtUncheckedBoundaries(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	ctx := context.Background()
	stable := dartGapScenario(t, f, srv)
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if err != nil {
		t.Fatal(err)
	}
	got := " " + strings.Join(names(b.Items), " ") + " "
	for _, want := range []string{"new1", "feedold", "pkg001", "pkg047", "pkg051", "pkg099"} {
		if !strings.Contains(got, " "+want+" ") || b.More {
			t.Fatalf("the pass did not report %s: %s (more %v)", want, got, b.More)
		}
	}
	if strings.Contains(got, " pkg048 ") || strings.Contains(got, " pkg100 ") {
		t.Fatalf("the pass: %s", got)
	}
	gaps := dartGapsOf(t, b.Next)
	if len(gaps) != 1 || gaps[0].Page != 2 || gaps[0].Since != time.Date(2026, 11, 16, 7, 0, 0, 0, time.UTC).Unix() ||
		fmt.Sprint(gaps[0].Before) != fmt.Sprint(dartAnchorsOf(stable[44:47], true)) || fmt.Sprint(gaps[0].After) != fmt.Sprint(dartAnchorsOf(stable[50:53], false)) {
		t.Fatalf("the boundary between pages 1 and 2 is not kept as it was read: %+v", gaps)
	}
	if c := dartCursorOf(t, b.Next).listingCursor; c.Pass || !c.Mark.Equal(time.Date(2026, 11, 16, 6, 50, 0, 0, time.UTC)) {
		t.Fatalf("the pass did not end at the feed's newest version: %+v", c)
	}

	// Five minutes later the listing is not looked at again: some instance
	// may still list what page 2 was read from.
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("new2", "1.0.0", "2026-11-16T06:40:00Z"),
		dartEntry("new3", "1.0.0", "2026-11-16T06:30:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 5))
	f.src.now = func() time.Time { return time.Date(2026, 11, 16, 7, 5, 0, 0, time.UTC) }
	before := len(srv.requests())
	quiet, err := f.Changes(ctx, b.Next)
	if err != nil || len(quiet.Items) != 0 || len(srv.requests())-before != 1 || len(dartGapsOf(t, quiet.Next)) != 1 {
		t.Fatalf("a poll within the listing settle period: %v %v %v", names(quiet.Items), err, srv.requests()[before:])
	}

	// At 07:40 every instance lists new1..new3. Page 2 starts after pkg047,
	// which ends page 1: the packages before pkg051 are the missing ones.
	f.src.now = func() time.Time { return time.Date(2026, 11, 16, 7, 40, 0, 0, time.UTC) }
	fresh := append([]string{"new1", "new2", "new3"}, stable...)
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("new2", "1.0.0", "2026-11-16T06:40:00Z"),
		dartEntry("new3", "1.0.0", "2026-11-16T06:30:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 40))
	srv.on("GET", "/packages.json?page=1").json(dartListingOf(fresh[0:50], true)).withHeader("Date", dartAt(7, 40))
	// pub.dev's clock is what counts: a page it serves at 07:20 may still
	// come from an instance that has not taken in what page 1 was read from.
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(fresh[50:100], true)).withHeader("Date", dartAt(7, 20))
	srv.on("GET", "/packages.json?page=3").json(dartListingOf(fresh[100:150], true)).withHeader("Date", dartAt(7, 20))
	early, err := f.Changes(ctx, quiet.Next)
	if gaps := dartGapsOf(t, early.Next); err != nil || len(early.Items) != 0 || len(gaps) != 1 || gaps[0].Rounds != 1 {
		t.Fatalf("a look at a page pub.dev served within the listing settle period: %v %+v %v", names(early.Items), gaps, err)
	}
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(fresh[50:100], true)).withHeader("Date", dartAt(7, 40))
	late, err := f.Changes(ctx, quiet.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(names(late.Items)); got != "[pkg048 pkg049 pkg050]" {
		t.Errorf("the packages at the boundary: %s", got)
	}
	if gaps := dartGapsOf(t, late.Next); len(gaps) != 0 {
		t.Errorf("the boundary is still kept: %+v", gaps)
	}

	// Had a package been published in between (07:10), page 2 would list
	// pkg047 itself: what it lists between pkg047 and pkg051 is missing.
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(append([]string{"pkg047"}, fresh[50:99]...)[0:50], true)).withHeader("Date", dartAt(7, 40))
	srv.on("GET", "/packages.json?page=1").reply(599, nil) // not needed
	late, err = f.Changes(ctx, quiet.Next)
	if err != nil || fmt.Sprint(names(late.Items)) != "[pkg048 pkg049 pkg050]" || len(dartGapsOf(t, late.Next)) != 0 {
		t.Errorf("a page listing both sides: %v %v", names(late.Items), err)
	}
}

// dartCursorOf reads a dart cursor.
func dartCursorOf(t *testing.T, cursor string) dartCursor {
	t.Helper()
	var c dartCursor
	if err := decodeCursor(cursor, "dart/1", &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// A page that repeats the end of the page before continues it; nothing is
// published for 35 minutes before the feed is read, every instance lists the
// same: neither boundary is kept.
func TestDartGapPassChecksBoundaries(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	stable := dartGapScenario(t, f, srv)
	// Page 2 from an instance that has taken in a package more than page 1's.
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(stable[46:96], true)).withHeader("Date", dartAt(7, 0))
	srv.on("GET", "/api/packages/pkg096").json(dartDocOf("pkg096", "2026-11-16T00:30:00Z"))
	b, err := f.Changes(context.Background(), encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if err != nil || len(dartGapsOf(t, b.Next)) != 0 || !strings.Contains(fmt.Sprint(names(b.Items)), "pkg048") {
		t.Fatalf("overlapping pages: %v %v %v", names(b.Items), dartGapsOf(t, b.Next), err)
	}
	// Nothing published since 06:20: pages 1 and 2 as before, read at 07:30.
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:20:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 30))
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(stable[50:100], true)).withHeader("Date", dartAt(7, 30))
	b, err = f.Changes(context.Background(), encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if err != nil || len(dartGapsOf(t, b.Next)) != 0 {
		t.Fatalf("a quiet listing: %v %v %v", names(b.Items), dartGapsOf(t, b.Next), err)
	}
}

// A boundary whose sides are on two pages when it is looked at again stays
// kept, as does one whose packages are found nowhere; one not resolved within
// a day of looks starts the enumeration over rather than leave a gap.
func TestDartGapPassBoundaryNotFoundAgain(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	ctx := context.Background()
	stable := dartGapScenario(t, f, srv)
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if err != nil || len(dartGapsOf(t, b.Next)) != 1 {
		t.Fatalf("%v %v", names(b.Items), err)
	}
	cursor := b.Next
	// At 07:40, pkg047 ends page 2 and pkg051 starts page 3: the boundary's
	// sides are on two pages.
	f.src.now = func() time.Time { return time.Date(2026, 11, 16, 7, 40, 0, 0, time.UTC) }
	var top []string
	for i := 0; i < 53; i++ {
		top = append(top, fmt.Sprintf("burst%02d", i))
	}
	moved := append(top, stable...)
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 40))
	srv.on("GET", "/packages.json?page=2").json(dartListingOf(moved[50:100], true)).withHeader("Date", dartAt(7, 40))
	srv.on("GET", "/packages.json?page=3").json(dartListingOf(moved[100:150], true)).withHeader("Date", dartAt(7, 40))
	b, err = f.Changes(ctx, cursor)
	if err != nil || len(b.Items) != 0 {
		t.Fatalf("a split boundary: %v %v", names(b.Items), err)
	}
	gaps := dartGapsOf(t, b.Next)
	if len(gaps) != 1 || gaps[0].Rounds != 1 {
		t.Fatalf("the split boundary is not kept: %+v", gaps)
	}
	// Its packages found nowhere a day later, in the twelfth look: the
	// registry is enumerated again.
	var nothing []string
	for i := 0; i < 50; i++ {
		nothing = append(nothing, fmt.Sprintf("other%02d", i))
	}
	for p := 2; p <= 80; p++ {
		srv.on("GET", fmt.Sprintf("/packages.json?page=%d", p)).json(dartListingOf(nothing, true)).withHeader("Date", dartAt(7, 40))
	}
	f.src.now = func() time.Time { return time.Date(2026, 11, 17, 7, 30, 0, 0, time.UTC) }
	gaps[0].Rounds = dartVerifyRounds - 2
	c := dartCursorOf(t, b.Next)
	c.Gaps = []string{gaps[0].String()}
	b, err = f.Changes(ctx, encodeCursor(&c))
	if err != nil || len(dartGapsOf(t, b.Next)) != 1 {
		t.Fatalf("the eleventh look: %v %v", names(b.Items), err)
	}
	_, err = f.Changes(ctx, b.Next)
	mustErr(t, err, false, true, "enumerated again")
}

// While pub.dev publishes more versions in 35 minutes than its feed holds,
// the instances list the latest packages in places the feed cannot tell: a
// pass that needs the listing waits.
func TestDartGapPassWaitsOutABurst(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:59:00Z"), dartEntry("new2", "1.0.0", "2026-11-16T06:30:00Z"))).withHeader("Date", dartAt(7, 0))
	_, err := f.Changes(context.Background(), encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if d, ok := RetryAfterOf(err); !ok || d != dartBurstWait || !strings.Contains(err.Error(), "settled") {
		t.Errorf("a burst: %v", err)
	}
}

// pub.dev's feed carries each version's changelog excerpt escaped only for
// markup (app/lib/frontend/dom/dom.dart): an excerpt with a terminal's colour
// codes holds characters XML does not allow, which are replaced, not taken as
// a malformed feed.
func TestDartFeedWithControlCharacters(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	feed := strings.Replace(string(fixture(t, "dart", "feed.atom")), "</content>", "Changelog excerpt:\n* \x1b[32mfixed\x1b[0m the build \xff\xfe</content>", 1)
	srv.on("GET", "/feed.atom").reply(200, []byte(feed))
	mark := encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 6, 6, 2, 2074000, time.UTC),
		Seen: listingSeenAt(time.Date(2026, 11, 16, 6, 6, 2, 2074000, time.UTC), "html_to_markdown_ffi_macos@1.3.0")})
	b, err := f.Changes(context.Background(), mark)
	if err != nil || fmt.Sprint(dartViewOf(t, b).Items) != "[bones_api html_to_markdown_ffi html_to_markdown_ffi_flutter open_at_login]" {
		t.Errorf("a feed with control characters: %v %v", names(b.Items), err)
	}
	// A control character in a title makes that entry no version.
	entries, err := dartParseFeed(dartFeedOf(dartEntry("ok_pkg", "1.0.0", "2026-11-16T06:00:00Z"), dartEntry("bad\x01pkg", "1.0.0", "2026-11-16T06:00:00Z")))
	if err != nil || len(entries) != 1 || entries[0].name != "ok_pkg" {
		t.Errorf("entries: %+v %v", entries, err)
	}
	if got := string(dartXMLText([]byte("a\x00b\tc\xc3\xa9\xed\xa0\x80￾"))); got != "a�b\tcé����" {
		t.Errorf("dartXMLText: %q", got)
	}
}

// Behind a server in front of pub.dev the settle period (2h30m) is longer
// than the feed's span: none of its versions has settled. The pass reads the
// listing from its top and reports the packages the feed does not name; the
// mark is the start of the settle period, and the next pass reports them
// again (a package's newer version may be known to the listing alone).
// Bootstrap marks the start of the settle period.
func TestDartSettleLongerThanTheFeed(t *testing.T) {
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "dart", "https://pub.flutter-io.cn", newFakeReads(), map[string]string{"url": srv.URL()})).(*dartFeed)
	if f.src.settle != dartIntermediarySettle {
		t.Fatalf("settle %s", f.src.settle)
	}
	ctx := context.Background()
	feed := dartFeedOf(dartEntry("fresh_a", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("fresh_b", "2.0.0", "2026-11-16T05:00:00Z"))
	srv.on("GET", "/feed.atom").reply(200, feed).withHeader("Date", dartAt(7, 0))
	srv.on("GET", "/packages.json?page=1").json(dartListingOf([]string{"fresh_a", "fresh_b", "between", "settled", "older"}, false)).withHeader("Date", dartAt(7, 0))
	srv.on("GET", "/api/packages/older").json(dartDocOf("older", "2026-11-16T03:00:00Z"))
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 4, 0, 0, 0, time.UTC)}))
	if err != nil || fmt.Sprint(dartViewOf(t, b).Items) != "[between settled]" {
		t.Fatalf("the first pass: %v %v", names(b.Items), err)
	}
	var c listingCursor
	if err := decodeCursor(b.Next, "dart/1", &c); err != nil || !c.Mark.Equal(time.Date(2026, 11, 16, 4, 30, 0, 0, time.UTC)) {
		t.Fatalf("the mark: %+v %v", c, err)
	}
	srv.on("GET", "/feed.atom").reply(200, feed).withHeader("Date", dartAt(7, 5))
	srv.on("GET", "/packages.json?page=1").json(dartListingOf([]string{"fresh_a", "fresh_b", "between", "settled", "older"}, false)).withHeader("Date", dartAt(7, 5))
	b, err = f.Changes(ctx, b.Next)
	if err != nil || fmt.Sprint(dartViewOf(t, b).Items) != "[between settled]" {
		t.Errorf("the next pass: %v %v", names(b.Items), err)
	}
	dartServeNames(t, srv, fixture(t, "dart", "package-names.json"))
	boot, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeCursor(boot.Next, "dart/1", &c); err != nil || !c.Mark.Equal(time.Date(2026, 11, 16, 4, 35, 0, 0, time.UTC)) {
		t.Errorf("Bootstrap's mark: %+v %v", c, err)
	}
}

// The page after a boundary starts right after the page before's last
// package only while that package is listed: once it is withdrawn, the
// boundary is kept for a page that lists packages of both sides.
func TestDartGapPassNeedsTheLastPackageBefore(t *testing.T) {
	f, srv, _ := dartTestFeed(t)
	ctx := context.Background()
	stable := dartGapScenario(t, f, srv)
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "dart/1", Mark: time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)}))
	if err != nil || len(dartGapsOf(t, b.Next)) != 1 {
		t.Fatalf("%v %v", names(b.Items), err)
	}
	f.src.now = func() time.Time { return time.Date(2026, 11, 16, 7, 40, 0, 0, time.UTC) }
	withdrawn := append([]string{"new1", "new2", "new3"}, append(append([]string(nil), stable[:46]...), stable[47:]...)...)
	srv.on("GET", "/feed.atom").reply(200, dartFeedOf(dartEntry("new1", "1.0.0", "2026-11-16T06:50:00Z"), dartEntry("feedold", "1.0.0", "2026-11-16T05:00:00Z"))).withHeader("Date", dartAt(7, 40))
	for p := 1; p <= 3; p++ {
		srv.on("GET", fmt.Sprintf("/packages.json?page=%d", p)).json(dartListingOf(withdrawn[(p-1)*50:p*50], true)).withHeader("Date", dartAt(7, 40))
	}
	b, err = f.Changes(ctx, b.Next)
	if gaps := dartGapsOf(t, b.Next); err != nil || len(b.Items) != 0 || len(gaps) != 1 || gaps[0].Rounds != 1 {
		t.Errorf("pkg047 withdrawn: %v %+v %v", names(b.Items), gaps, err)
	}
}
