package fullmirror

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/composer"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// composerStart is the change log's position Packagist answered a request
// without since with (nosince.json), and where changes.json continues.
const composerStart = 17947953040021

// composerTestFeed builds the adapter against a fixture server standing in for
// both packagist.org (the change log and the package list, through the feed
// option) and the repository (the HEAD requests of the Last-Modified check).
func composerTestFeed(t *testing.T) (*composerFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "composer", srv.URL(), reads, map[string]string{"url": srv.URL()})).(*composerFeed)
	return f, srv, reads
}

// composerProxied is a package's v2 metadata as the gated pipeline serves it:
// the recorded document fetched and rewritten by the real backend, with
// publicBase as the proxy's public base for the upstream ("" for the
// root-relative mount).
func composerProxied(t *testing.T, upstreamName, publicBase, path string, doc []byte) []byte {
	t.Helper()
	up := newFixtureServer(t)
	up.on("GET", path).reply(200, doc)
	b, err := composer.New(composer.Options{Name: upstreamName, UpstreamURL: up.URL(), PublicBaseURL: publicBase, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: path, Query: url.Values{}})
	if err != nil {
		t.Fatal(err)
	}
	fr, err := b.Fetch(context.Background(), res)
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Content.Close()
	body, err := io.ReadAll(fr.Content)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestComposerFeedLocation(t *testing.T) {
	for _, u := range []string{"https://repo.packagist.org", "https://packagist.org/", "https://repo-eu-fra-2.packagist.org"} {
		f, err := composerNewFeed(Env{Upstream: "p", Type: "composer", URL: u})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if got := f.(*composerFeed).feed.String(); got != composerPublicFeed {
			t.Errorf("%s: feed %s", u, got)
		}
	}
	// Satis, Artifactory, Nexus: no change log is known; the configuration
	// is refused at load time, with what to set.
	err := Check(Env{Upstream: "corp", Type: "composer", URL: "https://satis.internal.example"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a private repository without a feed: %v", err)
	}
	f, err := composerNewFeed(Env{Upstream: "corp", Type: "composer", URL: "https://satis.internal.example", Options: map[string]string{"url": "https://packagist.internal.example/"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*composerFeed).feed.String(); got != "https://packagist.internal.example" {
		t.Errorf("option url: %s", got)
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://x"}, {"url": "https://u:p@x"}} {
		if err := Check(Env{Upstream: "p", Type: "composer", URL: "https://repo.packagist.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestComposerBootstrapListsEveryPackageFromTheStart(t *testing.T) {
	f, srv, _ := composerTestFeed(t)
	f.page = 4
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, fixture(t, "composer", "nosince.json"))
	srv.on("GET", "/packages/list.json").reply(200, fixture(t, "composer", "list.json"))
	// The listing starts a margin before the log's position (the list is
	// CDN-cached), and every batch after the first reads the log from the
	// listing's position and moves it on: the recorded log (dev-branch
	// updates only, none to add), then nothing new.
	listStart := int64(composerStart - composerStartMargin)
	srv.on("GET", fmt.Sprintf("/metadata/changes.json?since=%d", listStart)).reply(200, fixture(t, "composer", "changes.json"))
	srv.on("GET", fmt.Sprintf("/metadata/changes.json?since=%d", composerStart)).json(fmt.Sprintf(`{"actions":[],"timestamp":%d}`, composerStart))
	ctx := context.Background()
	var batches []Batch
	cursors := []string{""}
	for i := 1; ; i++ {
		b, err := f.Bootstrap(ctx, cursors[len(cursors)-1])
		if err != nil {
			t.Fatal(err)
		}
		checkGolden(t, "composer", fmt.Sprintf("bootstrap-page-%d", i), viewBatch(t, b))
		batches = append(batches, b)
		if !b.More {
			break
		}
		cursors = append(cursors, b.Next)
	}
	if len(batches) != 3 {
		t.Fatalf("%d batches", len(batches))
	}
	// The start position is taken first (without since), then the list,
	// once; then the log, once per later batch.
	if got, want := fmt.Sprint(srv.requests()), fmt.Sprintf("[GET /metadata/changes.json GET /packages/list.json GET /metadata/changes.json?since=%d GET /metadata/changes.json?since=%d]", listStart, composerStart); got != want {
		t.Errorf("requests %s, want %s", got, want)
	}
	last := batches[len(batches)-1]
	var c composerCursor
	if err := decodeCursor(last.Next, f.format(), &c); err != nil || c.Listing || c.Since != composerStart {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	if _, err := f.Changes(ctx, batches[0].Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, last.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	// A list that does not match the cursor, or is gone, is not trusted.
	p := filepath.Join(f.files.dir, composerListFile(listStart))
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(data), "psr/log", "psr/lag", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = f.Bootstrap(ctx, cursors[1])
	mustErr(t, err, false, true, "does not match")
	os.Remove(p)
	_, err = f.Bootstrap(ctx, cursors[1])
	mustErr(t, err, false, true, "not stored")
}

func TestComposerChangesFollowTheLog(t *testing.T) {
	f, srv, _ := composerTestFeed(t)
	srv.on("GET", "/metadata/changes.json?since=17947952500000").reply(200, fixture(t, "composer", "changes.json"))
	b, err := f.Changes(context.Background(), f.cursor(composerCursor{Since: 17947952500000}))
	if err != nil {
		t.Fatal(err)
	}
	// Updates of release documents are reported by name; the "~dev"
	// documents, of branch versions, are not.
	checkGolden(t, "composer", "changes", viewBatch(t, b))
	if f.times["dpc-sdp/tide_marina"] != 1794795287 || f.times["bangsamu/export-runner"] != 1794795296 || len(f.times) != 2 {
		t.Errorf("update times %v", f.times)
	}
}

func TestComposerResyncAndRefusedPositions(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := composerTestFeed(t)
	cursor := f.cursor(composerCursor{Since: 17947000000000})
	// A since older than the 24-hour log: Packagist asks for a resync.
	srv.on("GET", "/metadata/changes.json").reply(200, fixture(t, "composer", "changes-old.json"))
	_, err := f.Changes(ctx, cursor)
	mustErr(t, err, false, true, "resync")
	// A since it does not take.
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, fixture(t, "composer", "nosince.json"))
	_, err = f.Changes(ctx, cursor)
	mustErr(t, err, false, true, "refuses since")
	// A log that went back.
	srv.on("GET", "/metadata/changes.json").json(`{"actions":[],"timestamp":17946000000000}`)
	_, err = f.Changes(ctx, cursor)
	mustErr(t, err, false, true, "went back")
	// Cursors of another adapter or format, and garbage, are not trusted.
	for _, bad := range []string{"", "x", `{"format":"composer/1"}`, `{"format":"composer/1","since":-5}`, `{"format":"npm/1","since":"1"}`,
		`{"format":"composer/1","since":1,"extra":1}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestComposerActionsAreChecked(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := composerTestFeed(t)
	srv.on("GET", "/metadata/changes.json").json(`{"actions":[
		{"type":"update","package":"acme\/later","time":1794795300},
		{"type":"update","package":"acme\/gone","time":1794795200},
		{"type":"delete","package":"acme\/gone","time":1794795210},
		{"type":"delete","package":"acme\/back","time":1794795220},
		{"type":"update","package":"acme\/back","time":1794795230},
		{"type":"update","package":"acme\/lib~dev","time":1794795240},
		{"type":"update","package":"Acme\/Upper","time":1794795240},
		{"type":"update","package":"no-vendor","time":1794795240},
		{"type":"update","package":"..\/etc","time":1794795240},
		{"type":"rename","package":"acme\/other","time":1794795240},
		{"type":"update","package":"acme\/bad-time","time":-1},
		{"type":"update","time":1794795240},
		7
	],"timestamp":17947953040021}`)
	b, err := f.Changes(ctx, f.cursor(composerCursor{Since: 17947952000000}))
	if err != nil {
		t.Fatal(err)
	}
	// In the order of the log; a package updated and deleted is deleted, one
	// deleted and published again is updated.
	want := []Coordinate{{Name: "acme/gone", Deleted: true}, {Name: "acme/back"}, {Name: "acme/later"}}
	if len(b.Items) != len(want) || b.Items[0] != want[0] || b.Items[1] != want[1] || b.Items[2] != want[2] {
		t.Errorf("items %+v, want %+v", b.Items, want)
	}
	if b.More || !b.LagKnown {
		t.Errorf("batch %+v", b)
	}

	// More packages than a batch carries: the next batch reads the log again
	// from the second of the first package left out.
	f.maxItems = 2
	b, err = f.Changes(ctx, f.cursor(composerCursor{Since: 17947952000000}))
	if err != nil {
		t.Fatal(err)
	}
	var c composerCursor
	// (since is exclusive: one before that second's first position.)
	if err := decodeCursor(b.Next, f.format(), &c); err != nil || !b.More || c.Since != 17947952999999 || len(b.Items) != 2 {
		t.Errorf("a capped batch: %+v, cursor %+v (%v)", b.Items, c, err)
	}
	// … unless that second is where the batch starts.
	_, err = f.Changes(ctx, f.cursor(composerCursor{Since: 17947952999999}))
	mustErr(t, err, false, true, "within one second")
}

func TestComposerReleasesComeFromTheRewrittenMetadata(t *testing.T) {
	ctx := context.Background()
	f, _, reads := composerTestFeed(t)
	doc := fixture(t, "composer", "psr-log.json")
	backend, err := composer.New(composer.Options{Name: f.k.env.Upstream, UpstreamURL: "https://repo.packagist.org",
		PublicBaseURL: "https://proxy.example/v1/" + f.k.env.Upstream, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	// With the proxy's absolute public base, and with the root-relative mount
	// (dist URLs then name the mount, and the root document advertises the
	// dist endpoint as a mirror): the same paths.
	var golden []Release
	for _, base := range []string{"https://proxy.example/v1/" + f.k.env.Upstream, ""} {
		reads.set("/p2/psr/log.json", composerProxied(t, f.k.env.Upstream, base, "/p2/psr/log.json", doc))
		rels, err := f.Releases(ctx, "psr/log")
		if err != nil {
			t.Fatal(err)
		}
		if golden == nil {
			golden = rels
			checkGolden(t, "composer", "releases-psr-log", viewReleases(rels))
		} else if fmt.Sprint(viewReleases(rels)) != fmt.Sprint(viewReleases(golden)) {
			t.Errorf("public base %q: other releases", base)
		}
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "psr/log", r.Version })
	}
	// Metadata the backend did not rewrite names no dist the proxy serves;
	// dev versions are not mirrored, nor a version without a dist.
	reads.set("/p2/psr/log.json", doc)
	if rels, err := f.Releases(ctx, "psr/log"); err != nil || len(rels) != 0 {
		t.Errorf("unrewritten metadata: %v %v", viewReleases(rels), err)
	}
	mixed := `{"packages":{"acme/lib":[
		{"name":"acme/lib","version":"dev-main","dist":{"type":"zip","url":"https://api.github.com/x/zipball/aaa","reference":"aaa"}},
		{"name":"acme/lib","version":"2.0.x-dev","dist":{"type":"zip","url":"https://api.github.com/x/zipball/bbb","reference":"bbb"}},
		{"name":"acme/lib","version":"1.1.0","source":{"type":"git","url":"https://github.com/acme/lib.git","reference":"ccc"}},
		{"name":"acme/lib","version":"1.0.0","dist":{"type":"zip","url":"https://api.github.com/x/zipball/ddd","reference":"ddd","shasum":""},"time":"2020-01-02T03:04:05+00:00"},
		{"name":"acme/lib","version":"0.9.0","dist":{"type":"zip","url":"/srv/archives/lib-0.9.0.zip","reference":"eee"}}
	]}}`
	reads.set("/p2/acme/lib.json", composerProxied(t, f.k.env.Upstream, "https://proxy.example/v1/"+f.k.env.Upstream, "/p2/acme/lib.json", []byte(mixed)))
	rels, err := f.Releases(ctx, "acme/lib")
	if err != nil || len(rels) != 1 || rels[0].Version != "1.0.0" || rels[0].Published.IsZero() {
		t.Errorf("mixed versions: %v %v", viewReleases(rels), err)
	}
	// An unknown package, a name that is not one, a gate's verdict, metadata
	// that is not, and metadata of another package.
	_, err = f.Releases(ctx, "acme/missing")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../etc/passwd")
	mustErr(t, err, true, false, "not a Composer package name")
	reads.setDoc("/p2/typo/squat.json", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo/squat")
	mustErr(t, err, true, false, "nameguard")
	reads.set("/p2/acme/broken.json", []byte(`[1,2]`))
	_, err = f.Releases(ctx, "acme/broken")
	mustErr(t, err, true, false, "metadata of acme/broken")
	reads.set("/p2/acme/other.json", []byte(`{"packages":{"acme/else":[]}}`))
	_, err = f.Releases(ctx, "acme/other")
	mustErr(t, err, true, false, "does not list")
}

func TestComposerReleasesWaitForCurrentMetadata(t *testing.T) {
	ctx := context.Background()
	f, srv, reads := composerTestFeed(t)
	reads.set("/p2/psr/log.json", composerProxied(t, f.k.env.Upstream, "https://proxy.example/v1/"+f.k.env.Upstream, "/p2/psr/log.json", fixture(t, "composer", "psr-log.json")))
	srv.on("GET", "/metadata/changes.json").json(`{"actions":[{"type":"update","package":"psr\/log","time":1794795287}],"timestamp":17947953040021}`)
	if _, err := f.Changes(ctx, f.cursor(composerCursor{Since: 17947952000000})); err != nil {
		t.Fatal(err)
	}
	update := time.Unix(1794795287, 0).UTC()
	// The CDN still serves the metadata from before the update: asked again
	// later, not an error on the package.
	srv.on("HEAD", "/p2/psr/log.json").reply(200, nil).withHeader("Last-Modified", update.Add(-time.Minute).Format(http.TimeFormat))
	_, err := f.Releases(ctx, "psr/log")
	mustErr(t, err, false, false, "has not caught up")
	// Current metadata: read, and not checked again.
	srv.on("HEAD", "/p2/psr/log.json").reply(200, nil).withHeader("Last-Modified", update.Format(http.TimeFormat))
	if rels, err := f.Releases(ctx, "psr/log"); err != nil || len(rels) == 0 {
		t.Fatalf("current metadata: %v %v", len(rels), err)
	}
	heads := func() int {
		n := 0
		for _, r := range srv.requests() {
			if strings.HasPrefix(r, "HEAD ") {
				n++
			}
		}
		return n
	}
	if _, err := f.Releases(ctx, "psr/log"); err != nil {
		t.Fatal(err)
	}
	if n := heads(); n != 2 {
		t.Errorf("%d HEAD requests, want 2: %v", n, srv.requests())
	}
	// The engine's workers check at once.
	if _, err := f.Changes(ctx, f.cursor(composerCursor{Since: 17947952000000})); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Releases(ctx, "psr/log"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// A package Packagist no longer has.
	if _, err := f.Changes(ctx, f.cursor(composerCursor{Since: 17947952000000})); err != nil {
		t.Fatal(err)
	}
	srv.on("HEAD", "/p2/psr/log.json").reply(404, nil)
	_, err = f.Releases(ctx, "psr/log")
	mustErr(t, err, true, false, "not found")
}

func TestComposerMalformedAnswers(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := composerTestFeed(t)
	cursor := f.cursor(composerCursor{Since: 17947952000000})
	for _, tc := range []struct{ body, want string }{
		{`not json`, "change log"},
		{`{"actions":[]}`, "no timestamp"},
		{`{"actions":[],"timestamp":"soon"}`, "change log"},
		{`{"actions":[],"timestamp":1.5}`, "not a position"},
		{`{"actions":{"x":1},"timestamp":17947953040021}`, "change log"},
	} {
		srv.on("GET", "/metadata/changes.json").json(tc.body)
		_, err := f.Changes(ctx, cursor)
		mustErr(t, err, true, false, tc.want)
	}
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadGateway, nil)
	_, err := f.Changes(ctx, cursor)
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/metadata/changes.json").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "5")
	_, err = f.Changes(ctx, cursor)
	if d, ok := RetryAfterOf(err); !ok || d != 5*time.Second {
		t.Errorf("Retry-After not carried: %v", err)
	}
	// The start without a timestamp, a list that is not one.
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, []byte(`<html>bad request</html>`))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "400")
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, []byte(`{"error":"no since"}`))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "no timestamp")
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, fixture(t, "composer", "nosince.json"))
	srv.on("GET", "/packages/list.json").json(`{"packages":["psr/log"]}`)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "packageNames")
}

func TestComposerListingKeepsTheLogPositionFresh(t *testing.T) {
	// Listing Packagist takes longer than the 24 hours its log reaches back:
	// every batch after the first reads the log from the listing's position,
	// reports what changed and moves the position on, so the listing ends
	// at a position the log still knows.
	f, srv, _ := composerTestFeed(t)
	f.page = 4
	srv.on("GET", "/metadata/changes.json").reply(http.StatusBadRequest, fixture(t, "composer", "nosince.json"))
	srv.on("GET", "/packages/list.json").reply(200, fixture(t, "composer", "list.json"))
	listStart := int64(composerStart - composerStartMargin)
	srv.on("GET", fmt.Sprintf("/metadata/changes.json?since=%d", listStart)).json(`{"actions":[
		{"type":"update","package":"acme/new-one","time":1794795300},
		{"type":"delete","package":"acme/removed","time":1794795301},
		{"type":"update","package":"acme/branch~dev","time":1794795302}],"timestamp":17947953100000}`)
	ctx := context.Background()
	b1, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f.Bootstrap(ctx, b1.Next)
	if err != nil {
		t.Fatal(err)
	}
	got := names(b2.Items)
	if len(got) != 6 || got[4] != "acme/new-one" || got[5] != "acme/removed" || !b2.Items[5].Deleted {
		t.Errorf("the second batch %v: four listed packages, then the log's changes (no dev branch)", got)
	}
	var c composerCursor
	if err := decodeCursor(b2.Next, f.format(), &c); err != nil || c.Since != 17947953100000 || c.Started != listStart || !c.Listing {
		t.Errorf("cursor %+v (%v): the position moved on, the list's name did not", c, err)
	}
	// A listing that took longer than the log keeps starts over.
	srv.on("GET", "/metadata/changes.json?since=17947953100000").json(`{"actions":[{"type":"resync","time":1794795400,"package":"*"}],"timestamp":17947954000000}`)
	_, err = f.Bootstrap(ctx, b2.Next)
	mustErr(t, err, false, true, "resync")
}
