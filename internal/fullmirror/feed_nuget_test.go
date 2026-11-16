package fullmirror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// nugetPublicOrigin is the registry the NuGet fixtures were recorded from.
const nugetPublicOrigin = "https://api.nuget.org"

// nugetTestFeed builds the adapter against a fixture server standing in for
// api.nuget.org: the recorded service index, catalog index and pages, with
// the registry's origin swapped for the server's.
func nugetTestFeed(t *testing.T, opts map[string]string) (*nugetFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "nuget", srv.URL(), reads, opts)).(*nugetFeed)
	f.now = nugetTestNow
	return f, srv, reads
}

// nugetTestNow is the clock of the NuGet tests: a day after the recorded and
// synthetic commits, so that every commit has settled unless a test says
// otherwise.
func nugetTestNow() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }

// nugetFixture reads a recorded document with the registry's origin swapped
// for the fixture server's.
func nugetFixture(t *testing.T, srv *fixtureServer, name string) []byte {
	t.Helper()
	return bytes.ReplaceAll(fixture(t, "nuget", name), []byte(nugetPublicOrigin), []byte(srv.URL()))
}

// nugetServeCatalog has the server answer as api.nuget.org did.
func nugetServeCatalog(t *testing.T, srv *fixtureServer) {
	t.Helper()
	srv.on("GET", "/v3/index.json").reply(200, nugetFixture(t, srv, "service-index.json"))
	srv.on("GET", "/v3/catalog0/index.json").reply(200, nugetFixture(t, srv, "catalog-index.json"))
	for _, n := range []int{0, 8600, 15964, 23552, 23567, 23568} {
		srv.on("GET", fmt.Sprintf("/v3/catalog0/page%d.json", n)).reply(200, nugetFixture(t, srv, fmt.Sprintf("page-%d.json", n)))
	}
}

// nugetView is viewBatch with the cursor shown as it would be against
// api.nuget.org: the fixture server's origin is the registry's, and the
// digest of the stored page list (which holds the server's URLs) is elided.
// The golden files then do not depend on the server's port.
func nugetView(t *testing.T, srv *fixtureServer, b Batch) batchView {
	t.Helper()
	v := viewBatch(t, b)
	var c nugetCursor
	if err := json.Unmarshal(v.Next, &c); err != nil {
		t.Fatalf("cursor %s: %v", v.Next, err)
	}
	c.Catalog = strings.ReplaceAll(c.Catalog, srv.URL(), nugetPublicOrigin)
	if c.Digest != "" {
		c.Digest = "(the page list's SHA-256)"
	}
	v.Next, _ = json.Marshal(c)
	return v
}

// nugetCursorAt is a follow cursor at a commit timestamp of the fixture
// server's catalog.
func nugetCursorAt(f *nugetFeed, srv *fixtureServer, since string) string {
	return f.cursor(nugetCursor{Catalog: srv.URL() + "/v3/catalog0/index.json", Since: since})
}

// nugetCountRequests counts the requests the server answered for a path.
func nugetCountRequests(srv *fixtureServer, path string) int {
	n := 0
	for _, r := range srv.requests() {
		if strings.HasSuffix(r, " "+path) {
			n++
		}
	}
	return n
}

func TestNuGetFeedLocation(t *testing.T) {
	f, err := nugetNewFeed(Env{Upstream: "n", Type: "nuget", URL: "https://api.nuget.org"})
	if err != nil {
		t.Fatal(err)
	}
	if f.(*nugetFeed).fixed != nil {
		t.Errorf("nuget.org's catalog is read from its service index, not fixed")
	}
	f, err = nugetNewFeed(Env{Upstream: "n", Type: "nuget", URL: "https://nuget.internal.example/v3/index", Options: map[string]string{"url": "https://mirror.internal.example/catalog/index.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.(*nugetFeed).fixed.String(); got != "https://mirror.internal.example/catalog/index.json" {
		t.Errorf("option url: %s", got)
	}
	// Whether a private feed publishes a catalog shows in its service index
	// at the first poll: the configuration is accepted without I/O.
	if err := Check(Env{Upstream: "corp", Type: "nuget", URL: "https://artifactory.internal.example/api/nuget/v3/nuget-remote"}); err != nil {
		t.Errorf("a private feed: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://x/index.json"}, {"url": "https://u:p@x/index.json"}, {"url": "https://x/index.json?a=b"}} {
		if err := Check(Env{Upstream: "n", Type: "nuget", URL: "https://api.nuget.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestNuGetBootstrapReplaysTheCatalogFromItsFirstPage(t *testing.T) {
	f, srv, _ := nugetTestFeed(t, nil)
	f.pages = 2
	nugetServeCatalog(t, srv)
	ctx := context.Background()

	// The pages are replayed in commit order, though the index lists them
	// out of order; each batch names a package once.
	var batches []Batch
	cursor := ""
	for i := 1; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatalf("batch %d: %v", i, err)
		}
		checkGolden(t, "nuget", fmt.Sprintf("bootstrap-page-%d", i), nugetView(t, srv, b))
		batches = append(batches, b)
		if !b.More {
			break
		}
		if i > 5 {
			t.Fatal("the replay does not end")
		}
		cursor = b.Next
	}
	if len(batches) != 3 {
		t.Fatalf("%d batches, want 3", len(batches))
	}
	// The replay continues with the commit the index stood at when it began;
	// the index was read once.
	var c nugetCursor
	last := batches[len(batches)-1]
	if err := decodeCursor(last.Next, f.format(), &c); err != nil || c.Listing || c.Since != "2026-11-16T02:14:09.8253348Z" {
		t.Errorf("final cursor %+v (%v)", c, err)
	}
	if n := nugetCountRequests(srv, "/v3/catalog0/index.json"); n != 1 {
		t.Errorf("the catalog index was read %d times", n)
	}
	if _, err := f.Changes(ctx, batches[0].Next); err == nil {
		t.Errorf("Changes accepted a replay cursor")
	}
	if _, err := f.Bootstrap(ctx, last.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

func TestNuGetReplayReportsAPackageOnce(t *testing.T) {
	f, srv, _ := nugetTestFeed(t, nil)
	f.pages = 1
	nugetServeCatalog(t, srv)
	ctx := context.Background()
	var cursors []string
	var got [][]string
	cursor := ""
	for {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		cursors = append(cursors, cursor)
		got = append(got, names(b.Items))
		if !b.More {
			break
		}
		cursor = b.Next
	}
	// EggEncoder is on the last two pages: the batch of the second does not
	// report it again.
	if len(got) != 6 || fmt.Sprint(got[4]) != "[Soenneker.GitHub.Artifacts EggEncoder Credfeto.Build.Dotnet.Server]" ||
		strings.Contains(fmt.Sprint(got[5]), "EggEncoder") {
		t.Fatalf("batches %q", got)
	}
	// The same batch asked for again (the engine could not store it) reports
	// its packages again.
	again, err := f.Bootstrap(ctx, cursors[4])
	if err != nil || fmt.Sprint(names(again.Items)) != fmt.Sprint(got[4]) {
		t.Errorf("the batch asked for again: %v (%v)", names(again.Items), err)
	}
	// After a restart the page list comes from Env.Dir; what the process
	// reported before is not known, so EggEncoder is reported again.
	env := f.k.env
	restarted := mustFeed(t, env).(*nugetFeed)
	restarted.pages = 1
	b, err := restarted.Bootstrap(ctx, cursors[5])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(names(b.Items)), "EggEncoder") || b.More {
		t.Errorf("after a restart: %v more=%v", names(b.Items), b.More)
	}
	if n := nugetCountRequests(srv, "/v3/catalog0/index.json"); n != 1 {
		t.Errorf("the catalog index was read %d times", n)
	}
	// A page list that is missing, or does not match the cursor, is not
	// trusted.
	matches, _ := filepath.Glob(filepath.Join(env.Dir, nugetPagesPrefix+"*"))
	if len(matches) != 1 {
		t.Fatalf("page lists %v", matches)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(matches[0], bytes.Replace(data, []byte("page0.json"), []byte("page1.json"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = restarted.Bootstrap(ctx, cursors[3])
	mustErr(t, err, false, true, "does not match")
	os.Remove(matches[0])
	_, err = restarted.Bootstrap(ctx, cursors[3])
	mustErr(t, err, false, true, "not stored")
}

func TestNuGetChangesReadTheNewerPagesInCommitOrder(t *testing.T) {
	f, srv, _ := nugetTestFeed(t, nil)
	nugetServeCatalog(t, srv)
	// The cursor is EggEncoder 4.107.12's commit on page 23567: that page's
	// newer leaves and all of page 23568 follow, sorted by commit, versions
	// as the flat container spells them.
	b, err := f.Changes(context.Background(), nugetCursorAt(f, srv, "2026-11-16T01:19:18.1601316Z"))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "nuget", "changes", nugetView(t, srv, b))
	for _, p := range []string{"/v3/catalog0/page0.json", "/v3/catalog0/page23552.json"} {
		if n := nugetCountRequests(srv, p); n != 0 {
			t.Errorf("%s, committed before the cursor, was read", p)
		}
	}
}

func TestNuGetChangesEndAtACommitBoundary(t *testing.T) {
	ctx := context.Background()
	from := "2026-11-13T00:00:00Z"
	// All at once, for comparison.
	whole, srv0, _ := nugetTestFeed(t, nil)
	nugetServeCatalog(t, srv0)
	all, err := whole.Changes(ctx, nugetCursorAt(whole, srv0, from))
	if err != nil || all.More {
		t.Fatalf("one batch: more=%v %v", all.More, err)
	}

	// One page per batch: page 23552 ends with Soenneker.Flywheel.Memory's
	// commit, which page 23567 might continue, so the first batch ends at the
	// commit before it. A version deleted and pushed again in the batch is
	// reported as pushed.
	f, srv, _ := nugetTestFeed(t, nil)
	f.pages = 1
	nugetServeCatalog(t, srv)
	first, err := f.Changes(ctx, nugetCursorAt(f, srv, from))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "nuget", "changes-boundary", nugetView(t, srv, first))
	if !first.More {
		t.Fatal("a capped batch must ask for more")
	}
	seen := map[string]bool{}
	for _, c := range first.Items {
		seen[c.String()] = true
	}
	cursor := first.Next
	for i := 0; ; i++ {
		b, err := f.Changes(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range b.Items {
			seen[c.String()] = true
		}
		if !b.More {
			var end, whole nugetCursor
			_ = decodeCursor(b.Next, f.format(), &end)
			_ = decodeCursor(all.Next, f.format(), &whole)
			if end.Since == "" || end.Since != whole.Since {
				t.Errorf("the batches end at %q, the whole feed at %q", end.Since, whole.Since)
			}
			break
		}
		if b.Next == cursor || i > 10 {
			t.Fatalf("no progress from %s", cursor)
		}
		cursor = b.Next
	}
	// Nothing is lost; what is delivered twice is harmless.
	for _, c := range all.Items {
		if !c.Deleted && !seen[c.String()] {
			t.Errorf("%s was not delivered in batches", c)
		}
	}
}

func TestNuGetCaughtUpRewoundAndMovedCatalogs(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := nugetTestFeed(t, nil)
	nugetServeCatalog(t, srv)
	head := nugetCursorAt(f, srv, "2026-11-16T02:14:09.8253348Z")
	b, err := f.Changes(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	if b.Next != head || len(b.Items) != 0 || b.More || !b.LagKnown {
		t.Errorf("caught up: %+v", b)
	}
	// A position beyond the catalog's last commit: the catalog was rebuilt.
	_, err = f.Changes(ctx, nugetCursorAt(f, srv, "2026-11-17T00:00:00Z"))
	mustErr(t, err, false, true, "rebuilt or rewound")
	// A catalog at another URL is another catalog.
	_, err = f.Changes(ctx, f.cursor(nugetCursor{Catalog: srv.URL() + "/v3/catalog1/index.json", Since: "2026-11-16T00:00:00Z"}))
	mustErr(t, err, false, true, "catalog is now")
	// Cursors of another adapter or format, and garbage, are not trusted.
	for _, bad := range []string{"", "x", `{"format":"npm/1","since":"1"}`, `{"format":"nuget/1","catalog":"x","since":"yesterday"}`,
		`{"format":"nuget/1","catalog":"x","since":"2026-11-16T00:00:00Z","extra":1}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestNuGetLeavesAreChecked(t *testing.T) {
	srv := newFixtureServer(t)
	f := mustFeed(t, testEnv(t, "nuget", srv.URL(), newFakeReads(), map[string]string{"url": srv.URL() + "/catalog/index.json"})).(*nugetFeed)
	f.now = nugetTestNow
	srv.on("GET", "/catalog/index.json").json(`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[{"@id":"` + srv.URL() + `/catalog/p1.json","commitTimeStamp":"2026-11-16T10:00:00Z"}]}`)
	srv.on("GET", "/catalog/p1.json").json(`{"items":[
		{"@type":"nuget:PackageDetails","nuget:id":"Good.Package","nuget:version":"1.0.0-RC.1+sha.5","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":["PackageDelete","catalog:Permalink"],"nuget:id":"Gone_Package","nuget:version":"2.0.0","commitTimeStamp":"2026-11-16T09:30:00.5Z"},
		{"@type":"nuget:PackageEdit","nuget:id":"Other","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"../etc/passwd","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"a..b","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"` + strings.Repeat("a", 101) + `","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Bad.Version","nuget:version":"1.0/../x","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Bad.Version","nuget:version":"v1.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Bad.Time","nuget:version":"1.0.0","commitTimeStamp":"yesterday"},
		{"@type":"nuget:PackageDetails","nuget:id":"Old","nuget:version":"1.0.0","commitTimeStamp":"2026-11-15T00:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Good.Package","nuget:version":"1.0.0-rc.1","commitTimeStamp":"2026-11-16T09:10:00Z"},
		{"@type":7,"nuget:id":"x","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"}
	]}`)
	b, err := f.Changes(context.Background(), f.cursor(nugetCursor{Catalog: srv.URL() + "/catalog/index.json", Since: "2026-11-16T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	// The version edited twice is reported once; build metadata and case
	// are dropped as the flat container drops them.
	want := []Coordinate{{Name: "Good.Package", Version: "1.0.0-rc.1"}, {Name: "Gone_Package", Version: "2.0.0", Deleted: true}}
	if len(b.Items) != len(want) || b.Items[0] != want[0] || b.Items[1] != want[1] {
		t.Errorf("items %+v, want %+v", b.Items, want)
	}
	if b.More || !b.LagKnown {
		t.Errorf("batch %+v", b)
	}
}

func TestNuGetFeedsWithoutACatalog(t *testing.T) {
	ctx := context.Background()
	// Artifactory's service index names no catalog.
	f, srv, _ := nugetTestFeed(t, nil)
	srv.on("GET", "/v3/index.json").json(`{"version":"3.0.0","resources":[{"@id":"` + srv.URL() + `/api/v3/flat/","@type":"PackageBaseAddress/3.0.0"},{"@id":"` + srv.URL() + `/api/v3/query","@type":["SearchQueryService","SearchQueryService/3.0.0-beta"]}]}`)
	_, err := f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "fullMirror.feed.url")
	// With the option, the service index is not read at all (the server
	// would fail the test on the request).
	srv2 := newFixtureServer(t)
	g := mustFeed(t, testEnv(t, "nuget", srv2.URL(), newFakeReads(), map[string]string{"url": srv2.URL() + "/v3/catalog0/index.json"})).(*nugetFeed)
	g.now = nugetTestNow
	srv2.on("GET", "/v3/catalog0/index.json").reply(200, nugetFixture(t, srv2, "catalog-index.json"))
	b, err := g.Changes(ctx, nugetCursorAt(g, srv2, "2026-11-16T02:14:09.8253348Z"))
	if err != nil || len(b.Items) != 0 || b.More {
		t.Errorf("a fixed catalog: %+v %v", b, err)
	}
}

func TestNuGetMalformedAnswers(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := nugetTestFeed(t, nil)
	srv.on("GET", "/v3/index.json").reply(200, nugetFixture(t, srv, "service-index.json"))
	cursor := nugetCursorAt(f, srv, "2026-11-16T00:00:00Z")
	page := func(n int) string {
		return fmt.Sprintf(`{"@id":"%s/v3/catalog0/page%d.json","commitTimeStamp":"2026-11-16T10:00:00Z"}`, srv.URL(), n)
	}
	for _, tc := range []struct{ index, page, want string }{
		{`not json`, ``, "catalog index"},
		{`{"items":[]}`, ``, "commitTimeStamp"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z"}`, ``, "lists no pages"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[{"@id":"x","commitTimeStamp":"soon"}]}`, ``, "not a time"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[{"@id":"https://elsewhere.example/p.json","commitTimeStamp":"2026-11-16T10:00:00Z"}]}`, ``, "origin"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[` + page(1) + `]}`, `<html>`, "catalog page"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[` + page(1) + `]}`, `{"items":"x"}`, "catalog page"},
		{`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[` + page(1) + `]}`, `{}`, "lists no items"},
	} {
		srv.on("GET", "/v3/catalog0/index.json").json(tc.index)
		srv.on("GET", "/v3/catalog0/page1.json").json(tc.page)
		_, err := f.Changes(ctx, cursor)
		mustErr(t, err, true, false, tc.want)
	}
	// A 5xx is worth retrying; a 429 asks for its wait.
	srv.on("GET", "/v3/catalog0/index.json").reply(http.StatusBadGateway, nil)
	_, err := f.Changes(ctx, cursor)
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/v3/catalog0/index.json").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "30")
	_, err = f.Changes(ctx, cursor)
	if d, ok := RetryAfterOf(err); !ok || d.Seconds() != 30 {
		t.Errorf("Retry-After not carried: %v", err)
	}
	// A service index that is not one.
	g, srv2, _ := nugetTestFeed(t, nil)
	srv2.on("GET", "/v3/index.json").json(`{"resources":"x"}`)
	_, err = g.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "service index")
}

// nugetProxiedIndex is the service index as the gated pipeline serves it: the
// backend substitutes its public base for the upstream's (pkgmgr nuget.go,
// rules {upstreamBase + "/" → publicBase + "/"}).
func nugetProxiedIndex(t *testing.T, upstreamName string) []byte {
	t.Helper()
	return bytes.ReplaceAll(fixture(t, "nuget", "service-index.json"), []byte(nugetPublicOrigin+"/"), []byte("https://proxy.example/v1/"+upstreamName+"/"))
}

func TestNuGetReleasesComeFromTheFlatContainer(t *testing.T) {
	ctx := context.Background()
	f, _, reads := nugetTestFeed(t, nil)
	reads.set("/v3/index.json", nugetProxiedIndex(t, f.k.env.Upstream))
	reads.set("/v3-flatcontainer/newtonsoft.json/index.json", fixture(t, "nuget", "flat-newtonsoft.json"))
	backend, err := pkgmgr.NewNuGet(pkgmgr.Options{Name: f.k.env.Upstream, UpstreamURL: nugetPublicOrigin, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	rels, err := f.Releases(ctx, "Newtonsoft.Json")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "nuget", "releases-newtonsoft-json", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "newtonsoft.json", r.Version })
	// The service index is read once for every package, by the engine's
	// workers at once.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.Releases(ctx, "newtonsoft.json"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n := reads.count("/v3/index.json"); n != 1 {
		t.Errorf("the service index was read %d times", n)
	}
	// An unknown package, a name that is not one, a gate's verdict and an
	// access-control refusal.
	_, err = f.Releases(ctx, "No.Such.Package")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../../etc/passwd")
	mustErr(t, err, true, false, "not a NuGet package id")
	reads.setDoc("/v3-flatcontainer/typo.squat/index.json", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "Typo.Squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/v3-flatcontainer/held/index.json", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "Held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	reads.set("/v3-flatcontainer/broken/index.json", []byte(`{"versions":[1,2]}`))
	_, err = f.Releases(ctx, "Broken")
	mustErr(t, err, true, false, "version list of Broken")

	// A service index whose flat container the proxy does not serve (left
	// on its own host), and one the gate refused.
	g, _, reads2 := nugetTestFeed(t, nil)
	reads2.set("/v3/index.json", fixture(t, "nuget", "service-index.json"))
	_, err = g.Releases(ctx, "Newtonsoft.Json")
	mustErr(t, err, true, false, "package base address")
	h, _, reads3 := nugetTestFeed(t, nil)
	reads3.setDoc("/v3/index.json", fakeDoc{status: 403, gate: "policy", code: "blocked"})
	_, err = h.Releases(ctx, "Newtonsoft.Json")
	mustErr(t, err, true, false, "policy")
}

func TestNuGetTimesAndVersions(t *testing.T) {
	// Catalog timestamps carry a varying number of fractional digits, so
	// they are compared as times, not strings.
	a, _ := nugetTime("2026-11-16T01:12:26.919542Z")
	b, _ := nugetTime("2026-11-16T01:12:26.9195421Z")
	if !a.Before(b) || "2026-11-16T01:12:26.919542Z" < "2026-11-16T01:12:26.9195421Z" {
		t.Errorf("%v %v", a, b)
	}
	for in, want := range map[string]string{"1.0.0": "1.0.0", "6.0.0-Prerelease.1009": "6.0.0-prerelease.1009", "10.0.41851+b333": "10.0.41851", "v1": "", "1.0 beta": "", "": "", "+x": ""} {
		got, ok := nugetVersion(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	ids := map[string]bool{"Newtonsoft.Json": true, "a": true, "_x": true, "A-B.C_D": true, ".x": false, "x.": false, "a..b": false, "a b": false, "a/b": false, "": false}
	for id, want := range ids {
		if nugetValidID(id) != want {
			t.Errorf("%q: valid %v", id, !want)
		}
	}
	sorted := []string{"page2.json", "page10.json", "page1.json"}
	sort.Slice(sorted, func(i, j int) bool { return nugetPageNumber(sorted[i]) < nugetPageNumber(sorted[j]) })
	if fmt.Sprint(sorted) != "[page1.json page2.json page10.json]" || nugetPageNumber("x/index.json") != -1 {
		t.Errorf("page numbers: %v", sorted)
	}
}

func TestNuGetCommitsWaitUntilTheyHaveSettled(t *testing.T) {
	// The flat container lists a version minutes after the catalog commits
	// it: a commit younger than the settle period is not reported yet, and
	// the cursor stays where it was.
	f, srv, _ := nugetTestFeed(t, map[string]string{"url": ""})
	cat := srv.URL() + "/catalog/index.json"
	f.fixed, _ = parseBaseURL("u", cat)
	srv.on("GET", "/catalog/index.json").json(`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[{"@id":"` + srv.URL() + `/catalog/p1.json","commitTimeStamp":"2026-11-16T10:00:00Z"}]}`)
	srv.on("GET", "/catalog/p1.json").json(`{"items":[
		{"@type":"nuget:PackageDetails","nuget:id":"Early","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Late","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T09:55:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"Head","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:00:00Z"}]}`)
	start := f.cursor(nugetCursor{Catalog: cat, Since: "2026-11-16T00:00:00Z"})
	f.now = func() time.Time { return time.Date(2026, 11, 16, 10, 2, 0, 0, time.UTC) } // settle 10m: up to 09:52
	b, err := f.Changes(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 1 || b.Items[0].Name != "Early" || b.More {
		t.Fatalf("only the settled commit is reported: %+v", b)
	}
	var c nugetCursor
	_ = decodeCursor(b.Next, f.format(), &c)
	if c.Since != "2026-11-16T09:00:00Z" {
		t.Errorf("the cursor %s, want the settled commit", c.Since)
	}
	// Nothing settled since the cursor: the cursor stays.
	f.now = func() time.Time { return time.Date(2026, 11, 16, 9, 5, 0, 0, time.UTC) }
	b2, err := f.Changes(context.Background(), b.Next)
	if err != nil || len(b2.Items) != 0 || b2.Next != b.Next {
		t.Fatalf("an unsettled poll: %+v %v", b2, err)
	}
	// Later, the rest has settled.
	f.now = nugetTestNow
	b3, err := f.Changes(context.Background(), b.Next)
	if err != nil || len(b3.Items) != 2 {
		t.Fatalf("the settled rest: %+v %v", b3, err)
	}
	// settle 0 reports everything at once.
	if err := Check(Env{Upstream: "n", Type: "nuget", URL: "https://api.nuget.org", Options: map[string]string{"settle": "0"}}); err != nil {
		t.Errorf("settle 0: %v", err)
	}
	if err := Check(Env{Upstream: "n", Type: "nuget", URL: "https://api.nuget.org", Options: map[string]string{"settle": "soon"}}); err == nil {
		t.Errorf("a bad settle accepted")
	}
}

func TestNuGetLeavesNewerThanTheIndexWaitForTheNextPoll(t *testing.T) {
	// The last page was rewritten after the index was read: a commit (D)
	// newer than the index's last commit, continued on a page the index
	// did not list. It must be reported by the next poll, not lost.
	f, srv, _ := nugetTestFeed(t, nil)
	cat := srv.URL() + "/catalog/index.json"
	f.fixed, _ = parseBaseURL("u", cat)
	srv.on("GET", "/catalog/index.json").once().json(`{"commitTimeStamp":"2026-11-16T10:00:00Z","items":[{"@id":"` + srv.URL() + `/catalog/p1.json","commitTimeStamp":"2026-11-16T10:00:00Z"}]}`)
	srv.on("GET", "/catalog/p1.json").json(`{"items":[
		{"@type":"nuget:PackageDetails","nuget:id":"C","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:00:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"D","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:05:00Z"}]}`)
	b, err := f.Changes(context.Background(), f.cursor(nugetCursor{Catalog: cat, Since: "2026-11-16T09:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(names(b.Items)) != "[C@1.0.0]" {
		t.Fatalf("first poll %v", names(b.Items))
	}
	// The next index lists the page that continues D's commit.
	srv.on("GET", "/catalog/index.json").json(`{"commitTimeStamp":"2026-11-16T10:06:00Z","items":[{"@id":"` + srv.URL() + `/catalog/p1.json","commitTimeStamp":"2026-11-16T10:05:00Z"},{"@id":"` + srv.URL() + `/catalog/p2.json","commitTimeStamp":"2026-11-16T10:06:00Z"}]}`)
	srv.on("GET", "/catalog/p2.json").json(`{"items":[
		{"@type":"nuget:PackageDetails","nuget:id":"D","nuget:version":"2.0.0","commitTimeStamp":"2026-11-16T10:05:00Z"},
		{"@type":"nuget:PackageDetails","nuget:id":"E","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:06:00Z"}]}`)
	b2, err := f.Changes(context.Background(), b.Next)
	if err != nil {
		t.Fatal(err)
	}
	got := fmt.Sprint(names(b2.Items))
	if !strings.Contains(got, "D@1.0.0") || !strings.Contains(got, "D@2.0.0") || !strings.Contains(got, "E@1.0.0") {
		t.Errorf("second poll %s: D's commit and E must be reported", got)
	}
}

func TestNuGetACommitOnTwoPagesIsReportedOnce(t *testing.T) {
	// The catalog's newest commit (D, 10:05) continues from page p1 onto
	// page p2, both stamped with it — NuGet's own catalog writer keeps a
	// commit on one page, but the feed does not rely on that. The commit has
	// settled, so it is reported in full and once: in the batch that reports
	// the older commit before it (C), and in batches of one page, where it
	// comes after C — and polls after it report nothing.
	const index = `{"commitTimeStamp":"2026-11-16T10:05:00Z","items":[` +
		`{"@id":"%[1]s/catalog/p1.json","commitTimeStamp":"2026-11-16T10:05:00Z"},` +
		`{"@id":"%[1]s/catalog/p2.json","commitTimeStamp":"2026-11-16T10:05:00Z"}]}`
	for _, tc := range []struct {
		name    string
		p1      string
		pages   int
		batches string
	}{
		{"after an older commit", `{"@type":"nuget:PackageDetails","nuget:id":"C","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:00:00Z"},`,
			nugetPagesPerBatch, "[[C@1.0.0 D@1.0.0 D@2.0.0]]"},
		{"after an older commit, a page a batch", `{"@type":"nuget:PackageDetails","nuget:id":"C","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:00:00Z"},`,
			1, "[[C@1.0.0] [D@1.0.0 D@2.0.0]]"},
		{"alone", ``, nugetPagesPerBatch, "[[D@1.0.0 D@2.0.0]]"},
		{"alone, a page a batch", ``, 1, "[[D@1.0.0 D@2.0.0]]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f, srv, _ := nugetTestFeed(t, nil)
			f.pages = tc.pages
			cat := srv.URL() + "/catalog/index.json"
			f.fixed, _ = parseBaseURL("u", cat)
			srv.on("GET", "/catalog/index.json").json(fmt.Sprintf(index, srv.URL()))
			srv.on("GET", "/catalog/p1.json").json(`{"items":[` + tc.p1 +
				`{"@type":"nuget:PackageDetails","nuget:id":"D","nuget:version":"1.0.0","commitTimeStamp":"2026-11-16T10:05:00Z"}]}`)
			srv.on("GET", "/catalog/p2.json").json(`{"items":[` +
				`{"@type":"nuget:PackageDetails","nuget:id":"D","nuget:version":"2.0.0","commitTimeStamp":"2026-11-16T10:05:00Z"}]}`)
			cursor := f.cursor(nugetCursor{Catalog: cat, Since: "2026-11-16T09:00:00Z"})
			var batches [][]string
			for i := 0; ; i++ {
				if i == 5 {
					t.Fatalf("no end after %d batches: %v", i, batches)
				}
				b, err := f.Changes(ctx, cursor)
				if err != nil {
					t.Fatal(err)
				}
				batches = append(batches, names(b.Items))
				cursor = b.Next
				if !b.More {
					break
				}
			}
			if got := fmt.Sprint(batches); got != tc.batches {
				t.Errorf("batches %s, want %s", got, tc.batches)
			}
			var c nugetCursor
			if err := decodeCursor(cursor, f.format(), &c); err != nil || c.Since != "2026-11-16T10:05:00Z" {
				t.Errorf("the cursor stands at %q (%v), want D's commit", c.Since, err)
			}
			for i := 0; i < 2; i++ {
				b, err := f.Changes(ctx, cursor)
				if err != nil || len(b.Items) != 0 || b.More || b.Next != cursor {
					t.Fatalf("a poll after the commit: %v more=%v moved=%v (%v)", names(b.Items), b.More, b.Next != cursor, err)
				}
			}
		})
	}
}
