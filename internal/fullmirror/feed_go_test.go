package fullmirror

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The go fixtures (testdata/feeds/go) were recorded from index.golang.org
// and proxy.golang.org on 2026-11-16: the index's first records
// (index-start.jsonl, limit=3) and the page after them (index-start-2.jsonl,
// limit=2), two consecutive pages from 02:40 UTC (index-recent.jsonl from
// since=2026-11-16T02:40:00Z; index-recent-2.jsonl from the first page's
// last timestamp, which since repeats), the answer to a bad since (bad.txt),
// and the version lists of github.com/google/uuid, github.com/BurntSushi/toml
// and (trimmed) github.com/coreos/etcd.

// goIndexTestNow is the clock the tests run at (the recordings' day).
var goIndexTestNow = time.Date(2026, 11, 16, 3, 0, 0, 0, time.UTC)

// goIndexTestFeed builds the Go adapter against a fixture server standing in
// for an Athens-style proxy (the index at the upstream's /index).
func goIndexTestFeed(t *testing.T, limit int) (*goIndexFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "go", srv.URL(), reads, nil)).(*goIndexFeed)
	f.limit = limit
	f.now = func() time.Time { return goIndexTestNow }
	return f, srv, reads
}

func goIndexTestCursor(f *goIndexFeed, since string, seen ...string) string {
	return encodeCursor(&goIndexCursor{Format: f.format(), Since: since, Seen: seen})
}

func TestGoFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://proxy.golang.org", nil, "https://index.golang.org/index"},
		{"https://proxy.golang.org/", nil, "https://index.golang.org/index"},
		{"https://athens.internal.example", nil, "https://athens.internal.example/index"},
		{"https://athens.internal.example/go/", nil, "https://athens.internal.example/go/index"},
		{"https://goproxy.cn", map[string]string{"url": "https://index.golang.org"}, "https://index.golang.org/index"},
		{"https://artifactory.internal.example/api/go/golang", map[string]string{"url": "https://index.golang.org/index/"}, "https://index.golang.org/index"},
		{"https://nexus.internal.example/repository/go", map[string]string{"url": "https://mirror.internal.example/feed/index"}, "https://mirror.internal.example/feed/index"},
	} {
		f, err := newGoIndexFeed(Env{Upstream: "g", Type: "go", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*goIndexFeed).index.String(); got != tc.want {
			t.Errorf("%s: index %s, want %s", tc.url, got, tc.want)
		}
	}
	// A GOPROXY known to have no index needs the option.
	err := Check(Env{Upstream: "g", Type: "go", URL: "https://goproxy.io"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("goproxy.io without a feed URL: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"url": "ftp://index.golang.org"}, {"url": "https://u:p@index.golang.org"}, {"url": "https://index.golang.org/index?limit=5"}} {
		if err := Check(Env{Upstream: "g", Type: "go", URL: "https://proxy.golang.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestGoBootstrapReplaysTheIndexThenFollowsIt(t *testing.T) {
	f, srv, _ := goIndexTestFeed(t, 3)
	srv.on("GET", "/index?limit=3").reply(200, fixture(t, "go", "index-start.jsonl"))
	srv.on("GET", "/index?limit=3&since=2019-04-10T20:30:31.325463Z").reply(200, fixture(t, "go", "index-start-2.jsonl"))
	ctx := context.Background()
	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// The pseudo-version (golang.org/x/crypto) is not reported; the page is
	// full and the replay goes on.
	checkGolden(t, "go", "bootstrap-page-1", viewBatch(t, first))
	second, err := f.Bootstrap(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	// since repeats mkcert, which the cursor remembers; the other record is
	// a pseudo-version. The page is not full: the replay is over, and its
	// cursor follows the index from there.
	checkGolden(t, "go", "bootstrap-page-2", viewBatch(t, second))
	if len(second.Items) != 0 || second.More {
		t.Errorf("second page %v more=%v", names(second.Items), second.More)
	}
	c, _, err := f.decode(second.Next)
	if err != nil || c.Replay || c.Since != "2019-04-10T20:30:36.555706Z" {
		t.Errorf("follow cursor %+v (%v)", c, err)
	}
	_, err = f.Changes(ctx, first.Next)
	mustErr(t, err, false, true, "continues a replay")
	_, err = f.Bootstrap(ctx, second.Next)
	mustErr(t, err, false, true, "does not continue a replay")
}

func TestGoChangesFollowTheIndex(t *testing.T) {
	f, srv, _ := goIndexTestFeed(t, 20)
	srv.on("GET", "/index?limit=20&since=2026-11-16T02:40:00Z").reply(200, fixture(t, "go", "index-recent.jsonl"))
	srv.on("GET", "/index?limit=20&since=2026-11-16T02:40:18.170947Z").reply(200, fixture(t, "go", "index-recent-2.jsonl"))
	ctx := context.Background()
	b, err := f.Changes(ctx, goIndexTestCursor(f, "2026-11-16T02:40:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	// Pseudo-versions are left out; "+incompatible", pre-releases and paths
	// in any case are kept, each as the index spells it.
	checkGolden(t, "go", "changes-1", viewBatch(t, b))
	// The next page starts with the record read last (since is inclusive):
	// it is not reported twice.
	b2, err := f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "go", "changes-2", viewBatch(t, b2))
	for _, c := range b2.Items {
		if c.String() == "proto.prod.wtf/gen/go/bufbuild/protovalidate/protocolbuffers/go@v1.29.0-20240212214536-30aaac4addc0.7" {
			t.Errorf("the record at the cursor's timestamp was reported again")
		}
	}
	// Nothing newer: the cursor stays and the head is where it stands.
	srv.on("GET", "/index?limit=20&since=2026-11-16T02:40:34.736755Z").reply(200, []byte(`{"Path":"github.com/no42-org/blittermib","Version":"v0.17.16","Timestamp":"2026-11-16T02:40:34.736755Z"}`+"\n"))
	b3, err := f.Changes(ctx, b2.Next)
	if err != nil {
		t.Fatal(err)
	}
	if len(b3.Items) != 0 || b3.Next != b2.Next || b3.More || b3.Head != "2026-11-16T02:40:34.736755Z" || !b3.LagKnown {
		t.Errorf("idle poll %+v", b3)
	}
}

func TestGoFullPageAtOneInstantStepsPastIt(t *testing.T) {
	// Synthetic records in the index's format: three versions at one
	// instant, a page of three.
	f, srv, _ := goIndexTestFeed(t, 3)
	instant := `,"Timestamp":"2026-11-16T02:00:00.5Z"}` + "\n"
	page := `{"Path":"example.com/a","Version":"v1.0.0"` + instant + `{"Path":"example.com/b","Version":"v1.0.0"` + instant + `{"Path":"example.com/c","Version":"v1.0.0"` + instant
	srv.on("GET", "/index?since=2026-11-16T01:00:00Z").reply(200, []byte(page))
	srv.on("GET", "/index?since=2026-11-16T02:00:00.5Z").reply(200, []byte(page))
	srv.on("GET", "/index?since=2026-11-16T02:00:00.500001Z").reply(200, []byte(`{"Path":"example.com/d","Version":"v1.0.0","Timestamp":"2026-11-16T02:00:01Z"}`+"\n"))
	ctx := context.Background()
	b, err := f.Changes(ctx, goIndexTestCursor(f, "2026-11-16T01:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Items) != 3 || !b.More {
		t.Fatalf("first page %v", names(b.Items))
	}
	// The index repeats the instant's records, all reported: the feed steps
	// a microsecond past the instant rather than ask again forever.
	b, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	c, _, _ := f.decode(b.Next)
	if len(b.Items) != 0 || !b.More || c.Since != "2026-11-16T02:00:00.500001Z" || len(c.Seen) != 0 {
		t.Fatalf("stuck page: items %v, cursor %+v", names(b.Items), c)
	}
	b, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(b.Items), " "); got != "example.com/d@v1.0.0" || b.More {
		t.Errorf("after the instant: %s more=%v", got, b.More)
	}
}

func TestGoMalformedIndexPages(t *testing.T) {
	ctx := context.Background()
	f, srv, _ := goIndexTestFeed(t, 3)
	cur := goIndexTestCursor(f, "2026-11-16T02:40:00Z")
	// A GOPROXY without an index (Artifactory, Nexus): permanent, with what
	// to set.
	srv.on("GET", "/index").reply(http.StatusNotFound, []byte("404 page not found\n"))
	_, err := f.Changes(ctx, cur)
	mustErr(t, err, true, false, "fullMirror.feed.url")
	// The index refuses a since it cannot read: a permanent error.
	srv.on("GET", "/index").reply(http.StatusBadRequest, fixture(t, "go", "bad.txt"))
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, true, false, "400")
	// A page none of whose lines is a record.
	srv.on("GET", "/index").reply(200, []byte("<html>\nnot the index\n"))
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, true, false, "none of its 2 lines")
	// Records of another shape are left out; the rest are read.
	srv.on("GET", "/index").reply(200, []byte(`{"Path":"example.com/a","Version":"v1.0.0","Timestamp":"yesterday"}
{"Path":"example.com/b\nx","Version":"v1.0.0","Timestamp":"2026-11-16T02:41:00Z"}
{"Path":"Example.com/c","Version":"v1.0.0","Timestamp":"2026-11-16T02:41:00Z"}
{"Path":"example.com/d","Version":"1.0.0","Timestamp":"2026-11-16T02:41:01Z"}
[1]
{"Path":"example.com/e","Version":"v2.0.0","Timestamp":"2026-11-16T02:41:02Z"}
`))
	b, err := f.Changes(ctx, cur)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(b.Items), " "); got != "example.com/e@v2.0.0" || !b.More {
		t.Errorf("items %s more=%v", got, b.More)
	}
	// An index that ignores since would be read forever: a full page of
	// older records is refused.
	srv.on("GET", "/index").reply(200, fixture(t, "go", "index-start.jsonl"))
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, true, false, "without a record between the since asked for and now")
	// A record dated in the future is left out: the cursor does not follow
	// it there (the next poll would refuse it and replay the index).
	srv.on("GET", "/index").reply(200, []byte(`{"Path":"example.com/f","Version":"v1.0.0","Timestamp":"2026-11-16T02:41:00Z"}
{"Path":"example.com/g","Version":"v1.0.0","Timestamp":"2099-01-01T00:00:00Z"}
`))
	b, err = f.Changes(ctx, cur)
	if err != nil {
		t.Fatal(err)
	}
	if c, _, err := f.decode(b.Next); err != nil || c.Since != "2026-11-16T02:41:00Z" || strings.Join(names(b.Items), " ") != "example.com/f@v1.0.0" {
		t.Errorf("a future record: %v, cursor %+v (%v)", names(b.Items), c, err)
	}
	// A 5xx is retried; a 429 asks for its wait.
	srv.on("GET", "/index").reply(http.StatusBadGateway, nil)
	_, err = f.Changes(ctx, cur)
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/index").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "7")
	_, err = f.Changes(ctx, cur)
	if d, ok := RetryAfterOf(err); !ok || d != 7*time.Second {
		t.Errorf("a 429: %v", err)
	}
	// Cursors of another kind, damaged ones, and one in the future.
	for _, bad := range []string{
		"2026-11-16T02:40:00Z",
		`{"format":"pip/1","mode":"xmlrpc","serial":1}`,
		`{"format":"go/1","since":"2026-11-16T02:40:00Z","extra":1}`,
		`{"format":"go/1","since":"yesterday"}`,
		`{"format":"go/1","seen":["0123456789abcdef"]}`,
		`{"format":"go/1","since":"2026-11-16T02:40:00Z","seen":["../x"]}`,
		`{"format":"go/1","since":"2026-11-18T02:40:00Z"}`,
	} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

func TestGoReleasesComeFromTheVersionList(t *testing.T) {
	f, _, reads := goIndexTestFeed(t, 3)
	reads.set("/github.com/google/uuid/@v/list", fixture(t, "go", "list-uuid.txt"))
	reads.set("/github.com/!burnt!sushi/toml/@v/list", fixture(t, "go", "list-toml.txt"))
	reads.set("/github.com/coreos/etcd/@v/list", fixture(t, "go", "list-etcd.txt"))
	ctx := context.Background()
	backend, err := pkgmgr.NewGoProxy(pkgmgr.Options{Name: f.k.env.Upstream, UpstreamURL: "https://proxy.golang.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ module, escaped, golden string }{
		{"github.com/google/uuid", "github.com/google/uuid", "releases-uuid"},
		{"github.com/BurntSushi/toml", "github.com/!burnt!sushi/toml", "releases-toml"},
		{"github.com/coreos/etcd", "github.com/coreos/etcd", "releases-etcd"},
	} {
		rels, err := f.Releases(ctx, tc.module)
		if err != nil {
			t.Fatalf("%s: %v", tc.module, err)
		}
		checkGolden(t, "go", tc.golden, viewReleases(rels))
		// The backend names a module by its escaped path.
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return tc.escaped, r.Version })
		if n := reads.count("/" + tc.escaped + "/@v/list"); n != 1 {
			t.Errorf("%s: the list was read %d times", tc.module, n)
		}
	}
	// A module without tagged versions has no releases.
	reads.set("/example.com/untagged/@v/list", nil)
	if rels, err := f.Releases(ctx, "example.com/untagged"); err != nil || len(rels) != 0 {
		t.Errorf("an empty list: %v %v", rels, err)
	}
	// A gate's verdict on the list is final; access control is not.
	reads.setDoc("/example.com/flagged/@v/list", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "example.com/flagged")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/example.com/held/@v/list", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "example.com/held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	// Unknown, malformed, not a module path.
	_, err = f.Releases(ctx, "example.com/missing")
	mustErr(t, err, true, false, "not found")
	reads.set("/example.com/garbage/@v/list", []byte("<html>\n<body>\n"))
	_, err = f.Releases(ctx, "example.com/garbage")
	mustErr(t, err, true, false, "none of its 2 lines")
	for _, bad := range []string{"../etc/passwd", "Example.com/x", "example.com/a!b", "example.com//x", "example.com/ü", "nodot/x", ""} {
		_, err = f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a module path")
	}
}

func TestGoAnnouncedVersionsOutrunAStaleList(t *testing.T) {
	// The index announces a version the module's @v/list does not show yet
	// (synthetic record): Releases lists it, so the engine does not find it
	// gone.
	f, srv, reads := goIndexTestFeed(t, 3)
	srv.on("GET", "/index").reply(200, []byte(`{"Path":"github.com/google/uuid","Version":"v1.7.0","Timestamp":"2026-11-16T02:50:00Z"}`+"\n"))
	reads.set("/github.com/google/uuid/@v/list", fixture(t, "go", "list-uuid.txt"))
	ctx := context.Background()
	b, err := f.Changes(ctx, goIndexTestCursor(f, "2026-11-16T02:40:00Z"))
	if err != nil || len(b.Items) != 1 {
		t.Fatalf("%v %v", b.Items, err)
	}
	rels, err := f.Releases(ctx, "github.com/google/uuid")
	if err != nil {
		t.Fatal(err)
	}
	if !hasVersion(rels, "v1.7.0") || !hasVersion(rels, "v1.6.0") || rels[len(rels)-1].Version != "v1.7.0" {
		t.Errorf("releases %v", viewReleases(rels))
	}
	// Two batches later it is the list's to say.
	srv.on("GET", "/index").reply(200, nil)
	for i := 0; i < 2; i++ {
		if _, err := f.Changes(ctx, b.Next); err != nil {
			t.Fatal(err)
		}
	}
	if rels, _ := f.Releases(ctx, "github.com/google/uuid"); hasVersion(rels, "v1.7.0") {
		t.Errorf("an announcement is kept beyond two batches")
	}
}

func TestGoVersionListParsing(t *testing.T) {
	got, err := goIndexParseList([]byte("v1.0.0\nv1.0.0\n\nv0.0.0-20190404164418-38d8ce5564a5\nv2.0.0+incompatible 2026-01-01T00:00:00Z\nv1.1.0-rc.1\nnot-a-version\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != "v1.0.0 v2.0.0+incompatible v1.1.0-rc.1" {
		t.Errorf("versions %v", got)
	}
	if got, err := goIndexParseList([]byte("v0.0.0-20190404164418-38d8ce5564a5\n")); err != nil || len(got) != 0 {
		t.Errorf("a list of pseudo-versions only: %v %v", got, err)
	}
}

func TestGoAnnouncedVersionsSurviveARestart(t *testing.T) {
	// The engine resumes a stored batch after a restart before it polls
	// again: a version the index announced, which @v/list does not list yet,
	// must still be among the module's releases.
	dir := t.TempDir()
	reads := newFakeReads()
	env := testEnv(t, "go", "https://proxy.golang.org", reads, nil)
	env.Dir = dir
	f := mustFeed(t, env).(*goIndexFeed)
	f.remember([]Coordinate{{Name: "github.com/jrmarcco/herdr-chat", Version: "v1.0.2"}})
	// A new process: a fresh adapter over the same directory.
	g := mustFeed(t, env).(*goIndexFeed)
	reads.set("/github.com/jrmarcco/herdr-chat/@v/list", []byte("v1.0.0\nv1.0.1\n"))
	rels, err := g.Releases(context.Background(), "github.com/jrmarcco/herdr-chat")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rels {
		got = append(got, r.Version)
	}
	if strings.Join(got, " ") != "v1.0.0 v1.0.1 v1.0.2" {
		t.Errorf("releases after a restart %v", got)
	}
	// A damaged file is no worse than none.
	os.WriteFile(filepath.Join(dir, goIndexAnnounced), []byte(`{"recent":{"../x":["v1"]},"older":{"github.com/a/b":["v1.0.0/../x"]}`), 0o600)
	h := mustFeed(t, env).(*goIndexFeed)
	if got := h.announced("../x"); len(got) != 0 {
		t.Errorf("a damaged file was trusted: %v", got)
	}
}
