package fullmirror

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// npmTestFeed builds the npm adapter against a fixture server standing in for
// a CouchDB-backed registry (the feed at the upstream's root).
func npmTestFeed(t *testing.T, limit int) (*npmFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "npm", srv.URL(), reads, nil)).(*npmFeed)
	f.limit = limit
	return f, srv, reads
}

func TestNPMFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url  string
		opts map[string]string
		want string
	}{
		{"https://registry.npmjs.org", nil, "https://replicate.npmjs.com"},
		{"https://registry.yarnpkg.com/", nil, "https://replicate.npmjs.com"},
		{"https://couch.internal.example/registry", nil, "https://couch.internal.example/registry"},
		{"https://npm.internal.example", map[string]string{"url": "https://replica.internal.example/"}, "https://replica.internal.example"},
	} {
		f, err := newNPMFeed(Env{Upstream: "n", Type: "npm", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		if got := f.(*npmFeed).feed.String(); got != tc.want {
			t.Errorf("%s: feed %s, want %s", tc.url, got, tc.want)
		}
	}
	for _, opts := range []map[string]string{{"since": "1"}, {"url": "ftp://x"}, {"url": "https://u:p@x"}} {
		if err := Check(Env{Upstream: "n", Type: "npm", URL: "https://registry.npmjs.org", Options: opts}); err == nil {
			t.Errorf("Check accepted options %v", opts)
		}
	}
}

func TestNPMBootstrapListsEveryNameThenFollowsFromTheStart(t *testing.T) {
	f, srv, _ := npmTestFeed(t, 3)
	srv.on("GET", "/").reply(200, fixture(t, "npm", "root.json"))
	srv.on("GET", "/_all_docs?limit=3").reply(200, fixture(t, "npm", "all-docs-first.json"))
	// The second page starts at the last name of the first (startkey is
	// inclusive) and asks for one more.
	srv.on("GET", `/_all_docs?limit=4&startkey="-----hsad-----"`).reply(200, fixture(t, "npm", "all-docs-after-left-pad.json"))
	ctx := context.Background()

	first, err := f.Bootstrap(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "npm", "bootstrap-page-1", viewBatch(t, first))
	if !first.More {
		t.Fatalf("a full page must ask for more")
	}
	// The registry's left-pad page stands in for what follows "-----hsad-----";
	// it is not full (3 rows of 4), so the listing ends there.
	second, err := f.Bootstrap(ctx, first.Next)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "npm", "bootstrap-page-2", viewBatch(t, second))
	if second.More {
		t.Fatalf("the last page asks for more")
	}
	// The listing ends with the change cursor taken when it began.
	var c npmCursor
	if err := decodeCursor(second.Next, f.format(), &c); err != nil || c.Listing || c.Since != "144855492" {
		t.Errorf("final cursor %+v (%v), want the follow cursor at 144855492", c, err)
	}
	// Changes refuses a listing cursor; Bootstrap a follow cursor.
	if _, err := f.Changes(ctx, first.Next); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
	if _, err := f.Bootstrap(ctx, second.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

func TestNPMChangesFollowTheSequence(t *testing.T) {
	f, srv, _ := npmTestFeed(t, 4)
	srv.on("GET", "/").reply(200, fixture(t, "npm", "root.json"))
	srv.on("GET", "/_changes?since=144855486&limit=4").reply(200, fixture(t, "npm", "changes.json"))
	b, err := f.Changes(context.Background(), encodeCursor(&npmCursor{Format: f.format(), Since: "144855486"}))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "npm", "changes", viewBatch(t, b))
	if !b.More {
		t.Errorf("a full page of changes must ask for more")
	}
}

func TestNPMChangesDeletionsAndForeignIDs(t *testing.T) {
	f, srv, _ := npmTestFeed(t, 10)
	srv.on("GET", "/").json(`{"update_seq":20}`)
	srv.on("GET", "/_changes?since=10&limit=10").json(`{"results":[
		{"seq":11,"id":"_design/app","changes":[{"rev":"1-a"}]},
		{"seq":12,"id":"gone-package","changes":[{"rev":"3-b"}],"deleted":true},
		{"seq":13,"id":"@scope/pkg","changes":[{"rev":"1-c"}]},
		{"seq":14,"id":"bad\nname","changes":[{"rev":"1-d"}]},
		{"seq":15,"id":"a/b/c","changes":[{"rev":"1-e"}]}
	],"last_seq":15}`)
	b, err := f.Changes(context.Background(), encodeCursor(&npmCursor{Format: f.format(), Since: "10"}))
	if err != nil {
		t.Fatal(err)
	}
	want := []Coordinate{{Name: "gone-package", Deleted: true}, {Name: "@scope/pkg"}}
	if len(b.Items) != len(want) || b.Items[0] != want[0] || b.Items[1] != want[1] {
		t.Errorf("items %+v, want %+v", b.Items, want)
	}
	if b.More || !b.LagKnown || b.Lag != 5 || b.Head != "20" {
		t.Errorf("batch %+v", b)
	}
}

func TestNPMSequenceResetInvalidatesTheCursor(t *testing.T) {
	// The registry's sequence went back below the stored cursor (npm's 2021
	// reset): the feed answers an empty page for a since beyond its head, so
	// only the root's update_seq tells.
	f, srv, _ := npmTestFeed(t, 4)
	srv.on("GET", "/").reply(200, fixture(t, "npm", "root.json"))
	srv.on("GET", "/_changes").reply(200, fixture(t, "npm", "changes-beyond-head.json"))
	_, err := f.Changes(context.Background(), encodeCursor(&npmCursor{Format: f.format(), Since: "145855492"}))
	mustErr(t, err, false, true, "reset its sequence")

	// A feed whose last_seq goes backwards is no better.
	srv.on("GET", "/").json(`{"update_seq":200}`)
	srv.on("GET", "/_changes").json(`{"results":[],"last_seq":100}`)
	_, err = f.Changes(context.Background(), encodeCursor(&npmCursor{Format: f.format(), Since: "150"}))
	mustErr(t, err, false, true, "went back")
}

func TestNPMMalformedAnswers(t *testing.T) {
	ctx := context.Background()
	f, srv, reads := npmTestFeed(t, 4)
	cur := encodeCursor(&npmCursor{Format: f.format(), Since: "1"})
	for _, tc := range []struct{ root, changes, want string }{
		{`not json`, ``, "not the JSON document"},
		{`{"db_name":"registry"}`, ``, "no update_seq"},
		{`{"update_seq":5}`, `{"results":"x"}`, "change feed"},
		{`{"update_seq":5}`, `{"last_seq":3}`, "no results"},
		{`{"update_seq":5}`, `{"results":[],"last_seq":{"x":1}}`, "not a sequence"},
	} {
		srv.on("GET", "/").json(tc.root)
		srv.on("GET", "/_changes").json(tc.changes)
		_, err := f.Changes(ctx, cur)
		mustErr(t, err, true, false, tc.want)
	}
	// Cursors of another adapter or format, and garbage, are not trusted.
	for _, bad := range []string{"12345", `{"format":"pip/1","since":"1"}`, `{"format":"npm/1","since":"1","extra":1}`, `{"format":"npm/1"}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
	// A 5xx is worth retrying; a 429 asks for its wait.
	srv.on("GET", "/").reply(http.StatusBadGateway, nil)
	_, err := f.Changes(ctx, cur)
	mustErr(t, err, false, false, "502")
	srv.on("GET", "/").reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "120")
	_, err = f.Changes(ctx, cur)
	if d, ok := RetryAfterOf(err); !ok || d.Seconds() != 120 {
		t.Errorf("Retry-After not carried: %v (%v)", err, d)
	}
	// A packument that is not one, and a package the registry does not have.
	reads.set("/broken", []byte(`{"versions":[1,2]}`))
	_, err = f.Releases(ctx, "broken")
	mustErr(t, err, true, false, "packument of broken")
	_, err = f.Releases(ctx, "missing")
	mustErr(t, err, true, false, "not found")
	_, err = f.Releases(ctx, "../etc/passwd")
	mustErr(t, err, true, false, "not an npm package name")
}

func TestNPMReleasesComeFromTheRewrittenPackument(t *testing.T) {
	f, _, reads := npmTestFeed(t, 4)
	reads.set("/left-pad", fixture(t, "npm", "packument-left-pad.json"))
	reads.set("/@types/node", fixture(t, "npm", "packument-types-node.json"))
	ctx := context.Background()
	backend, err := pkgmgr.NewNPM(pkgmgr.Options{Name: f.k.env.Upstream, UpstreamURL: "https://registry.npmjs.org", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"left-pad", "@types/node"} {
		rels, err := f.Releases(ctx, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		checkGolden(t, "npm", "releases-"+strings.NewReplacer("@", "", "/", "-").Replace(name), viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return name, r.Version })
	}
	// Every version is located from one packument read.
	if n := reads.count("/left-pad"); n != 1 {
		t.Errorf("the packument was read %d times", n)
	}
	// A gate's verdict on the packument is final; access control is not a
	// verdict on the package.
	reads.setDoc("/typo-squat", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "typo-squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/held", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
}

// keep the backends import used by expectServed's signature in this file's
// build even when the helper moves.
var _ backends.Backend = nil
