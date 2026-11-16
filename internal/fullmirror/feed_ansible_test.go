package fullmirror

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/ansible"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestAnsibleFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url      string
		settings map[string]string
		opts     map[string]string
		feed     string
		repo     string
	}{
		{"https://galaxy.ansible.com", nil, nil, "https://galaxy.ansible.com", "published"},
		{"https://galaxy.ansible.com/", map[string]string{"repository": "published"}, nil, "https://galaxy.ansible.com", "published"},
		// A pulp_ansible distribution serves the same layout under its URL.
		{"https://pulp.example/pulp_ansible/galaxy/default", map[string]string{"repository": "community"}, nil, "https://pulp.example/pulp_ansible/galaxy/default", "community"},
		// An Artifactory remote of Galaxy, following the Galaxy it proxies.
		{"https://artifactory.example/artifactory/api/ansible/galaxy-remote", nil, map[string]string{"url": "https://galaxy.ansible.com/"}, "https://galaxy.ansible.com", "published"},
	} {
		f, err := newAnsibleFeed(Env{Upstream: "galaxy", Type: "ansible", URL: tc.url, Settings: tc.settings, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		af := f.(*ansibleFeed)
		if got := af.src.feed.String(); got != tc.feed || af.repo != tc.repo || af.src.repo != tc.repo {
			t.Errorf("%s: feed %s repository %s/%s, want %s %s", tc.url, got, af.repo, af.src.repo, tc.feed, tc.repo)
		}
		if af.src.first != ansibleFirstPage || af.src.page != ansiblePage || af.src.overlap != ansibleOverlap || af.src.settle != ansibleDefaultSettle ||
			af.src.maxPage != ansibleMaxPage || af.versionsPage != ansiblePage || af.maxPage != ansibleMaxPage || af.lookback != ansibleLookback {
			t.Errorf("%s: defaults %+v", tc.url, af.src)
		}
	}
	if err := Check(Env{Upstream: "galaxy", Type: "ansible", URL: "https://galaxy.ansible.com", Options: map[string]string{"settle": "0"}}); err != nil {
		t.Errorf("settle 0: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"settle": "later"}, {"settle": "-5m"}, {"url": "ftp://galaxy.example"}, {"url": "https://u:p@galaxy.example"}} {
		if err := Check(Env{Upstream: "galaxy", Type: "ansible", URL: "https://galaxy.ansible.com", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
	for _, repo := range []string{"a/b", "..", "pub lished", "x?y"} {
		if err := Check(Env{Upstream: "galaxy", Type: "ansible", URL: "https://galaxy.ansible.com", Settings: map[string]string{"repository": repo}}); err == nil {
			t.Errorf("repository %q accepted", repo)
		}
	}
}

// ansibleTestFeed builds the adapter against a fixture server standing in for
// Galaxy, with small pages: three versions first, then four, each repeating
// one of the page before.
func ansibleTestFeed(t *testing.T, settings map[string]string) (*ansibleFeed, *fixtureServer) {
	t.Helper()
	srv := newFixtureServer(t)
	env := testEnv(t, "ansible", srv.URL(), newFakeReads(), nil)
	env.Settings = settings
	f := mustFeed(t, env).(*ansibleFeed)
	f.src.first, f.src.page, f.src.overlap = 3, 4, 1
	return f, srv
}

// ansibleSearch is the search's route for a page.
func ansibleSearch(limit, offset int) string {
	return fmt.Sprintf("/api/v3/plugin/ansible/search/collection-versions/?order_by=-pulp_created&distribution_base_path=published&limit=%d&offset=%d", limit, offset)
}

// ansibleIndex is the collection index's route for a page.
func ansibleIndex(limit, offset int) string {
	return fmt.Sprintf("/api/v3/plugin/ansible/content/published/collections/index/?limit=%d&offset=%d", limit, offset)
}

// ansibleView is a batch as the ansible golden files show it: its items
// sorted and whether more follows (the order of a listing batch and its
// cursor are the listing driver's).
type ansibleView struct {
	Items []string `json:"items"`
	More  bool     `json:"more"`
}

func ansibleViewOf(t *testing.T, b Batch) ansibleView {
	t.Helper()
	if err := validateBatch(b); err != nil {
		t.Fatalf("the engine would refuse the batch: %v", err)
	}
	items := names(b.Items)
	sort.Strings(items)
	return ansibleView{Items: items, More: b.More}
}

// The search pages are Galaxy's, recorded at offsets 41 and 43 on 2026-11-16:
// served for the first pages, they are the listing as it stood when the 41
// (or 43) newest versions were not published yet.
func TestAnsibleBootstrapListsEveryCollectionThenFollowsTheNewest(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	f.maxPages = 2
	// When the enumeration begins, the newest version is den_is.tools 26.11.2;
	// the one before it is five hours older.
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset43.json"))
	srv.on("GET", ansibleIndex(4, 0)).reply(200, fixture(t, "ansible", "index-limit4-offset0.json"))
	srv.on("GET", ansibleIndex(4, 3)).reply(200, fixture(t, "ansible", "index-limit4-offset3.json"))
	// The index's last page (it links no next page).
	srv.on("GET", ansibleIndex(4, 6)).reply(200, fixture(t, "ansible", "index-limit4-offset4694.json"))
	// The versions of the day below the mark are remembered: the first page
	// ends within it, the next reaches on.
	srv.on("GET", ansibleSearch(4, 2)).reply(200, fixture(t, "ansible", "search-limit4-offset43.json"))
	ctx := context.Background()
	var views []ansibleView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, ansibleViewOf(t, b))
		cursor = b.Next
		if !b.More {
			break
		}
		if i > 10 {
			t.Fatal("the enumeration does not end")
		}
	}
	checkGolden(t, "ansible", "bootstrap", views)
	var c listingCursor
	if err := decodeCursor(cursor, "ansible/1", &c); err != nil || c.Listing || !c.Mark.Equal(time.Date(2026, 11, 15, 12, 57, 21, 274467000, time.UTC)) {
		t.Errorf("the final cursor %+v (%v): want a follow cursor marked at den_is.tools 26.11.2", c, err)
	}

	// Two versions were published since: the first page holds them and the
	// mark, the second the mark and the day below it, the third versions far
	// below.
	f.maxPages = listingPages
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset41.json"))
	srv.on("GET", ansibleSearch(4, 2)).reply(200, fixture(t, "ansible", "search-limit4-offset43.json"))
	srv.on("GET", ansibleSearch(4, 5)).reply(200, fixture(t, "ansible", "search-limit4-offset54000.json"))
	ch, err := f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "ansible", "changes", ansibleViewOf(t, ch))

	// Nothing new since the mark: the listing is read down to a day below the
	// mark (here three pages of the test's few versions; Galaxy's first page
	// of 50 holds more than a day of them), nothing reported.
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset43.json"))
	before := len(srv.requests())
	quiet, err := f.Changes(ctx, cursor)
	if err != nil || len(quiet.Items) != 0 || quiet.More {
		t.Errorf("a quiet poll: %+v %v", quiet, err)
	}
	if n := len(srv.requests()) - before; n != 3 {
		t.Errorf("a quiet poll made %d requests", n)
	}
	if _, err := f.Bootstrap(ctx, ch.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
	if _, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: c.Mark, Listing: true})); err == nil {
		t.Errorf("Changes accepted a listing cursor")
	}
}

// A version younger than the settle period — its import may still be adding
// versions created before it — is reported by a later pass.
func TestAnsibleHoldsBackUnsettledVersions(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	ctx := context.Background()
	mark := encodeCursor(&listingCursor{Format: "ansible/1", Mark: time.Date(2026, 11, 15, 12, 57, 21, 274467000, time.UTC),
		Seen: listingSeenAt(time.Date(2026, 11, 15, 12, 57, 21, 274467000, time.UTC), "den_is.tools@26.11.2", "ryclarke.home@0.2.2", "ryclarke.home@0.2.0", "ryclarke.home@0.1.0")})
	// Galaxy's clock stands two minutes after plopoyop.kubernetes_apps 13.2.0.
	early := time.Date(2026, 11, 15, 13, 34, 22, 0, time.UTC).Format(http.TimeFormat)
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset41.json")).withHeader("Date", early)
	srv.on("GET", ansibleSearch(4, 2)).reply(200, fixture(t, "ansible", "search-limit4-offset43.json")).withHeader("Date", early)
	srv.on("GET", ansibleSearch(4, 5)).reply(200, fixture(t, "ansible", "search-limit4-offset54000.json")).withHeader("Date", early)
	b, err := f.Changes(ctx, mark)
	if err != nil || len(b.Items) != 0 {
		t.Fatalf("unsettled versions were reported: %v %v", names(b.Items), err)
	}
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset41.json"))
	srv.on("GET", ansibleSearch(4, 2)).reply(200, fixture(t, "ansible", "search-limit4-offset43.json"))
	b, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := ansibleViewOf(t, b).Items; fmt.Sprint(got) != "[plopoyop.kubernetes@11.4.0 plopoyop.kubernetes_apps@13.2.0]" {
		t.Errorf("the settled versions: %v", got)
	}
}

// ansibleTestBackend is the backend the adapter's paths are checked against.
func ansibleTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := ansible.New(ansible.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "https://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnsibleReleasesComeFromTheVersionsList(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	versions := "/api/v3/plugin/ansible/content/published/collections/index/%s/versions/?limit=%d&offset=%d"
	srv.on("GET", fmt.Sprintf(versions, "fjacquet/ppdm", 2, 0)).reply(200, fixture(t, "ansible", "versions-fjacquet-ppdm-limit2-offset0.json"))
	srv.on("GET", fmt.Sprintf(versions, "fjacquet/ppdm", 2, 2)).reply(200, fixture(t, "ansible", "versions-fjacquet-ppdm-limit2-offset2.json"))
	srv.on("GET", fmt.Sprintf(versions, "danmwallace/hermes", 100, 0)).reply(200, fixture(t, "ansible", "versions-danmwallace-hermes-limit100-offset0.json"))
	backend := ansibleTestBackend(t, f.k.env)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		page int
	}{{"fjacquet.ppdm", 2}, {"danmwallace.hermes", 100}} {
		f.versionsPage = tc.page
		rels, err := f.Releases(ctx, tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		checkGolden(t, "ansible", "releases-"+strings.ReplaceAll(tc.name, ".", "-"), viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return tc.name, r.Version })
	}
	// hermes lists 1.3.0 and 1.3.1 between 1.11.0 and 1.10.1: the releases
	// are in SemVer order.
	rels, _ := f.Releases(ctx, "danmwallace.hermes")
	var vs []string
	for _, r := range rels {
		vs = append(vs, r.Version)
	}
	if got := strings.Join(vs, " "); !strings.Contains(got, "1.2.6 1.3.0 1.3.1 1.3.3 1.4.0") || !strings.HasSuffix(got, "1.11.0 1.11.1 1.12.0 1.12.1") {
		t.Errorf("order: %s", got)
	}
	for _, r := range rels {
		if r.Yanked || len(r.Artifacts) != 1 || r.Artifacts[0].Size != 0 || r.Published.IsZero() {
			t.Errorf("%s: %+v", r.Version, r)
		}
	}
}

// The repository setting names the repository the versions are read from and
// the artifacts are fetched from.
func TestAnsibleRepositorySetting(t *testing.T) {
	f, srv := ansibleTestFeed(t, map[string]string{"repository": "validated"})
	srv.on("GET", "/api/v3/plugin/ansible/content/validated/collections/index/fjacquet/ppdm/versions/?limit=2&offset=0").reply(200, fixture(t, "ansible", "versions-fjacquet-ppdm-limit2-offset0.json"))
	srv.on("GET", "/api/v3/plugin/ansible/content/validated/collections/index/fjacquet/ppdm/versions/?limit=2&offset=2").reply(200, fixture(t, "ansible", "versions-fjacquet-ppdm-limit2-offset2.json"))
	f.versionsPage = 2
	rels, err := f.Releases(context.Background(), "fjacquet.ppdm")
	if err != nil || len(rels) != 3 {
		t.Fatalf("%v %v", viewReleases(rels), err)
	}
	for _, r := range rels {
		if p := r.Artifacts[0].Path; !strings.HasPrefix(p, "/api/v3/plugin/ansible/content/validated/collections/artifacts/fjacquet-ppdm-") {
			t.Errorf("%s: %s", r.Version, p)
		}
	}
	expectServed(t, ansibleTestBackend(t, f.k.env), rels, func(r Release, _ Artifact) (string, string) { return "fjacquet.ppdm", r.Version })
	// The search is filtered by the distribution's base path: the repository
	// behind it may be named otherwise.
	srv.on("GET", "/api/v3/plugin/ansible/search/collection-versions/?order_by=-pulp_created&distribution_base_path=validated&limit=3&offset=0").
		reply(200, fixture(t, "ansible", "search-limit3-offset43.json"))
	pg, err := f.src.recent(context.Background(), "")
	if err != nil || len(pg.Items) != 3 {
		t.Errorf("the distribution validated: %+v %v", pg, err)
	}
}

func TestAnsibleMalformedAndRefused(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	ctx := context.Background()
	for _, tc := range []struct{ body, want string }{
		{`<html>cloudflare</html>`, "reading Galaxy's search"},
		{`{"meta":{"count":1},"links":{}}`, "not a search page"},
		{`{"data":[]}`, "not a Galaxy list"},
		{`{"meta":{"count":1},"links":{"next":null},"data":{"x":1}}`, "reading Galaxy's search"},
	} {
		srv.on("GET", ansibleSearch(3, 0)).json(tc.body)
		_, err := f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, tc.want)
	}
	// One bad entry does not fail the page: names and versions the backend
	// does not read, a time that does not.
	entry := func(repo, ns, name, version, created string) string {
		return fmt.Sprintf(`{"repository":{"name":%q},"collection_version":{"namespace":%q,"name":%q,"version":%q,"pulp_created":%q},"is_highest":true}`, repo, ns, name, version, created)
	}
	srv.on("GET", ansibleSearch(3, 0)).json(`{"meta":{"count":9},"links":{"next":null},"data":[` + strings.Join([]string{
		entry("published", "acme", "new", "2.0.0", "2026-11-14T10:00:00.5Z"),
		entry("published", "Acme", "upper", "1.0.0", "2026-11-14T09:58:00Z"),
		entry("published", "acme", "mod", "1.0 0", "2026-11-14T09:57:00Z"),
		entry("published", "acme", "mod", "1.1.0", "yesterday"),
		entry("published", "acme", "old", "1.0.0", "2026-11-01T10:00:00Z"),
	}, ",") + `]}`)
	mark := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: mark}))
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme.new@2.0.0]" {
		t.Errorf("a page with bad entries: %v %v", names(b.Items), err)
	}
	// A page past its bound is refused, not cut.
	f.src.maxPage = 64
	srv.on("GET", ansibleSearch(3, 0)).json(`{"meta":{"count":0},"links":{"next":null},"data":[` + strings.Repeat(" ", 100) + `]}`)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "larger than the adapter reads")
	f.src.maxPage = ansibleMaxPage
	// A registry without the search says what to do.
	srv.on("GET", ansibleSearch(3, 0)).reply(http.StatusNotFound, []byte(`{"detail":"Not found."}`))
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "fullMirror.feed.url")
	srv.on("GET", ansibleSearch(3, 0)).reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "45")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 45*time.Second {
		t.Errorf("a 429: %v", err)
	}
	for _, tok := range []string{"x", "-5", "0", "007", "99999999999"} {
		_, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: mark, Pass: true, Token: tok}))
		mustErr(t, err, false, true, "")
	}

	// Versions lists: garbage, a wrong shape, a collection Galaxy does not
	// have, names the proxy does not serve, a list that does not end.
	versions := "/api/v3/plugin/ansible/content/published/collections/index/acme/%s/versions/"
	srv.on("GET", fmt.Sprintf(versions, "garbage")).json(`<html>`)
	_, err = f.Releases(ctx, "acme.garbage")
	mustErr(t, err, true, false, "versions list of acme.garbage")
	srv.on("GET", fmt.Sprintf(versions, "shape")).json(`{"meta":{"count":1},"links":{"next":null},"data":"1.0.0"}`)
	_, err = f.Releases(ctx, "acme.shape")
	mustErr(t, err, true, false, "versions list of acme.shape")
	srv.on("GET", fmt.Sprintf(versions, "missing")).reply(http.StatusNotFound, []byte(`{"errors":[{"status":"404"}]}`))
	_, err = f.Releases(ctx, "acme.missing")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"Acme.mod", "acme", "acme.mod.x", "acme/mod", "../etc", ""} {
		_, err := f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a Galaxy collection name")
	}
	srv.on("GET", fmt.Sprintf(versions, "endless")).json(`{"meta":{"count":99999},"links":{"next":"/api/next"},"data":[{"version":"1.0.0","created_at":"2026-01-01T00:00:00Z"}]}`)
	f.versionsPage = ansibleMaxVersions / 2
	_, err = f.Releases(ctx, "acme.endless")
	mustErr(t, err, true, false, "runs past")
	// Bad versions are left out; a list with a version repeated across pages
	// lists it once.
	f.versionsPage = 2
	srv.on("GET", fmt.Sprintf(versions, "mixed")+"?limit=2&offset=0").json(`{"meta":{"count":4},"links":{"next":"/n"},"data":[{"version":"2.0.0","created_at":"2026-02-01T00:00:00Z"},{"version":"bad version","created_at":"2026-01-15T00:00:00Z"}]}`)
	srv.on("GET", fmt.Sprintf(versions, "mixed")+"?limit=2&offset=2").json(`{"meta":{"count":4},"links":{"next":null},"data":[{"version":"2.0.0","created_at":"2026-02-01T00:00:00Z"},{"version":"1.0.0","created_at":"not a time"}]}`)
	rels, err := f.Releases(ctx, "acme.mixed")
	if err != nil || len(rels) != 2 || rels[0].Version != "1.0.0" || !rels[0].Published.IsZero() || rels[1].Version != "2.0.0" {
		t.Errorf("mixed: %+v %v", viewReleases(rels), err)
	}
}

// A first page of versions all younger than the settle period is followed by
// the next: Bootstrap's mark is a version that is reported.
func TestAnsibleSkipsUnsettledPages(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	clock := time.Date(2026, 11, 15, 13, 5, 0, 0, time.UTC).Format(http.TimeFormat)
	srv.on("GET", ansibleSearch(3, 0)).reply(200, fixture(t, "ansible", "search-limit3-offset41.json")).withHeader("Date", clock)
	srv.on("GET", ansibleSearch(4, 2)).reply(200, fixture(t, "ansible", "search-limit4-offset43.json")).withHeader("Date", clock)
	pg, err := f.src.recent(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	top, at := newest(pg.Items)
	if !top.Equal(time.Date(2026, 11, 15, 7, 33, 36, 651729000, time.UTC)) || fmt.Sprint(at) != "[ryclarke.home@0.2.2]" || pg.Next != "5" {
		t.Errorf("the first settled page: newest %s %v, next %q", top, at, pg.Next)
	}
}

// ansibleResult is a result of Galaxy's collection-version search.
func ansibleResult(repo, ns, name, version, created string) string {
	return fmt.Sprintf(`{"repository":{"name":%q},"collection_version":{"namespace":%q,"name":%q,"version":%q,"pulp_created":%q}}`, repo, ns, name, version, created)
}

// ansibleResults is a page of Galaxy's collection-version search.
func ansibleResults(count int, more bool, results ...string) string {
	next := "null"
	if more {
		next = `"/next"`
	}
	return fmt.Sprintf(`{"meta":{"count":%d},"links":{"next":%s},"data":[%s]}`, count, next, strings.Join(results, ","))
}

// pulp_ansible serves a distribution's index, versions lists and artifacts
// beneath content/<base path>/, while the repository behind it has a name of
// its own ("community" and "community-repo", as the pulp CLI sets them up):
// the search is filtered by the base path, and takes the repository's
// versions whatever its name. A search that is not filtered (it lists
// several repositories), or lists nothing while the index lists collections,
// is refused rather than followed.
func TestAnsibleSearchFiltersByDistribution(t *testing.T) {
	f, srv := ansibleTestFeed(t, map[string]string{"repository": "community"})
	ctx := context.Background()
	search := "/api/v3/plugin/ansible/search/collection-versions/?order_by=-pulp_created&distribution_base_path=community&limit=3&offset=0"
	srv.on("GET", search).json(ansibleResults(2, false, ansibleResult("community-repo", "acme", "tools", "1.1.0", "2026-11-15T10:00:00Z"),
		ansibleResult("community-repo", "acme", "tools", "1.0.0", "2026-11-01T10:00:00Z")))
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}))
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme.tools@1.1.0]" {
		t.Errorf("the distribution's repository: %v %v", names(b.Items), err)
	}
	// A search that lists several repositories was not filtered.
	srv.on("GET", search).json(ansibleResults(2, false, ansibleResult("community-repo", "acme", "tools", "1.1.0", "2026-11-15T10:00:00Z"),
		ansibleResult("staging", "acme", "staged", "1.0.0", "2026-11-15T09:00:00Z")))
	_, err = f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}))
	mustErr(t, err, true, false, "distribution_base_path")
	// An empty search while the index lists collections: Bootstrap would mark
	// nothing, and every poll would follow nothing.
	srv.on("GET", search).json(ansibleResults(0, false))
	srv.on("GET", "/api/v3/plugin/ansible/content/community/collections/index/?limit=1&offset=0").
		json(`{"meta":{"count":1},"links":{"next":null},"data":[{"namespace":"acme","name":"tools"}]}`)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "distribution_base_path")
	_, err = f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)}))
	mustErr(t, err, true, false, "lists 1 collections")
	// An empty distribution has nothing to follow yet.
	srv.on("GET", "/api/v3/plugin/ansible/content/community/collections/index/?limit=1&offset=0").json(`{"meta":{"count":0},"links":{"next":null},"data":[]}`)
	srv.on("GET", "/api/v3/plugin/ansible/content/community/collections/index/?limit=4&offset=0").json(`{"meta":{"count":0},"links":{"next":null},"data":[]}`)
	boot, err := f.Bootstrap(ctx, "")
	if err != nil || len(boot.Items) != 0 || boot.More {
		t.Errorf("an empty distribution: %+v %v", boot, err)
	}
}

// Galaxy orders its search by when a version's content was created, not by
// when the version was added to the repository (an import queue, an approval,
// a copy of content created earlier): a version added late lies below the
// mark when it shows. The pass reads a day below the mark and reports the
// versions it had not seen there.
func TestAnsibleReportsVersionsAddedLate(t *testing.T) {
	f, srv := ansibleTestFeed(t, nil)
	ctx := context.Background()
	// 10:30 by Galaxy's clock: acme.b 2.0.0 (10:00) is the newest version.
	srv.on("GET", ansibleSearch(3, 0)).json(ansibleResults(99, true, ansibleResult("published", "acme", "b", "2.0.0", "2026-11-15T10:00:00Z"),
		ansibleResult("published", "acme", "old", "1.0.0", "2026-11-01T00:00:00Z"))).withHeader("Date", time.Date(2026, 11, 15, 10, 30, 0, 0, time.UTC).Format(http.TimeFormat))
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "ansible/1", Mark: time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)}))
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme.b@2.0.0]" {
		t.Fatalf("poll 1: %v %v", names(b.Items), err)
	}
	// 11:00: acme.a 1.0.0, whose content was created at 09:45, was added to
	// the repository at 10:50.
	srv.on("GET", ansibleSearch(3, 0)).json(ansibleResults(99, true, ansibleResult("published", "acme", "b", "2.0.0", "2026-11-15T10:00:00Z"),
		ansibleResult("published", "acme", "a", "1.0.0", "2026-11-15T09:45:00Z"), ansibleResult("published", "acme", "old", "1.0.0", "2026-11-01T00:00:00Z"))).
		withHeader("Date", time.Date(2026, 11, 15, 11, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	b, err = f.Changes(ctx, b.Next)
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme.a@1.0.0]" {
		t.Errorf("a version added 65 minutes after its content was created: %v %v", names(b.Items), err)
	}
}
