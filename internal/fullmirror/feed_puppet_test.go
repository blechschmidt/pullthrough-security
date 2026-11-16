package fullmirror

import (
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
	"github.com/blechschmidt/pullthrough-security/internal/backends/puppet"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestPuppetFeedLocation(t *testing.T) {
	for _, tc := range []struct {
		url    string
		opts   map[string]string
		want   string
		settle time.Duration
	}{
		{"https://forgeapi.puppet.com", nil, "https://forgeapi.puppet.com", puppetDefaultSettle},
		{"https://forge.puppet.com/", nil, "https://forgeapi.puppet.com", puppetDefaultSettle},
		{"https://forgeapi.puppetlabs.com", nil, "https://forgeapi.puppet.com", puppetDefaultSettle},
		// An Artifactory remote of the Forge, following the Forge it mirrors:
		// the module documents come through Artifactory's cache.
		{"https://artifactory.example/artifactory/api/puppet/forge-remote", map[string]string{"url": "https://forgeapi.puppet.com/"}, "https://forgeapi.puppet.com", puppetIntermediarySettle},
		{"https://artifactory.example/artifactory/api/puppet/forge-remote", map[string]string{"url": "https://forgeapi.puppet.com/", "settle": "2h"}, "https://forgeapi.puppet.com", 2 * time.Hour},
		// A server that lists releases by date itself.
		{"https://forge.internal.example", map[string]string{"url": "https://forge.internal.example"}, "https://forge.internal.example", puppetDefaultSettle},
	} {
		f, err := newPuppetFeed(Env{Upstream: "forge", Type: "puppet", URL: tc.url, Options: tc.opts})
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		pf := f.(*puppetFeed)
		if got := pf.src.feed.String(); got != tc.want {
			t.Errorf("%s: feed %s, want %s", tc.url, got, tc.want)
		}
		if pf.src.first != puppetFirstPage || pf.src.page != puppetPage || pf.src.overlap != puppetOverlap || pf.src.maxListing != puppetMaxListing ||
			pf.maxModule != puppetMaxModule || pf.src.settle != tc.settle || pf.lookback != puppetLookback {
			t.Errorf("%s: defaults %+v %d %s", tc.url, pf.src, pf.maxModule, pf.lookback)
		}
	}
	// Anything but the Forge is refused at load time, saying what to set.
	err := Check(Env{Upstream: "art", Type: "puppet", URL: "https://artifactory.example/artifactory/api/puppet/puppet-local"})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("a private upstream without a feed URL: %v", err)
	}
	if err := Check(Env{Upstream: "forge", Type: "puppet", URL: "https://forgeapi.puppet.com", Options: map[string]string{"settle": "2h"}}); err != nil {
		t.Errorf("settle 2h: %v", err)
	}
	for _, opts := range []map[string]string{{"since": "x"}, {"settle": "soon"}, {"settle": "-1m"}, {"url": "ftp://forge.example"}, {"url": "https://u:p@forge.example"}, {"url": "https://forge.example/?x=1"}} {
		if err := Check(Env{Upstream: "forge", Type: "puppet", URL: "https://forgeapi.puppet.com", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// puppetTestFeed builds the adapter against a fixture server standing in for
// the Forge (given as the feed option url), with small pages: three releases
// first, then four, each repeating one of the page before.
func puppetTestFeed(t *testing.T) (*puppetFeed, *fixtureServer, *fakeReads) {
	t.Helper()
	srv := newFixtureServer(t)
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "puppet", "https://forgeapi.puppet.com", reads, map[string]string{"url": srv.URL()})).(*puppetFeed)
	f.src.first, f.src.page, f.src.overlap = 3, 4, 1
	return f, srv, reads
}

// puppetByDate is the newest-first listing's route for a page.
func puppetByDate(limit, offset int) string {
	return fmt.Sprintf("/v3/releases?sort_by=release_date&limit=%d&offset=%d&with_html=false&exclude_fields=%s", limit, offset, url.QueryEscape(puppetExcluded))
}

// puppetByModule is the by-module listing's route for a page.
func puppetByModule(limit, offset int) string {
	return fmt.Sprintf("/v3/releases?sort_by=module&limit=%d&offset=%d&with_html=false&exclude_fields=%s", limit, offset, url.QueryEscape(puppetExcluded))
}

// puppetView is a batch as the puppet golden files show it: its items sorted
// and whether more follows. The order of a listing batch and its cursor are
// the listing driver's (listfeed.go), not the adapter's.
type puppetView struct {
	Items []string `json:"items"`
	More  bool     `json:"more"`
}

func puppetViewOf(t *testing.T, b Batch) puppetView {
	t.Helper()
	if err := validateBatch(b); err != nil {
		t.Fatalf("the engine would refuse the batch: %v", err)
	}
	items := names(b.Items)
	sort.Strings(items)
	return puppetView{Items: items, More: b.More}
}

func TestPuppetBootstrapListsEveryModuleThenFollowsTheNewest(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	f.maxPages = 2
	// When the enumeration begins, the newest release is treydock-root 8.0.0
	// (the live listing's fourth, recorded at offset 3); the one before it is
	// 17 hours older.
	srv.on("GET", puppetByDate(3, 0)).reply(200, fixture(t, "puppet", "releases-by-date-limit3-offset3.json"))
	for _, off := range []int{0, 3, 6, 9} {
		srv.on("GET", puppetByModule(4, off)).reply(200, fixture(t, "puppet", fmt.Sprintf("releases-by-module-limit4-offset%d.json", off)))
	}
	// The listing's last page (it states no next page).
	srv.on("GET", puppetByModule(4, 12)).reply(200, fixture(t, "puppet", "releases-by-module-limit4-offset54826.json"))
	// The releases of the day below the mark are remembered: the first page
	// ends within it, the next holds older releases.
	srv.on("GET", puppetByDate(4, 2)).reply(200, fixture(t, "puppet", "releases-by-module-limit4-offset54826.json"))
	ctx := context.Background()
	var views []puppetView
	cursor := ""
	for i := 0; ; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		views = append(views, puppetViewOf(t, b))
		if i == 0 {
			if _, err := f.Changes(ctx, b.Next); err == nil {
				t.Errorf("Changes accepted a listing cursor")
			}
		}
		cursor = b.Next
		if !b.More {
			break
		}
		if i > 10 {
			t.Fatal("the enumeration does not end")
		}
	}
	checkGolden(t, "puppet", "bootstrap", views)
	if len(views) != 3 {
		t.Errorf("%d Bootstrap batches, want 3 (two pages each)", len(views))
	}
	var c listingCursor
	if err := decodeCursor(cursor, "puppet/1", &c); err != nil || c.Listing || !c.Mark.Equal(time.Date(2026, 11, 15, 14, 20, 55, 0, time.UTC)) {
		t.Errorf("the final cursor %+v (%v): want a follow cursor marked at treydock-root's release", c, err)
	}

	// Three releases were published since: the first page of the pass holds
	// them, the second the mark and the day below it, the third releases far
	// below.
	f.maxPages = listingPages
	srv.on("GET", puppetByDate(3, 0)).reply(200, fixture(t, "puppet", "releases-by-date-limit3-offset0.json"))
	srv.on("GET", puppetByDate(4, 2)).reply(200, fixture(t, "puppet", "releases-by-date-limit4-offset2.json"))
	srv.on("GET", puppetByDate(4, 5)).reply(200, fixture(t, "puppet", "releases-by-module-limit4-offset54826.json"))
	ch, err := f.Changes(ctx, cursor)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "puppet", "changes", puppetViewOf(t, ch))
	for _, it := range ch.Items {
		if it.Version != "" {
			t.Errorf("%s: changes name modules alone", it)
		}
	}
	// A quiet poll reads the listing down to a day below the mark (here two
	// pages of the test's few releases; the Forge's first page of 25 holds two
	// days of them) and reports nothing.
	before := len(srv.requests())
	quiet, err := f.Changes(ctx, ch.Next)
	if err != nil || len(quiet.Items) != 0 || quiet.More {
		t.Errorf("a quiet poll: %+v %v", quiet, err)
	}
	if n := len(srv.requests()) - before; n != 2 {
		t.Errorf("a quiet poll made %d requests", n)
	}
	if _, err := f.Bootstrap(ctx, ch.Next); err == nil {
		t.Errorf("Bootstrap accepted a follow cursor")
	}
}

// A release younger than the settle period is reported by a later pass, once
// the module document the CDN serves lists it.
func TestPuppetHoldsBackUnsettledReleases(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	ctx := context.Background()
	mark := encodeCursor(&listingCursor{Format: "puppet/1", Mark: time.Date(2026, 11, 15, 14, 20, 55, 0, time.UTC),
		Seen: listingSeenAt(time.Date(2026, 11, 15, 14, 20, 55, 0, time.UTC), "treydock-root-8.0.0", "treydock-yum_cron-10.0.0", "waveclaw-subscription_manager-5.8.0")})
	// The Forge's clock stands half an hour after albatrossflavour-soundwave
	// 0.2.0 was published.
	early := time.Date(2026, 11, 16, 2, 52, 48, 0, time.UTC).Format(http.TimeFormat)
	srv.on("GET", puppetByDate(3, 0)).reply(200, fixture(t, "puppet", "releases-by-date-limit3-offset0.json")).withHeader("Date", early)
	srv.on("GET", puppetByDate(4, 2)).reply(200, fixture(t, "puppet", "releases-by-date-limit4-offset2.json")).withHeader("Date", early)
	srv.on("GET", puppetByDate(4, 5)).reply(200, fixture(t, "puppet", "releases-by-module-limit4-offset54826.json")).withHeader("Date", early)
	b, err := f.Changes(ctx, mark)
	if err != nil {
		t.Fatal(err)
	}
	if got := puppetViewOf(t, b).Items; fmt.Sprint(got) != "[jdowning-rbenv treydock-slurm]" {
		t.Errorf("an unsettled release was reported: %v", got)
	}
	// An hour later it is.
	srv.on("GET", puppetByDate(3, 0)).reply(200, fixture(t, "puppet", "releases-by-date-limit3-offset0.json"))
	srv.on("GET", puppetByDate(4, 2)).reply(200, fixture(t, "puppet", "releases-by-date-limit4-offset2.json"))
	b, err = f.Changes(ctx, b.Next)
	if err != nil {
		t.Fatal(err)
	}
	if got := puppetViewOf(t, b).Items; fmt.Sprint(got) != "[albatrossflavour-soundwave]" {
		t.Errorf("the settled release: %v", got)
	}
}

// puppetServed serves recorded module documents through the real puppet
// backend — what the gated pipeline hands the adapter — into a fake pipeline.
func puppetServed(t *testing.T, upstreamName string, docs map[string][]byte) *fakeReads {
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
	b, err := puppet.New(puppet.Options{Name: upstreamName, UpstreamURL: srv.URL, PublicBaseURL: "https://proxy.example/v1/" + upstreamName,
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

// puppetTestBackend is the backend the adapter's paths are checked against.
func puppetTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := puppet.New(puppet.Options{Name: env.Upstream, UpstreamURL: env.URL, PublicBaseURL: "https://proxy.example/v1/" + env.Upstream,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPuppetReleasesComeFromTheModuleDocument(t *testing.T) {
	modules := []string{"albatrossflavour-soundwave", "pepabo-tcpdp", "puppetlabs-cem_linux"}
	docs := map[string][]byte{}
	for _, m := range modules {
		docs["/v3/modules/"+m] = fixture(t, "puppet", "module-"+m+".json")
	}
	env := testEnv(t, "puppet", "https://forgeapi.puppet.com", nil, nil)
	env.Read = puppetServed(t, env.Upstream, docs).read
	f := mustFeed(t, env).(*puppetFeed)
	backend := puppetTestBackend(t, env)
	ctx := context.Background()
	for _, m := range []string{"albatrossflavour-soundwave", "pepabo-tcpdp"} {
		rels, err := f.Releases(ctx, m)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		checkGolden(t, "puppet", "releases-"+m, viewReleases(rels))
		expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return m, r.Version })
	}
	// A premium module's tarballs answer 401 without a Forge entitlement: it
	// is followed only when the upstream carries credentials.
	if rels, err := f.Releases(ctx, "puppetlabs-cem_linux"); err != nil || len(rels) != 0 {
		t.Errorf("a premium module without credentials: %v %v", viewReleases(rels), err)
	}
	f.k.env.Authorize = func(r *http.Request) { r.Header.Set("Authorization", "Bearer forge-key") }
	rels, err := f.Releases(ctx, "puppetlabs-cem_linux")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "puppet", "releases-puppetlabs-cem_linux", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "puppetlabs-cem_linux", r.Version })
}

func TestPuppetModuleDocumentEdgeCases(t *testing.T) {
	reads := newFakeReads()
	f := mustFeed(t, testEnv(t, "puppet", "https://forgeapi.puppet.com", reads, nil)).(*puppetFeed)
	ctx := context.Background()
	release := func(version, created, deleted, fileURI string) string {
		return fmt.Sprintf(`{"uri":"/v3/releases/acme-mod-%[1]s","slug":"acme-mod-%[1]s","version":%[1]q,"supported":false,"created_at":%[2]q,"deleted_at":%[3]s,"file_uri":%[4]q,"file_size":1234}`,
			version, created, deleted, fileURI)
	}
	// Versions out of order, a duplicate, a version no path carries, a file
	// another release's name, a release without a time: the document is read
	// in SemVer order, what cannot be served left out.
	reads.set("/v3/modules/acme-mod", []byte(`{"slug":"acme-mod","premium":false,"login_required":false,"current_release":null,"releases":[`+
		strings.Join([]string{
			release("1.10.0", "2026-01-05 10:00:00 +0100", "null", "/v3/files/acme-mod-1.10.0.tar.gz"),
			release("1.2.0", "2026-01-03 10:00:00 +0100", "null", "/v3/files/acme-mod-1.2.0.tar.gz"),
			release("1.2.0", "2026-01-03 10:00:00 +0100", "null", "/v3/files/acme-mod-1.2.0.tar.gz"),
			release("2.0.0-rc.1", "bad time", `"2026-01-06 10:00:00 +0100"`, "/v3/files/acme-mod-2.0.0-rc.1.tar.gz"),
			release("1.9.0", "2026-01-04 10:00:00 +0100", "null", "/v3/files/other-mod-1.9.0.tar.gz"),
			release("1.0/0", "2026-01-01 10:00:00 +0100", "null", "/v3/files/acme-mod-1.0.tar.gz"),
			release("1.0.0", "2026-01-01 10:00:00 +0100", "null", ""),
		}, ",")+`]}`))
	rels, err := f.Releases(ctx, "acme-mod")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rels {
		got = append(got, fmt.Sprintf("%s/%v/%s", r.Version, r.Yanked, r.Published.Format(time.RFC3339)))
	}
	if want := "[1.0.0/false/2026-01-01T09:00:00Z 1.2.0/false/2026-01-03T09:00:00Z 1.10.0/false/2026-01-05T09:00:00Z 2.0.0-rc.1/true/0001-01-01T00:00:00Z]"; fmt.Sprint(got) != want {
		t.Errorf("releases %v, want %s", got, want)
	}

	for name, tc := range map[string]struct{ body, want string }{
		"garbage":  {"<html>busy</html>", "module document of acme-garbage"},
		"shape":    {`{"slug":"acme-shape","releases":{"1.0.0":{}}}`, "module document of acme-shape"},
		"noslug":   {`{"releases":[]}`, "not a module document"},
		"norel":    {`{"slug":"acme-norel"}`, "not a module document"},
		"another":  {`{"slug":"acme-other","releases":[]}`, `describes "acme-other"`},
		"toolarge": {`{"slug":"acme-toolarge","releases":[` + strings.Repeat(release("1.0.0", "", "null", "")+",", 50) + release("1.0.0", "", "null", "") + `]}`, "larger than the adapter reads"},
	} {
		mod := "acme-" + name
		reads.set("/v3/modules/"+mod, []byte(tc.body))
		if name == "toolarge" {
			f.maxModule = 4096
		}
		_, err := f.Releases(ctx, mod)
		f.maxModule = puppetMaxModule
		mustErr(t, err, true, false, tc.want)
	}
	_, err = f.Releases(ctx, "acme-missing")
	mustErr(t, err, true, false, "not found")
	for _, bad := range []string{"Slashbunny-phpfpm", "acme/mod", "acme", "acme-mod/../x", ""} {
		_, err := f.Releases(ctx, bad)
		mustErr(t, err, true, false, "not a Forge module slug")
	}
	// A gate's verdict on the document is final; access control is no verdict
	// on the module.
	reads.setDoc("/v3/modules/acme-typo", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "acme-typo")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/v3/modules/acme-held", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "acme-held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
}

func TestPuppetMalformedListings(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	ctx := context.Background()
	for _, tc := range []struct{ body, want string }{
		{`<html>maintenance</html>`, "listing the Forge's releases"},
		{`{"results":[]}`, "not a release listing"},
		{`{"pagination":{"total":1}}`, "not a release listing"},
		{`{"pagination":{},"results":{"a":1}}`, "listing the Forge's releases"},
	} {
		srv.on("GET", puppetByDate(3, 0)).json(tc.body)
		_, err := f.Bootstrap(ctx, "")
		mustErr(t, err, true, false, tc.want)
	}
	// One bad entry does not fail the page: a module slug the backend does
	// not read, a slug that is not its module's, a version no path carries,
	// an unreadable time.
	item := func(slug, module, version, created string) string {
		return fmt.Sprintf(`{"slug":%q,"module":{"slug":%q},"version":%q,"created_at":%q}`, slug, module, version, created)
	}
	srv.on("GET", puppetByDate(3, 0)).json(`{"pagination":{"total":9,"next":null},"results":[` + strings.Join([]string{
		item("acme-new-2.0.0", "acme-new", "2.0.0", "2026-11-14 10:00:00 +0000"),
		item("Upper-mod-1.0.0", "Upper-mod", "1.0.0", "2026-11-14 09:59:00 +0000"),
		item("acme-other-1.0.0", "acme-mod", "1.0.0", "2026-11-14 09:58:00 +0000"),
		item("acme-mod-1.0 0", "acme-mod", "1.0 0", "2026-11-14 09:57:00 +0000"),
		item("acme-mod-1.1.0", "acme-mod", "1.1.0", "yesterday"),
		item("acme-old-1.0.0", "acme-old", "1.0.0", "2026-11-01 10:00:00 +0000"),
	}, ",") + `]}`)
	mark := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "puppet/1", Mark: mark}))
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme-new]" {
		t.Errorf("a page with bad entries: %v %v", names(b.Items), err)
	}
	// A page past its bound is refused, not cut.
	f.src.maxListing = 64
	srv.on("GET", puppetByDate(3, 0)).json(`{"pagination":{"total":0,"next":null},"results":[` + strings.Repeat(" ", 100) + `]}`)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, true, false, "larger than the adapter reads")
	f.src.maxListing = puppetMaxListing
	// A 5xx is retried; a 429 asks for its wait.
	srv.on("GET", puppetByDate(3, 0)).reply(http.StatusBadGateway, nil)
	_, err = f.Bootstrap(ctx, "")
	mustErr(t, err, false, false, "502")
	srv.on("GET", puppetByDate(3, 0)).reply(http.StatusTooManyRequests, nil).withHeader("Retry-After", "30")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 30*time.Second {
		t.Errorf("a 429: %v", err)
	}
	// Tokens the listing never hands out are not followed.
	for _, tok := range []string{"x", "-5", "0", "007", "99999999999"} {
		_, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "puppet/1", Mark: mark, Pass: true, Token: tok}))
		mustErr(t, err, false, true, "")
	}
	for _, bad := range []string{"", "{}", `{"format":"dart/1","mark":"2026-01-01T00:00:00Z"}`, `{"format":"puppet/1","mark":"2026-01-01T00:00:00Z","extra":1}`} {
		_, err := f.Changes(ctx, bad)
		mustErr(t, err, false, true, "")
	}
}

// A page that ends short of its limit while the listing says there is more
// moves on by what it held; a page of nothing ends the pass.
func TestPuppetListingPagesAlwaysAdvance(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	item := `{"slug":"acme-mod-1.0.0","module":{"slug":"acme-mod"},"version":"1.0.0","created_at":"2026-11-14 10:00:00 +0000"}`
	srv.on("GET", puppetByModule(4, 0)).json(`{"pagination":{"total":50,"next":"/v3/releases?offset=4"},"results":[` + item + `]}`)
	srv.on("GET", puppetByModule(4, 1)).json(`{"pagination":{"total":50,"next":"/v3/releases?offset=5"},"results":[]}`)
	srv.on("GET", puppetByDate(3, 0)).json(`{"pagination":{"total":50,"next":null},"results":[` + item + `]}`)
	var all []string
	cursor := ""
	for i := 0; i < 5; i++ {
		b, err := f.Bootstrap(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, names(b.Items)...)
		cursor = b.Next
		if !b.More {
			break
		}
	}
	if fmt.Sprint(all) != "[acme-mod]" {
		t.Errorf("listed %v", all)
	}
	if reqs := strings.Join(srv.requests(), "\n"); !strings.Contains(reqs, "offset=1&") || strings.Contains(reqs, "offset=2&") {
		t.Errorf("requests:\n%s", reqs)
	}
}

// A first page of releases all younger than the settle period is followed by
// the next: Bootstrap's mark is a release that is reported.
func TestPuppetSkipsUnsettledPages(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	// The Forge's clock stands half an hour after treydock-slurm 7.1.1:
	// every release of the first page, and the first two of the second, are
	// younger than an hour.
	clock := time.Date(2026, 11, 15, 15, 18, 9, 0, time.UTC).Format(http.TimeFormat)
	srv.on("GET", puppetByDate(3, 0)).reply(200, fixture(t, "puppet", "releases-by-date-limit3-offset0.json")).withHeader("Date", clock)
	srv.on("GET", puppetByDate(4, 2)).reply(200, fixture(t, "puppet", "releases-by-date-limit4-offset2.json")).withHeader("Date", clock)
	pg, err := f.src.recent(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	top, at := newest(pg.Items)
	if !top.Equal(time.Date(2026, 11, 14, 21, 35, 2, 0, time.UTC)) || fmt.Sprint(at) != "[treydock-yum_cron-10.0.0]" || pg.Next != "5" {
		t.Errorf("the first settled page: newest %s %v, next %q", top, at, pg.Next)
	}
}

// A release the Forge lists later than its time says (an upload it processes
// first) lies below the mark when it shows: the pass looks a day below the
// mark for releases it has not seen.
func TestPuppetReportsReleasesListedLate(t *testing.T) {
	f, srv, _ := puppetTestFeed(t)
	ctx := context.Background()
	release := func(module, version, created string) string {
		return fmt.Sprintf(`{"slug":"%[1]s-%[2]s","version":%[2]q,"module":{"slug":%[1]q},"created_at":%[3]q}`, module, version, created)
	}
	page := func(releases ...string) string {
		return `{"pagination":{"total":99,"next":null},"results":[` + strings.Join(releases, ",") + `]}`
	}
	// 12:00 by the Forge's clock: acme-b 2.0.0 (09:00) is the newest release.
	srv.on("GET", puppetByDate(3, 0)).json(page(release("acme-b", "2.0.0", "2026-11-15 01:00:00 -0800"), release("acme-old", "1.0.0", "2026-11-01 00:00:00 -0800"))).
		withHeader("Date", time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	b, err := f.Changes(ctx, encodeCursor(&listingCursor{Format: "puppet/1", Mark: time.Date(2026, 11, 15, 6, 0, 0, 0, time.UTC)}))
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme-b]" {
		t.Fatalf("poll 1: %v %v", names(b.Items), err)
	}
	// 13:00: acme-a 1.0.0, created at 08:30, shows only now.
	srv.on("GET", puppetByDate(3, 0)).json(page(release("acme-b", "2.0.0", "2026-11-15 01:00:00 -0800"), release("acme-a", "1.0.0", "2026-11-15 00:30:00 -0800"),
		release("acme-old", "1.0.0", "2026-11-01 00:00:00 -0800"))).withHeader("Date", time.Date(2026, 11, 15, 13, 0, 0, 0, time.UTC).Format(http.TimeFormat))
	b, err = f.Changes(ctx, b.Next)
	if err != nil || fmt.Sprint(names(b.Items)) != "[acme-a]" {
		t.Errorf("a release listed half an hour late: %v %v", names(b.Items), err)
	}
}
