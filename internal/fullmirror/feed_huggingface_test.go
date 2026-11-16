package fullmirror

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The huggingface fixtures are real, recorded on 2026-11-16: every page of
// huggingface.co/api/models for author HuggingFaceTB and search SmolVLM
// (limit 3, five pages) with the Link header of each, a page of
// /api/datasets for author fka, and the metadata at main of
// HuggingFaceTB/SmolVLM-256M-Instruct, fka/prompts.chat (a dataset) and
// meta-llama/Llama-3.2-1B (gated; trimmed of its card, widget and config).
// The backend serves the metadata unchanged. Changes are tested against
// huggingfaceFakeHub, a listing with the Hub's keyset paging over repositories the
// tests modify.

// huggingfaceTestFeed builds the huggingface adapter for the public Hub with base as
// its API.
func huggingfaceTestFeed(t *testing.T, base string, reads *fakeReads, opts map[string]string) *huggingfaceFeed {
	t.Helper()
	all := map[string]string{"url": base}
	for k, v := range opts {
		all[k] = v
	}
	return mustFeed(t, testEnv(t, "huggingface", "https://huggingface.co", reads, all)).(*huggingfaceFeed)
}

// huggingfaceTestBackend is the backend the adapter's paths are checked against.
func huggingfaceTestBackend(t *testing.T, env Env) backends.Backend {
	t.Helper()
	b, err := huggingface.New(huggingface.Options{Name: env.Upstream, UpstreamURL: env.URL, Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// huggingfaceItemsView is a batch's items and whether more follow, as the golden
// files show them (the listing driver's cursor is its own).
type huggingfaceItemsView struct {
	Items []Coordinate `json:"items"`
	More  bool         `json:"more"`
}

func TestHuggingFaceFeedLocation(t *testing.T) {
	scope := map[string]string{"author": "HuggingFaceTB"}
	for _, u := range []string{"https://huggingface.co", "https://hf.co/"} {
		f, err := newHuggingFaceFeed(Env{Upstream: "hf", Type: "huggingface", URL: u, Options: scope})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		hf := f.(*huggingfaceFeed)
		// hf.co answers the API with a redirect to huggingface.co (a 307,
		// checked 2026-11-16): both read it there.
		if got := hf.src.api.String(); got != "https://huggingface.co" {
			t.Errorf("%s: API %s", u, got)
		}
		if hf.src.kind != "models" || hf.repoType != huggingface.RepoModel || hf.restricted || hf.files != nil {
			t.Errorf("%s: defaults %+v", u, hf)
		}
	}
	err := Check(Env{Upstream: "hf", Type: "huggingface", URL: "https://artifactory.example/artifactory/api/huggingfaceml/hf-remote", Options: scope})
	if err == nil || !strings.Contains(err.Error(), "fullMirror.feed.url") {
		t.Errorf("an Artifactory upstream without a feed URL: %v", err)
	}
	f, err := newHuggingFaceFeed(Env{Upstream: "hf", Type: "huggingface", URL: "https://artifactory.example/artifactory/api/huggingfaceml/hf-remote",
		Options: map[string]string{"url": "https://huggingface.co", "author": " meta-llama, google ,meta-llama", "kind": "Datasets", "restricted": "include", "files": "*.safetensors, config.json"}})
	if err != nil {
		t.Fatal(err)
	}
	hf := f.(*huggingfaceFeed)
	if hf.src.api.String() != "https://huggingface.co" || strings.Join(hf.src.authors, ",") != "google,meta-llama" || hf.src.kind != "datasets" ||
		hf.repoType != huggingface.RepoDataset || !hf.restricted || len(hf.files) != 2 {
		t.Errorf("options %+v %+v", hf, hf.src)
	}
	// Unscoped: refused, saying why.
	err = Check(Env{Upstream: "hf", Type: "huggingface", URL: "https://huggingface.co"})
	if err == nil || !strings.Contains(err.Error(), "needs a scope") || !strings.Contains(err.Error(), "docs/full-mirroring.md#huggingface") {
		t.Errorf("an unscoped feed: %v", err)
	}
	if err := Check(Env{Upstream: "hf", Type: "huggingface", URL: "https://huggingface.co", Options: map[string]string{"search": "llama"}}); err != nil {
		t.Errorf("a search alone is a scope: %v", err)
	}
	many := make([]string, huggingfaceMaxAuthors+1)
	for i := range many {
		many[i] = fmt.Sprintf("org%d", i)
	}
	for _, opts := range []map[string]string{{"author": "a", "since": "x"}, {"author": "a", "kind": "collections"}, {"author": "a b"}, {"author": "a,,b"},
		{"author": "-a"}, {"author": "a--b"}, {"author": strings.Join(many, ",")}, {"search": strings.Repeat("s", huggingfaceMaxSearch+1)}, {"author": "a", "restricted": "yes"},
		{"author": "a", "files": "["}, {"author": "a", "files": "a,,b"}, {"author": "a", "url": "ftp://huggingface.co"}, {"author": "a", "url": "https://u:p@huggingface.co"}} {
		if err := Check(Env{Upstream: "hf", Type: "huggingface", URL: "https://huggingface.co", Options: opts}); err == nil {
			t.Errorf("options %v accepted", opts)
		}
	}
}

// huggingfaceServeRecorded serves the recorded listing of HuggingFaceTB's SmolVLM
// models, every page with its Link header pointing at the fixture server.
func huggingfaceServeRecorded(t *testing.T, srv *fixtureServer) {
	t.Helper()
	links := strings.Split(strings.TrimSuffix(string(fixture(t, "huggingface", "models-smolvlm-links.txt")), "\n"), "\n")
	if len(links) != 5 {
		t.Fatalf("%d links", len(links))
	}
	cursor := ""
	for n := 1; n <= 5; n++ {
		target := "/api/models?author=HuggingFaceTB&search=SmolVLM&limit=3&sort=lastModified&direction=-1&expand=lastModified&expand=sha"
		if cursor != "" {
			target = "/api/models?" + url.Values{"cursor": {cursor}}.Encode()
		}
		r := srv.on("GET", target).reply(200, fixture(t, "huggingface", fmt.Sprintf("models-smolvlm-page%d.json", n)))
		cursor = ""
		if link := links[n-1]; link != "" {
			r.withHeader("Link", strings.ReplaceAll(link, "https://huggingface.co", srv.URL()))
			start, end := strings.Index(link, "<"), strings.Index(link, ">")
			u, err := url.Parse(link[start+1 : end])
			if err != nil {
				t.Fatal(err)
			}
			cursor = u.Query().Get("cursor")
		}
	}
}

// Bootstrap takes its mark from the newest page and lists the scope, page by
// page through the Link headers.
func TestHuggingFaceBootstrapListsTheScope(t *testing.T) {
	srv := newFixtureServer(t)
	huggingfaceServeRecorded(t, srv)
	f := huggingfaceTestFeed(t, srv.URL(), newFakeReads(), map[string]string{"author": "HuggingFaceTB", "search": "SmolVLM"})
	f.src.limit = 3
	f.list.batch = 5
	ctx := context.Background()
	var pages []huggingfaceItemsView
	cursor := ""
	for i := 0; i < 10; i++ {
		b, err := f.Bootstrap(ctx, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateBatch(b); err != nil {
			t.Fatal(err)
		}
		pages = append(pages, huggingfaceItemsView{Items: b.Items, More: b.More})
		cursor = b.Next
		if !b.More {
			break
		}
	}
	checkGolden(t, "huggingface", "bootstrap-smolvlm", pages)
	var c huggingfaceCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil || c.Scope != f.scope {
		t.Fatalf("final cursor %s (%v)", cursor, err)
	}
	var inner struct {
		Mark time.Time `json:"mark"`
	}
	if err := json.Unmarshal([]byte(c.Inner), &inner); err != nil || inner.Mark.Format(time.RFC3339) != "2026-11-13T08:37:57Z" {
		t.Errorf("the mark %v (%v), want the newest repository's lastModified", inner.Mark, err)
	}
	for _, r := range srv.requests() {
		u, _ := url.Parse(strings.TrimPrefix(r, "GET "))
		if q := u.Query(); q.Get("sort") != "lastModified" || q.Get("direction") != "-1" || strings.Join(q["expand"], ",") != "lastModified,sha" || q.Get("author") != "HuggingFaceTB" {
			t.Errorf("a listing request %s", r)
		}
	}
}

func TestHuggingFaceListingParse(t *testing.T) {
	items, err := huggingfaceParseListing(fixture(t, "huggingface", "models-smolvlm-page1.json"))
	if err != nil || len(items) != 3 {
		t.Fatalf("%+v %v", items, err)
	}
	it := items[0].listing()
	if it.Name != "HuggingFaceTB/SmolVLM-500M-Instruct" || it.Version != "" || it.Time.Format(time.RFC3339) != "2026-11-13T08:37:57Z" || it.ID != "678e5cb387ba422cae1fe649@753c1752602b" {
		t.Errorf("item %+v", it)
	}
	if items, err := huggingfaceParseListing(fixture(t, "huggingface", "datasets-fka-page1.json")); err != nil || len(items) != 1 || items[0].id != "fka/prompts.chat" {
		t.Errorf("datasets %+v %v", items, err)
	}
	items, err = huggingfaceParseListing([]byte(`[{"_id":"x","id":"a/b","lastModified":"2026-01-01T00:00:00.000Z"},{"id":"a/../b","lastModified":"2026-01-01T00:00:00.000Z"},
		{"id":"a/c","lastModified":"yesterday"},{"id":"a/d"},{"_id":"0123456789abcdef01234567","id":"a/e","lastModified":"2026-01-02T00:00:00Z","sha":"nope"},{"id":"a b","lastModified":"2026-01-01T00:00:00Z"}]`))
	if err != nil || len(items) != 2 {
		t.Fatalf("%+v %v", items, err)
	}
	if got := items[0].listing().ID + " " + items[1].listing().ID; got != "a/b@2026-01-01T00:00:00.000Z 0123456789abcdef01234567@2026-01-02T00:00:00Z" {
		t.Errorf("ids without an _id or a sha: %s", got)
	}
	for _, bad := range []string{"", "{}", `{"items":[]}`, "<html>", "null"} {
		if _, err := huggingfaceParseListing([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}

	src := &huggingfaceSource{api: mustParseURL(t, "https://huggingface.co"), kind: "models"}
	links := strings.Split(strings.TrimSuffix(string(fixture(t, "huggingface", "models-smolvlm-links.txt")), "\n"), "\n")
	c, err := src.nextCursor([]string{links[0]}, nil)
	if err != nil || !strings.HasPrefix(c, "eyIkb3IiOlt7") || strings.Contains(c, "%") {
		t.Errorf("the recorded link's cursor %q (%v)", c, err)
	}
	mirror := mustParseURL(t, "https://mirror.example/api/models?author=a")
	for _, tc := range []struct {
		links  []string
		served *url.URL
		want   string
		err    string
	}{
		{nil, nil, "", ""},
		// After a redirect, the next page's link names the origin the page
		// was served from: that is the listing too.
		{[]string{`<https://mirror.example/api/models?cursor=abc>; rel="next"`}, mirror, "abc", ""},
		{[]string{`<https://mirror.example/api/datasets?cursor=abc>; rel="next"`}, mirror, "", "leaves the listing"},
		{[]string{`<https://mirror.example/api/models?cursor=abc>; rel="next"`}, nil, "", "leaves the listing"},
		{[]string{`<https://huggingface.co/api/models?cursor=abc>; rel="prev"`}, nil, "", ""},
		{[]string{`<https://huggingface.co/api/models?cursor=abc>; rel="prev", <https://huggingface.co/api/models?limit=1&cursor=d%3D>; rel=next`}, nil, "d=", ""},
		{[]string{`<https://huggingface.co/api/models?cursor=x,y>; rel="next"`}, nil, "x,y", ""},
		{[]string{`<https://evil.example/api/models?cursor=abc>; rel="next"`}, nil, "", "leaves the listing"},
		{[]string{`<http://huggingface.co/api/models?cursor=abc>; rel="next"`}, nil, "", "leaves the listing"},
		{[]string{`<https://huggingface.co/api/datasets?cursor=abc>; rel="next"`}, nil, "", "leaves the listing"},
		{[]string{`</api/models?cursor=abc>; rel="next"`}, nil, "", "not a URL"},
		{[]string{`<https://huggingface.co/api/models?page=2>; rel="next"`}, nil, "", "carries no cursor"},
		{[]string{`<https://huggingface.co/api/models?cursor=` + strings.Repeat("a", huggingfaceMaxCursor+1) + `>; rel="next"`}, nil, "", "carries no cursor"},
	} {
		got, err := src.nextCursor(tc.links, tc.served)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%v: %q %v, want an error saying %q", tc.links, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%v: %q %v, want %q", tc.links, got, err, tc.want)
		}
	}
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// huggingfaceFakeRepo is one repository of huggingfaceFakeHub.
type huggingfaceFakeRepo struct {
	id, oid, sha string
	modified     time.Time
}

// huggingfaceFakeHub is a listing of model repositories with the Hub's keyset
// paging: newest lastModified first, then _id; the Link header names the
// next page by a cursor on the last repository of the page, of the real
// one's shape and size (base64 of {"$or":[…keyset…],"searchSequenceToken":…},
// 344 characters, as recorded on 2026-11-16).
type huggingfaceFakeHub struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	repos map[string]*huggingfaceFakeRepo
	seq   int
	calls int
	// pages counts the requests of each page ("<author> <cursor>"), and
	// longest is the longest cursor handed out.
	pages   map[string]int
	longest int
	// date, when set, is the Date the hub serves its pages with; noDate
	// serves them without one.
	date   time.Time
	noDate bool
}

func newHFFakeHub(t *testing.T) *huggingfaceFakeHub {
	h := &huggingfaceFakeHub{t: t, repos: map[string]*huggingfaceFakeRepo{}, pages: map[string]int{}}
	h.srv = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.srv.Close)
	return h
}

// put creates or modifies a repository: a new commit at a time.
func (h *huggingfaceFakeHub) put(id string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	r, ok := h.repos[id]
	if !ok {
		r = &huggingfaceFakeRepo{id: id, oid: fmt.Sprintf("%024x", h.seq)}
		h.repos[id] = r
	}
	r.modified = at.UTC().Truncate(time.Second)
	r.sha = fmt.Sprintf("%040x", h.seq)
}

// setDate sets the Date the hub serves its pages with.
func (h *huggingfaceFakeHub) setDate(at time.Time) {
	h.mu.Lock()
	h.date = at
	h.mu.Unlock()
}

// requests returns how many listing pages the hub served, and how often the
// page asked for most often was.
func (h *huggingfaceFakeHub) requests() (int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	most := 0
	for _, n := range h.pages {
		most = max(most, n)
	}
	return h.calls, most
}

// resetRequests forgets the requests served.
func (h *huggingfaceFakeHub) resetRequests() {
	h.mu.Lock()
	h.calls, h.pages = 0, map[string]int{}
	h.mu.Unlock()
}

const huggingfaceFakeTime = "2006-01-02T15:04:05.000Z"

func (h *huggingfaceFakeHub) serve(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.URL.Path != "/api/models" || q.Get("sort") != "lastModified" || q.Get("direction") != "-1" || strings.Join(q["expand"], ",") != "lastModified,sha" {
		h.t.Errorf("unexpected request %s", r.URL)
		http.NotFound(w, r)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	author, search := q.Get("author"), strings.ToLower(q.Get("search"))
	h.mu.Lock()
	h.calls++
	h.pages[author+" "+q.Get("cursor")]++
	date, noDate := h.date, h.noDate
	var list []huggingfaceFakeRepo
	for _, rp := range h.repos {
		if (author == "" || strings.HasPrefix(rp.id, author+"/")) && strings.Contains(strings.ToLower(rp.id), search) {
			list = append(list, *rp)
		}
	}
	h.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if !list[i].modified.Equal(list[j].modified) {
			return list[i].modified.After(list[j].modified)
		}
		return list[i].oid < list[j].oid
	})
	if c := q.Get("cursor"); c != "" {
		var cur struct {
			Or []struct {
				LastModified json.RawMessage `json:"lastModified"`
				ID           struct {
					GT string `json:"$gt"`
				} `json:"_id"`
			} `json:"$or"`
		}
		var lm string
		raw, err := base64.StdEncoding.DecodeString(c)
		if err != nil || json.Unmarshal(raw, &cur) != nil || len(cur.Or) == 0 || json.Unmarshal(cur.Or[0].LastModified, &lm) != nil {
			h.t.Errorf("a cursor the hub did not hand out: %q", c)
			http.Error(w, "bad cursor", http.StatusBadRequest)
			return
		}
		at, _ := time.Parse(huggingfaceFakeTime, lm)
		i := 0
		for i < len(list) && (list[i].modified.After(at) || list[i].modified.Equal(at) && list[i].oid <= cur.Or[0].ID.GT) {
			i++
		}
		list = list[i:]
	}
	if len(list) > limit {
		list = list[:limit]
		last := list[len(list)-1]
		lm := last.modified.Format(huggingfaceFakeTime)
		cur := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, `{"$or":[{"lastModified":%q,"_id":{"$gt":%q}},{"lastModified":{"$lt":%q}},{"lastModified":null}],`+
			`"searchSequenceToken":"CJ3MzgIaCSloHA7UoQEAABoOWgxnO2/54Xosepes+aIiDloMZztv+eF6LHqXrPmi"}`, lm, last.oid, lm))
		h.mu.Lock()
		h.longest = max(h.longest, len(cur))
		h.mu.Unlock()
		q.Set("cursor", cur)
		w.Header().Set("Link", fmt.Sprintf("<http://%s/api/models?%s>; rel=\"next\"", r.Host, q.Encode()))
	}
	switch {
	case noDate:
		w.Header()["Date"] = nil
	case !date.IsZero():
		w.Header().Set("Date", date.UTC().Format(http.TimeFormat))
	}
	out := make([]map[string]string, 0, len(list))
	for _, rp := range list {
		out = append(out, map[string]string{"_id": rp.oid, "id": rp.id, "lastModified": rp.modified.Format(huggingfaceFakeTime), "sha": rp.sha})
	}
	_ = json.NewEncoder(w).Encode(out)
}

// A pass of Changes reads the authors one after another, each down to the
// lookback window below the mark: an older repository of one author ends
// that author, not the pass — the later authors' changes are reported — and
// every page is read once.
func TestHuggingFacePassReadsTheAuthorsInTurn(t *testing.T) {
	for _, limit := range []int{1, 2, 3, 100} {
		hub := newHFFakeHub(t)
		now := time.Now()
		for i := 0; i < 4; i++ {
			for _, a := range []string{"a0", "a1", "a2"} {
				hub.put(fmt.Sprintf("%s/old%d", a, i), now.Add(-time.Duration(30-i)*24*time.Hour))
			}
		}
		f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "a2,a0,a1"})
		f.src.limit = limit
		_, cursor := drainBootstrap(t, f)
		// The first author's change is newer than the third's, and its old
		// repositories come before them.
		hub.put("a0/new", now.Add(-time.Minute))
		for i := 0; i < 5; i++ {
			hub.put(fmt.Sprintf("a2/new%d", i), now.Add(-time.Duration(10+i)*time.Minute))
		}
		hub.resetRequests()
		got, next := drainChanges(t, f, cursor)
		sort.Strings(got)
		if strings.Join(got, ",") != "a0/new,a2/new0,a2/new1,a2/new2,a2/new3,a2/new4" {
			t.Errorf("limit %d: Changes = %v", limit, got)
		}
		// Each author is read down to its first repository below the window
		// (old2: old3 is the mark), each page once.
		want := 0
		for _, first := range []int{2, 1, 6} { // its place in a0's, a1's and a2's listing
			want += first/limit + 1
		}
		if n, most := hub.requests(); n != want || most != 1 {
			t.Errorf("limit %d: the pass made %d requests (a page read %d times), want %d, each page once", limit, n, most, want)
		}
		if again, _ := drainChanges(t, f, next); len(again) != 0 {
			t.Errorf("limit %d: reported twice: %v", limit, again)
		}
	}
}

// huggingfaceBusyScope builds a scope of n organisations, enumerates it, then
// lets every organisation update perOrg repositories (interleaved in time): a
// busy stretch since the mark (a long Bootstrap, a paused mirror, an outage).
func huggingfaceBusyScope(t *testing.T, n, perOrg, limit int) (*huggingfaceFakeHub, *huggingfaceFeed, string) {
	t.Helper()
	hub := newHFFakeHub(t)
	now := time.Now().UTC()
	var orgs []string
	for a := 0; a < n; a++ {
		org := fmt.Sprintf("org%02d", a)
		orgs = append(orgs, org)
		for j := 0; j < 3; j++ {
			hub.put(fmt.Sprintf("%s/old%d", org, j), now.Add(-30*24*time.Hour).Add(time.Duration(a*3+j)*time.Minute))
		}
	}
	f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": strings.Join(orgs, ",")})
	f.src.limit = limit
	_, cursor := drainBootstrap(t, f)
	for j := 0; j < perOrg; j++ {
		for a := 0; a < n; a++ {
			hub.put(fmt.Sprintf("org%02d/new%d", a, j), now.Add(-time.Duration(j*n+a+1)*time.Minute))
		}
	}
	hub.resetRequests()
	return hub, f, cursor
}

// huggingfaceCountNew counts the updated repositories of a busy scope a pass
// reported, failing on one reported twice. (Old repositories within the
// lookback window below the mark past an author's first page were not
// remembered by Bootstrap, which reads first pages only: they may come
// again, once.)
func huggingfaceCountNew(t *testing.T, got []string) int {
	t.Helper()
	seen := map[string]bool{}
	for _, name := range got {
		if !strings.Contains(name, "/new") {
			continue
		}
		if seen[name] {
			t.Errorf("%s reported twice", name)
		}
		seen[name] = true
	}
	return len(seen)
}

// However many authors a pass reads, a page token holds the Hub's cursor of
// one: at the real cursor's length and at the longest a token takes, it fits
// the listing driver's bound (review of Task 191: a token of every author's
// cursor overflowed it from nine busy authors on, failing every poll).
func TestHuggingFaceManyAuthorsFitTheToken(t *testing.T) {
	src := &huggingfaceSource{authors: make([]string, huggingfaceMaxAuthors)}
	token := src.passToken(huggingfaceMaxAuthors-1, time.Unix(huggingfaceMaxCeiling, 0), strings.Repeat("A", huggingfaceMaxCursor))
	if len(token) > listingMaxToken {
		t.Errorf("the longest page token is %d bytes; the listing driver keeps %d", len(token), listingMaxToken)
	}
	if a, c, cur, err := src.parsePassToken(token); err != nil || a != huggingfaceMaxAuthors-1 || c.Unix() != huggingfaceMaxCeiling || len(cur) != huggingfaceMaxCursor {
		t.Errorf("the longest page token reads %d %s %d (%v)", a, c, len(cur), err)
	}
	if every := src.everyToken(huggingfaceMaxAuthors-1, strings.Repeat("A", huggingfaceMaxCursor)); len(every) > listingMaxToken {
		t.Errorf("the longest enumeration token is %d bytes", len(every))
	}
	for _, n := range []int{8, 9, 12, huggingfaceMaxAuthors} {
		hub, f, cursor := huggingfaceBusyScope(t, n, 6, 2)
		got, _ := drainChanges(t, f, cursor)
		if c := huggingfaceCountNew(t, got); c != n*6 || len(got) > n*6+n {
			t.Errorf("%d authors: %d of %d changes reported (%d in all)", n, c, n*6, len(got))
		}
		if hub.longest != 344 {
			t.Errorf("the hub's cursors are %d characters long, not the real 344", hub.longest)
		}
	}
}

// A deep pass reads each page of each author once (review of Task 191: the
// merged listing read every unfinished author's page again for each page it
// handed the driver — 236 requests for these 40 pages).
func TestHuggingFacePassCost(t *testing.T) {
	hub, f, cursor := huggingfaceBusyScope(t, 8, 6, 2)
	got, _ := drainChanges(t, f, cursor)
	if c := huggingfaceCountNew(t, got); c != 48 {
		t.Errorf("%d of 48 changes reported", c)
	}
	// 8 authors of 9 repositories, 2 a page: at most 5 pages each.
	if n, most := hub.requests(); n > 40 || most != 1 {
		t.Errorf("a pass over 8 authors' 40 pages made %d requests (a page read %d times)", n, most)
	}
}

// A pass that runs over several calls, a batch worked between them, keeps
// the next mark at the pass's ceiling, when the Hub served its first page: a
// repository of an author read early that is modified meanwhile comes with
// the next pass, although a later author's change, newer still, is reported
// in this one (at the ceiling).
func TestHuggingFaceALongPassLosesNothing(t *testing.T) {
	for _, clock := range []string{"the Hub's Date", "the proxy's clock"} {
		hub := newHFFakeHub(t)
		start := time.Now().UTC().Truncate(time.Second)
		for i := 0; i < 3; i++ {
			hub.put(fmt.Sprintf("a0/old%d", i), start.Add(-time.Duration(30-i)*24*time.Hour))
			hub.put(fmt.Sprintf("a1/old%d", i), start.Add(-time.Duration(30-i)*24*time.Hour))
		}
		f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "a0,a1"})
		f.src.limit = 2
		_, cursor := drainBootstrap(t, f)
		for i := 0; i < 4; i++ {
			hub.put(fmt.Sprintf("a0/new%d", i), start.Add(-time.Duration(20+i)*time.Minute))
		}
		if clock == "the Hub's Date" {
			hub.setDate(start)
		} else {
			hub.mu.Lock()
			hub.noDate = true
			hub.mu.Unlock()
			f.list.now = func() time.Time { return start.Add(500 * time.Millisecond) }
		}
		f.list.maxPages = 1
		var got []string
		for call := 0; ; call++ {
			b, err := f.Changes(context.Background(), cursor)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, names(b.Items)...)
			cursor = b.Next
			if call == 2 {
				// a0 is read; a1 not yet. While the batch is worked, a0/old0
				// changes, and a1/new later still.
				hub.put("a0/old0", start.Add(5*time.Minute))
				hub.put("a1/new", start.Add(40*time.Minute))
			}
			if !b.More {
				if !b.HeadTime.Equal(start) {
					t.Errorf("%s: the pass's mark is %s, want its ceiling %s", clock, b.HeadTime, start)
				}
				break
			}
			if call > 20 {
				t.Fatalf("%s: the pass does not end", clock)
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != "a0/new0,a0/new1,a0/new2,a0/new3,a1/new" {
			t.Errorf("%s: the pass reported %v", clock, got)
		}
		f.list.maxPages = listingPages
		if next, _ := drainChanges(t, f, cursor); strings.Join(next, ",") != "a0/old0" {
			t.Errorf("%s: the next pass reported %v, want a0/old0", clock, next)
		}
	}
}

// A pass's ceiling is never below its mark: with the Hub's Date behind the
// mark (another server's clock, a stale answer), a change reported at the
// ceiling must not fall below the lookback window, where the driver would
// take it for the end of the pass and miss the next authors' changes.
func TestHuggingFaceCeilingBehindTheMark(t *testing.T) {
	hub := newHFFakeHub(t)
	now := time.Now().UTC()
	for _, a := range []string{"a0", "a1"} {
		hub.put(a+"/old", now.Add(-48*time.Hour))
	}
	f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "a0,a1"})
	_, cursor := drainBootstrap(t, f)
	hub.put("a0/new", now.Add(-2*time.Minute))
	hub.put("a1/new", now.Add(-time.Minute))
	hub.setDate(now.Add(-72 * time.Hour))
	got, next := drainChanges(t, f, cursor)
	if sort.Strings(got); strings.Join(got, ",") != "a0/new,a1/new" {
		t.Errorf("Changes = %v", got)
	}
	if again, _ := drainChanges(t, f, next); len(again) != 0 {
		t.Errorf("reported again: %v", again)
	}
}

// Changes reports the repositories modified since the last pass, across the
// scope's authors; another scope starts the enumeration over.
func TestHuggingFaceChangesFollowTheScope(t *testing.T) {
	hub := newHFFakeHub(t)
	now := time.Now()
	for i := 0; i < 9; i++ {
		hub.put(fmt.Sprintf("%s/old%d", []string{"acme", "beta"}[i%2], i), now.Add(-time.Duration(30-i)*24*time.Hour))
	}
	hub.put("other/x", now.Add(-time.Hour))
	f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "beta, acme"})
	f.src.limit = 2
	listed, cursor := drainBootstrap(t, f)
	sort.Strings(listed)
	if len(listed) != 9 || listed[0] != "acme/old0" || listed[8] != "beta/old7" {
		t.Fatalf("listed %v", listed)
	}
	if got, _ := drainChanges(t, f, cursor); len(got) != 0 {
		t.Errorf("nothing new, yet %v", got)
	}
	hub.put("acme/old2", now.Add(-3*time.Minute))
	hub.put("beta/new", now.Add(-2*time.Minute))
	hub.put("beta/old1", now.Add(-time.Minute))
	hub.put("other/y", now.Add(-time.Minute))
	got, next := drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "acme/old2,beta/new,beta/old1" {
		t.Errorf("Changes = %v", got)
	}
	if again, _ := drainChanges(t, f, next); len(again) != 0 {
		t.Errorf("reported twice: %v", again)
	}

	// The same scope, spelt otherwise, continues; another starts over.
	same := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "acme,beta,acme"})
	if _, err := same.Changes(context.Background(), next); err != nil {
		t.Errorf("the same scope: %v", err)
	}
	for _, opts := range []map[string]string{{"author": "acme"}, {"author": "acme,beta,gamma"}, {"author": "acme,beta", "search": "old"}, {"author": "acme,beta", "kind": "datasets"}} {
		other := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), opts)
		_, err := other.Changes(context.Background(), next)
		mustErr(t, err, false, true, "another scope")
		if _, err := other.Bootstrap(context.Background(), next); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("Bootstrap with another scope's cursor: %v", err)
		}
	}
	for _, bad := range []string{"", "x", `{"format":"huggingface/1","scope":"` + f.scope + `"}`, `{"format":"jsr/1","snap":"x"}`} {
		_, err := f.Changes(context.Background(), bad)
		mustErr(t, err, false, true, "")
	}
	// Tokens of another shape are not trusted; a pass's tokens are not
	// Bootstrap's.
	long := strings.Repeat("A", huggingfaceMaxCursor+1)
	f.src.setPass(&huggingfacePass{})
	for _, token := range []string{"!", "0", "0:", "2:1:", "-1:1:", "01:1:", "0:-1:", "0:x:", "0:1:a b", "0:1:" + long, "0:253402300800:", "0:01:", "e30"} {
		if _, err := f.src.recent(context.Background(), token); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("recent(%q): %v", token, err)
		}
	}
	f.src.setPass(nil)
	if _, err := f.src.recent(context.Background(), "0:1:"); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a pass's token outside a pass: %v", err)
	}
	for _, token := range []string{"!", "0", "2:", "-1:", "01:", "0:a b", "0:" + long, "e30"} {
		if _, err := f.src.every(context.Background(), token); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("every(%q): %v", token, err)
		}
	}
}

// The public Hub's API is huggingface.co, for an upstream on hf.co too, whose
// API answers with a redirect there (a 307, checked 2026-11-16: the next
// page's link then names huggingface.co). An API given by the option url
// that redirects keeps paging too: a next page's link may name the origin
// the page was served from.
func TestHuggingFaceRedirectedListingPages(t *testing.T) {
	hub := newHFFakeHub(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		hub.put(fmt.Sprintf("acme/r%d", i), now.Add(-time.Duration(i+1)*time.Hour))
	}
	alias := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, hub.srv.URL+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	}))
	t.Cleanup(alias.Close)
	f := huggingfaceTestFeed(t, alias.URL, newFakeReads(), map[string]string{"author": "acme"})
	f.src.limit = 2
	listed, cursor := drainBootstrap(t, f)
	if sort.Strings(listed); strings.Join(listed, ",") != "acme/r0,acme/r1,acme/r2,acme/r3,acme/r4" {
		t.Errorf("listed %v", listed)
	}
	hub.put("acme/r3", now.Add(-time.Minute))
	hub.put("acme/r5", now.Add(-2*time.Minute))
	got, _ := drainChanges(t, f, cursor)
	if sort.Strings(got); strings.Join(got, ",") != "acme/r3,acme/r5" {
		t.Errorf("Changes = %v", got)
	}
}

// With restricted repositories included, a 401 on a repository's metadata
// is asked about: a token the Hub refuses holds the upstream (an expired or
// revoked token has every gated and private repository answer 401, while
// public ones still read — checked 2026-11-16), a token it takes leaves the
// 401 the repository's own answer (renamed, deleted, private).
func TestHuggingFaceRefusedTokenHoldsTheUpstream(t *testing.T) {
	srv := newFixtureServer(t)
	reads := newFakeReads()
	reads.setDoc("/api/models/o/gone/revision/main", fakeDoc{status: http.StatusUnauthorized})
	env := testEnv(t, "huggingface", srv.URL(), reads, map[string]string{"url": srv.URL(), "author": "o", "restricted": "include"})
	env.Authorize = func(r *http.Request) { r.Header.Set("Authorization", "Bearer hf_test") }
	f := mustFeed(t, env).(*huggingfaceFeed)
	ctx := context.Background()
	srv.on("GET", "/api/whoami-v2").requireHeader("Authorization", "Bearer hf_test").reply(401, []byte(`{"error":"Invalid credentials in Authorization header"}`))
	_, err := f.Releases(ctx, "o/gone")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal || !strings.Contains(err.Error(), "refuses the upstream's token") {
		t.Errorf("a refused token: %v", err)
	}
	srv.on("GET", "/api/whoami-v2").reply(503, nil)
	if _, err := f.Releases(ctx, "o/gone"); err == nil || IsPermanent(err) {
		t.Errorf("a token that could not be asked about: %v", err)
	}
	srv.on("GET", "/api/whoami-v2").requireHeader("Authorization", "Bearer hf_test").json(`{"type":"user","name":"mirror"}`)
	_, err = f.Releases(ctx, "o/gone")
	mustErr(t, err, true, false, "does not show this repository")
	// A 403, restricted repositories skipped, or no token: nothing to ask.
	asked := len(srv.requests())
	reads.setDoc("/api/models/o/denied/revision/main", fakeDoc{status: http.StatusForbidden})
	_, err = f.Releases(ctx, "o/denied")
	mustErr(t, err, true, false, "does not show this repository")
	f.restricted = false
	_, err = f.Releases(ctx, "o/gone")
	mustErr(t, err, true, false, "does not show this repository")
	f.restricted = true
	f.k.env.Authorize = nil
	_, err = f.Releases(ctx, "o/gone")
	mustErr(t, err, true, false, "does not show this repository")
	if n := len(srv.requests()); n != asked {
		t.Errorf("%d more requests: %v", n-asked, srv.requests()[asked:])
	}
}

// huggingfaceRevisionWith returns the recorded SmolVLM metadata with fields replaced.
func huggingfaceRevisionWith(t *testing.T, edits map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "huggingface", "revision-smolvlm-256m-instruct.json"), &doc); err != nil {
		t.Fatal(err)
	}
	for k, v := range edits {
		if v == nil {
			delete(doc, k)
		} else {
			doc[k] = v
		}
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestHuggingFaceReleasesFromTheMetadata(t *testing.T) {
	reads := newFakeReads()
	reads.set("/api/models/HuggingFaceTB/SmolVLM-256M-Instruct/revision/main", fixture(t, "huggingface", "revision-smolvlm-256m-instruct.json"))
	reads.set("/api/models/meta-llama/Llama-3.2-1B/revision/main", fixture(t, "huggingface", "revision-llama-3.2-1b.json"))
	f := huggingfaceTestFeed(t, "https://huggingface.co", reads, map[string]string{"author": "HuggingFaceTB"})
	backend := huggingfaceTestBackend(t, f.k.env)
	ctx := context.Background()
	rels, err := f.Releases(ctx, "HuggingFaceTB/SmolVLM-256M-Instruct")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "huggingface", "releases-smolvlm-256m-instruct", viewReleases(rels))
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "HuggingFaceTB/SmolVLM-256M-Instruct", r.Version })

	// The files option keeps some files.
	f.files, _ = huggingfaceParsePatterns("*.json, onnx/vision_encoder_q4.onnx, model.*")
	rels, err = f.Releases(ctx, "HuggingFaceTB/SmolVLM-256M-Instruct")
	if err != nil || len(rels) != 1 {
		t.Fatal(rels, err)
	}
	var kept []string
	for _, a := range rels[0].Artifacts {
		_, file, _ := strings.Cut(a.Path, "/resolve/d039ab0d4b9311b617e8ffec1d06c8464364aeb3/")
		kept = append(kept, file)
	}
	if strings.Join(kept, " ") != "added_tokens.json chat_template.json config.json generation_config.json model.safetensors onnx/vision_encoder_q4.onnx preprocessor_config.json processor_config.json special_tokens_map.json tokenizer.json tokenizer_config.json vocab.json" {
		t.Errorf("kept %v", kept)
	}
	f.files = nil

	// A gated repository is skipped, unless restricted ones are included.
	_, err = f.Releases(ctx, "meta-llama/Llama-3.2-1B")
	mustErr(t, err, true, false, "gated")
	f.restricted = true
	rels, err = f.Releases(ctx, "meta-llama/Llama-3.2-1B")
	if err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 13 || rels[0].Version != "4e20de362430cd3b72f300e6b0f18e50e7166e08" {
		t.Fatalf("an included gated repository: %+v %v", viewReleases(rels), err)
	}
	expectServed(t, backend, rels, func(r Release, _ Artifact) (string, string) { return "meta-llama/Llama-3.2-1B", r.Version })
	f.restricted = false

	for name, tc := range map[string]struct {
		edits map[string]any
		want  string
	}{
		"private":  {map[string]any{"private": true}, "is private"},
		"disabled": {map[string]any{"disabled": true}, "is disabled"},
		"nosha":    {map[string]any{"sha": "main"}, "names no commit"},
		"nofiles":  {map[string]any{"siblings": nil}, "lists no files"},
		"badshape": {map[string]any{"siblings": "x"}, "metadata of o/badshape"},
	} {
		reads.set("/api/models/o/"+name+"/revision/main", huggingfaceRevisionWith(t, tc.edits))
		_, err := f.Releases(ctx, "o/"+name)
		mustErr(t, err, true, false, tc.want)
	}
	many := make([]map[string]string, huggingfaceMaxFiles+1)
	for i := range many {
		many[i] = map[string]string{"rfilename": fmt.Sprintf("f%d", i)}
	}
	reads.set("/api/models/o/huge/revision/main", huggingfaceRevisionWith(t, map[string]any{"siblings": many}))
	_, err = f.Releases(ctx, "o/huge")
	mustErr(t, err, true, false, "at most 100000")
	// Files no resolve path carries are left out; none left: no release.
	reads.set("/api/models/o/odd/revision/main", huggingfaceRevisionWith(t, map[string]any{"siblings": []map[string]string{{"rfilename": "a/../b"}, {"rfilename": ""}, {"rfilename": "/abs"}, {"rfilename": "ok.txt"}}}))
	if rels, err := f.Releases(ctx, "o/odd"); err != nil || len(rels) != 1 || len(rels[0].Artifacts) != 1 {
		t.Errorf("odd files: %+v %v", viewReleases(rels), err)
	}
	reads.set("/api/models/o/empty/revision/main", huggingfaceRevisionWith(t, map[string]any{"siblings": []map[string]string{}}))
	if rels, err := f.Releases(ctx, "o/empty"); err != nil || len(rels) != 0 {
		t.Errorf("no files: %+v %v", rels, err)
	}

	// The Hub's 401 and 403 for a repository it does not show are that
	// repository's answer, not a hold of the upstream; the proxy's own
	// refusals keep their meaning.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		reads.setDoc("/api/models/o/hidden/revision/main", fakeDoc{status: status})
		_, err := f.Releases(ctx, "o/hidden")
		mustErr(t, err, true, false, "does not show this repository")
		if _, ok := RetryAfterOf(err); ok {
			t.Errorf("a %d holds the upstream: %v", status, err)
		}
	}
	reads.setDoc("/api/models/o/held/revision/main", fakeDoc{status: 403, gate: "access-control", code: "forbidden"})
	_, err = f.Releases(ctx, "o/held")
	if d, ok := RetryAfterOf(err); !ok || IsPermanent(err) || d != holdAfterRefusal {
		t.Errorf("an access-control refusal: %v", err)
	}
	reads.setDoc("/api/models/o/squat/revision/main", fakeDoc{status: 403, gate: "nameguard", code: "typosquat"})
	_, err = f.Releases(ctx, "o/squat")
	mustErr(t, err, true, false, "nameguard")
	reads.setDoc("/api/models/o/busy/revision/main", fakeDoc{status: 429, retry: 40 * time.Second})
	_, err = f.Releases(ctx, "o/busy")
	if d, ok := RetryAfterOf(err); !ok || d != 40*time.Second {
		t.Errorf("a 429: %v", err)
	}
	reads.setDoc("/api/models/o/quota/revision/main", fakeDoc{status: 429})
	_, err = f.Releases(ctx, "o/quota")
	if d, ok := RetryAfterOf(err); !ok || d != huggingfaceRateLimitWait || IsPermanent(err) {
		t.Errorf("a 429 that states no wait: %v", err)
	}
	_, err = f.Releases(ctx, "o/missing")
	mustErr(t, err, true, false, "not found")
	reads.set("/api/models/o/garbage/revision/main", []byte("<html>"))
	_, err = f.Releases(ctx, "o/garbage")
	mustErr(t, err, true, false, "metadata of o/garbage")
	for _, bad := range []string{"", "a/b/c", "../x", "a b/c", "-a/b", "a/b-", "datasets", "o/tree"} {
		_, err := f.Releases(ctx, bad)
		if bad == "datasets" || bad == "o/tree" {
			// Valid ids the backend reads otherwise.
			if err == nil {
				t.Errorf("%q: accepted", bad)
			}
			continue
		}
		mustErr(t, err, true, false, "not a Hugging Face repository id")
	}
}

// A dataset feed lists datasets and mirrors them at their dataset paths.
func TestHuggingFaceDatasets(t *testing.T) {
	srv := newFixtureServer(t)
	srv.on("GET", "/api/datasets?author=fka&limit=100&sort=lastModified&direction=-1").reply(200, fixture(t, "huggingface", "datasets-fka-page1.json"))
	reads := newFakeReads()
	reads.set("/api/datasets/fka/prompts.chat/revision/main", fixture(t, "huggingface", "revision-prompts-chat.json"))
	f := huggingfaceTestFeed(t, srv.URL(), reads, map[string]string{"author": "fka", "kind": "datasets"})
	listed, _ := drainBootstrap(t, f)
	if strings.Join(listed, ",") != "fka/prompts.chat" {
		t.Fatalf("listed %v", listed)
	}
	rels, err := f.Releases(context.Background(), "fka/prompts.chat")
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "huggingface", "releases-prompts-chat", viewReleases(rels))
	expectServed(t, huggingfaceTestBackend(t, f.k.env), rels, func(r Release, _ Artifact) (string, string) { return "datasets/fka/prompts.chat", r.Version })
}

func TestHuggingFaceListingErrors(t *testing.T) {
	srv := newFixtureServer(t)
	f := huggingfaceTestFeed(t, srv.URL(), newFakeReads(), map[string]string{"author": "acme"})
	ctx := context.Background()
	// A 429 says how long its window lasts in the RateLimit header.
	srv.on("GET", "/api/models").reply(429, nil).withHeader("RateLimit", `"api";r=0;t=42`)
	_, err := f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 42*time.Second || IsPermanent(err) {
		t.Errorf("a 429 with RateLimit: %v", err)
	}
	srv.on("GET", "/api/models").reply(429, nil).withHeader("RateLimit", `"api";r=0;t=42`).withHeader("Retry-After", "7")
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != 7*time.Second {
		t.Errorf("a 429 with Retry-After: %v", err)
	}
	srv.on("GET", "/api/models").reply(401, nil)
	_, err = f.Bootstrap(ctx, "")
	if d, ok := RetryAfterOf(err); !ok || d != holdAfterRefusal {
		t.Errorf("a refused listing (an expired token) holds the upstream: %v", err)
	}
	for name, tc := range map[string]struct {
		body, link, want string
	}{
		"garbage":   {"<html>", "", "not the listing expected"},
		"an object": {`{"models":[]}`, "", "not the listing expected"},
		"elsewhere": {`[{"id":"acme/a","lastModified":"2026-01-01T00:00:00.000Z"}]`, `<https://evil.example/api/models?cursor=x>; rel="next"`, "leaves the listing"},
	} {
		r := srv.on("GET", "/api/models").reply(200, []byte(tc.body))
		if tc.link != "" {
			r.withHeader("Link", tc.link)
		}
		_, err := f.Bootstrap(ctx, "")
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		mustErr(t, err, true, false, tc.want)
	}
	for v, want := range map[string]time.Duration{`"api";r=0;t=42`: 42 * time.Second, `"api";r=3;t=42`: 0, `"api";r=0;t=0`: 0, `garbage`: 0,
		`"pages";r=10;t=5, "api";r=0;t=99`: 99 * time.Second, `"api";r=0;t=999999999`: maxRetryAfter} {
		if d, _ := huggingfaceRateLimitReset(v); d != want {
			t.Errorf("RateLimit %q: %s, want %s", v, d, want)
		}
	}
}

func TestHuggingFaceFilePatterns(t *testing.T) {
	f := &huggingfaceFeed{}
	f.files, _ = huggingfaceParsePatterns("*.safetensors,config.json,onnx/*_q4.onnx")
	for name, want := range map[string]bool{"model.safetensors": true, "sub/model-00001.safetensors": true, "config.json": true, "sub/config.json": true,
		"onnx/x_q4.onnx": true, "onnx/x_fp16.onnx": false, "x_q4.onnx": false, "README.md": false, "pytorch_model.bin": false} {
		if got := f.wantFile(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// A pass that takes several calls goes on while repositories change under
// it: a repository modified during the pass comes with the next one; an
// author without repositories ends at once.
func TestHuggingFaceChangesDuringAPass(t *testing.T) {
	hub := newHFFakeHub(t)
	now := time.Now()
	for i := 0; i < 6; i++ {
		hub.put(fmt.Sprintf("%s/old%d", []string{"acme", "beta"}[i%2], i), now.Add(-time.Duration(40-i)*24*time.Hour))
	}
	f := huggingfaceTestFeed(t, hub.srv.URL, newFakeReads(), map[string]string{"author": "acme,beta,empty"})
	f.src.limit = 2
	_, cursor := drainBootstrap(t, f)
	for i := 0; i < 7; i++ {
		hub.put(fmt.Sprintf("%s/new%d", []string{"acme", "beta"}[i%3%2], i), now.Add(-time.Duration(60-i)*time.Minute))
	}
	f.list.maxPages = 1
	var got []string
	for i := 0; ; i++ {
		b, err := f.Changes(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, names(b.Items)...)
		cursor = b.Next
		if i == 1 {
			hub.put("acme/old2", now.Add(-time.Minute))
		}
		if !b.More {
			break
		}
		if i > 50 {
			t.Fatal("the pass does not end")
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "acme/new0,acme/new2,acme/new3,acme/new5,acme/new6,beta/new1,beta/new4" {
		t.Errorf("the pass reported %v", got)
	}
	f.list.maxPages = listingPages
	next, _ := drainChanges(t, f, cursor)
	if strings.Join(next, ",") != "acme/old2" {
		t.Errorf("the next pass reported %v", next)
	}
}
