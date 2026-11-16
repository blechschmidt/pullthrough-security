package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends/huggingface"
)

// huggingface follows the repositories of chosen authors on the Hugging Face
// Hub (Task 191).
//
// The Hub lists repositories by last modification, newest first
// ("GET /api/models?sort=lastModified&direction=-1&limit=100", likewise
// /api/datasets and /api/spaces), the next page named by the response's
// Link header: a keyset cursor on (lastModified, _id) that stays put while
// new commits arrive. A commit to a repository moves its lastModified, so the
// listing is a change feed of whole repositories, which listingFeed follows
// (listfeed.go): each item names a repository, without a version.
//
// The Hub is not enumerated whole — millions of repositories, more than 20
// PB, and 500 API calls per five minutes for an anonymous client: the feed
// needs a scope, the option "author" (users or organisations, comma-
// separated) and/or "search" (the Hub's search of repository names). The
// Hub takes one author per request, so each author is a listing of its own,
// and the source hands the listing driver them one after another
// (huggingfaceSource.recent). A pass of Changes reads each author newest
// first down to the oldest change the driver looks for — its mark less its
// lookback window, which the feed reads from the cursor and hands the
// source — and leaves out what is older: the driver would take an old
// repository of one author for the end of the pass, before the next
// author's changes. A page token names one author and one page of the Hub
// however many authors there are, and a pass reads every page once: a
// request per author, and one per further page of changes.
//
// The driver's next mark is the newest time a pass reports, and a pass may
// run over several calls with a batch worked between them. A repository of
// an author read early in the pass and modified meanwhile must not fall
// below the next mark's lookback window because a later author's newer
// change set the mark: so no time a pass reports lies past its ceiling — when
// the Hub served the pass's first page (its Date header; the proxy's clock
// without one), carried in every page token after it — and a later change
// is reported at the ceiling. What is modified during a pass is then newer
// than the next mark, and comes with the next pass. Bootstrap takes its mark
// from the first page of every author, and lists the scope's repositories
// author by author. The cursor names the scope it was made for: another
// kind, author list or search starts the enumeration over.
//
// Releases reads the repository's metadata at its main branch
// ("/api/models/<repo>/revision/main", as huggingface_hub's snapshot_download
// does) through the gated pipeline and lists one release: the commit main is
// at, with one artifact per file ("siblings") at
// "/<repo>/resolve/<commit>/<file>" — the backend caches a resolve only when
// it is pinned to a commit (huggingface.ResolvePath). The metadata states no
// sizes through the proxy (a system fetch carries no query, and sizes need
// "?blobs=true"). The option "files" (comma-separated globs, matched against
// a file's path and, for a pattern without "/", its name) keeps some files;
// by default every file is mirrored. A gated or private repository is
// skipped (a Permanent error naming why) unless the option "restricted" is
// "include", for an upstream whose token may download it; a disabled one is
// always skipped. The Hub answers a repository it will not show — private,
// renamed, deleted — with a 401 for an anonymous client: on a metadata read
// that is the repository's answer, not a hold of the upstream. With
// restricted repositories included, the Hub is then asked whether it still
// takes the upstream's token (GET /api/whoami-v2): an expired or revoked
// token has every gated and private repository answer 401 while public ones
// still read, and holds the upstream instead.
//
// The public Hub's API is https://huggingface.co, for an upstream on hf.co
// too (hf.co answers the API with a redirect there; the upstream's token is
// sent to the upstream's own origin only, so give the upstream as
// https://huggingface.co for it to apply to the listing). An upstream
// elsewhere — Artifactory's or Nexus' Hugging Face repositories, which serve
// models but no listing — needs the option "url", an API that lists
// repositories as the Hub does (the Hub itself: the listing is then read
// from the Hub while metadata and files come through the upstream). A next
// page's link may name the origin the page was served from after a redirect.

// Defaults and bounds of the huggingface feed.
const (
	// huggingfacePageSize is how many repositories a listing page asks for.
	huggingfacePageSize = 100
	// huggingfaceMaxAuthors bounds the authors of the scope (a listing each).
	huggingfaceMaxAuthors = 32
	// huggingfaceMaxSearch bounds the search option.
	huggingfaceMaxSearch = 256
	// huggingfaceMaxPatterns bounds the files option.
	huggingfaceMaxPatterns = 64
	// huggingfaceMaxPage bounds a listing page and huggingfaceMaxInfo a repository's metadata.
	huggingfaceMaxPage = 16 << 20
	huggingfaceMaxInfo = 64 << 20
	// huggingfaceMaxFiles bounds the files of a repository's revision.
	huggingfaceMaxFiles = 100_000
	// huggingfaceMaxCursor bounds the Hub's cursor of a page (344 characters
	// on 2026-11-16): a page token is the author's index, the pass's
	// ceiling and the cursor (huggingfaceSource.passToken), and must fit the
	// listing driver's listingMaxToken.
	huggingfaceMaxCursor = listingMaxToken - 32
	// huggingfaceMaxCeiling bounds a pass's ceiling, in Unix seconds (the
	// end of the year 9999).
	huggingfaceMaxCeiling = 253402300799
	// huggingfaceRateLimitWait is the wait after a 429 that states none.
	huggingfaceRateLimitWait = time.Minute
)

// huggingfacePublicHosts are the public Hub's names, and huggingfacePublicAPI
// its API.
var huggingfacePublicHosts = []string{"huggingface.co", "hf.co"}

const huggingfacePublicAPI = "https://huggingface.co"

// huggingfaceKinds maps the kind option to the API's collection and the backend's
// repository kind.
var huggingfaceKinds = map[string]string{"models": huggingface.RepoModel, "datasets": huggingface.RepoDataset, "spaces": huggingface.RepoSpace}

type huggingfaceFeed struct {
	list *listingFeed
	src  *huggingfaceSource
	k    kit
	// repoType is the backend's kind of the repositories followed.
	repoType string
	// restricted mirrors gated and private repositories.
	restricted bool
	// files are the glob patterns of the files mirrored; nil mirrors every
	// file.
	files []string
	// scope fingerprints the listing the cursor is for.
	scope string
}

// huggingfaceSource reads the Hub's listings of one kind of repository.
type huggingfaceSource struct {
	k   kit
	api *url.URL
	// kind is the API's collection ("models").
	kind string
	// authors are the authors listed, each a listing (sorted); nil lists
	// the search alone.
	authors []string
	search  string
	limit   int
	// now is the proxy's clock: the ceiling of a pass whose first page
	// states no Date.
	now func() time.Time

	// pass is the pass of Changes running; nil while Bootstrap takes its
	// mark.
	mu   sync.Mutex
	pass *huggingfacePass
}

// huggingfacePass is what the source knows of the listing driver's pass: its
// mark, and its floor — the oldest lastModified the driver reports, the mark
// less the lookback window.
type huggingfacePass struct {
	mark, floor time.Time
}

// setPass sets the pass of Changes the source reads for (nil: Bootstrap).
func (s *huggingfaceSource) setPass(p *huggingfacePass) {
	s.mu.Lock()
	s.pass = p
	s.mu.Unlock()
}

func newHuggingFaceFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "kind", "author", "search", "restricted", "files")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var api *url.URL
	switch {
	case opts["url"] != "":
		if api, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, huggingfacePublicHosts...):
		api, _ = url.Parse(huggingfacePublicAPI)
	default:
		return nil, fmt.Errorf("upstream %s is not the Hugging Face Hub, whose listing is known: set fullMirror.feed.url to an API that lists repositories as the Hub does (https://huggingface.co itself: the listing is read there, metadata and files through the upstream)", k.upstream.Redacted())
	}
	kind, err := opts.oneOf("kind", "models", "datasets", "spaces")
	if err != nil {
		return nil, err
	}
	authors, err := huggingfaceParseAuthors(opts["author"])
	if err != nil {
		return nil, err
	}
	search := opts["search"]
	if len(search) > huggingfaceMaxSearch {
		return nil, fmt.Errorf("option search is %d bytes long; at most %d are taken", len(search), huggingfaceMaxSearch)
	}
	if len(authors) == 0 && search == "" {
		return nil, errors.New("full mirroring of the Hugging Face Hub needs a scope: set fullMirror.feed.author (users or organisations, comma-separated) " +
			"and/or fullMirror.feed.search — the Hub holds millions of repositories (more than 20 PB) and lets an anonymous client make 500 API calls " +
			"per five minutes, so it is not enumerated whole (see docs/full-mirroring.md#huggingface)")
	}
	restricted, err := opts.oneOf("restricted", "skip", "include")
	if err != nil {
		return nil, err
	}
	patterns, err := huggingfaceParsePatterns(opts["files"])
	if err != nil {
		return nil, err
	}
	src := &huggingfaceSource{k: k, api: api, kind: kind, authors: authors, search: search, limit: huggingfacePageSize}
	sum := sha256.Sum256([]byte(kind + "\n" + strings.Join(authors, ",") + "\n" + search))
	f := &huggingfaceFeed{src: src, k: k, repoType: huggingfaceKinds[kind], restricted: restricted == "include", files: patterns, scope: hex.EncodeToString(sum[:8])}
	f.list = newListingFeed("huggingface-listing", src)
	src.now = func() time.Time { return f.list.now() }
	return f, nil
}

func init() { Register("huggingface", newHuggingFaceFeed) }

// huggingfaceParseAuthors reads the author option: names separated by commas, sorted
// and each once.
func huggingfaceParseAuthors(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, a := range strings.Split(v, ",") {
		a = strings.TrimSpace(a)
		if !huggingfaceValidSegment(a) {
			return nil, fmt.Errorf("option author: %q is not a user or organisation name of the Hub", a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if len(out) > huggingfaceMaxAuthors {
		return nil, fmt.Errorf("option author names %d authors; at most %d are followed (each is a listing of its own)", len(out), huggingfaceMaxAuthors)
	}
	sort.Strings(out)
	return out, nil
}

// huggingfaceParsePatterns reads the files option: glob patterns separated by commas.
func huggingfaceParsePatterns(v string) ([]string, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" || len(p) > 256 {
			return nil, fmt.Errorf("option files: %q is not a file pattern", p)
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("option files: %q is not a glob pattern: %v", p, err)
		}
		out = append(out, p)
	}
	if len(out) > huggingfaceMaxPatterns {
		return nil, fmt.Errorf("option files names %d patterns; at most %d are taken", len(out), huggingfaceMaxPatterns)
	}
	return out, nil
}

// wantFile reports whether a repository file is mirrored.
func (f *huggingfaceFeed) wantFile(name string) bool {
	if f.files == nil {
		return true
	}
	base := name[strings.LastIndex(name, "/")+1:]
	for _, p := range f.files {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
		if !strings.Contains(p, "/") {
			if ok, _ := path.Match(p, base); ok {
				return true
			}
		}
	}
	return false
}

// huggingfaceValidSegment reports whether s is a user, organisation or repository name
// of the Hub: letters, digits, "-", "_" and ".", at most 96 characters, not
// starting or ending with "-" or ".", without "--" or "..".
func huggingfaceValidSegment(s string) bool {
	if s == "" || len(s) > 96 || strings.Contains(s, "--") || strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s[0] != '-' && s[0] != '.' && s[len(s)-1] != '-' && s[len(s)-1] != '.'
}

// huggingfaceValidRepoID reports whether s is a repository id: "owner/name", or a
// canonical name of one segment.
func huggingfaceValidRepoID(s string) bool {
	owner, name, nested := strings.Cut(s, "/")
	if !nested {
		return huggingfaceValidSegment(s)
	}
	return huggingfaceValidSegment(owner) && huggingfaceValidSegment(name)
}

// huggingfaceCursor wraps the listing feed's cursor with the scope it was made for.
type huggingfaceCursor struct {
	Format string `json:"format"`
	Scope  string `json:"scope"`
	Inner  string `json:"inner"`
}

func (c *huggingfaceCursor) cursorFormat() string { return c.Format }

func (f *huggingfaceFeed) format() string { return cursorFormat("huggingface", 1) }

// unwrap returns the listing cursor a cursor carries ("" for "").
func (f *huggingfaceFeed) unwrap(cursor string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	var c huggingfaceCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return "", err
	}
	if c.Scope != f.scope {
		return "", fmt.Errorf("%w: the huggingface cursor was made for another scope (kind, author or search changed)", ErrCursorInvalid)
	}
	if c.Inner == "" {
		return "", fmt.Errorf("%w: the huggingface cursor carries no position", ErrCursorInvalid)
	}
	return c.Inner, nil
}

func (f *huggingfaceFeed) wrap(b Batch) Batch {
	b.Next = encodeCursor(&huggingfaceCursor{Format: f.format(), Scope: f.scope, Inner: b.Next})
	return b
}

// Bootstrap takes the mark from the newest repositories of the scope, then
// lists the scope's repositories.
func (f *huggingfaceFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	inner, err := f.unwrap(cursor)
	if err != nil {
		return Batch{}, err
	}
	f.src.setPass(nil)
	b, err := f.list.Bootstrap(ctx, inner)
	if err != nil {
		return Batch{}, err
	}
	return f.wrap(b), nil
}

// Changes pages the scope's listings down to the mark.
func (f *huggingfaceFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	inner, err := f.unwrap(cursor)
	if err != nil {
		return Batch{}, err
	}
	if inner == "" {
		return Batch{}, fmt.Errorf("%w: the huggingface feed has no cursor to continue from", ErrCursorInvalid)
	}
	// The driver reports nothing older than its mark less its lookback
	// window: the source reads each author down to there.
	c, err := f.list.decode(inner)
	if err != nil {
		return Batch{}, err
	}
	f.src.setPass(&huggingfacePass{mark: c.Mark, floor: c.Mark.Add(-f.list.lookback)})
	defer f.src.setPass(nil)
	b, err := f.list.Changes(ctx, inner)
	if err != nil {
		return Batch{}, err
	}
	return f.wrap(b), nil
}

// huggingfaceItem is one repository of a listing.
type huggingfaceItem struct {
	id  string
	oid string
	sha string
	// time is lastModified, the listing's sort key; raw is it as the Hub
	// spells it.
	time time.Time
	raw  string
}

func (it huggingfaceItem) listing() listingItem {
	key := it.oid
	if key == "" {
		key = it.id
	}
	mod := it.sha
	if len(mod) > 12 {
		mod = mod[:12]
	}
	if mod == "" {
		mod = it.raw
	}
	return listingItem{Name: it.id, Time: it.time, ID: key + "@" + mod}
}

// huggingfaceParseListing reads a listing page; items that cannot be followed (no
// valid id or time) are dropped, the page's order kept.
func huggingfaceParseListing(body []byte) ([]huggingfaceItem, error) {
	var page []struct {
		OID          string `json:"_id"`
		ID           string `json:"id"`
		LastModified string `json:"lastModified"`
		SHA          string `json:"sha"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, err
	}
	if page == nil {
		return nil, errors.New("the page is not a list")
	}
	out := make([]huggingfaceItem, 0, len(page))
	for _, p := range page {
		t, err := time.Parse(time.RFC3339Nano, p.LastModified)
		if err != nil || !huggingfaceValidRepoID(p.ID) || len(p.LastModified) > 64 {
			continue
		}
		it := huggingfaceItem{id: p.ID, time: t.UTC(), raw: p.LastModified}
		if huggingfaceIsObjectID(p.OID) {
			it.oid = p.OID
		}
		if huggingfaceIsSHA(p.SHA) {
			it.sha = strings.ToLower(p.SHA)
		}
		out = append(out, it)
	}
	return out, nil
}

// huggingfaceGated reads a "gated" field: false, or the kind of gate ("auto",
// "manual").
func huggingfaceGated(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "false" || string(raw) == "null" {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s != "" && s != "false"
	}
	return string(raw) == "true"
}

// huggingfaceIsObjectID reports whether s is a repository's _id (24 hex digits).
func huggingfaceIsObjectID(s string) bool {
	if len(s) != 24 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// huggingfaceIsSHA reports whether s is a full commit SHA.
func huggingfaceIsSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// pageURL is the URL of a listing page of author i (or of the search
// alone), at the Hub's cursor ("" for the first page).
func (s *huggingfaceSource) pageURL(i int, cursor string) string {
	// The two fields expanded are all the listing is read for (an expanded
	// listing holds nothing else but the ids): whether a repository is gated,
	// private or disabled is read from its metadata when it is mirrored.
	q := url.Values{"sort": {"lastModified"}, "direction": {"-1"}, "limit": {strconv.Itoa(s.limit)}, "expand": {"lastModified", "sha"}}
	if len(s.authors) > 0 {
		q.Set("author", s.authors[i])
	}
	if s.search != "" {
		q.Set("search", s.search)
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	return join(s.api, "api/"+s.kind) + "?" + q.Encode()
}

// sources is how many listings the scope reads.
func (s *huggingfaceSource) sources() int {
	if len(s.authors) == 0 {
		return 1
	}
	return len(s.authors)
}

// huggingfacePage is a page of a listing: its repositories, the Hub's cursor
// of the next page ("" at the end), and when the Hub served it (its Date
// header; zero when it states none).
type huggingfacePage struct {
	items []huggingfaceItem
	next  string
	date  time.Time
}

// fetch reads a listing page of author i (or of the search alone).
func (s *huggingfaceSource) fetch(ctx context.Context, i int, cursor string) (huggingfacePage, error) {
	target := s.pageURL(i, cursor)
	body, resp, err := s.k.get(ctx, target, http.Header{"Accept": {"application/json"}}, huggingfaceMaxPage)
	if err != nil {
		return huggingfacePage{}, fmt.Errorf("listing the Hub's %s: %w", s.kind, huggingfaceRateLimited(resp, err))
	}
	items, err := huggingfaceParseListing(body)
	if err != nil {
		return huggingfacePage{}, Permanent(fmt.Errorf("listing the Hub's %s: the page is not the listing expected: %w", s.kind, err))
	}
	var served *url.URL
	if resp.Request != nil {
		served = resp.Request.URL
	}
	next, err := s.nextCursor(resp.Header.Values("Link"), served)
	if err != nil {
		return huggingfacePage{}, Permanent(fmt.Errorf("listing the Hub's %s: %w", s.kind, err))
	}
	if len(items) == 0 || next == cursor {
		// An empty page ends the listing, and so does a next page that is
		// this one: the listing would not advance.
		next = ""
	}
	pg := huggingfacePage{items: items, next: next}
	if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
		pg.date = t.UTC()
	}
	return pg, nil
}

// nextCursor finds the Hub's cursor in a page's Link header: the URL of
// rel="next" must stay on the listing — the API's origin and listing path, or
// the origin and path the page was served from after a redirect (served;
// nil when unknown). Only the cursor is kept: the next request goes to the
// API again.
func (s *huggingfaceSource) nextCursor(values []string, served *url.URL) (string, error) {
	for _, v := range values {
		for _, link := range huggingfaceSplitLinks(v) {
			target, params, ok := strings.Cut(link, ">")
			target = strings.TrimSpace(target)
			if !ok || !strings.HasPrefix(target, "<") || !huggingfaceRelNext(params) {
				continue
			}
			u, err := url.Parse(target[1:])
			if err != nil || !u.IsAbs() {
				return "", fmt.Errorf("the next page's link %q is not a URL", truncate(target, 120))
			}
			listing, _ := url.Parse(join(s.api, "api/"+s.kind))
			on := func(at *url.URL) bool {
				return at != nil && strings.EqualFold(u.Scheme, at.Scheme) && strings.EqualFold(u.Host, at.Host) && u.Path == at.Path
			}
			if !on(listing) && !on(served) {
				return "", fmt.Errorf("the next page's link leaves the listing (%s)", truncate(u.Redacted(), 120))
			}
			c := u.Query().Get("cursor")
			if !huggingfaceValidCursor(c) {
				return "", errors.New("the next page's link carries no cursor")
			}
			return c, nil
		}
	}
	return "", nil
}

// huggingfaceSplitLinks splits a Link header into its links ("<…>; rel=…").
func huggingfaceSplitLinks(v string) []string {
	var out []string
	for {
		v = strings.TrimLeft(v, " ,")
		if v == "" {
			return out
		}
		end := strings.Index(v, ">")
		if end < 0 {
			return append(out, v)
		}
		next := strings.Index(v[end:], ",")
		if next < 0 {
			return append(out, v)
		}
		out = append(out, v[:end+next])
		v = v[end+next+1:]
	}
}

// huggingfaceRelNext reports whether a link's parameters name it rel="next".
func huggingfaceRelNext(params string) bool {
	for _, p := range strings.Split(params, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "rel") {
			for _, rel := range strings.Fields(strings.Trim(strings.TrimSpace(v), `"`)) {
				if strings.EqualFold(rel, "next") {
					return true
				}
			}
		}
	}
	return false
}

// huggingfaceRateLimited adds the wait a 429 states in its RateLimit header
// ("api";r=0;t=<seconds until the window resets>) when it has no
// Retry-After.
func huggingfaceRateLimited(resp *http.Response, err error) error {
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		return err
	}
	if _, ok := RetryAfterOf(err); ok {
		return err
	}
	if d, ok := huggingfaceRateLimitReset(resp.Header.Get("RateLimit")); ok {
		return RetryAfter(err, d)
	}
	return err
}

// huggingfaceRateLimitReset reads the seconds a RateLimit header says remain in the
// exhausted window (draft-ietf-httpapi-ratelimit-headers: "policy";r=…;t=…).
func huggingfaceRateLimitReset(v string) (time.Duration, bool) {
	best := time.Duration(0)
	for _, item := range strings.Split(v, ",") {
		remaining, reset := -1, -1
		for _, p := range strings.Split(item, ";") {
			k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
			if !ok {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || n < 0 {
				continue
			}
			switch strings.TrimSpace(k) {
			case "r":
				remaining = n
			case "t":
				reset = n
			}
		}
		if remaining == 0 && reset > 0 {
			if d := time.Duration(reset) * time.Second; d > best {
				best = d
			}
		}
	}
	if best <= 0 {
		return 0, false
	}
	if best > maxRetryAfter {
		best = maxRetryAfter
	}
	return best, true
}

// huggingfaceValidCursor reports whether c is a Hub cursor a page token can
// carry: printable ASCII without a blank, a quote or a backslash, at most
// huggingfaceMaxCursor characters.
func huggingfaceValidCursor(c string) bool {
	if c == "" || len(c) > huggingfaceMaxCursor {
		return false
	}
	for i := 0; i < len(c); i++ {
		if b := c[i]; b <= ' ' || b >= 0x7f || b == '"' || b == '\\' {
			return false
		}
	}
	return true
}

// A page token names an author, by its index in the sorted author list, and
// a page of its listing, by the Hub's cursor ("" for the author's first
// page): "<author>:<cursor>" in Bootstrap's enumeration, and with the pass's
// ceiling in Unix seconds, "<author>:<ceiling>:<cursor>", in a pass of
// Changes. The token "" is the first page of the first author.

// everyToken is a page token of Bootstrap's enumeration.
func (s *huggingfaceSource) everyToken(author int, cursor string) string {
	return strconv.Itoa(author) + ":" + cursor
}

// passToken is a page token of a pass of Changes.
func (s *huggingfaceSource) passToken(author int, ceiling time.Time, cursor string) string {
	return strconv.Itoa(author) + ":" + strconv.FormatInt(ceiling.Unix(), 10) + ":" + cursor
}

// author reads the author's index of a page token.
func (s *huggingfaceSource) author(n string) (int, bool) {
	a, err := strconv.Atoi(n)
	return a, err == nil && a >= 0 && a < s.sources() && n == strconv.Itoa(a)
}

// parseEveryToken reads a page token of Bootstrap's enumeration.
func (s *huggingfaceSource) parseEveryToken(token string) (int, string, error) {
	if token == "" {
		return 0, "", nil
	}
	n, cursor, ok := strings.Cut(token, ":")
	author, valid := s.author(n)
	if !ok || !valid || (cursor != "" && !huggingfaceValidCursor(cursor)) {
		return 0, "", fmt.Errorf("%w: the huggingface page token %q does not read", ErrCursorInvalid, truncate(token, 40))
	}
	return author, cursor, nil
}

// parsePassToken reads a page token of a pass of Changes (the ceiling is
// zero for "", the pass's first page).
func (s *huggingfaceSource) parsePassToken(token string) (int, time.Time, string, error) {
	if token == "" {
		return 0, time.Time{}, "", nil
	}
	n, rest, ok := strings.Cut(token, ":")
	c, cursor, ok2 := strings.Cut(rest, ":")
	author, valid := s.author(n)
	sec, err := strconv.ParseInt(c, 10, 64)
	if !ok || !ok2 || !valid || err != nil || sec < 0 || sec > huggingfaceMaxCeiling || c != strconv.FormatInt(sec, 10) ||
		(cursor != "" && !huggingfaceValidCursor(cursor)) {
		return 0, time.Time{}, "", fmt.Errorf("%w: the huggingface page token %q does not read", ErrCursorInvalid, truncate(token, 40))
	}
	return author, time.Unix(sec, 0).UTC(), cursor, nil
}

// recent reads the next page of the scope's listings for the listing driver.
//
// In a pass of Changes it reads the authors one after another, each newest
// first down to the pass's floor: an older repository is left out — the
// driver would take it for the end of the pass — and ends the author. The
// pass's first page (token "") sets the pass's ceiling, which every token
// after it carries: a repository modified since is reported at the ceiling,
// so that the next mark stays below what changed during the pass.
//
// While Bootstrap takes its mark (no pass), it reads the first page of every
// author, newest first, and ends there: the newest repository of the scope
// is the mark, and those of these pages within the lookback window below it
// are remembered (an author's past its first page may come again, once).
func (s *huggingfaceSource) recent(ctx context.Context, token string) (listingPage, error) {
	s.mu.Lock()
	pass := s.pass
	s.mu.Unlock()
	if pass == nil {
		if token != "" {
			return listingPage{}, fmt.Errorf("%w: the huggingface page token %q continues a pass of Changes", ErrCursorInvalid, truncate(token, 40))
		}
		return s.newest(ctx)
	}
	author, ceiling, cursor, err := s.parsePassToken(token)
	if err != nil {
		return listingPage{}, err
	}
	pg, err := s.fetch(ctx, author, cursor)
	if err != nil {
		return listingPage{}, err
	}
	if token == "" {
		if ceiling = pg.date; ceiling.Unix() <= 0 {
			now := time.Now
			if s.now != nil {
				now = s.now
			}
			ceiling = now().UTC().Truncate(time.Second)
		}
	}
	if ceiling.Before(pass.mark) {
		// The Hub's clock behind the mark: a clamped time must not fall
		// below the floor, where the driver would end the pass.
		ceiling = pass.mark
	}
	var out listingPage
	reached := false
	for _, it := range pg.items {
		if it.time.Before(pass.floor) {
			reached = true
			continue
		}
		li := it.listing()
		if li.Time.After(ceiling) {
			li.Time = ceiling
		}
		out.Items = append(out.Items, li)
	}
	switch {
	case !reached && pg.next != "":
		out.Next = s.passToken(author, ceiling, pg.next)
	case author+1 < s.sources():
		out.Next = s.passToken(author+1, ceiling, "")
	}
	return out, nil
}

// newest reads the first page of every author: the scope's newest
// repositories, newest first.
func (s *huggingfaceSource) newest(ctx context.Context) (listingPage, error) {
	var out []listingItem
	for i := 0; i < s.sources(); i++ {
		pg, err := s.fetch(ctx, i, "")
		if err != nil {
			return listingPage{}, err
		}
		for _, it := range pg.items {
			out = append(out, it.listing())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return listingPage{Items: out}, nil
}

// every reads the next page of the scope's repositories, author by author.
func (s *huggingfaceSource) every(ctx context.Context, token string) (listingPage, error) {
	author, cursor, err := s.parseEveryToken(token)
	if err != nil {
		return listingPage{}, err
	}
	pg, err := s.fetch(ctx, author, cursor)
	if err != nil {
		return listingPage{}, err
	}
	out := listingPage{Items: make([]listingItem, 0, len(pg.items))}
	for _, it := range pg.items {
		out.Items = append(out.Items, it.listing())
	}
	switch {
	case pg.next != "":
		out.Next = s.everyToken(author, pg.next)
	case author+1 < s.sources():
		out.Next = s.everyToken(author+1, "")
	}
	return out, nil
}

// huggingfaceRevision is what Releases reads of a repository's metadata.
type huggingfaceRevision struct {
	sha      string
	modified time.Time
	gated    bool
	private  bool
	disabled bool
	files    []string
}

// huggingfaceParseRevision reads a repository's metadata document.
func huggingfaceParseRevision(body []byte) (huggingfaceRevision, error) {
	var doc struct {
		SHA          string          `json:"sha"`
		LastModified string          `json:"lastModified"`
		Private      bool            `json:"private"`
		Gated        json.RawMessage `json:"gated"`
		Disabled     bool            `json:"disabled"`
		Siblings     *[]struct {
			RFilename string `json:"rfilename"`
		} `json:"siblings"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return huggingfaceRevision{}, err
	}
	if doc.Siblings == nil {
		return huggingfaceRevision{}, errors.New("it lists no files (siblings)")
	}
	if len(*doc.Siblings) > huggingfaceMaxFiles {
		return huggingfaceRevision{}, fmt.Errorf("it lists %d files; at most %d are followed", len(*doc.Siblings), huggingfaceMaxFiles)
	}
	rev := huggingfaceRevision{gated: huggingfaceGated(doc.Gated), private: doc.Private, disabled: doc.Disabled}
	if huggingfaceIsSHA(doc.SHA) {
		rev.sha = strings.ToLower(doc.SHA)
	}
	if t, err := time.Parse(time.RFC3339Nano, doc.LastModified); err == nil {
		rev.modified = t.UTC()
	}
	for _, s := range *doc.Siblings {
		if s.RFilename != "" && len(s.RFilename) <= 1024 && snapValidString(s.RFilename, 1024) {
			rev.files = append(rev.files, s.RFilename)
		}
	}
	return rev, nil
}

// readInfo reads a repository's metadata through the gated pipeline. A 401
// or 403 the Hub answered (no gate refused it) is the repository's answer —
// private, gated, renamed or deleted — and permanent: it must not hold the
// upstream as a refused authorization would. With restricted repositories
// included, a 401 may also be the upstream's token, expired or revoked (the
// Hub answers public metadata whatever the token): the Hub is asked whether
// it takes the token (checkToken), and a refused token holds the upstream
// instead.
func (f *huggingfaceFeed) readInfo(ctx context.Context, p string) ([]byte, error) {
	if f.k.env.Read == nil {
		return nil, errValidationOnly
	}
	buf := &boundedBuffer{limit: huggingfaceMaxInfo}
	res, err := f.k.env.Read(ctx, p, "application/json", buf)
	if buf.exceeded {
		return nil, Permanent(fmt.Errorf("reading %s: %w (%d bytes)", p, errTooLarge, int64(huggingfaceMaxInfo)))
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s through the proxy: %w", p, err)
	}
	switch {
	case res.Status == http.StatusOK:
		return buf.buf.Bytes(), nil
	case res.Gate == "" && (res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden):
		if res.Status == http.StatusUnauthorized {
			if err := f.checkToken(ctx); err != nil {
				return nil, err
			}
		}
		return nil, Permanent(fmt.Errorf("reading %s: status %d: the Hub does not show this repository to the upstream's credentials "+
			"(private, gated without access, renamed or deleted)", p, res.Status))
	case res.Gate == "" && res.Status == http.StatusTooManyRequests && res.RetryAfter <= 0:
		// The Hub states when its five-minute window resets in a RateLimit
		// header the pipeline does not relay: asked again at once, the read
		// would only spend more of the quota.
		return nil, RetryAfter(fmt.Errorf("reading %s: status 429: the Hub's rate limit", p), huggingfaceRateLimitWait)
	}
	return nil, readError(p, res)
}

// checkToken asks the Hub whether it takes the upstream's token
// (GET /api/whoami-v2), when restricted repositories are mirrored with one —
// an upstream with credentials whose API is its own origin. A refused token
// holds the upstream (kit's answer to a 401); any other failure is returned
// too, to be tried again. Nil: the token is fine, or there is none to ask
// about.
func (f *huggingfaceFeed) checkToken(ctx context.Context) error {
	if !f.restricted || f.k.env.Authorize == nil || !f.k.sameOrigin(f.src.api) {
		return nil
	}
	if _, _, err := f.k.get(ctx, join(f.src.api, "api/whoami-v2"), http.Header{"Accept": {"application/json"}}, 1<<20); err != nil {
		return fmt.Errorf("the Hub answered 401 for a repository's metadata, and refuses the upstream's token (or could not be asked about it): %w", err)
	}
	return nil
}

// Releases lists the commit the repository's main branch is at, with its
// files.
func (f *huggingfaceFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !huggingfaceValidRepoID(name) {
		return nil, Permanent(fmt.Errorf("%q is not a Hugging Face repository id", truncate(name, 200)))
	}
	info, ok := huggingface.InfoPath(f.repoType, name, "main")
	if !ok {
		return nil, Permanent(fmt.Errorf("the backend serves no metadata document for %s", name))
	}
	body, err := f.readInfo(ctx, info)
	if err != nil {
		return nil, err
	}
	rev, err := huggingfaceParseRevision(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the metadata of %s: %w", name, err))
	}
	switch {
	case rev.disabled:
		return nil, Permanent(fmt.Errorf("%s is disabled on the Hub: its files are not served", name))
	case (rev.gated || rev.private) && !f.restricted:
		what := "gated: its files are served only to accounts that accepted its conditions"
		if rev.private {
			what = "private"
		}
		return nil, Permanent(fmt.Errorf("%s is %s; it is not mirrored (set fullMirror.feed.restricted to include, with a token that may download it, or exclude it)", name, what))
	case rev.sha == "":
		return nil, Permanent(fmt.Errorf("the metadata of %s names no commit", name))
	}
	rel := Release{Version: rev.sha, Published: rev.modified}
	for _, file := range rev.files {
		if !f.wantFile(file) {
			continue
		}
		if p, ok := huggingface.ResolvePath(f.repoType, name, rev.sha, file); ok {
			rel.Artifacts = append(rel.Artifacts, Artifact{Path: p})
		}
	}
	if len(rel.Artifacts) == 0 {
		return nil, nil
	}
	sort.Slice(rel.Artifacts, func(i, j int) bool { return rel.Artifacts[i].Path < rel.Artifacts[j].Path })
	return []Release{rel}, nil
}
