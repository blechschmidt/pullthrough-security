package fullmirror

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/backends/dart"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// dart follows pub.dev's feed of recently published versions, and its
// listing of packages by last publication where the feed does not reach back
// far enough.
//
// pub.dev's listings state no times: `/api/packages?page=N` and the lighter
// `/packages.json?page=N` (50 names, 2.7 KB a page) order every package by
// when its newest version was published (prereleases and retracted versions
// included) and name each package's latest stable version, not that time. The
// times are in the Atom feed (`/feed.atom`, 80 KB): the 100 most recently
// published versions with their publication times, retracted ones left out —
// two to four hours of pub.dev's publishing (2h16m on 2026-11-16). Changes
// reads the feed and reports, by name, every package with a version newer
// than the high-water mark (listfeed.go). The feed carries changelog excerpts
// escaped for markup only: a character XML does not allow in them (a
// terminal's escape code) is replaced before the feed is parsed.
//
// When the feed does not reach back to the mark (the follower was stopped,
// paused, outside its off-peak window, or busy with a long batch), the pass
// goes on through the listing `/packages.json?page=N`: it reports every
// package the listing names that the feed does not, and reads the document of
// each page's last package (`/api/packages/<name>`) for the time the listing
// is ordered by, stopping at the first page that ends before the mark — so at
// most a page of unchanged packages is reported again. A pass that would need
// more than 400 pages (20,000 packages) starts over with Bootstrap.
//
// Every pub.dev instance serves the listing from its own copy, which takes in
// the packages published since every 15 minutes, and consecutive requests
// reach different instances: a page from an instance that has taken in the
// latest packages, followed by the next page from one that has not, skips as
// many packages as the second lists fewer above that place. So the pass
// checks each boundary between two pages: the page after it continues the
// page before when it repeats one of that page's last packages, and every
// page does when nothing was published in the 35 minutes before the feed was
// read (every instance lists the same then). Any other boundary is kept in the
// cursor, identified by the packages listed on its two sides, and looked at
// again once 35 minutes have passed, when every instance lists at least what
// the two pages were read from: a page listing both sides names the packages
// in between, and so does the page after the boundary when it starts after
// the side before it (which the page before still lists) — those are reported
// then. A boundary not found again within 12 polls and a day starts the
// enumeration over rather than leave a gap. Packages published in the 35
// minutes before a page is read are listed in different places by different
// instances and identify no boundary; while pub.dev publishes more versions
// in that time than its feed holds, a pass that needs the listing waits for
// them to settle.
//
// Changes are names alone: a package's document can lag the feed behind
// caches, and the engine mirrors whatever versions the document lists.
// Versions younger than the feed option "settle" (by pub.dev's clock) are held
// back until a later pass, to give the document time to list them. The
// default is 5 minutes when the documents are pub.dev's own (pub.dev empties
// its caches on publication), and 2h30m when the upstream is another server in
// front of pub.dev whose feed the option "url" names (an Artifactory remote
// keeps a document two hours by default; a mirror syncs late). A settle
// period longer than the feed's span leaves none of its versions to report:
// the pass then reads the listing from its top, reporting the packages the
// feed does not name in every pass until they are older than the mark.
//
// Bootstrap takes the mark from the feed (the start of the settle period when
// none of its versions has settled), then lists every package of
// `/api/package-names` (one document of every name, which pub.dev serves only
// gzip-compressed and caches for up to two hours) together with the packages
// of the feed — a package created while the name list was cached is older than
// the mark, and would be missed — in name order, 5,000 names a batch, each
// batch continuing after the last name listed. Names spelt with upper-case
// letters (a dozen legacy packages) are not names the backend serves, and are
// left out.
//
// Releases reads the package's document (`/api/packages/<name>`) through the
// gated pipeline, in which the backend has rewritten every archive_url to its
// own `/api/archives/<name>-<version>.tar.gz` endpoint: every version with its
// `published` time, a `retracted` one as yanked (pub still resolves a
// retracted version a lock file pins). pub states no archive size.
//
// The public repository is pub.dev (pub.dartlang.org names it too). The
// hosted-repository specification has no listing, so another pub server
// (unpub, OnePub, Artifactory, a mirror of pub.dev) cannot be followed unless
// the feed option "url" names a site that serves pub.dev's feed and listings —
// pub.dev itself, for a server in front of it.

var dartPublicHosts = []string{"pub.dev", "pub.dartlang.org"}

const dartPublicFeed = "https://pub.dev"

// Bounds and defaults of the dart feed.
const (
	// dartDefaultSettle is how old a version must be before it is reported
	// when the documents are pub.dev's own; dartIntermediarySettle when they
	// are read through another server in front of pub.dev.
	dartDefaultSettle      = 5 * time.Minute
	dartIntermediarySettle = 2*time.Hour + 30*time.Minute
	// dartListingSettle is how long after a publication every pub.dev
	// instance lists the package in its new place: each instance's name
	// tracker takes in the recently published packages every 15 minutes; 35
	// minutes allow for one failed scan.
	dartListingSettle = 35 * time.Minute
	// dartMaxFeed bounds the Atom feed (80 KB; changelog excerpts are cut at
	// 512 characters), dartMaxFeedEntries the entries read from it.
	dartMaxFeed        = 4 << 20
	dartMaxFeedEntries = 1000
	// dartMaxListing bounds a page of /packages.json (50 URLs, 2.7 KB).
	dartMaxListing = 4 << 20
	// dartMaxNames bounds the name list, compressed and decompressed (1.8 MB
	// decompressed for 95,685 names), and dartMaxNameCount its names.
	dartMaxNames     = 64 << 20
	dartMaxNameCount = 2_000_000
	// dartMaxDocument bounds a package's document; the backend serves none
	// larger.
	dartMaxDocument = 32 << 20
	// dartMaxVersions bounds the versions of one package.
	dartMaxVersions = 50_000
	// dartGapPages bounds the listing pages one pass reads.
	dartGapPages = 400
	// dartBoundaryTries is how many of a listing page's last packages are
	// tried for the time the page ends at (a package can vanish between the
	// listing and its document).
	dartBoundaryTries = 3
	// dartAnchors is how many stable packages on each side of a page boundary
	// identify it; dartAnchorSlack how far apart two of them that were listed
	// next to each other may be listed later (packages published since are
	// listed between them by instances that have not taken them in).
	dartAnchors     = 3
	dartAnchorSlack = 20
	// dartMaxGaps bounds the page boundaries a cursor keeps for a second
	// look. A boundary still unresolved after dartVerifyRounds looks and
	// dartVerifyFor since its pages were read starts the enumeration over.
	dartMaxGaps      = 400
	dartVerifyRounds = 12
	dartVerifyFor    = 24 * time.Hour
	// dartDriftPerHour bounds how many packages pub.dev publishes an hour
	// (some 40 on 2026-11-16): how far down the listing a boundary's packages
	// can have moved since it was read.
	dartDriftPerHour = 120
	// dartBurstWait is how long a pass that needs the listing waits while
	// pub.dev publishes more versions within dartListingSettle than its feed
	// holds.
	dartBurstWait = 10 * time.Minute
	// dartAccept is what pub asks for.
	dartAccept = "application/vnd.pub.v2+json"
)

type dartFeed struct {
	*listingFeed
	k   kit
	src *dartSource
	// maxDocument bounds a package's document (dartMaxDocument).
	maxDocument int64
}

// dartSource reads pub.dev's feed, listing and name list.
type dartSource struct {
	k kit
	// feed is the pub.dev-compatible site the listings are read from.
	feed *url.URL
	// settle holds back the versions younger than it; now is the clock used
	// when a response states no Date.
	settle time.Duration
	now    func() time.Time
	// listingSettle is dartListingSettle.
	listingSettle time.Duration
	// namesPage is how many names an enumeration page lists; gapPages bounds
	// the listing pages of one pass.
	namesPage, gapPages int
	// The bounds (see the constants).
	maxFeed, maxListing, maxNames, maxDocument int64
	// call is what the current Bootstrap or Changes call has learnt (the
	// engine makes one such call at a time).
	call dartCall
}

// dartCall is what the source learns during one Bootstrap or Changes call.
type dartCall struct {
	// feed is the feed as the call read it.
	feed *dartFeedState
	// gaps are the page boundaries of the call's pass to look at again.
	gaps []dartGap
	// cutoff is the start of the settle period when no version of the feed
	// had settled: Bootstrap's mark then.
	cutoff time.Time
}

// dartFeedState is the feed as one call read it.
type dartFeedState struct {
	// entries are its versions, newest first; oldest the time of the oldest.
	entries []dartFeedEntry
	oldest  time.Time
	// at is pub.dev's clock when it served the feed.
	at time.Time
	// names are the packages it names; recent those with a version published
	// within dartListingSettle before at, which pub.dev's instances list in
	// different places.
	names, recent map[string]bool
	// covers reports that the feed reaches back dartListingSettle, so that
	// recent names every package published in that time.
	covers bool
}

func newDartFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	var feed *url.URL
	switch {
	case opts["url"] != "":
		if feed, err = parseBaseURL("the feed option url", opts["url"]); err != nil {
			return nil, err
		}
	case hostIs(k.upstream, dartPublicHosts...):
		feed, _ = url.Parse(dartPublicFeed)
	default:
		return nil, fmt.Errorf("upstream %s is not pub.dev, whose feed and listings are known: the hosted pub repository specification lists no packages, "+
			"so set fullMirror.feed.url to a site that serves pub.dev's /feed.atom, /packages.json and /api/package-names (pub.dev itself, for a mirror of it)",
			k.upstream.Redacted())
	}
	def := dartDefaultSettle
	if !hostIs(k.upstream, dartPublicHosts...) && !strings.EqualFold(feed.Host, k.upstream.Host) {
		// The documents come through a server in front of the site the feed
		// is read from, which caches them.
		def = dartIntermediarySettle
	}
	settle, err := gitSettleOption(opts, def)
	if err != nil {
		return nil, err
	}
	src := &dartSource{k: k, feed: feed, settle: settle, now: time.Now, listingSettle: dartListingSettle, namesPage: listingBatch, gapPages: dartGapPages,
		maxFeed: dartMaxFeed, maxListing: dartMaxListing, maxNames: dartMaxNames, maxDocument: dartMaxDocument}
	return &dartFeed{listingFeed: newListingFeed("dart", src), k: k, src: src, maxDocument: dartMaxDocument}, nil
}

func init() { Register("dart", newDartFeed) }

// dartCursor is the listing driver's cursor with the page boundaries the
// adapter looks at again.
type dartCursor struct {
	listingCursor
	Gaps []string `json:"gaps,omitempty"`
}

// begin starts a Bootstrap or Changes call: what the last one learnt is
// dropped.
func (s *dartSource) begin() { s.call = dartCall{} }

// Bootstrap enumerates the registry (listfeed.go). When no version of the
// feed has settled, the mark is the start of the settle period.
func (f *dartFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	f.src.begin()
	b, err := f.listingFeed.Bootstrap(ctx, cursor)
	if err != nil || cursor != "" || f.src.call.cutoff.IsZero() {
		return b, err
	}
	var c listingCursor
	if err := decodeCursor(b.Next, f.format(), &c); err != nil || !c.Mark.IsZero() {
		return b, err
	}
	c.Mark = f.src.call.cutoff.UTC()
	b.Next, b.HeadTime, b.CursorTime = encodeCursor(&c), c.Mark, c.Mark
	return b, nil
}

// Changes first looks again at the page boundaries earlier passes could not
// check, then follows the feed (listfeed.go). It reports each package once per
// batch: the feed names a package once per version, and the listing may name
// it again.
func (f *dartFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	var c dartCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return Batch{}, err
	}
	gaps, err := dartParseGaps(c.Gaps, f.src.gapPages, f.src.now())
	if err != nil {
		return Batch{}, err
	}
	f.src.begin()
	found, gaps, err := f.verify(ctx, gaps)
	if err != nil {
		return Batch{}, err
	}
	b, err := f.listingFeed.Changes(ctx, encodeCursor(&c.listingCursor))
	if err != nil {
		return b, err
	}
	gaps = dartMergeGaps(gaps, f.src.call.gaps)
	if len(gaps) > dartMaxGaps {
		return Batch{}, fmt.Errorf("%w: more than %d page boundaries of pub.dev's listing await a second look: the registry is enumerated again", ErrCursorInvalid, dartMaxGaps)
	}
	var next dartCursor
	if err := decodeCursor(b.Next, f.format(), &next.listingCursor); err != nil {
		return Batch{}, err
	}
	for _, g := range gaps {
		next.Gaps = append(next.Gaps, g.String())
	}
	if b.Next = encodeCursor(&next); len(b.Next) > maxCursorBytes {
		// The engine would refuse the cursor on every poll.
		return Batch{}, fmt.Errorf("%w: the dart cursor with %d page boundaries to look at again is %d bytes long: the registry is enumerated again",
			ErrCursorInvalid, len(gaps), len(b.Next))
	}
	items := make([]Coordinate, 0, len(found)+len(b.Items))
	for _, n := range found {
		items = append(items, Coordinate{Name: n})
	}
	b.Items = dartUniqueNames(append(items, b.Items...))
	return b, nil
}

// dartUniqueNames keeps the first item of each name.
func dartUniqueNames(items []Coordinate) []Coordinate {
	seen := make(map[string]bool, len(items))
	out := items[:0:0]
	for _, c := range items {
		if !seen[c.Name] {
			seen[c.Name] = true
			out = append(out, c)
		}
	}
	return out
}

// dartServerTime is the time a response states (its Date), else now: the
// settle period is measured by the registry's clock.
func dartServerTime(resp *http.Response, now func() time.Time) time.Time {
	if resp != nil {
		if t, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
			return t
		}
	}
	return now()
}

// dartAnchor is the hash a package listed at a page boundary is remembered by.
func dartAnchor(name string) string {
	sum := sha256.Sum256([]byte("dart-listing:" + name))
	return base64.RawURLEncoding.EncodeToString(sum[:6])
}

// dartValidAnchor reports whether s is a hash dartAnchor makes.
func dartValidAnchor(s string) bool {
	if len(s) != 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// dartAnchorsOf hashes the first (or the last) dartAnchors names.
func dartAnchorsOf(names []string, last bool) []string {
	if len(names) > dartAnchors {
		if last {
			names = names[len(names)-dartAnchors:]
		} else {
			names = names[:dartAnchors]
		}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, dartAnchor(n))
	}
	return out
}

// dartToken is a page of the listing a pass reads: its number, the time its
// packages were published at or before, and — after the first page — its
// boundary with the page before: pub.dev's clock when that page was read and
// the last stable packages it listed (hashed).
type dartToken struct {
	page   int
	upper  time.Time
	since  time.Time
	before []string
}

func (t dartToken) String() string {
	s := "p" + strconv.Itoa(t.page) + "@" + strconv.FormatInt(t.upper.UnixNano(), 10)
	if t.page > 1 {
		s += "@" + strconv.FormatInt(t.since.Unix(), 10) + "@" + strings.Join(t.before, ".")
	}
	return s
}

// dartParseToken reads a listing token.
func dartParseToken(token string, maxPages int) (dartToken, error) {
	bad := fmt.Errorf("%w: %q is not a dart listing token", ErrCursorInvalid, truncate(token, 64))
	rest, ok := strings.CutPrefix(token, "p")
	if !ok {
		return dartToken{}, bad
	}
	parts := strings.Split(rest, "@")
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 || n > maxPages+1 || strconv.Itoa(n) != parts[0] {
		return dartToken{}, bad
	}
	if want := 2 + 2*min(n-1, 1); len(parts) != want {
		return dartToken{}, bad
	}
	nanos, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || nanos <= 0 || strconv.FormatInt(nanos, 10) != parts[1] {
		return dartToken{}, bad
	}
	t := dartToken{page: n, upper: time.Unix(0, nanos).UTC()}
	if n == 1 {
		return t, nil
	}
	sec, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || sec <= 0 || sec > math.MaxInt64/int64(time.Second) || strconv.FormatInt(sec, 10) != parts[2] {
		return dartToken{}, bad
	}
	t.since = time.Unix(sec, 0).UTC()
	if parts[3] != "" {
		t.before = strings.Split(parts[3], ".")
	}
	if len(t.before) > dartAnchors {
		return dartToken{}, bad
	}
	for _, a := range t.before {
		if !dartValidAnchor(a) {
			return dartToken{}, bad
		}
	}
	return t, nil
}

// recent reads the feed (token "") or a page of the listing.
func (s *dartSource) recent(ctx context.Context, token string) (listingPage, error) {
	if token == "" {
		return s.feedPage(ctx)
	}
	tok, err := dartParseToken(token, s.gapPages)
	if err != nil {
		return listingPage{}, err
	}
	return s.listingPage(ctx, tok)
}

// readFeed reads the Atom feed: its versions, newest first, and which
// packages it names and were published within the listing settle period.
func (s *dartSource) readFeed(ctx context.Context) (*dartFeedState, error) {
	body, resp, err := s.k.get(ctx, join(s.feed, "feed.atom"), http.Header{"Accept": {"application/atom+xml"}}, s.maxFeed)
	if err != nil {
		return nil, fmt.Errorf("reading pub.dev's feed: %w", err)
	}
	entries, err := dartParseFeed(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("reading pub.dev's feed: %w", err))
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("reading pub.dev's feed: it lists no version")
	}
	st := &dartFeedState{entries: entries, oldest: entries[0].published, at: dartServerTime(resp, s.now), names: map[string]bool{}, recent: map[string]bool{}}
	settled := st.at.Add(-s.listingSettle)
	for _, e := range entries {
		st.names[e.name] = true
		if e.published.After(settled) {
			st.recent[e.name] = true
		}
		if e.published.Before(st.oldest) {
			st.oldest = e.published
		}
	}
	st.covers = !st.oldest.After(settled)
	s.call.feed = st
	return st, nil
}

// feedState is the feed as the current call read it, read now if it has not.
func (s *dartSource) feedState(ctx context.Context) (*dartFeedState, error) {
	if s.call.feed != nil {
		return s.call.feed, nil
	}
	return s.readFeed(ctx)
}

// feedPage reads the Atom feed: its settled versions, newest first. The next
// page is the listing's first, whose packages were published before the
// feed's oldest version, or the settle period, whichever is earlier.
func (s *dartSource) feedPage(ctx context.Context) (listingPage, error) {
	st, err := s.readFeed(ctx)
	if err != nil {
		return listingPage{}, err
	}
	var cutoff time.Time
	if s.settle > 0 {
		cutoff = st.at.Add(-s.settle)
	}
	pg := listingPage{}
	for _, e := range st.entries {
		if cutoff.IsZero() || !e.published.After(cutoff) {
			pg.Items = append(pg.Items, listingItem{Name: e.name, Time: e.published, ID: e.name + "@" + e.version})
		}
	}
	upper := st.oldest.Add(-time.Nanosecond)
	if !cutoff.IsZero() && upper.After(cutoff) {
		upper = cutoff
	}
	if len(pg.Items) == 0 {
		// None of the feed's versions has settled (a burst, or a settle
		// period longer than the feed's span): the pass goes on through the
		// listing, and Bootstrap marks the start of the settle period.
		s.call.cutoff = cutoff
	}
	if upper.UnixNano() > 0 {
		pg.Next = dartToken{page: 1, upper: upper}.String()
	}
	return pg, nil
}

// burst is the error of a pass that cannot rely on the listing's order while
// pub.dev publishes more than its feed shows.
func (s *dartSource) burst() error {
	return RetryAfter(fmt.Errorf("pub.dev published more versions in the last %s than its feed holds, or listed a page of nothing older: "+
		"its listing is read once they have settled", s.listingSettle), dartBurstWait)
}

// dartListed is a page of the listing as one pub.dev instance served it.
type dartListed struct {
	// names are the packages it lists, in its order; count is how many URLs
	// it held, more whether a next page follows.
	names []string
	count int
	more  bool
	// at is pub.dev's clock when it served the page.
	at time.Time
}

// readListing reads page n of the listing.
func (s *dartSource) readListing(ctx context.Context, n int) (dartListed, error) {
	body, resp, err := s.k.get(ctx, join(s.feed, "packages.json")+"?page="+strconv.Itoa(n), http.Header{"Accept": {"application/json"}}, s.maxListing)
	if err != nil {
		return dartListed{}, fmt.Errorf("reading pub.dev's listing: %w", err)
	}
	names, count, more, err := dartParseListing(body)
	if err != nil {
		return dartListed{}, Permanent(fmt.Errorf("reading pub.dev's listing: %w", err))
	}
	return dartListed{names: names, count: count, more: more, at: dartServerTime(resp, s.now)}, nil
}

// listingPage reads page tok.page of the live listing. Its packages were
// published at tok.upper or before: each the backend serves and the feed does
// not name is reported with that time, except the last, whose document states
// its time — a time before the mark ends the pass. The page's boundary with
// the page before is checked, or kept to look at again.
func (s *dartSource) listingPage(ctx context.Context, tok dartToken) (listingPage, error) {
	if tok.page > s.gapPages {
		return listingPage{}, fmt.Errorf("%w: the pass would read more than %d pages of pub.dev's listing: the registry is enumerated again", ErrCursorInvalid, s.gapPages)
	}
	st, err := s.feedState(ctx)
	if err != nil {
		return listingPage{}, err
	}
	if !st.covers {
		return listingPage{}, s.burst()
	}
	lst, err := s.readListing(ctx, tok.page)
	if err != nil {
		return listingPage{}, err
	}
	upper := tok.upper
	if s.settle > 0 {
		if cutoff := lst.at.Add(-s.settle); upper.After(cutoff) {
			upper = cutoff
		}
	}
	// Every instance lists the stable packages — those not published within
	// the listing settle period — in the same order.
	var stable []string
	for _, n := range lst.names {
		if !st.recent[n] {
			stable = append(stable, n)
		}
	}
	quiet := len(st.recent) == 0
	if tok.page > 1 && len(lst.names) > 0 && !quiet {
		if err := s.boundary(tok, lst, stable); err != nil {
			return listingPage{}, err
		}
	}
	pg := listingPage{}
	at := "@" + strconv.FormatInt(upper.UnixNano(), 10)
	for _, name := range lst.names {
		if dart.ValidPackageName(name) && !st.names[name] {
			pg.Items = append(pg.Items, listingItem{Name: name, Time: upper, ID: "listing:" + name + at})
		}
	}
	next := upper
	for i, tries := len(pg.Items)-1, 0; i >= 0 && tries < dartBoundaryTries; i, tries = i-1, tries+1 {
		t, err := s.lastPublished(ctx, pg.Items[i].Name)
		if err != nil {
			if IsPermanent(err) {
				continue // gone since the listing was made: the one before
			}
			return listingPage{}, err
		}
		if t.Before(upper) {
			pg.Items[i].Time, next = t, t
		}
		break
	}
	if lst.more && lst.count > 0 && next.UnixNano() > 0 {
		before := dartAnchorsOf(stable, true)
		if len(before) == 0 && !quiet {
			return listingPage{}, s.burst()
		}
		pg.Next = dartToken{page: tok.page + 1, upper: next, since: lst.at, before: before}.String()
	}
	return pg, nil
}

// boundary checks that page tok.page continues the page before it: it does
// when it lists one of that page's last stable packages. Otherwise the
// boundary is kept to look at again (see verify).
func (s *dartSource) boundary(tok dartToken, lst dartListed, stable []string) error {
	if len(tok.before) == 0 {
		return s.burst()
	}
	before := map[string]bool{}
	for _, a := range tok.before {
		before[a] = true
	}
	for _, n := range lst.names {
		if before[dartAnchor(n)] {
			return nil
		}
	}
	after := dartAnchorsOf(stable, false)
	if len(after) == 0 {
		return s.burst()
	}
	s.call.gaps = append(s.call.gaps, dartGap{Page: tok.page, Since: tok.since.Unix(), Before: tok.before, After: after})
	return nil
}

// lastPublished reads when a package's newest version was published, from
// its document on the feed's site.
func (s *dartSource) lastPublished(ctx context.Context, name string) (time.Time, error) {
	body, _, err := s.k.get(ctx, join(s.feed, "api/packages/"+name), http.Header{"Accept": {dartAccept}}, s.maxDocument)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading the document of %s: %w", name, err)
	}
	doc, err := dartParseDocument(body)
	if err != nil {
		return time.Time{}, Permanent(fmt.Errorf("the document of %s: %w", name, err))
	}
	if doc.name != name {
		return time.Time{}, Permanent(fmt.Errorf("the document of %s describes %q", name, truncate(doc.name, 200)))
	}
	var last time.Time
	for _, v := range doc.versions {
		if v.published.After(last) {
			last = v.published
		}
	}
	if last.IsZero() {
		return time.Time{}, Permanent(fmt.Errorf("the document of %s states no publication time", name))
	}
	return last, nil
}

// dartGap is a boundary between two pages of the listing that may have come
// from instances listing different packages above it: the packages between
// its two sides are looked for once every instance lists at least what the
// pages were read from.
type dartGap struct {
	// Page is the page after the boundary; Since pub.dev's clock (Unix
	// seconds) when the page before it was read.
	Page  int
	Since int64
	// Rounds counts the looks that did not resolve it.
	Rounds int
	// Before are the last stable packages the page before listed, After the
	// first the page after listed (hashed, in listing order).
	Before, After []string
}

// String is the gap as a cursor keeps it: "page.since.rounds:before:after".
func (g dartGap) String() string {
	return strconv.Itoa(g.Page) + "." + strconv.FormatInt(g.Since, 10) + "." + strconv.Itoa(g.Rounds) + ":" + strings.Join(g.Before, ",") + ":" + strings.Join(g.After, ",")
}

// key identifies the gap among others.
func (g dartGap) key() string {
	return strconv.Itoa(g.Page) + "." + strconv.FormatInt(g.Since, 10) + ":" + strings.Join(g.Before, ",")
}

// dartParseGap reads a gap a cursor kept.
func dartParseGap(s string, maxPages int, now time.Time) (dartGap, error) {
	bad := fmt.Errorf("%w: %q is not a boundary of pub.dev's listing", ErrCursorInvalid, truncate(s, 80))
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return dartGap{}, bad
	}
	nums := strings.Split(parts[0], ".")
	if len(nums) != 3 {
		return dartGap{}, bad
	}
	var g dartGap
	var err error
	if g.Page, err = strconv.Atoi(nums[0]); err != nil || g.Page < 2 || g.Page > maxPages || strconv.Itoa(g.Page) != nums[0] {
		return dartGap{}, bad
	}
	if g.Since, err = strconv.ParseInt(nums[1], 10, 64); err != nil || g.Since <= 0 || g.Since > now.Add(listingSkew).Unix() || strconv.FormatInt(g.Since, 10) != nums[1] {
		return dartGap{}, bad
	}
	if g.Rounds, err = strconv.Atoi(nums[2]); err != nil || g.Rounds < 0 || g.Rounds > 1_000_000 || strconv.Itoa(g.Rounds) != nums[2] {
		return dartGap{}, bad
	}
	for i, side := range []*[]string{&g.Before, &g.After} {
		if parts[1+i] == "" {
			return dartGap{}, bad
		}
		*side = strings.Split(parts[1+i], ",")
		if len(*side) > dartAnchors {
			return dartGap{}, bad
		}
		for _, a := range *side {
			if !dartValidAnchor(a) {
				return dartGap{}, bad
			}
		}
	}
	return g, nil
}

// dartParseGaps reads the gaps a cursor kept.
func dartParseGaps(list []string, maxPages int, now time.Time) ([]dartGap, error) {
	if len(list) > dartMaxGaps {
		return nil, fmt.Errorf("%w: the dart cursor keeps %d page boundaries; at most %d are", ErrCursorInvalid, len(list), dartMaxGaps)
	}
	out := make([]dartGap, 0, len(list))
	for _, s := range list {
		g, err := dartParseGap(s, maxPages, now)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// dartMergeGaps adds the gaps of a pass to those kept, each once (a pass
// continued in a later call reads its last page again), in page order.
func dartMergeGaps(kept, added []dartGap) []dartGap {
	seen := map[string]bool{}
	out := make([]dartGap, 0, len(kept)+len(added))
	for _, g := range append(append([]dartGap(nil), kept...), added...) {
		if k := g.key(); !seen[k] {
			seen[k] = true
			out = append(out, g)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Since != out[j].Since {
			return out[i].Since < out[j].Since
		}
		return out[i].Page < out[j].Page
	})
	return out
}

// verify looks again at the page boundaries kept from earlier passes whose
// pages were read at least the listing settle period ago: every instance now
// lists at least what those pages were read from. It returns the packages
// found between the two sides of each boundary it resolves, and the
// boundaries still to look at.
func (f *dartFeed) verify(ctx context.Context, gaps []dartGap) ([]string, []dartGap, error) {
	s := f.src
	now := s.now()
	pages := map[int]dartListed{}
	read := func(n int) (dartListed, error) {
		if l, ok := pages[n]; ok {
			return l, nil
		}
		l, err := s.readListing(ctx, n)
		if err != nil {
			return dartListed{}, err
		}
		pages[n] = l
		return l, nil
	}
	shift := map[int64]int{}
	var found []string
	keep := make([]dartGap, 0, len(gaps))
	for _, g := range gaps {
		since := time.Unix(g.Since, 0)
		if now.Before(since.Add(s.listingSettle)) {
			keep = append(keep, g)
			continue
		}
		names, ok, err := s.resolve(g, now.Sub(since), read, shift)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			found = append(found, names...)
			continue
		}
		if g.Rounds++; g.Rounds >= dartVerifyRounds && now.After(since.Add(dartVerifyFor)) {
			return nil, nil, fmt.Errorf("%w: the packages at a boundary of pub.dev's listing (page %d, read %s) were not found again in %d looks: the registry is enumerated again",
				ErrCursorInvalid, g.Page, since.UTC().Format(time.RFC3339), g.Rounds)
		}
		keep = append(keep, g)
	}
	return found, keep, nil
}

// resolve looks for a gap's packages, from its page down as far as the
// listing can have moved since (or around where the other gaps of its pass
// were found). A page that lists one of the packages before the boundary and,
// after it, one of the packages after it names what lies between. So does the
// gap's own page when, read the listing settle period after the page before
// it, it lists two of the packages after the boundary and none before, while
// the page before still lists the last package before it: every instance has
// taken in what that page was read from, so the gap's page starts right after
// that package.
func (s *dartSource) resolve(g dartGap, age time.Duration, read func(int) (dartListed, error), shift map[int64]int) ([]string, bool, error) {
	before := map[string]bool{}
	for _, a := range g.Before {
		before[a] = true
	}
	after := map[string]int{}
	for i, a := range g.After {
		after[a] = i
	}
	lo, hi := g.Page, g.Page+1+int(math.Ceil(age.Hours()*dartDriftPerHour/50))
	if d, ok := shift[g.Since]; ok {
		lo, hi = max(g.Page, g.Page+d-1), g.Page+d+1
	}
	hi = min(hi, g.Page+s.gapPages)
	settled := g.Since + int64(s.listingSettle/time.Second)
	for p := lo; p <= hi; p++ {
		lst, err := read(p)
		if err != nil {
			return nil, false, err
		}
		// bi is the last package before the boundary the page lists, ai the
		// first after the boundary listed after it, pair the first after the
		// boundary that the next one after it follows close by.
		bi, ai, pair, seen := -1, -1, -1, false
		for i, n := range lst.names {
			h := dartAnchor(n)
			if before[h] {
				bi, ai, seen = i, -1, true
				continue
			}
			k, ok := after[h]
			if !ok {
				continue
			}
			seen = true
			if bi >= 0 && ai < 0 {
				ai = i
			}
			if pair < 0 && k+1 < len(g.After) {
				for j := i + 1; j < len(lst.names) && j <= i+dartAnchorSlack; j++ {
					if dartAnchor(lst.names[j]) == g.After[k+1] {
						pair = i
						break
					}
				}
			}
		}
		if seen {
			// Found: only the next page can still hold the boundary's other
			// side.
			shift[g.Since], hi = p-g.Page, min(hi, p+1)
		}
		if bi >= 0 && ai > bi {
			return dartServedNames(lst.names[bi+1 : ai]), true, nil
		}
		if p == g.Page && bi < 0 && pair >= 0 && lst.at.Unix() >= settled {
			prev, err := read(p - 1)
			if err != nil {
				return nil, false, err
			}
			last := g.Before[len(g.Before)-1]
			for _, n := range prev.names {
				if dartAnchor(n) == last {
					return dartServedNames(lst.names[:pair]), true, nil
				}
			}
		}
		if len(lst.names) == 0 {
			break
		}
	}
	return nil, false, nil
}

// dartServedNames keeps the names the backend serves.
func dartServedNames(names []string) []string {
	var out []string
	for _, n := range names {
		if dart.ValidPackageName(n) {
			out = append(out, n)
		}
	}
	return out
}

// every reads the names after token's ("after:<name>"; "" for the first),
// in name order: the name list's and the feed's.
func (s *dartSource) every(ctx context.Context, token string) (listingPage, error) {
	after := ""
	if token != "" {
		a, ok := strings.CutPrefix(token, "after:")
		if !ok || !dart.ValidPackageName(a) {
			return listingPage{}, fmt.Errorf("%w: %q is not a dart enumeration token", ErrCursorInvalid, truncate(token, 64))
		}
		after = a
	}
	names, err := s.names(ctx)
	if err != nil {
		return listingPage{}, err
	}
	st, err := s.readFeed(ctx)
	if err != nil {
		return listingPage{}, err
	}
	names = dartAddNames(names, st.entries)
	start := 0
	if after != "" {
		start = sort.SearchStrings(names, after)
		if start < len(names) && names[start] == after {
			start++
		}
	}
	end := start + s.namesPage
	if end > len(names) {
		end = len(names)
	}
	pg := listingPage{Total: int64(len(names)), TotalKnown: true}
	for _, n := range names[start:end] {
		pg.Items = append(pg.Items, listingItem{Name: n})
	}
	if end < len(names) {
		pg.Next = "after:" + names[end-1]
	}
	return pg, nil
}

// names reads the name list: the names the backend serves, sorted, once each.
// pub.dev answers 406 unless the request accepts gzip; the body is
// decompressed here whether the transport left it compressed or not.
func (s *dartSource) names(ctx context.Context) ([]string, error) {
	target := join(s.feed, "api/package-names")
	_, body, err := s.k.getStream(ctx, target, http.Header{"Accept": {"application/json"}, "Accept-Encoding": {"gzip"}}, s.maxNames)
	if err != nil {
		return nil, fmt.Errorf("reading pub.dev's name list: %w", err)
	}
	defer body.Close()
	r, release, err := openContent(body, "pub.dev's name list", s.maxNames)
	if err != nil {
		return nil, err
	}
	defer release()
	names, err := dartParseNames(r)
	if err != nil {
		if IsPermanent(err) {
			return nil, fmt.Errorf("reading pub.dev's name list: %w", err)
		}
		return nil, Permanent(fmt.Errorf("reading pub.dev's name list: %w", err))
	}
	return names, nil
}

// dartAddNames adds the feed's packages to a sorted name list.
func dartAddNames(names []string, entries []dartFeedEntry) []string {
	var extra []string
	for _, e := range entries {
		i := sort.SearchStrings(names, e.name)
		if i == len(names) || names[i] != e.name {
			extra = append(extra, e.name)
		}
	}
	if len(extra) == 0 {
		return names
	}
	out := append(append([]string(nil), names...), extra...)
	sort.Strings(out)
	uniq := out[:0]
	for i, n := range out {
		if i == 0 || n != out[i-1] {
			uniq = append(uniq, n)
		}
	}
	return uniq
}

// dartParseNames reads a name list ({"packages":[…]}): the names the backend
// serves, sorted, once each.
func dartParseNames(r io.Reader) ([]string, error) {
	var doc struct {
		Packages *[]string `json:"packages"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Packages == nil {
		return nil, fmt.Errorf("it is not a name list (no packages)")
	}
	if len(*doc.Packages) > dartMaxNameCount {
		return nil, fmt.Errorf("it lists %d names; at most %d are read", len(*doc.Packages), dartMaxNameCount)
	}
	out := make([]string, 0, len(*doc.Packages))
	for _, n := range *doc.Packages {
		if dart.ValidPackageName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	uniq := out[:0]
	for i, n := range out {
		if i == 0 || n != out[i-1] {
			uniq = append(uniq, n)
		}
	}
	return uniq, nil
}

// dartFeedEntry is one version the Atom feed lists.
type dartFeedEntry struct {
	name, version string
	published     time.Time
}

// dartParseFeed reads the Atom feed's entries ("v<version> of <package>",
// published at <updated>). An entry whose package the backend does not serve,
// whose version is not one, or whose time does not read is left out.
// Characters XML does not allow are replaced first (see dartXMLText).
func dartParseFeed(body []byte) ([]dartFeedEntry, error) {
	var feed struct {
		XMLName xml.Name `xml:"feed"`
		Entries []struct {
			Title   string `xml:"title"`
			Updated string `xml:"updated"`
			Links   []struct {
				Rel   string `xml:"rel,attr"`
				Title string `xml:"title,attr"`
			} `xml:"link"`
		} `xml:"entry"`
	}
	if err := xml.NewDecoder(bytes.NewReader(dartXMLText(body))).Decode(&feed); err != nil {
		return nil, err
	}
	var out []dartFeedEntry
	for i, e := range feed.Entries {
		if i >= dartMaxFeedEntries {
			break
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(e.Title), "v")
		if !ok {
			continue
		}
		version, name, ok := strings.Cut(rest, " of ")
		if !ok || !dart.ValidPackageName(name) || !dartValidVersion(version) {
			continue
		}
		consistent := true
		for _, l := range e.Links {
			if l.Rel == "alternate" && l.Title != "" && l.Title != name {
				consistent = false
			}
		}
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.Updated))
		if !consistent || err != nil || t.UnixNano() <= 0 {
			continue
		}
		out = append(out, dartFeedEntry{name: name, version: version, published: t.UTC()})
	}
	return out, nil
}

// dartXMLText replaces what XML does not allow in a document — control
// characters but tab, line feed and carriage return, U+FFFE, U+FFFF, and
// bytes that are not UTF-8 — with U+FFFD. pub.dev puts each version's
// changelog excerpt into its feed escaped only for markup: one excerpt with a
// terminal's colour codes would otherwise fail the whole feed.
func dartXMLText(body []byte) []byte {
	bad := func(r rune, n int) bool {
		return r == utf8.RuneError && n == 1 || !(r == '\t' || r == '\n' || r == '\r' || r >= 0x20 && r <= 0xD7FF || r >= 0xE000 && r <= 0xFFFD || r >= 0x10000 && r <= 0x10FFFF)
	}
	i := 0
	for i < len(body) {
		r, n := utf8.DecodeRune(body[i:])
		if bad(r, n) {
			break
		}
		i += n
	}
	if i == len(body) {
		return body
	}
	out := append(make([]byte, 0, len(body)+64), body[:i]...)
	for i < len(body) {
		r, n := utf8.DecodeRune(body[i:])
		if bad(r, n) {
			out = utf8.AppendRune(out, utf8.RuneError)
		} else {
			out = append(out, body[i:i+n]...)
		}
		i += n
	}
	return out
}

// dartListedName reports whether s can be a package name of the listing:
// letters, digits and "_", at most 64 bytes. The listing still names a dozen
// legacy packages spelt with upper-case letters; they mark positions in it,
// but the backend serves none of them.
func dartListedName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// dartParseListing reads a page of /packages.json: the names its package URLs
// end in ("…/packages/<name>.json"), in its order and once each, how many URLs
// it held, and whether a next page follows.
func dartParseListing(body []byte) ([]string, int, bool, error) {
	var doc struct {
		Packages *[]string       `json:"packages"`
		Next     json.RawMessage `json:"next"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, 0, false, err
	}
	if doc.Packages == nil {
		return nil, 0, false, fmt.Errorf("it is not a package listing (no packages)")
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range *doc.Packages {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		segs := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(segs) < 2 || segs[len(segs)-2] != "packages" {
			continue
		}
		name, ok := strings.CutSuffix(segs[len(segs)-1], ".json")
		if !ok || !dartListedName(name) || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	next := strings.TrimSpace(string(doc.Next))
	return out, len(*doc.Packages), next != "" && next != "null" && next != `""`, nil
}

// dartValidVersion reports whether s is a pub version a path can carry: a
// digit, then digits, letters, ".", "+" and "-" (SemVer), at most 128 bytes.
func dartValidVersion(s string) bool {
	if s == "" || len(s) > 128 || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

// dartDocument is what the adapter reads from a package's document.
type dartDocument struct {
	name     string
	versions []dartVersion
}

// dartVersion is one version of a package's document.
type dartVersion struct {
	version    string
	archiveURL string
	published  time.Time
	retracted  bool
}

// dartParseDocument reads a package's document (the list-versions document):
// its name and its versions, in the document's order. A version that is not
// one is left out.
func dartParseDocument(body []byte) (dartDocument, error) {
	var doc struct {
		Name     string `json:"name"`
		Versions *[]struct {
			Version    string          `json:"version"`
			ArchiveURL string          `json:"archive_url"`
			Published  string          `json:"published"`
			Retracted  json.RawMessage `json:"retracted"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return dartDocument{}, err
	}
	if doc.Name == "" || doc.Versions == nil {
		return dartDocument{}, fmt.Errorf("it is not a package document (no name or versions)")
	}
	if len(*doc.Versions) > dartMaxVersions {
		return dartDocument{}, fmt.Errorf("it lists %d versions; at most %d are followed", len(*doc.Versions), dartMaxVersions)
	}
	out := dartDocument{name: doc.Name}
	seen := map[string]bool{}
	for _, v := range *doc.Versions {
		if !dartValidVersion(v.Version) || seen[v.Version] {
			continue
		}
		seen[v.Version] = true
		dv := dartVersion{version: v.Version, archiveURL: v.ArchiveURL, retracted: strings.TrimSpace(string(v.Retracted)) == "true"}
		if t, err := time.Parse(time.RFC3339Nano, v.Published); err == nil {
			dv.published = t.UTC()
		}
		out.versions = append(out.versions, dv)
	}
	return out, nil
}

// Releases reads the package's document through the gated pipeline.
func (f *dartFeed) Releases(ctx context.Context, name string) ([]Release, error) {
	if !dart.ValidPackageName(name) {
		return nil, Permanent(fmt.Errorf("%q is not a pub package name the proxy serves", truncate(name, 200)))
	}
	body, err := f.k.read(ctx, "/api/packages/"+name, dartAccept, f.maxDocument)
	if err != nil {
		return nil, err
	}
	doc, err := dartParseDocument(body)
	if err != nil {
		return nil, Permanent(fmt.Errorf("the document of %s: %w", name, err))
	}
	if doc.name != name {
		return nil, Permanent(fmt.Errorf("the document of %s describes %q", name, truncate(doc.name, 200)))
	}
	rels := make([]Release, 0, len(doc.versions))
	for _, v := range doc.versions {
		p, ok := f.k.proxyPath(v.archiveURL)
		if !ok {
			// The backend rewrites every archive_url; a document it did not
			// rewrite still has its archive at the backend's endpoint.
			arts, err := f.k.locate(ctx, lockfiles.Dependency{Name: name, Version: v.version}, nil)
			if err != nil {
				if IsPermanent(err) {
					continue
				}
				return nil, err
			}
			p = arts[0].Path
		}
		dec, err := url.PathUnescape(p)
		if err != nil {
			continue
		}
		if n, ver, ok := dart.ArchivePathCoordinate(dec); !ok || n != name || ver != v.version {
			continue
		}
		rels = append(rels, Release{Version: v.version, Published: v.published, Yanked: v.retracted, Artifacts: []Artifact{{Path: p}}})
	}
	// pub versions are SemVer 2.0, which the npm scheme orders; build
	// metadata, which pub orders too, keeps the document's ascending order.
	orderReleases("npm", rels)
	return rels, nil
}
