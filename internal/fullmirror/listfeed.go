package fullmirror

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This file drives the adapters of registries that offer only listings (tier
// (c) of the catalog, Task 191) sorted newest first: Puppet Forge's releases,
// Galaxy's collection versions, pub.dev's packages, the Hugging Face Hub's
// repositories. An adapter supplies a listingSource; listingFeed keeps a
// high-water mark — the newest time it has reported — and the items it saw
// in a lookback window below the mark, and
//
//   - Bootstrap reads the newest page first, whose newest item becomes the
//     mark the follower continues from (what is published while the
//     enumeration runs is newer, and comes with the first Changes), then
//     enumerates the registry through the source's enumeration (a name list,
//     a listing of every package), page by page;
//   - Changes pages the newest-first listing from its first page down to the
//     lookback window below the mark, reporting every item it has not seen:
//     the newer ones, and those in the window that became visible late (a
//     time stamp taken before the item's transaction committed, a lagging
//     read replica). The newest item of the pass becomes the new mark. A
//     pass longer than one call continues in the next from where it stopped.
//
// A time more than an hour ahead of the proxy's clock is reported but never
// becomes the mark: one bogus date must not hide everything published after
// it. Offset-paged listings shift while they are read: an item published
// during a pass pushes the others down, so a page may repeat an item of the
// page before (reported once per call; again in a later call, which is
// harmless: the engine finds the files cached) — and an item deleted during a
// pass pulls the others up, so the item at a page's edge can be skipped.
// Sources overlap their pages by a few items to absorb deletions within a
// call; a pass continued across calls relies on that overlap too, and on a
// listing whose pages a call reads faster than the registry adds items
// (keyset-paged listings do not shift at all).

// Bounds of a listing feed's calls and cursors.
const (
	// listingPages is how many pages one call reads at most.
	listingPages = 50
	// listingBatch is how many items a call collects before it stops at a
	// page's end.
	listingBatch = 5_000
	// listingMaxSeen bounds the items remembered in the lookback window, and
	// those a pass remembers (the newest are kept; an item forgotten there may
	// be reported again). With an entry at most 28 bytes in the cursor, two
	// full sets and a token fit maxCursorBytes with room to spare.
	listingMaxSeen = 900
	// listingMaxToken bounds a page token kept in the cursor, as the cursor
	// encodes it (JSON escapes "<", ">" and "&" in six bytes).
	listingMaxToken = 4 << 10
	// listingLookback is the default lookback window below the mark.
	listingLookback = 10 * time.Minute
	// listingSkew is how far ahead of the proxy's clock a time may lie and
	// still move the mark.
	listingSkew = time.Hour
	// listingSplitMargin is how many items of a split enumeration page are
	// listed again when the item it stopped at is gone.
	listingSplitMargin = 100
)

// listingSource is what a listing adapter supplies. A source may also have a
// method `lookback() time.Duration` to set the lookback window (default ten
// minutes; zero turns it off).
type listingSource interface {
	// recent reads one page of the registry's listing sorted newest first:
	// token "" for the first page, then the Next of the previous page. Every
	// item states its Time, which must be exactly the listing's sort key.
	recent(ctx context.Context, token string) (listingPage, error)
	// every reads one page of the enumeration Bootstrap lists: token as
	// above. Items need no Time.
	every(ctx context.Context, token string) (listingPage, error)
}

// listingPage is one page of a listing.
type listingPage struct {
	Items []listingItem
	// Next is the token of the following page; "" at the listing's end. At
	// most listingMaxToken bytes.
	Next string
	// Total is how many items the listing holds, when it says.
	Total      int64
	TotalKnown bool
}

// listingItem is one item of a listing.
type listingItem struct {
	// Name and Version are what the change names: Version "" leaves the
	// versions to the engine's policy (the listing names only a package's
	// latest version, and others may have been published since the last
	// pass).
	Name    string
	Version string
	// Time is the listing's sort key: when the item was published or last
	// changed.
	Time time.Time
	// ID tells apart the items of one time stamp; Name@Version when empty.
	ID string
}

func (it listingItem) id() string {
	if it.ID != "" {
		return it.ID
	}
	return it.Name + "@" + it.Version
}

func (it listingItem) valid() bool {
	return cleanName(it.Name) && snapValidString(it.Name, 1024) && snapValidString(it.Version, 1024) && len(it.id()) <= 4096
}

// listingTokenSize is a page token's size as the cursor encodes it.
func listingTokenSize(token string) int {
	b, err := json.Marshal(token)
	if err != nil {
		return listingMaxToken + 1
	}
	return len(b) - 2
}

// listingSeconds is the time an item is remembered at, within the years 1970
// to 9999 (so that an entry has at most 12 digits).
func listingSeconds(t time.Time) int64 {
	const max = 253402300799 // 9999-12-31T23:59:59Z
	switch s := t.Unix(); {
	case s < 0:
		return 0
	case s > max:
		return max
	default:
		return s
	}
}

// listingHash is the short hash an item's id is remembered by.
func listingHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

// listingFeed implements Bootstrap and Changes over a listingSource; the
// adapter embeds it and adds Releases.
type listingFeed struct {
	typ      string
	src      listingSource
	maxPages int
	batch    int
	lookback time.Duration
	now      func() time.Time
}

func newListingFeed(typ string, src listingSource) *listingFeed {
	f := &listingFeed{typ: typ, src: src, maxPages: listingPages, batch: listingBatch, lookback: listingLookback, now: time.Now}
	if lb, ok := src.(interface{ lookback() time.Duration }); ok {
		if d := lb.lookback(); d >= 0 {
			f.lookback = d
		}
	}
	return f
}

// listingCursor is the cursor of a listingFeed.
type listingCursor struct {
	Format string `json:"format"`
	// Mark is the newest time reported; Seen the items seen at or after the
	// start of the lookback window below it ("<unix seconds>:<hash of id>").
	Mark time.Time `json:"mark"`
	Seen []string  `json:"seen,omitempty"`
	// Listing marks Bootstrap's enumeration; Token is the page it continues
	// with, Skip how many of that page's items were listed (a page larger
	// than a batch is listed over several) and After the hash of the last
	// one, and Listed how many items it listed in all.
	Listing bool   `json:"listing,omitempty"`
	Listed  int64  `json:"listed,omitempty"`
	Token   string `json:"token,omitempty"`
	Skip    int    `json:"skip,omitempty"`
	After   string `json:"after,omitempty"`
	// Pass marks a pass over the newest-first listing that continues at
	// Token; Top is the newest time it has seen, Fresh the items it saw.
	Pass  bool      `json:"pass,omitempty"`
	Top   time.Time `json:"top,omitempty"`
	Fresh []string  `json:"fresh,omitempty"`
}

func (c *listingCursor) cursorFormat() string { return c.Format }

func (f *listingFeed) format() string { return cursorFormat(f.typ, 1) }

func (f *listingFeed) decode(cursor string) (listingCursor, error) {
	var c listingCursor
	if err := decodeCursor(cursor, f.format(), &c); err != nil {
		return c, err
	}
	switch {
	case c.Listing && c.Pass:
		return c, fmt.Errorf("%w: the %s cursor both lists and passes", ErrCursorInvalid, f.typ)
	case len(c.Seen) > listingMaxSeen || len(c.Fresh) > listingMaxSeen || listingTokenSize(c.Token) > listingMaxToken:
		return c, fmt.Errorf("%w: the %s cursor remembers too much", ErrCursorInvalid, f.typ)
	case !c.Listing && !c.Pass && c.Token != "", c.Skip < 0, c.Skip > 0 && !c.Listing, c.After != "" && !c.Listing:
		return c, fmt.Errorf("%w: the %s cursor has a stray position", ErrCursorInvalid, f.typ)
	case c.Mark.After(f.now().Add(listingSkew)):
		return c, fmt.Errorf("%w: the %s cursor's mark lies in the future", ErrCursorInvalid, f.typ)
	}
	if _, err := listingParseSeen(c.Seen); err != nil {
		return c, fmt.Errorf("%w: the %s cursor: %v", ErrCursorInvalid, f.typ, err)
	}
	if _, err := listingParseSeen(c.Fresh); err != nil {
		return c, fmt.Errorf("%w: the %s cursor: %v", ErrCursorInvalid, f.typ, err)
	}
	return c, nil
}

// listingParseSeen reads a cursor's remembered items.
func listingParseSeen(list []string) (map[string]int64, error) {
	out := make(map[string]int64, len(list))
	for _, e := range list {
		t, h, ok := strings.Cut(e, ":")
		sec, err := strconv.ParseInt(t, 10, 64)
		if !ok || err != nil || h == "" || len(h) > 16 {
			return nil, fmt.Errorf("a remembered item %q is not one", truncate(e, 40))
		}
		out[h] = sec
	}
	return out, nil
}

// listingEncodeSeen keeps the remembered items at or after floor, the newest
// listingMaxSeen of them, in a stable order.
func listingEncodeSeen(seen map[string]int64, floor time.Time) []string {
	type entry struct {
		h   string
		sec int64
	}
	var all []entry
	for h, sec := range seen {
		if sec >= floor.Unix() {
			all = append(all, entry{h, sec})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].sec != all[j].sec {
			return all[i].sec > all[j].sec
		}
		return all[i].h < all[j].h
	})
	if len(all) > listingMaxSeen {
		all = all[:listingMaxSeen]
	}
	out := make([]string, 0, len(all))
	for _, e := range all {
		out = append(out, strconv.FormatInt(e.sec, 10)+":"+e.h)
	}
	return out
}

// newest returns the newest time of a page's items that may move the mark,
// and the items in the lookback window below it.
func (f *listingFeed) newest(items []listingItem) (time.Time, map[string]int64) {
	limit := f.now().Add(listingSkew)
	var top time.Time
	for _, it := range items {
		if it.valid() && !it.Time.IsZero() && !it.Time.After(limit) && it.Time.After(top) {
			top = it.Time
		}
	}
	seen := map[string]int64{}
	for _, it := range items {
		if it.valid() && !it.Time.IsZero() && !it.Time.Before(top.Add(-f.lookback)) {
			seen[listingHash(it.id())] = listingSeconds(it.Time)
		}
	}
	return top, seen
}

// Bootstrap takes the mark from the newest page, then enumerates the
// registry.
func (f *listingFeed) Bootstrap(ctx context.Context, cursor string) (Batch, error) {
	if cursor != "" {
		c, err := f.decode(cursor)
		if err != nil {
			return Batch{}, err
		}
		if !c.Listing {
			return Batch{}, fmt.Errorf("%w: the %s cursor does not continue a listing", ErrCursorInvalid, f.typ)
		}
		return f.enumerate(ctx, c)
	}
	pg, err := f.src.recent(ctx, "")
	if err != nil {
		return Batch{}, err
	}
	items := pg.Items
	top, _ := f.newest(items)
	// Remember every item of the lookback window below the mark, which may
	// reach past the first page, so that the first Changes does not report
	// them again.
	for pages := 1; pages < f.maxPages && pg.Next != "" && len(pg.Items) > 0; pages++ {
		if last := pg.Items[len(pg.Items)-1]; last.Time.Before(top.Add(-f.lookback)) {
			break
		}
		token := pg.Next
		if pg, err = f.src.recent(ctx, token); err != nil {
			return Batch{}, err
		}
		if pg.Next == token {
			break
		}
		items = append(items, pg.Items...)
	}
	_, seen := f.newest(items)
	return f.enumerate(ctx, listingCursor{Format: f.format(), Mark: top.UTC(), Seen: listingEncodeSeen(seen, top.Add(-f.lookback)), Listing: true})
}

// resumeAt is where a split enumeration page continues: after the item the
// last call stopped at, wherever it is now (items deleted before it shift
// the page), or a little before the position when it is gone.
func listingResumeAt(items []listingItem, skip int, after string) int {
	if skip <= 0 {
		return 0
	}
	if after != "" {
		if skip-1 < len(items) && listingHash(items[skip-1].id()) == after {
			return skip
		}
		for i, it := range items {
			if listingHash(it.id()) == after {
				return i + 1
			}
		}
	}
	if skip -= listingSplitMargin; skip < 0 {
		skip = 0
	}
	return skip
}

// enumerate lists the next pages of the enumeration.
func (f *listingFeed) enumerate(ctx context.Context, c listingCursor) (Batch, error) {
	seen := map[string]bool{}
	var items []Coordinate
	token, skip, after, done := c.Token, c.Skip, c.After, false
	var total int64
	totalKnown := false
	listed := int64(0)
	for pages := 0; pages < f.maxPages && len(items) < f.batch; pages++ {
		pg, err := f.src.every(ctx, token)
		if err != nil {
			return Batch{}, err
		}
		if n := listingTokenSize(pg.Next); n > listingMaxToken {
			return Batch{}, Permanent(fmt.Errorf("the %s listing's next-page token is %d bytes long; at most %d are kept", f.typ, n, listingMaxToken))
		}
		total, totalKnown = pg.Total, pg.TotalKnown
		start := listingResumeAt(pg.Items, skip, after)
		if start > len(pg.Items) {
			start = len(pg.Items)
		}
		rest := pg.Items[start:]
		split := false
		if room := f.batch - len(items); len(rest) > room {
			// The page is larger than what is left of the batch: list part
			// of it, and the rest of it in the next call.
			rest, split = rest[:room], true
		}
		for _, it := range rest {
			listed++
			if !it.valid() {
				continue
			}
			co := Coordinate{Name: it.Name, Version: it.Version}
			if k := co.String(); !seen[k] {
				seen[k] = true
				items = append(items, co)
			}
		}
		if split {
			skip, after = start+len(rest), listingHash(rest[len(rest)-1].id())
			break
		}
		skip, after = 0, ""
		if pg.Next == "" || pg.Next == token {
			done = true
			break
		}
		token = pg.Next
	}
	c.Listed += listed
	b := Batch{Items: items, HeadTime: c.Mark, CursorTime: c.Mark}
	if totalKnown {
		b.Lag, b.LagKnown = total-c.Listed, true
		if b.Lag < 0 || done {
			b.Lag = 0
		}
	}
	if !done {
		c.Token, c.Skip, c.After = token, skip, after
		b.More, b.Next = true, encodeCursor(&c)
		return b, nil
	}
	b.Next = encodeCursor(&listingCursor{Format: c.Format, Mark: c.Mark, Seen: c.Seen})
	return b, nil
}

// Changes pages the newest-first listing down to the lookback window below
// the mark.
func (f *listingFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	c, err := f.decode(cursor)
	if err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the %s cursor continues a listing", ErrCursorInvalid, f.typ)
	}
	limit := f.now().Add(listingSkew)
	floor := c.Mark.Add(-f.lookback)
	seen, _ := listingParseSeen(c.Seen)
	token, top := "", c.Mark
	fresh := map[string]int64{}
	if c.Pass {
		token = c.Token
		if c.Top.After(top) {
			top = c.Top
		}
		fresh, _ = listingParseSeen(c.Fresh)
	}
	var items []Coordinate
	reached := false
	// lastToken is the token of the last page read: a pass continued in the
	// next call starts there again (its items are remembered, so nothing is
	// reported twice), so that items deleted above the page's edge in
	// between shift no unseen item past the continuation.
	lastToken, pages := token, 0
	var lastPage map[string]int64
	for ; pages < f.maxPages && len(items) < f.batch; pages++ {
		pg, err := f.src.recent(ctx, token)
		if err != nil {
			return Batch{}, err
		}
		if n := listingTokenSize(pg.Next); n > listingMaxToken {
			return Batch{}, Permanent(fmt.Errorf("the %s listing's next-page token is %d bytes long; at most %d are kept", f.typ, n, listingMaxToken))
		}
		lastToken = token
		lastPage = map[string]int64{}
		for _, it := range pg.Items {
			if !it.valid() || it.Time.IsZero() {
				continue
			}
			lastPage[listingHash(it.id())] = listingSeconds(it.Time)
			if it.Time.Before(floor) {
				reached = true
				continue
			}
			h := listingHash(it.id())
			if _, ok := seen[h]; ok {
				continue
			}
			if _, ok := fresh[h]; ok {
				continue
			}
			fresh[h] = listingSeconds(it.Time)
			items = append(items, Coordinate{Name: it.Name, Version: it.Version})
			if it.Time.After(top) && !it.Time.After(limit) {
				top = it.Time
			}
		}
		if reached || pg.Next == "" || pg.Next == token {
			reached = true
			break
		}
		token = pg.Next
	}
	// The listing is newest first; a batch is oldest first.
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	window := top.Add(-f.lookback)
	if !reached {
		next := token
		if pages >= 2 {
			// Start the next call one page back (a call that read one page
			// only would start where it began, and never get further).
			next = lastToken
		}
		c.Pass, c.Token, c.Top = true, next, top.UTC()
		// Remembered, within one bound: the last page, which the next call
		// reads again, then the newest of what the final mark's window needs.
		c.Fresh = listingEncodeSeen(lastPage, time.Time{})
		kept := map[string]bool{}
		for _, e := range c.Fresh {
			kept[e[strings.IndexByte(e, ':')+1:]] = true
		}
		for _, e := range listingEncodeSeen(fresh, window) {
			if len(c.Fresh) >= listingMaxSeen {
				break
			}
			if h := e[strings.IndexByte(e, ':')+1:]; !kept[h] {
				c.Fresh = append(c.Fresh, e)
			}
		}
		return Batch{Items: items, Next: encodeCursor(&c), More: true, HeadTime: top, CursorTime: c.Mark}, nil
	}
	for h, sec := range fresh {
		seen[h] = sec
	}
	next := listingCursor{Format: c.Format, Mark: top.UTC(), Seen: listingEncodeSeen(seen, window)}
	return Batch{Items: items, Next: encodeCursor(&next), HeadTime: next.Mark, CursorTime: next.Mark}, nil
}
