package fullmirror

import (
	"context"
	"fmt"
	"time"
)

// This file drives the adapters of registries that offer only listings (tier
// (c) of the catalog, Task 191) sorted newest first: Puppet Forge's releases,
// Galaxy's collection versions, pub.dev's packages, the Hugging Face Hub's
// repositories. An adapter supplies a listingSource; listingFeed keeps a
// high-water mark — the newest time it has reported, and the items it saw at
// exactly that time — and
//
//   - Bootstrap reads the newest page first, whose newest item becomes the
//     mark the follower continues from (what is published while the
//     enumeration runs is newer, and comes with the first Changes), then
//     enumerates the registry through the source's enumeration (a name list,
//     a listing of every package), page by page;
//   - Changes pages the newest-first listing from its first page until it
//     reaches an item older than the mark (or the listing's end), reporting
//     every item newer than the mark and those at the mark it had not seen;
//     the newest item of the pass becomes the new mark. A pass longer than
//     one call continues in the next from where it stopped.
//
// Offset-paged listings shift while they are read: an item published during a
// pass pushes the others down, so a page may repeat an item of the page before
// (reported once per call; again in a later call, which is harmless: the
// engine finds the files cached) — and an item deleted during a pass pulls the
// others up, so the item at a page's edge can be skipped. Sources overlap
// their pages by a few items to absorb deletions.

// Bounds of a listing feed's calls.
const (
	// listingPages is how many pages one call reads at most.
	listingPages = 50
	// listingBatch is how many items a call collects before it stops at a
	// page's end.
	listingBatch = 5_000
	// listingMaxAtMark bounds the items remembered at the mark.
	listingMaxAtMark = 1_000
)

// listingSource is what a listing adapter supplies.
type listingSource interface {
	// recent reads one page of the registry's listing sorted newest first:
	// token "" for the first page, then the Next of the previous page. Every
	// item states its Time.
	recent(ctx context.Context, token string) (listingPage, error)
	// every reads one page of the enumeration Bootstrap lists: token as
	// above. Items need no Time.
	every(ctx context.Context, token string) (listingPage, error)
}

// listingPage is one page of a listing.
type listingPage struct {
	Items []listingItem
	// Next is the token of the following page; "" at the listing's end.
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
	return cleanName(it.Name) && len(it.Version) <= 1024 && snapValidString(it.Version, 1024) && len(it.id()) <= 2048
}

// listingFeed implements Bootstrap and Changes over a listingSource; the
// adapter embeds it and adds Releases.
type listingFeed struct {
	typ      string
	src      listingSource
	maxPages int
	batch    int
}

func newListingFeed(typ string, src listingSource) *listingFeed {
	return &listingFeed{typ: typ, src: src, maxPages: listingPages, batch: listingBatch}
}

// listingCursor is the cursor of a listingFeed.
type listingCursor struct {
	Format string `json:"format"`
	// Mark is the newest time reported, AtMark the items seen at exactly
	// that time.
	Mark   time.Time `json:"mark"`
	AtMark []string  `json:"atMark,omitempty"`
	// Listing marks Bootstrap's enumeration; Token is the page it continues
	// with, Skip how many of that page's items were listed (a page larger
	// than a batch is listed over several), and Listed how many items it
	// listed in all.
	Listing bool   `json:"listing,omitempty"`
	Listed  int64  `json:"listed,omitempty"`
	Token   string `json:"token,omitempty"`
	Skip    int    `json:"skip,omitempty"`
	// Pass marks a pass over the newest-first listing that continues at
	// Token; Top is the newest time it has seen, AtTop the items at Top.
	Pass  bool      `json:"pass,omitempty"`
	Top   time.Time `json:"top,omitempty"`
	AtTop []string  `json:"atTop,omitempty"`
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
	case len(c.AtMark) > listingMaxAtMark || len(c.AtTop) > listingMaxAtMark:
		return c, fmt.Errorf("%w: the %s cursor remembers too many items", ErrCursorInvalid, f.typ)
	case !c.Listing && !c.Pass && c.Token != "", c.Skip < 0, c.Skip > 0 && !c.Listing:
		return c, fmt.Errorf("%w: the %s cursor has a stray position", ErrCursorInvalid, f.typ)
	}
	return c, nil
}

// addID adds id to a set kept as a bounded list.
func addID(set []string, id string) []string {
	for _, s := range set {
		if s == id {
			return set
		}
	}
	if len(set) >= listingMaxAtMark {
		return set
	}
	return append(set, id)
}

func hasID(set []string, id string) bool {
	for _, s := range set {
		if s == id {
			return true
		}
	}
	return false
}

// newest returns the newest time of a page's items and the items at it.
func newest(items []listingItem) (time.Time, []string) {
	var top time.Time
	var at []string
	for _, it := range items {
		if !it.valid() || it.Time.IsZero() {
			continue
		}
		switch {
		case it.Time.After(top):
			top, at = it.Time, []string{it.id()}
		case it.Time.Equal(top):
			at = addID(at, it.id())
		}
	}
	return top, at
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
	top, at := newest(pg.Items)
	return f.enumerate(ctx, listingCursor{Format: f.format(), Mark: top.UTC(), AtMark: at, Listing: true})
}

// enumerate lists the next pages of the enumeration.
func (f *listingFeed) enumerate(ctx context.Context, c listingCursor) (Batch, error) {
	seen := map[string]bool{}
	var items []Coordinate
	token, skip, done := c.Token, c.Skip, false
	var total int64
	totalKnown := false
	listed := int64(0)
	for pages := 0; pages < f.maxPages && len(items) < f.batch; pages++ {
		pg, err := f.src.every(ctx, token)
		if err != nil {
			return Batch{}, err
		}
		total, totalKnown = pg.Total, pg.TotalKnown
		if skip > len(pg.Items) {
			skip = len(pg.Items)
		}
		rest := pg.Items[skip:]
		if room := f.batch - len(items); len(rest) > room {
			// The page is larger than what is left of the batch: list part
			// of it, and the rest of it in the next call.
			rest, skip = rest[:room], skip+room
		} else {
			skip = -1
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
		if skip >= 0 {
			break
		}
		skip = 0
		if pg.Next == "" || pg.Next == token {
			done = true
			break
		}
		token = pg.Next
	}
	if skip < 0 {
		skip = 0
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
		c.Token, c.Skip = token, skip
		b.More, b.Next = true, encodeCursor(&c)
		return b, nil
	}
	b.Next = encodeCursor(&listingCursor{Format: c.Format, Mark: c.Mark, AtMark: c.AtMark})
	return b, nil
}

// Changes pages the newest-first listing down to the mark.
func (f *listingFeed) Changes(ctx context.Context, cursor string) (Batch, error) {
	c, err := f.decode(cursor)
	if err != nil {
		return Batch{}, err
	}
	if c.Listing {
		return Batch{}, fmt.Errorf("%w: the %s cursor continues a listing", ErrCursorInvalid, f.typ)
	}
	token := ""
	var top time.Time
	var atTop []string
	if c.Pass {
		token, top, atTop = c.Token, c.Top, c.AtTop
	}
	seen := map[string]bool{}
	var items []Coordinate
	reached := false
	for pages := 0; pages < f.maxPages && len(items) < f.batch; pages++ {
		pg, err := f.src.recent(ctx, token)
		if err != nil {
			return Batch{}, err
		}
		for _, it := range pg.Items {
			if !it.valid() || it.Time.IsZero() {
				continue
			}
			id := it.id()
			switch {
			case it.Time.After(top):
				top, atTop = it.Time, []string{id}
			case it.Time.Equal(top):
				atTop = addID(atTop, id)
			}
			if it.Time.Before(c.Mark) {
				reached = true
				continue
			}
			if (it.Time.Equal(c.Mark) && hasID(c.AtMark, id)) || seen[id] {
				continue
			}
			seen[id] = true
			items = append(items, Coordinate{Name: it.Name, Version: it.Version})
		}
		if reached || pg.Next == "" || pg.Next == token {
			reached = true
			break
		}
		token = pg.Next
	}
	if !reached {
		c.Pass, c.Token, c.Top, c.AtTop = true, token, top.UTC(), atTop
		return Batch{Items: items, Next: encodeCursor(&c), More: true, HeadTime: top, CursorTime: c.Mark}, nil
	}
	next := listingCursor{Format: c.Format, Mark: c.Mark, AtMark: c.AtMark}
	switch {
	case top.After(c.Mark):
		next.Mark, next.AtMark = top.UTC(), atTop
	case top.Equal(c.Mark):
		for _, id := range atTop {
			next.AtMark = addID(next.AtMark, id)
		}
	}
	return Batch{Items: items, Next: encodeCursor(&next), HeadTime: next.Mark, CursorTime: next.Mark}, nil
}
