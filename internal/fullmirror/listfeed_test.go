package fullmirror

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeListing is a registry whose listing is sorted newest first and paged by
// offset; its enumeration lists the package names.
type fakeListing struct {
	mu    sync.Mutex
	items []listingItem // newest first
	size  int
	calls int
	// onPage runs after each recent page is served (a publish during a pass).
	onPage func(n int)
}

func (l *fakeListing) publish(name, version string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = append(l.items, listingItem{Name: name, Version: version, Time: at})
	sort.SliceStable(l.items, func(i, j int) bool { return l.items[i].Time.After(l.items[j].Time) })
}

func (l *fakeListing) page(items []listingItem, token string) (listingPage, error) {
	off := 0
	if token != "" {
		var err error
		if off, err = strconv.Atoi(token); err != nil {
			return listingPage{}, err
		}
	}
	end := off + l.size
	if end > len(items) {
		end = len(items)
	}
	if off > end {
		off = end
	}
	pg := listingPage{Items: append([]listingItem(nil), items[off:end]...), Total: int64(len(items)), TotalKnown: true}
	if end < len(items) {
		pg.Next = strconv.Itoa(end)
	}
	return pg, nil
}

func (l *fakeListing) recent(_ context.Context, token string) (listingPage, error) {
	l.mu.Lock()
	l.calls++
	pg, err := l.page(l.items, token)
	n := l.calls
	hook := l.onPage
	l.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	return pg, err
}

func (l *fakeListing) every(_ context.Context, token string) (listingPage, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := map[string]bool{}
	var names []listingItem
	for _, it := range l.items {
		if !seen[it.Name] {
			seen[it.Name] = true
			names = append(names, listingItem{Name: it.Name})
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	return l.page(names, token)
}

var listT0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// testListingFeed is an adapter made of a listingFeed alone.
type testListingFeed struct{ *listingFeed }

func (testListingFeed) Releases(context.Context, string) ([]Release, error) { return nil, nil }

func newTestListingFeed(l listingSource) testListingFeed {
	f := newListingFeed("test", l)
	// The registry's clock: a day after the listings' times.
	f.now = func() time.Time { return listT0.Add(24 * time.Hour) }
	return testListingFeed{f}
}

func at(min int) time.Time { return listT0.Add(time.Duration(min) * time.Minute) }

func TestListingFeedFollowsTheNewest(t *testing.T) {
	l := &fakeListing{size: 2}
	l.publish("a", "1", at(0))
	l.publish("b", "1", at(1))
	l.publish("c", "1", at(2))
	f := newTestListingFeed(l)
	f.batch = 3

	listed, cursor := drainBootstrap(t, f)
	if strings.Join(listed, ",") != "a,b,c" {
		t.Fatalf("Bootstrap listed %v", listed)
	}
	if got, next := drainChanges(t, f, cursor); len(got) != 0 {
		t.Errorf("nothing new, yet %v (cursor %s)", got, next)
	}

	// Two new versions, one of them in the same instant as the mark.
	l.publish("a", "2", at(5))
	l.publish("d", "1", at(2))
	got, cursor := drainChanges(t, f, cursor)
	if strings.Join(got, ",") != "d@1,a@2" { // oldest first
		t.Errorf("Changes = %v", got)
	}
	if got, _ := drainChanges(t, f, cursor); len(got) != 0 {
		t.Errorf("reported twice: %v", got)
	}

	// Several in the same instant, across pages and calls.
	for i, n := range []string{"e", "f", "g", "h", "i", "j", "k"} {
		l.publish(n, "1", at(10+i/3))
	}
	f.maxPages = 1
	got, cursor = drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "e@1,f@1,g@1,h@1,i@1,j@1,k@1" {
		t.Errorf("a pass over several calls reported %v", got)
	}
	if got, _ := drainChanges(t, f, cursor); len(got) != 0 {
		t.Errorf("after the pass: %v", got)
	}
}

// What is published while Bootstrap enumerates comes with the first Changes.
func TestListingFeedBootstrapMarkIsTakenFirst(t *testing.T) {
	l := &fakeListing{size: 1}
	l.publish("a", "1", at(0))
	l.publish("b", "1", at(1))
	f := newTestListingFeed(l)
	f.maxPages = 1
	f.lookback = 0 // (one page per call cannot cover the window)
	b, err := f.Bootstrap(context.Background(), "")
	if err != nil || !b.More {
		t.Fatalf("first Bootstrap page: %+v %v", b, err)
	}
	l.publish("late", "1", at(3))
	_, cursor := drainBootstrap2(t, f, b.Next)
	got, _ := drainChanges(t, f, cursor)
	if strings.Join(got, ",") != "late@1" {
		t.Errorf("what was published during the enumeration: %v", got)
	}
}

func drainBootstrap2(t *testing.T, f Feed, cursor string) ([]string, string) {
	t.Helper()
	var all []string
	for {
		b, err := f.Bootstrap(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, names(b.Items)...)
		cursor = b.Next
		if !b.More {
			return all, cursor
		}
	}
}

// Items published during a pass push the others down: an item seen on one
// page and again on the next is reported once.
func TestListingFeedShiftingPages(t *testing.T) {
	l := &fakeListing{size: 2}
	for i := 0; i < 4; i++ {
		l.publish("old"+strconv.Itoa(i), "1", at(i))
	}
	f := newTestListingFeed(l)
	_, cursor := drainBootstrap(t, f)
	for i := 0; i < 4; i++ {
		l.publish("new"+strconv.Itoa(i), "1", at(10+i))
	}
	// Publish one more right after the first page of the pass is read.
	first := true
	l.onPage = func(int) {
		if first {
			first = false
			l.publish("during", "1", at(20))
		}
	}
	got, cursor := drainChanges(t, f, cursor)
	sort.Strings(got)
	if strings.Join(got, ",") != "new0@1,new1@1,new2@1,new3@1" {
		t.Errorf("Changes = %v", got)
	}
	l.onPage = nil
	if got, _ := drainChanges(t, f, cursor); strings.Join(got, ",") != "during@1" {
		t.Errorf("the publish during the pass comes next: %v", got)
	}
}

func TestListingFeedInvalidCursors(t *testing.T) {
	f := newTestListingFeed(&fakeListing{size: 1})
	for name, c := range map[string]string{
		"garbage":       "nope",
		"other adapter": `{"format":"x/1","mark":"2026-01-01T00:00:00Z"}`,
		"both":          `{"format":"test/1","mark":"2026-01-01T00:00:00Z","listing":true,"pass":true}`,
		"stray token":   `{"format":"test/1","mark":"2026-01-01T00:00:00Z","token":"5"}`,
	} {
		if _, err := f.Changes(context.Background(), c); !errors.Is(err, ErrCursorInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.Changes(context.Background(), `{"format":"test/1","mark":"2026-01-01T00:00:00Z","listing":true}`); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("Changes with a listing cursor: %v", err)
	}
}

// An enumeration page larger than a batch (pub.dev's name list is one page of
// every name) is listed over several calls.
func TestListingFeedSplitsALargePage(t *testing.T) {
	l := &fakeListing{size: 1000}
	for i := 0; i < 25; i++ {
		l.publish("p"+strconv.Itoa(100+i), "1", at(i))
	}
	f := newTestListingFeed(l)
	f.batch = 10
	listed, _ := drainBootstrap(t, f)
	if len(listed) != 25 {
		t.Errorf("listed %d names: %v", len(listed), listed)
	}
	seen := map[string]bool{}
	for _, n := range listed {
		if seen[n] {
			t.Errorf("%s listed twice", n)
		}
		seen[n] = true
	}
}

// listingReleases answers Releases from the fake listing: every version
// published, one file each.
type listingReleasesFeed struct {
	*listingFeed
	l *fakeListing
}

func (f listingReleasesFeed) Releases(_ context.Context, name string) ([]Release, error) {
	f.l.mu.Lock()
	defer f.l.mu.Unlock()
	var out []Release
	for i := len(f.l.items) - 1; i >= 0; i-- {
		if it := f.l.items[i]; it.Name == name {
			out = append(out, Release{Version: it.Version, Artifacts: []Artifact{{Path: "/f/" + name + "-" + it.Version}}})
		}
	}
	if len(out) == 0 {
		return nil, Permanent(errors.New("unknown"))
	}
	return out, nil
}

// The engine follows a listing adapter end to end: everything the Bootstrap
// lists is fetched, then — after a restart — only what was published since.
func TestListingFeedThroughTheEngine(t *testing.T) {
	l := &fakeListing{size: 2}
	l.publish("a", "1", at(0))
	l.publish("b", "1", at(1))
	l.publish("b", "2", at(2))
	stateDir := t.TempDir()
	fetcher := newFakeFetcher()
	run := func() {
		t.Helper()
		e, err := New(Options{
			Dir: stateDir, Upstreams: []Upstream{{Settings: testSettings("lst"), Feed: listingReleasesFeed{newTestListingFeed(l).listingFeed, l}}},
			Logger: discardLogger(), MaxAttempts: 2, BaseBackoff: time.Millisecond, MaxBackoff: time.Millisecond, MaxRounds: 2,
			RoundBackoff: time.Millisecond, PollBackoff: time.Millisecond, ControlRefresh: time.Millisecond,
			PersistInterval: time.Millisecond, StandbyInterval: time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer e.Close()
		e.Attach(fetcher)
		fl := e.followers[0]
		for i := 0; i < 20; i++ {
			wait := fl.safeStep(context.Background())
			if wait > time.Second {
				break
			}
			time.Sleep(wait)
		}
	}
	run()
	for _, p := range []string{"/f/a-1", "/f/b-1", "/f/b-2"} {
		if n := fetcher.fetchCount(p); n != 1 {
			t.Errorf("%s fetched %d times after the Bootstrap, want 1", p, n)
		}
	}
	l.publish("a", "2", at(10))
	l.publish("c", "1", at(11))
	run()
	for _, p := range []string{"/f/a-2", "/f/c-1"} {
		if n := fetcher.fetchCount(p); n != 1 {
			t.Errorf("%s fetched %d times, want 1", p, n)
		}
	}
	if n := fetcher.totalFetches(); n != 5 {
		t.Errorf("%d fetches in all, want 5", n)
	}
}

// listingSeenAt is a cursor's Seen list for items remembered at time at.
func listingSeenAt(at time.Time, ids ...string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, strconv.FormatInt(at.Unix(), 10)+":"+listingHash(id))
	}
	return out
}

// newest returns the newest time of a page's valid items and the ids at it:
// what a mark is taken from.
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
			at = append(at, it.id())
		}
	}
	return top, at
}
