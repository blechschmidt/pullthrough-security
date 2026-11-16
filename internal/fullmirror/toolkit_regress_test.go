package fullmirror

// Regression tests for the defects an independent review of the Task 191
// toolkit found (snapshot.go, pollfeed.go, listfeed.go, decompress.go).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// stateIndex is an indexSource of one part whose records and state the test
// sets.
type stateIndex struct {
	mu    sync.Mutex
	recs  []snapRecord
	state json.RawMessage
}

func (s *stateIndex) readIndex(_ context.Context, _ json.RawMessage, _ *snapHeader, b *snapBuilder) (indexRead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		b.Add(r)
	}
	return indexRead{State: s.state}, nil
}

func jsonString(c byte, n int) json.RawMessage {
	return json.RawMessage(`"` + strings.Repeat(string(c), n-2) + `"`)
}

// A difference over several batches carries two states: both fit a cursor.
func TestIndexFeedTwoStatesFitTheCursor(t *testing.T) {
	src := &stateIndex{recs: pkgs("p0@1"), state: jsonString('x', indexMaxState-8)}
	f := newTestIndexFeed(t, src, 2)
	_, cursor := drainBootstrap(t, f)
	src.mu.Lock()
	src.recs = pkgs("p0@1", "p1@1", "p2@1", "p3@1", "p4@1")
	src.state = jsonString('y', indexMaxState-8)
	src.mu.Unlock()
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || !b.More {
		t.Fatalf("%+v %v", b, err)
	}
	if err := validateBatch(b); err != nil {
		t.Errorf("the engine refuses the batch (cursor %d bytes): %v", len(b.Next), err)
	}
}

// A state's size is measured as the cursor encodes it ("&" takes six bytes),
// the same way when it is stored and when the cursor is read back; one that
// does not fit, or is not JSON, is the source's error, never a panic.
func TestIndexFeedStateIsMeasuredAsEncoded(t *testing.T) {
	var entries []string
	for i := 0; i < 180; i++ {
		entries = append(entries, fmt.Sprintf(`"https://repo.example.org/index?suite=trixie&component=main&arch=amd64&n=%04d":"W/%08x"`, i, i))
	}
	raw := json.RawMessage("{" + strings.Join(entries, ",") + "}")
	src := &stateIndex{recs: pkgs("a@1"), state: raw}
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	if _, err := f.Changes(context.Background(), cursor); err != nil {
		t.Errorf("Bootstrap's own cursor is refused: %v", err)
	}
	for name, state := range map[string]json.RawMessage{
		"too large": jsonString('&', indexMaxState/6+10),
		"not JSON":  json.RawMessage(`etag-without-quotes`),
	} {
		src.state = state
		if _, err := newTestIndexFeed(t, src, 10).Bootstrap(context.Background(), ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// silentlyDamage flips a byte in the last block of the copy a cursor names,
// keeping the file's time (a bit flipped on disk).
func silentlyDamage(t *testing.T, f testIndexFeed, cursor string) {
	t.Helper()
	var c indexCursor
	if err := json.Unmarshal([]byte(cursor), &c); err != nil {
		t.Fatal(err)
	}
	path := f.files.path(snapName(c.Snap))
	st, _ := os.Stat(path)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-12] ^= 0x55
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, st.ModTime(), st.ModTime())
}

// A damaged copy the source copies unchanged parts from invalidates the
// cursor (the engine enumerates again) instead of failing every poll.
func TestIndexFeedDamagedCopyInvalidatesTheCursor(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("alpha@1", "beta@1")...)
	src.set("b", pkgs("delta@1", "epsilon@1")...)
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	silentlyDamage(t, f, cursor)
	src.set("a", pkgs("alpha@1", "alpha@2", "beta@1")...) // part b unchanged → copied
	if _, err := f.Changes(context.Background(), cursor); !errors.Is(err, ErrCursorInvalid) {
		t.Fatalf("a damaged copy to copy from: %v", err)
	}
	// What the engine does next.
	_, cursor = drainBootstrap(t, f)
	if rels, err := f.Releases(context.Background(), "epsilon"); err != nil || len(rels) != 1 {
		t.Errorf("after the new enumeration: %v %v", rels, err)
	}
}

// A damaged copy found by Releases while the index is unchanged is removed:
// the next poll invalidates the cursor that names it, and the enumeration
// that follows stores a sound copy.
func TestIndexFeedDamagedCopyFoundByReleasesHeals(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("alpha@1", "beta@1")...)
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	silentlyDamage(t, f, cursor)
	if _, err := f.Releases(context.Background(), "beta"); err == nil || IsPermanent(err) {
		t.Fatalf("Releases from a damaged copy: %v", err)
	}
	if _, err := f.Changes(context.Background(), cursor); !errors.Is(err, ErrCursorInvalid) {
		t.Fatalf("the poll after: %v", err)
	}
	drainBootstrap(t, f)
	if _, err := f.Releases(context.Background(), "beta"); err != nil {
		t.Errorf("after the new enumeration: %v", err)
	}
}

// A lost pointer is set again at the next poll, also while the index is
// unchanged.
func TestIndexFeedLostPointerIsSetAgain(t *testing.T) {
	src := newFakeIndex()
	src.set("a", pkgs("alpha@1")...)
	f := newTestIndexFeed(t, src, 10)
	_, cursor := drainBootstrap(t, f)
	os.Remove(f.files.path(snapCurrent))
	if _, err := f.Changes(context.Background(), cursor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Releases(context.Background(), "alpha"); err != nil {
		t.Errorf("after a poll: %v", err)
	}
}

// smallGroups is an indexSource whose builder takes at most 100 records of a
// package.
type smallGroups struct{ *stateIndex }

func (s smallGroups) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	b.maxGroup = 100
	return s.stateIndex.readIndex(ctx, prev, old, b)
}

// One package with more records than a package may have is left out; the
// rest of the index is stored.
func TestSnapshotLeavesOutAnOversizedPackage(t *testing.T) {
	src := &stateIndex{state: json.RawMessage(`{}`), recs: pkgs("a@1", "b@1", "zz@1")}
	for i := 0; i <= 100; i++ {
		src.recs = append(src.recs, snapRecord{Name: "fat", Version: fmt.Sprint(i)})
	}
	f := newTestIndexFeed(t, smallGroups{src}, 10)
	listed, _ := drainBootstrap(t, f)
	if strings.Join(listed, ",") != "a,b,zz" {
		t.Errorf("listed %v", listed)
	}
	h, _ := f.current()
	if h.Oversized != 1 || len(h.OversizedNames) != 1 || h.OversizedNames[0] != "fat" {
		t.Errorf("oversized %d %v", h.Oversized, h.OversizedNames)
	}
}

// A lookup never answers from a block whose checksum it did not verify.
func TestSnapshotLookupVerifiesTheBlock(t *testing.T) {
	f := files{dir: t.TempDir()}
	var recs []snapRecord
	for i := 0; i < 40; i++ {
		recs = append(recs, snapRecord{Name: fmt.Sprintf("pkg%02d", i), Version: "1.2.3", Path: fmt.Sprintf("/pool/pkg%02d_1.2.3.deb", i), Size: 1000 + int64(i)})
	}
	h := buildSnap(t, f, recs, 0)
	want := map[string][]snapRecord{}
	for _, r := range recs {
		want[r.Name] = append(want[r.Name], r)
	}
	path := f.path(snapName(h.Digest))
	st, _ := os.Stat(path)
	orig, _ := os.ReadFile(path)
	start := int(h.dataStart) + 10
	end := int(h.dataStart+h.Blocks[0].Off+h.Blocks[0].Len) - 8
	step := 1
	if raceEnabled {
		step = 7
	}
	for pos := start; pos < end; pos += step {
		data := append([]byte(nil), orig...)
		data[pos] ^= 0x10
		os.WriteFile(path, data, 0o644)
		os.Chtimes(path, st.ModTime(), st.ModTime())
		for _, name := range []string{"pkg00", "pkg17", "pkg39"} {
			got, err := f.snapLookup(h, name)
			if err == nil && !reflect.DeepEqual(got, want[name]) {
				t.Fatalf("byte %d: lookup %s answered %+v from a damaged block", pos, name, got)
			}
		}
	}
}

// A source that panics leaves no spilled runs behind.
type panicIndex struct{}

func (panicIndex) readIndex(_ context.Context, _ json.RawMessage, _ *snapHeader, b *snapBuilder) (indexRead, error) {
	b.limit = 4 << 10
	for i := 0; i < 2000; i++ {
		b.Add(snapRecord{Name: fmt.Sprintf("p%05d", i), Version: "1"})
	}
	panic("parser bug")
}

func TestIndexFeedPanickingSourceLeavesNoRuns(t *testing.T) {
	f := newIndexFeed("test", Env{Dir: t.TempDir()}, panicIndex{})
	func() {
		defer func() { recover() }()
		f.Bootstrap(context.Background(), "")
	}()
	if ents, _ := os.ReadDir(f.files.dir); len(ents) > 0 {
		t.Errorf("%d files left behind, e.g. %s", len(ents), ents[0].Name())
	}
}

// One item dated in the future is reported but does not become the mark:
// what is published after it is still reported.
func TestListingFeedFutureItemDoesNotFreezeTheMark(t *testing.T) {
	l := &fakeListing{size: 10}
	l.publish("a", "1", at(0))
	f := newTestListingFeed(l)
	_, cursor := drainBootstrap(t, f)
	l.publish("bogus", "1", listT0.AddDate(70, 0, 0))
	got, cursor := drainChanges(t, f, cursor)
	if strings.Join(got, ",") != "bogus@1" {
		t.Errorf("the future item: %v", got)
	}
	l.publish("b", "1", at(10))
	l.publish("c", "1", at(20))
	if got, _ := drainChanges(t, f, cursor); strings.Join(got, ",") != "b@1,c@1" {
		t.Errorf("after an item dated 2096: %v", got)
	}
	// A cursor whose mark lies in the future is not trusted.
	bad := encodeCursor(&listingCursor{Format: f.format(), Mark: listT0.AddDate(70, 0, 0)})
	if _, err := f.Changes(context.Background(), bad); !errors.Is(err, ErrCursorInvalid) {
		t.Errorf("a mark in the future: %v", err)
	}
}

// An item that becomes visible after a newer one (its time stamp taken
// before it committed) is reported if it lies within the lookback window.
func TestListingFeedReportsALateItemInTheWindow(t *testing.T) {
	l := &fakeListing{size: 10}
	l.publish("a", "1", at(0))
	f := newTestListingFeed(l)
	_, cursor := drainBootstrap(t, f)
	l.publish("fast", "1", at(10).Add(2*time.Second))
	_, cursor = drainChanges(t, f, cursor)
	l.publish("slow", "1", at(10))
	got, cursor := drainChanges(t, f, cursor)
	if strings.Join(got, ",") != "slow@1" {
		t.Errorf("an item visible late: %v", got)
	}
	if got, _ := drainChanges(t, f, cursor); len(got) != 0 {
		t.Errorf("reported twice: %v", got)
	}
}

// Many items in one instant, with long ids, keep the cursor within bounds.
func TestListingFeedCursorStaysBounded(t *testing.T) {
	l := &fakeListing{size: 100}
	l.publish("seed", "1", at(0))
	f := newTestListingFeed(l)
	_, cursor := drainBootstrap(t, f)
	l.mu.Lock()
	for i := 0; i < 3000; i++ {
		l.items = append([]listingItem{{
			Name: fmt.Sprintf("some-organization/some-model-name-%06d", i),
			ID:   fmt.Sprintf("some-organization/some-model-name-%06d@%040x", i, i),
			Time: at(5),
		}}, l.items...)
	}
	l.mu.Unlock()
	for i := 0; i < 10; i++ {
		b, err := f.Changes(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateBatch(b); err != nil {
			t.Fatalf("the engine refuses the batch (cursor %d bytes): %v", len(b.Next), err)
		}
		cursor = b.Next
		if !b.More {
			break
		}
	}
}

// A next-page token longer than a cursor may keep is the listing's error.
type longTokenListing struct{ *fakeListing }

func (l longTokenListing) recent(ctx context.Context, token string) (listingPage, error) {
	pg, err := l.fakeListing.recent(ctx, strings.TrimLeft(token, "x"))
	if pg.Next != "" {
		pg.Next = strings.Repeat("x", 70_000) + pg.Next
	}
	return pg, err
}

func TestListingFeedRefusesALongToken(t *testing.T) {
	l := &fakeListing{size: 1}
	l.publish("a", "1", at(0))
	f := newTestListingFeed(longTokenListing{l})
	f.lookback = 0
	_, cursor := drainBootstrap(t, f)
	l.publish("b", "1", at(1))
	l.publish("c", "1", at(2))
	if _, err := f.Changes(context.Background(), cursor); err == nil {
		t.Errorf("a 70 KB token was kept")
	}
}

// A split enumeration page continues after the item it stopped at, wherever
// deletions moved it.
func TestListingFeedSplitPageSurvivesADeletion(t *testing.T) {
	l := &fakeListing{size: 1000}
	for i := 0; i < 25; i++ {
		l.publish(fmt.Sprintf("p%d", 100+i), "1", at(i))
	}
	f := newTestListingFeed(l)
	f.batch = 10
	listed := map[string]bool{}
	b, err := f.Bootstrap(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names(b.Items) {
		listed[n] = true
	}
	l.deleteName("p100")
	cursor := b.Next
	for b.More {
		if b, err = f.Bootstrap(context.Background(), cursor); err != nil {
			t.Fatal(err)
		}
		for _, n := range names(b.Items) {
			listed[n] = true
		}
		cursor = b.Next
	}
	for i := 101; i < 125; i++ {
		if n := fmt.Sprintf("p%d", i); !listed[n] {
			t.Errorf("%s was never listed", n)
		}
	}
}

// A pass longer than a call continues one page back: an item deleted above
// the continuation in between shifts no unseen item past it.
func TestListingFeedPassSurvivesADeletionBetweenCalls(t *testing.T) {
	l := &fakeListing{size: 2}
	l.publish("old", "1", at(0))
	f := newTestListingFeed(l)
	_, cursor := drainBootstrap(t, f)
	for i := 0; i < 8; i++ {
		l.publish(fmt.Sprintf("new%d", i), "1", at(20+i))
	}
	f.maxPages = 2
	reported := map[string]bool{}
	b, err := f.Changes(context.Background(), cursor)
	if err != nil || !b.More {
		t.Fatalf("%+v %v", b, err)
	}
	for _, n := range names(b.Items) {
		reported[strings.TrimSuffix(n, "@1")] = true
	}
	l.deleteName("new7")
	got, _ := drainChanges(t, f, b.Next)
	for _, g := range got {
		reported[strings.TrimSuffix(g, "@1")] = true
	}
	for i := 0; i < 7; i++ {
		if n := fmt.Sprintf("new%d", i); !reported[n] {
			t.Errorf("%s was published but never reported", n)
		}
	}
}

func (l *fakeListing) deleteName(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.items[:0]
	for _, it := range l.items {
		if it.Name != name {
			out = append(out, it)
		}
	}
	l.items = out
}

// The largest listing cursor — every remembered set full, entries at the
// longest time stamps, the longest token, escaped — fits what the engine
// stores.
func TestListingFeedLargestCursorFits(t *testing.T) {
	far := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	full := make([]string, 0, listingMaxSeen)
	for i := 0; i < listingMaxSeen; i++ {
		full = append(full, strconv.FormatInt(listingSeconds(far), 10)+":"+listingHash(fmt.Sprint(i)))
	}
	token := strings.Repeat("&", listingMaxToken/6)
	if listingTokenSize(token) > listingMaxToken {
		t.Fatalf("token %d", listingTokenSize(token))
	}
	c := listingCursor{Format: "huggingface-listing/1", Mark: far, Seen: full, Pass: true, Token: token, Top: far, Fresh: full}
	if n := len(encodeCursor(&c)); n > maxCursorBytes {
		t.Errorf("the largest listing cursor is %d bytes; the engine keeps %d", n, maxCursorBytes)
	} else {
		t.Logf("the largest listing cursor is %d bytes of %d", n, maxCursorBytes)
	}
	if got := listingSeconds(time.Date(200000, 1, 1, 0, 0, 0, 0, time.UTC)); got != listingSeconds(far) {
		t.Errorf("a time past 9999 is remembered at %d", got)
	}
}

// The largest index cursor — two full states, the longest head and name —
// fits what the engine stores.
func TestIndexFeedLargestCursorFits(t *testing.T) {
	state := jsonString('&', indexMaxState/6-2)
	if indexStateSize(state) > indexMaxState {
		t.Fatalf("state %d", indexStateSize(state))
	}
	c := indexCursor{Format: "maven/1", Snap: strings.Repeat("a", 64), State: state, To: strings.Repeat("b", 64), ToState: state,
		Skip: 1 << 30, Head: strings.Repeat("&", indexMaxHead), HeadTime: time.Now()}
	if n := len(encodeCursor(&c)); n > maxCursorBytes {
		t.Errorf("the largest index cursor is %d bytes; the engine keeps %d", n, maxCursorBytes)
	}
	l := indexCursor{Format: "maven/1", Snap: strings.Repeat("a", 64), State: state, Listing: true, After: strings.Repeat("&", 1024), Listed: 1 << 30}
	if n := len(encodeCursor(&l)); n > maxCursorBytes {
		t.Errorf("the largest listing cursor of an index is %d bytes", n)
	}
}
