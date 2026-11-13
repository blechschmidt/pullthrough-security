package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// pinSet is a mutable PinChecker for tests.
type pinSet struct {
	mu   sync.Mutex
	keys map[string]bool
}

func pins(keys ...string) *pinSet {
	p := &pinSet{keys: map[string]bool{}}
	for _, k := range keys {
		p.keys[k] = true
	}
	return p
}

func (p *pinSet) IsPinned(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys[key]
}

func put(t *testing.T, c Cache, key string, size int) {
	t.Helper()
	if _, err := c.Put(context.Background(), key, bytes.NewReader(bytes.Repeat([]byte{'x'}, size)), nil); err != nil {
		t.Fatalf("Put %s: %v", key, err)
	}
}

func present(c Cache, key string) bool {
	_, err := c.Stat(context.Background(), key)
	return err == nil
}

// LRU eviction for size never takes a pinned entry: the bound is enforced on
// what is not pinned, and an entry just written is not evicted either.
func TestFilesystemCacheLRUNeverEvictsPinned(t *testing.T) {
	p := pins("release/a", "release/b")
	fc, err := NewFilesystemCache(FilesystemOptions{Dir: t.TempDir(), MaxSizeBytes: 300, Pins: p})
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	put(t, fc, "release/a", 100) // least recently used: first in line for eviction
	put(t, fc, "release/b", 100)
	for i := 0; i < 20; i++ {
		put(t, fc, "filler/"+string(rune('a'+i)), 100)
	}
	if !present(fc, "release/a") || !present(fc, "release/b") {
		t.Fatal("a pinned entry was evicted for size")
	}
	if !present(fc, "filler/t") {
		t.Fatal("the entry just written was evicted")
	}
	if present(fc, "filler/a") {
		t.Fatal("unpinned entries are still evicted")
	}

	// Pinned entries alone over the bound: they stay, the cache stays over it.
	p2 := pins("p1", "p2", "p3")
	fc2, err := NewFilesystemCache(FilesystemOptions{Dir: t.TempDir(), MaxSizeBytes: 150, Pins: p2})
	if err != nil {
		t.Fatal(err)
	}
	defer fc2.Close()
	for _, k := range []string{"p1", "p2", "p3"} {
		put(t, fc2, k, 100)
	}
	for _, k := range []string{"p1", "p2", "p3"} {
		if !present(fc2, k) {
			t.Fatalf("%s evicted", k)
		}
	}
}

// A walk passes over a bounded number of pinned entries; with more of them at
// the cold end, later writes go on where it stopped, and the unpinned entries
// behind them are still evicted in the end.
func TestFilesystemCacheEvictionWalkIsBounded(t *testing.T) {
	saved := maxPinnedSkips
	maxPinnedSkips = 2
	defer func() { maxPinnedSkips = saved }()
	p := pins()
	for i := 0; i < 10; i++ {
		p.keys["pinned/"+string(rune('a'+i))] = true
	}
	fc, err := NewFilesystemCache(FilesystemOptions{Dir: t.TempDir(), MaxSizeBytes: 1500, Pins: p})
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	for i := 0; i < 10; i++ {
		put(t, fc, "pinned/"+string(rune('a'+i)), 100)
	}
	put(t, fc, "old", 100) // behind ten pinned entries
	for i := 0; i < 5; i++ {
		put(t, fc, "new/"+string(rune('a'+i)), 100)
	}
	// Over the bound since the last write, whose walk stopped after two
	// pinned entries, short of "old".
	if !present(fc, "old") {
		t.Fatal("one walk passed over more pinned entries than its bound")
	}
	// Each later write passes over two more, and the walks reach "old".
	for i := 0; i < 8; i++ {
		put(t, fc, "more/"+string(rune('a'+i)), 10)
	}
	if present(fc, "old") {
		t.Fatal("the unpinned entry behind the pinned ones was never evicted")
	}
	for k := range p.keys {
		if !present(fc, k) {
			t.Fatalf("%s evicted", k)
		}
	}
}

// The size bound enforced while the index is warmed at startup honours the
// pins passed in the options.
func TestFilesystemCacheWarmupKeepsPinned(t *testing.T) {
	dir := t.TempDir()
	fc, err := NewFilesystemCache(FilesystemOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	put(t, fc, "release/a", 200)
	time.Sleep(5 * time.Millisecond)
	put(t, fc, "filler", 200)
	_ = fc.Close()

	// Reopen with a bound below what is stored: the oldest entry is the pinned one.
	fc, err = NewFilesystemCache(FilesystemOptions{Dir: dir, MaxSizeBytes: 250, Pins: pins("release/a")})
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	if !present(fc, "release/a") {
		t.Fatal("warm-up evicted a pinned entry")
	}
}

func TestFilesystemCacheTTLNeverExpiresPinned(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	fc, err := NewFilesystemCache(FilesystemOptions{Dir: t.TempDir(), TTL: time.Hour, Pins: pins("release/a"), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	put(t, fc, "release/a", 10)
	put(t, fc, "plain", 10)
	now = now.Add(48 * time.Hour)
	fc.sweepExpired()
	if !present(fc, "release/a") {
		t.Fatal("a pinned entry expired")
	}
	if present(fc, "plain") {
		t.Fatal("an unpinned entry did not expire")
	}
	e, err := fc.Get(context.Background(), "release/a")
	if err != nil {
		t.Fatalf("a pinned entry past its TTL is still served: %v", err)
	}
	e.Content.Close()
}

// Delete refuses a pinned key — a quarantine, a GC run, an administrator's
// purge — except under the integrity layer's override.
func TestDeleteRefusesPinnedKeys(t *testing.T) {
	for name, c := range map[string]Cache{
		"filesystem": mustFS(t),
		"memory":     NewMemoryCache(),
	} {
		t.Run(name, func(t *testing.T) {
			if !SetPinChecker(NewIntegrityCache(NewSealedCache(c), IntegrityOptions{}), pins("release/a")) {
				t.Fatal("the pin checker did not reach the cache through its wrappers")
			}
			put(t, c, "release/a", 10)
			put(t, c, "plain", 10)
			err := c.Delete(context.Background(), "release/a")
			if !errors.Is(err, ErrPinned) || !strings.Contains(err.Error(), "release/a") {
				t.Fatalf("delete of a pinned key: %v", err)
			}
			if !present(c, "release/a") {
				t.Fatal("refused, yet gone")
			}
			if err := c.Delete(context.Background(), "plain"); err != nil {
				t.Fatalf("an unpinned key: %v", err)
			}
			if err := c.Delete(WithPinOverride(context.Background(), "integrity"), "release/a"); err != nil {
				t.Fatalf("override: %v", err)
			}
			if present(c, "release/a") {
				t.Fatal("the override did not delete")
			}
		})
	}
}

func mustFS(t *testing.T) *FilesystemCache {
	t.Helper()
	fc, err := NewFilesystemCache(FilesystemOptions{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fc.Close() })
	return fc
}

// The integrity layer removes a pinned object whose bytes went bad — they are
// worthless to the release, whose owner fetches it again — and tells the
// observer.
func TestIntegrityQuarantinesCorruptPinnedObject(t *testing.T) {
	ic, store, obs := newIntegrityFSCache(t)
	SetPinChecker(ic, pins("release/a"))
	put(t, ic, "release/a", 64)
	corruptBlob(t, store, "release/a", bytes.Repeat([]byte{'y'}, 64))
	e, err := ic.Get(context.Background(), "release/a")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(e.Content)
	e.Content.Close()
	evs := obs.snapshot()
	if len(evs) != 1 || !evs[0].Quarantined {
		t.Fatalf("corruption of a pinned object: %+v", evs)
	}
	if present(ic, "release/a") {
		t.Fatal("corrupt bytes of a pinned object were kept")
	}
}

// Tiering may demote a pinned object to the cold tier; it never drops it, and
// the object stays readable through the cache.
func TestTieringDemotesButKeepsPinnedObjects(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{PromoteOnRead: true, DemoteAfterIdle: time.Hour, now: clk.Now})
	fc, err := NewFilesystemCache(FilesystemOptions{Store: ts, Pins: pins("release/a")})
	if err != nil {
		t.Fatal(err)
	}
	put(t, fc, "release/a", 32)
	clk.advance(2 * time.Hour)
	rep, err := ts.SweepTiers(context.Background())
	if err != nil || rep.Demoted != 1 {
		t.Fatalf("sweep: %+v %v", rep, err)
	}
	if !storeHasKey(t, ts.cold, "release/a") || storeHasKey(t, ts.hot, "release/a") {
		t.Fatal("the pinned object was not demoted to the cold tier")
	}
	e, err := fc.Get(context.Background(), "release/a")
	if err != nil {
		t.Fatalf("a demoted pinned object must stay readable: %v", err)
	}
	b, _ := io.ReadAll(e.Content)
	e.Content.Close()
	if len(b) != 32 {
		t.Fatalf("content %d bytes", len(b))
	}
	if err := fc.Delete(context.Background(), "release/a"); !errors.Is(err, ErrPinned) {
		t.Fatalf("delete after demotion: %v", err)
	}
}
