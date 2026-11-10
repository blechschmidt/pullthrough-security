package cachegc

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// base is a fixed clock origin so tests are deterministic.
var base = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// fakeCache is an in-memory cachegc.Cache for testing the engine end to end.
type fakeCache struct {
	mu         sync.Mutex
	entries    map[string]cache.GCEntry
	deleted    []string
	failDelete map[string]error // keys whose Delete should fail with the given error
}

func newFakeCache(entries ...cache.GCEntry) *fakeCache {
	m := make(map[string]cache.GCEntry, len(entries))
	for _, e := range entries {
		m[e.Key] = e
	}
	return &fakeCache{entries: m, failDelete: map[string]error{}}
}

func (f *fakeCache) GCEntries(_ context.Context) ([]cache.GCEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cache.GCEntry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e)
	}
	// Deterministic order in, so the planner's stable tiebreak is exercised.
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (f *fakeCache) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.failDelete[key]; ok {
		return err
	}
	if _, ok := f.entries[key]; !ok {
		return cache.ErrNotFound
	}
	delete(f.entries, key)
	f.deleted = append(f.deleted, key)
	return nil
}

func (f *fakeCache) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.entries[key]
	return ok
}

// entry builds a GCEntry. idleSecs is how long ago it was accessed; ageSecs how
// long ago it was created.
func entry(key string, size int64, ageSecs, idleSecs int, hits int64) cache.GCEntry {
	return cache.GCEntry{
		Key:         key,
		Size:        size,
		CreatedAt:   base.Add(-time.Duration(ageSecs) * time.Second),
		AccessedAt:  base.Add(-time.Duration(idleSecs) * time.Second),
		AccessCount: hits,
		Metadata:    map[string]string{},
	}
}

func newEngine(t *testing.T, cfg Config, c Cache, sources ...ReferenceSource) *Engine {
	t.Helper()
	e, err := New(cfg, c, Options{Sources: sources, Now: func() time.Time { return base }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func evictedKeys(rep Report) []string {
	out := make([]string, 0, len(rep.Evicted))
	for _, r := range rep.Evicted {
		out = append(out, r.Key)
	}
	return out
}

// --- watermark ordering -----------------------------------------------------

func TestWatermarkEvictionLRUOrdering(t *testing.T) {
	// Capacity 1000, high 900, low 700. Used 1000 → must evict ≥300 bytes,
	// least-recently-accessed first.
	c := newFakeCache(
		entry("a", 250, 100, 10, 5), // most recently accessed (idle 10s)
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5), // least recently accessed (idle 50s)
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)

	rep := e.plan(mustEntries(t, c), base)
	// Evict oldest-access first: d (50s), then b (40s) → 500 bytes, leaving 500 ≤ 700.
	got := evictedKeys(rep)
	want := []string{"d", "b"}
	if !equalStrings(got, want) {
		t.Fatalf("LRU eviction order = %v, want %v", got, want)
	}
	if rep.BytesReclaimed != 500 {
		t.Errorf("BytesReclaimed = %d, want 500", rep.BytesReclaimed)
	}
}

func TestWatermarkEvictionLFUOrdering(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 100), // hot
		entry("b", 250, 100, 10, 1),   // coldest
		entry("c", 250, 100, 10, 2),
		entry("d", 250, 100, 10, 50),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLFU}, c)
	rep := e.plan(mustEntries(t, c), base)
	// Least-frequently-used first: b (1), c (2) → 500 bytes.
	got := evictedKeys(rep)
	want := []string{"b", "c"}
	if !equalStrings(got, want) {
		t.Fatalf("LFU eviction order = %v, want %v", got, want)
	}
}

func TestWatermarkEvictionFIFOOrdering(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 10, 5, 5), // newest
		entry("b", 250, 90, 5, 5), // oldest
		entry("c", 250, 50, 5, 5),
		entry("d", 250, 70, 5, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyFIFO}, c)
	rep := e.plan(mustEntries(t, c), base)
	// Oldest-created first: b (90s), d (70s).
	got := evictedKeys(rep)
	want := []string{"b", "d"}
	if !equalStrings(got, want) {
		t.Fatalf("FIFO eviction order = %v, want %v", got, want)
	}
}

func TestNoEvictionBelowHighWatermark(t *testing.T) {
	// Used 800 < high 900: nothing evicted even though above low (700).
	c := newFakeCache(
		entry("a", 400, 100, 10, 5),
		entry("b", 400, 100, 10, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	rep := e.plan(mustEntries(t, c), base)
	if rep.EvictedCount != 0 {
		t.Fatalf("expected no eviction below high watermark, evicted %d", rep.EvictedCount)
	}
	if rep.AboveHighWatermark {
		t.Errorf("AboveHighWatermark should be false at 80%% utilization")
	}
}

// --- pin / retention --------------------------------------------------------

func TestPinnedEntryRetainedUnderPressure(t *testing.T) {
	pinned := entry("pinned", 500, 100, 50, 1) // oldest+coldest, would be first victim
	pinned.Metadata[cache.MetaPin] = "true"
	c := newFakeCache(
		pinned,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, NewMetadataPinSource())
	rep := e.plan(mustEntries(t, c), base)
	for _, k := range evictedKeys(rep) {
		if k == "pinned" {
			t.Fatalf("pinned entry was evicted: %v", evictedKeys(rep))
		}
	}
	if !hasRetained(rep, "pinned") {
		t.Errorf("pinned entry should appear in Retained: %+v", rep.Retained)
	}
}

func TestAllowEvictPinnedOverridesPin(t *testing.T) {
	pinned := entry("pinned", 500, 100, 50, 1)
	pinned.Metadata[cache.MetaPin] = "yes"
	c := newFakeCache(
		pinned,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU, AllowEvictPinned: true}, c, NewMetadataPinSource())
	rep := e.plan(mustEntries(t, c), base)
	// With pin override the LRU victim "pinned" (idle 50s) is evicted first.
	if !contains(evictedKeys(rep), "pinned") {
		t.Fatalf("AllowEvictPinned should evict pinned entry, evicted %v", evictedKeys(rep))
	}
}

func TestQuarantineKeySetSourceRetains(t *testing.T) {
	// A quarantined digest must never be reclaimed (held for evidence).
	q := entry("sha256:evil", 500, 100, 50, 1)
	c := newFakeCache(
		q,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	src := NewKeySetSource("quarantine", func() map[string]struct{} {
		return map[string]struct{}{"sha256:evil": {}}
	})
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, src)
	rep := e.plan(mustEntries(t, c), base)
	if contains(evictedKeys(rep), "sha256:evil") {
		t.Fatalf("quarantined entry was evicted: %v", evictedKeys(rep))
	}
	if !hasRetained(rep, "sha256:evil") {
		t.Errorf("quarantined entry should be retained under pressure")
	}
}

func TestKeySetSourceMatchesMetadataValue(t *testing.T) {
	// The protected set holds a digest carried only in metadata, not the key.
	en := entry("npm/left-pad/1.0.0", 500, 100, 50, 1)
	en.Metadata["digest"] = "sha256:abc"
	c := newFakeCache(
		en,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	src := NewKeySetSource("quarantine", func() map[string]struct{} {
		return map[string]struct{}{"sha256:abc": {}}
	})
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, src)
	rep := e.plan(mustEntries(t, c), base)
	if contains(evictedKeys(rep), "npm/left-pad/1.0.0") {
		t.Fatalf("entry referenced by metadata digest was evicted")
	}
}

// --- reference-count safety -------------------------------------------------

func TestRefTrackerProtectsHeldEntry(t *testing.T) {
	held := entry("held", 500, 100, 50, 1) // would be LRU victim
	c := newFakeCache(
		held,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	rt := NewRefTracker()
	rt.Retain("held")
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, rt)

	rep := e.plan(mustEntries(t, c), base)
	if contains(evictedKeys(rep), "held") {
		t.Fatalf("entry with an active reference hold was evicted")
	}

	// Release the hold: it becomes evictable again.
	rt.Release("held")
	if rt.Count("held") != 0 {
		t.Fatalf("ref count after release = %d, want 0", rt.Count("held"))
	}
	rep2 := e.plan(mustEntries(t, c), base)
	if !contains(evictedKeys(rep2), "held") {
		t.Fatalf("released entry should be evictable, evicted %v", evictedKeys(rep2))
	}
}

func TestRefTrackerCountedReleases(t *testing.T) {
	rt := NewRefTracker()
	rt.Retain("k")
	rt.Retain("k")
	if rt.Count("k") != 2 {
		t.Fatalf("count = %d, want 2", rt.Count("k"))
	}
	rt.Release("k")
	if ok, _ := rt.Referenced(cache.GCEntry{Key: "k"}); !ok {
		t.Fatal("still one hold; should be referenced")
	}
	rt.Release("k")
	if ok, _ := rt.Referenced(cache.GCEntry{Key: "k"}); ok {
		t.Fatal("all holds released; should not be referenced")
	}
	// Over-release never goes negative.
	rt.Release("k")
	if rt.Count("k") != 0 {
		t.Fatalf("count after over-release = %d, want 0", rt.Count("k"))
	}
}

// --- in-flight / min-idle guards --------------------------------------------

func TestInFlightEntryNeverEvicted(t *testing.T) {
	inflight := entry("inflight", 500, 100, 50, 1) // LRU victim by recency
	inflight.InFlight = true
	c := newFakeCache(
		inflight,
		entry("b", 300, 100, 10, 5),
		entry("d", 300, 100, 40, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	rep := e.plan(mustEntries(t, c), base)
	if contains(evictedKeys(rep), "inflight") {
		t.Fatalf("in-flight entry was evicted (eviction mid-stream)")
	}
	if !hasRetained(rep, "inflight") {
		t.Errorf("in-flight entry should be retained")
	}
}

func TestMinIdleGuardProtectsRecentlyAccessed(t *testing.T) {
	c := newFakeCache(
		entry("fresh", 500, 100, 2, 1), // accessed 2s ago — within min-idle
		entry("b", 300, 100, 40, 5),
		entry("d", 300, 100, 50, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU, MinIdle: 10 * time.Second}, c)
	rep := e.plan(mustEntries(t, c), base)
	if contains(evictedKeys(rep), "fresh") {
		t.Fatalf("recently-accessed entry within min-idle was evicted")
	}
}

// --- TTL --------------------------------------------------------------------

func TestTTLEvictionIndependentOfWatermark(t *testing.T) {
	// No capacity → no watermark eviction. Only TTL applies.
	c := newFakeCache(
		entry("old", 100, 7200, 7200, 1), // 2h old
		entry("new", 100, 60, 60, 1),     // 1m old
	)
	e := newEngine(t, Config{Enabled: true, DefaultTTL: time.Hour}, c)
	rep := e.plan(mustEntries(t, c), base)
	want := []string{"old"}
	if !equalStrings(evictedKeys(rep), want) {
		t.Fatalf("TTL eviction = %v, want %v", evictedKeys(rep), want)
	}
	if rep.Evicted[0].Reason != ReasonTTL {
		t.Errorf("reason = %q, want %q", rep.Evicted[0].Reason, ReasonTTL)
	}
}

func TestPerTenantTTLOverride(t *testing.T) {
	a := entry("teamA/x", 100, 1800, 1800, 1) // 30m old
	b := entry("teamB/y", 100, 1800, 1800, 1)
	a.Metadata[cache.MetaTenant] = "teamA"
	b.Metadata[cache.MetaTenant] = "teamB"
	c := newFakeCache(a, b)
	e := newEngine(t, Config{
		Enabled:    true,
		DefaultTTL: time.Hour,
		TenantTTLs: map[string]time.Duration{"teamA": 15 * time.Minute}, // tighter
	}, c)
	rep := e.plan(mustEntries(t, c), base)
	// teamA's 30m-old entry exceeds its 15m TTL; teamB's is within the 1h default.
	if !equalStrings(evictedKeys(rep), []string{"teamA/x"}) {
		t.Fatalf("per-tenant TTL eviction = %v, want [teamA/x]", evictedKeys(rep))
	}
}

func TestPinSurvivesTTL(t *testing.T) {
	old := entry("old", 100, 7200, 7200, 1)
	old.Metadata[cache.MetaPin] = "true"
	c := newFakeCache(old)
	e := newEngine(t, Config{Enabled: true, DefaultTTL: time.Hour}, c, NewMetadataPinSource())
	rep := e.plan(mustEntries(t, c), base)
	if rep.EvictedCount != 0 {
		t.Fatalf("pinned-but-expired entry was evicted")
	}
	if !hasRetained(rep, "old") || !rep.Retained[0].Expired {
		t.Errorf("expected pinned expired entry retained with Expired=true: %+v", rep.Retained)
	}
}

// --- MaxDeletesPerRun -------------------------------------------------------

func TestMaxDeletesPerRunCaps(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU, MaxDeletesPerRun: 1}, c)
	rep := e.plan(mustEntries(t, c), base)
	if rep.EvictedCount != 1 {
		t.Fatalf("MaxDeletesPerRun=1 evicted %d", rep.EvictedCount)
	}
}

// --- helpers ----------------------------------------------------------------

func mustEntries(t *testing.T, c *fakeCache) []cache.GCEntry {
	t.Helper()
	es, err := c.GCEntries(context.Background())
	if err != nil {
		t.Fatalf("GCEntries: %v", err)
	}
	return es
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func hasRetained(rep Report, key string) bool {
	for _, r := range rep.Retained {
		if r.Key == key {
			return true
		}
	}
	return false
}
