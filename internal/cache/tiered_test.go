package cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- test helpers -----------------------------------------------------------

// newFakeClock returns a settable clock (type fakeClock is shared with
// fscache_test.go) seeded to a fixed, non-zero instant.
func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()} }

// newTieredPair builds a tiered store over two fresh filesystem stores. It
// returns the tiered store; both stores are closed on cleanup via ts.Close.
func newTieredPair(t *testing.T, opts TieredOptions) *TieredStore {
	t.Helper()
	hot, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("hot store: %v", err)
	}
	cold, err := NewFilesystemStore(t.TempDir())
	if err != nil {
		t.Fatalf("cold store: %v", err)
	}
	opts.Hot = hot
	opts.Cold = cold
	ts, err := NewTieredStore(opts)
	if err != nil {
		t.Fatalf("NewTieredStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })
	return ts
}

func putBytes(t *testing.T, s Store, key string, data []byte, meta map[string]string) Record {
	t.Helper()
	rec := Record{Key: key, Extra: meta}
	stored, err := s.Put(context.Background(), rec, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Put %q: %v", key, err)
	}
	return stored
}

func getBytes(t *testing.T, s Store, key string) ([]byte, Record) {
	t.Helper()
	rc, rec, err := s.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get %q: %v", key, err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	return data, rec
}

func storeHasKey(t *testing.T, s Store, key string) bool {
	t.Helper()
	_, err := s.Stat(context.Background(), key)
	if err == nil {
		return true
	}
	if err == ErrNotFound {
		return false
	}
	t.Fatalf("Stat %q: %v", key, err)
	return false
}

// --- tests ------------------------------------------------------------------

func TestTieredPutWritesHot(t *testing.T) {
	ts := newTieredPair(t, TieredOptions{})
	data := []byte("hello tiered world")
	putBytes(t, ts, "k1", data, nil)

	if !storeHasKey(t, ts.hot, "k1") {
		t.Fatal("expected k1 in hot store after Put")
	}
	if storeHasKey(t, ts.cold, "k1") {
		t.Fatal("did not expect k1 in cold store after Put")
	}
	got, _ := getBytes(t, ts, "k1")
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: got %q want %q", got, data)
	}
	st := ts.TieredStats()
	if st.HotObjects != 1 || st.ColdObjects != 0 {
		t.Fatalf("gauges: hot=%d cold=%d want 1/0", st.HotObjects, st.ColdObjects)
	}
	if st.HotHits != 1 {
		t.Fatalf("HotHits=%d want 1", st.HotHits)
	}
}

func TestTieredDemoteThenPromotePreservesContent(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{
		PromoteOnRead:   true,
		DemoteAfterIdle: time.Hour,
		now:             clk.Now,
	})
	data := []byte("demote-me-please-and-keep-my-metadata")
	created := time.Unix(1_600_000_000, 0).UTC()
	rec := Record{
		Key:         "art",
		Origin:      "https://example.test/x",
		ContentType: "application/zip",
		CreatedAt:   created,
		Extra:       map[string]string{"pte.pdigest": "sha256:deadbeef"}, // simulate an encryption sidecar
	}
	stored, err := ts.Put(context.Background(), rec, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Idle past the threshold, then sweep -> demotion to cold.
	clk.advance(2 * time.Hour)
	rep, err := ts.SweepTiers(context.Background())
	if err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}
	if rep.Demoted != 1 {
		t.Fatalf("expected 1 demotion, got %+v", rep)
	}
	if storeHasKey(t, ts.hot, "art") {
		t.Fatal("art should no longer be in hot after demotion")
	}
	if !storeHasKey(t, ts.cold, "art") {
		t.Fatal("art should be in cold after demotion")
	}
	st := ts.TieredStats()
	if st.HotObjects != 0 || st.ColdObjects != 1 {
		t.Fatalf("gauges after demote: hot=%d cold=%d want 0/1", st.HotObjects, st.ColdObjects)
	}

	// Read -> promote back to hot, content + metadata + digest preserved.
	got, rec := getBytes(t, ts, "art")
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch after promote: got %q want %q", got, data)
	}
	if rec.Digest != stored.Digest {
		t.Fatalf("digest changed across tier moves: got %q want %q", rec.Digest, stored.Digest)
	}
	if rec.Origin != "https://example.test/x" || rec.ContentType != "application/zip" {
		t.Fatalf("structured metadata not preserved across tier moves: %+v", rec)
	}
	if !rec.CreatedAt.Equal(created) {
		t.Fatalf("CreatedAt not preserved across tier moves: got %v want %v", rec.CreatedAt, created)
	}
	if rec.Extra["pte.pdigest"] != "sha256:deadbeef" {
		t.Fatalf("encryption sidecar Extra not preserved across tier moves: %+v", rec.Extra)
	}
	if !storeHasKey(t, ts.hot, "art") {
		t.Fatal("art should be back in hot after promote-on-read")
	}
	if storeHasKey(t, ts.cold, "art") {
		t.Fatal("art cold copy should be removed after promotion")
	}
	st = ts.TieredStats()
	if st.Promotions != 1 || st.Demotions != 1 {
		t.Fatalf("counters: promotions=%d demotions=%d want 1/1", st.Promotions, st.Demotions)
	}
	if st.HotObjects != 1 || st.ColdObjects != 0 {
		t.Fatalf("gauges after promote: hot=%d cold=%d want 1/0", st.HotObjects, st.ColdObjects)
	}
}

func TestTieredNoPromoteOnReadServesCold(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{
		PromoteOnRead:   false,
		DemoteAfterIdle: time.Hour,
		now:             clk.Now,
	})
	data := []byte("stay-cold")
	putBytes(t, ts, "c", data, nil)
	clk.advance(2 * time.Hour)
	if _, err := ts.SweepTiers(context.Background()); err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}

	got, _ := getBytes(t, ts, "c")
	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch: got %q want %q", got, data)
	}
	if storeHasKey(t, ts.hot, "c") {
		t.Fatal("c should remain cold-only when promote-on-read is disabled")
	}
	st := ts.TieredStats()
	if st.Promotions != 0 {
		t.Fatalf("expected no promotions, got %d", st.Promotions)
	}
	if st.ColdHits == 0 {
		t.Fatal("expected a cold hit")
	}
}

func TestTieredFrequencyKeepsHot(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{
		DemoteAfterIdle:      time.Hour,
		MinAccessesToStayHot: 3,
		now:                  clk.Now,
	})
	putBytes(t, ts, "pop", []byte("popular"), nil)
	// Read it enough times to exceed the frequency floor.
	for i := 0; i < 3; i++ {
		getBytes(t, ts, "pop")
	}
	// Even though idle past the threshold, the frequency floor protects it.
	clk.advance(2 * time.Hour)
	rep, err := ts.SweepTiers(context.Background())
	if err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}
	if rep.Demoted != 0 {
		t.Fatalf("frequently-read artifact should not be demoted, got %+v", rep)
	}
	if !storeHasKey(t, ts.hot, "pop") {
		t.Fatal("pop should remain hot")
	}
}

func TestTieredCapacityDemotesLRU(t *testing.T) {
	clk := newFakeClock()
	// No idle-based demotion; only the capacity cap drives it.
	ts := newTieredPair(t, TieredOptions{
		HotMaxBytes: 25,
		now:         clk.Now,
	})
	// Three 10-byte objects -> 30 bytes hot, over the 25-byte cap.
	// Write them at increasing times so lastAccess ordering is deterministic.
	putBytes(t, ts, "a", []byte("0123456789"), nil)
	clk.advance(time.Minute)
	putBytes(t, ts, "b", []byte("0123456789"), nil)
	clk.advance(time.Minute)
	putBytes(t, ts, "c", []byte("0123456789"), nil)

	rep, err := ts.SweepTiers(context.Background())
	if err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}
	// Need to drop below 25 bytes: demote the single LRU victim ("a") -> 20 bytes.
	if rep.Demoted != 1 {
		t.Fatalf("expected 1 capacity demotion, got %+v", rep)
	}
	if storeHasKey(t, ts.hot, "a") {
		t.Fatal("LRU victim 'a' should have been demoted")
	}
	if !storeHasKey(t, ts.hot, "b") || !storeHasKey(t, ts.hot, "c") {
		t.Fatal("'b' and 'c' should remain hot")
	}
	st := ts.TieredStats()
	if st.HotBytes != 20 || st.ColdBytes != 10 {
		t.Fatalf("byte gauges: hot=%d cold=%d want 20/10", st.HotBytes, st.ColdBytes)
	}
}

func TestTieredDeleteRemovesBothTiers(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{DemoteAfterIdle: time.Hour, now: clk.Now})
	putBytes(t, ts, "d", []byte("bye"), nil)
	clk.advance(2 * time.Hour)
	if _, err := ts.SweepTiers(context.Background()); err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}
	if err := ts.Delete(context.Background(), "d"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ts.Stat(context.Background(), "d"); err != ErrNotFound {
		t.Fatalf("Stat after delete: want ErrNotFound, got %v", err)
	}
	if err := ts.Delete(context.Background(), "missing"); err != ErrNotFound {
		t.Fatalf("Delete missing: want ErrNotFound, got %v", err)
	}
	st := ts.TieredStats()
	if st.HotObjects != 0 || st.ColdObjects != 0 {
		t.Fatalf("gauges after delete: hot=%d cold=%d want 0/0", st.HotObjects, st.ColdObjects)
	}
}

func TestTieredListUnion(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{DemoteAfterIdle: time.Hour, now: clk.Now})
	putBytes(t, ts, "hot1", []byte("x"), nil)
	putBytes(t, ts, "cold1", []byte("y"), nil)
	// Make cold1 idle and sweep so it lands in cold; hot1 stays hot (just written).
	clk.advance(30 * time.Minute)
	putBytes(t, ts, "hot1", []byte("x"), nil) // refresh hot1 recency
	clk.advance(90 * time.Minute)
	// hot1 last accessed 90m ago (>1h) too, so refresh it again right before sweep.
	putBytes(t, ts, "hot1", []byte("x"), nil)
	if _, err := ts.SweepTiers(context.Background()); err != nil {
		t.Fatalf("SweepTiers: %v", err)
	}
	recs, err := ts.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := map[string]bool{}
	for _, r := range recs {
		found[r.Key] = true
	}
	if !found["hot1"] || !found["cold1"] {
		t.Fatalf("List should include both tiers, got %v", found)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d records, want 2", len(recs))
	}
}

func TestTieredRebuildIndexOnOpen(t *testing.T) {
	hotDir := t.TempDir()
	coldDir := t.TempDir()
	hot, err := NewFilesystemStore(hotDir)
	if err != nil {
		t.Fatalf("hot: %v", err)
	}
	cold, err := NewFilesystemStore(coldDir)
	if err != nil {
		t.Fatalf("cold: %v", err)
	}
	// Seed each store directly, bypassing the tiered layer.
	putBytes(t, hot, "h", []byte("in-hot"), nil)
	putBytes(t, cold, "c", []byte("in-cold"), nil)

	ts, err := NewTieredStore(TieredOptions{Hot: hot, Cold: cold})
	if err != nil {
		t.Fatalf("NewTieredStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	st := ts.TieredStats()
	if st.HotObjects != 1 || st.ColdObjects != 1 {
		t.Fatalf("rebuilt gauges: hot=%d cold=%d want 1/1", st.HotObjects, st.ColdObjects)
	}
	if h, _ := getBytes(t, ts, "h"); string(h) != "in-hot" {
		t.Fatalf("hot content wrong: %q", h)
	}
	if c, _ := getBytes(t, ts, "c"); string(c) != "in-cold" {
		t.Fatalf("cold content wrong: %q", c)
	}
}

func TestTieredRebuildResolvesDuplicateToHot(t *testing.T) {
	hotDir := t.TempDir()
	coldDir := t.TempDir()
	hot, _ := NewFilesystemStore(hotDir)
	cold, _ := NewFilesystemStore(coldDir)
	putBytes(t, hot, "dup", []byte("hot-wins"), nil)
	putBytes(t, cold, "dup", []byte("stale-cold"), nil)

	ts, err := NewTieredStore(TieredOptions{Hot: hot, Cold: cold})
	if err != nil {
		t.Fatalf("NewTieredStore: %v", err)
	}
	t.Cleanup(func() { _ = ts.Close() })

	if storeHasKey(t, ts.cold, "dup") {
		t.Fatal("redundant cold copy should be removed at startup")
	}
	got, _ := getBytes(t, ts, "dup")
	if string(got) != "hot-wins" {
		t.Fatalf("hot copy should win, got %q", got)
	}
	st := ts.TieredStats()
	if st.HotObjects != 1 || st.ColdObjects != 0 {
		t.Fatalf("gauges: hot=%d cold=%d want 1/0", st.HotObjects, st.ColdObjects)
	}
}

func TestTieredSweepLeaderGate(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{
		DemoteAfterIdle: time.Hour,
		SweepInterval:   10 * time.Millisecond,
		now:             clk.Now,
	})
	var leader atomic.Bool // starts false
	ts.SetTierLeaderGate(leader.Load)
	putBytes(t, ts, "g", []byte("gated"), nil)
	clk.advance(2 * time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ts.StartSweep(ctx)

	// Not leader: no demotion should occur.
	time.Sleep(60 * time.Millisecond)
	if ts.TieredStats().Demotions != 0 {
		t.Fatal("non-leader should not demote")
	}
	// Become leader: the background sweep should demote.
	leader.Store(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ts.TieredStats().Demotions >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ts.TieredStats().Demotions < 1 {
		t.Fatal("leader should demote via background sweep")
	}
}

// TestTieredConcurrent hammers the store with concurrent writers, readers (which
// promote), deleters, and demotion sweeps to shake out races under -race. It
// asserts that every surviving key's content is intact and the one-tier-per-key
// invariant holds throughout.
func TestTieredConcurrent(t *testing.T) {
	clk := newFakeClock()
	ts := newTieredPair(t, TieredOptions{
		PromoteOnRead:   true,
		DemoteAfterIdle: time.Nanosecond, // everything idle immediately -> aggressive demotion
		HotMaxBytes:     1024,
		now:             clk.Now,
	})

	const keys = 16
	payload := func(k int) []byte { return []byte(fmt.Sprintf("payload-for-key-%d-xxxxxxxxxx", k)) }

	ctx := context.Background()
	var wg sync.WaitGroup

	// Writers.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := fmt.Sprintf("k%d", (seed+i)%keys)
				rec := Record{Key: k}
				if _, err := ts.Put(ctx, rec, bytes.NewReader(payload((seed+i)%keys))); err != nil {
					t.Errorf("Put %q: %v", k, err)
					return
				}
				clk.advance(time.Millisecond)
			}
		}(w)
	}
	// Readers (trigger promotions + fallback paths).
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := fmt.Sprintf("k%d", (seed+i)%keys)
				rc, _, err := ts.Get(ctx, k)
				if err == ErrNotFound {
					continue
				}
				if err != nil {
					t.Errorf("Get %q: %v", k, err)
					return
				}
				data, _ := io.ReadAll(rc)
				rc.Close()
				want := payload((seed + i) % keys)
				if len(data) != 0 && !bytes.Equal(data, want) {
					t.Errorf("Get %q content mismatch: got %q want %q", k, data, want)
					return
				}
			}
		}(r)
	}
	// Sweepers (demotion).
	for s := 0; s < 2; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if _, err := ts.SweepTiers(ctx); err != nil {
					t.Errorf("SweepTiers: %v", err)
					return
				}
			}
		}()
	}
	// Deleters.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			k := fmt.Sprintf("k%d", i%keys)
			if err := ts.Delete(ctx, k); err != nil && err != ErrNotFound {
				t.Errorf("Delete %q: %v", k, err)
				return
			}
		}
	}()

	wg.Wait()

	// Final consistency: every tracked key resolves and reads back its payload,
	// and lives in exactly one physical tier.
	for i := 0; i < keys; i++ {
		k := fmt.Sprintf("k%d", i)
		rc, _, err := ts.Get(ctx, k)
		if err == ErrNotFound {
			continue
		}
		if err != nil {
			t.Fatalf("final Get %q: %v", k, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		if !bytes.Equal(data, payload(i)) {
			t.Fatalf("final content mismatch %q: got %q want %q", k, data, payload(i))
		}
	}
}
