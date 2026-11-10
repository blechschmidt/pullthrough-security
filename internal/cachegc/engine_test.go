package cachegc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

func TestNewValidation(t *testing.T) {
	c := newFakeCache()
	cases := []struct {
		name string
		cfg  Config
	}{
		{"negative capacity", Config{CapacityBytes: -1}},
		{"high over 1", Config{HighWatermarkPct: 1.5}},
		{"low not below high", Config{HighWatermarkPct: 0.5, LowWatermarkPct: 0.6}},
		{"bad policy", Config{Policy: "random"}},
		{"negative interval", Config{Interval: -time.Second}},
		{"negative max deletes", Config{MaxDeletesPerRun: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg, c, Options{}); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
	if _, err := New(Config{}, nil, Options{}); err == nil {
		t.Fatal("expected error for nil cache")
	}
	// Defaults applied: empty watermarks become 0.9/0.7, empty policy becomes LRU.
	e, err := New(Config{Enabled: true}, c, Options{})
	if err != nil {
		t.Fatalf("New with defaults: %v", err)
	}
	if e.highPct != 0.9 || e.lowPct != 0.7 {
		t.Errorf("default watermarks = %.2f/%.2f, want 0.9/0.7", e.highPct, e.lowPct)
	}
	if e.cfg.Policy != PolicyLRU {
		t.Errorf("default policy = %q, want lru", e.cfg.Policy)
	}
}

func TestRunDeletesAndUpdatesMetrics(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)

	rep, err := e.Run(context.Background(), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.EvictedCount != 2 || rep.BytesReclaimed != 500 {
		t.Fatalf("evicted=%d bytes=%d, want 2/500", rep.EvictedCount, rep.BytesReclaimed)
	}
	// d and b (LRU) should be gone from the store.
	if c.has("d") || c.has("b") {
		t.Errorf("LRU victims not deleted from store: deleted=%v", c.deleted)
	}
	if !c.has("a") || !c.has("c") {
		t.Errorf("non-victims were deleted: deleted=%v", c.deleted)
	}

	s := e.Snapshot()
	if s.Runs != 1 || s.EvictedTotal != 2 || s.BytesReclaimedTotal != 500 {
		t.Errorf("snapshot counters = runs:%d evicted:%d bytes:%d", s.Runs, s.EvictedTotal, s.BytesReclaimedTotal)
	}
	if s.UsedBytes != 500 {
		t.Errorf("snapshot UsedBytes after sweep = %d, want 500", s.UsedBytes)
	}
	last, ok := e.LastReport()
	if !ok || last.EvictedCount != 2 {
		t.Errorf("LastReport not recorded correctly: %+v", last)
	}
}

func TestDryRunAccuracyAndNoSideEffects(t *testing.T) {
	mk := func() *fakeCache {
		return newFakeCache(
			entry("a", 250, 100, 10, 5),
			entry("b", 250, 100, 40, 5),
			entry("c", 250, 100, 30, 5),
			entry("d", 250, 100, 50, 5),
		)
	}

	// Dry run.
	cDry := mk()
	eDry := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, cDry)
	dry, err := eDry.Run(context.Background(), true)
	if err != nil {
		t.Fatalf("dry Run: %v", err)
	}
	if len(cDry.deleted) != 0 {
		t.Fatalf("dry-run deleted entries: %v", cDry.deleted)
	}
	if cnt := eDry.Snapshot(); cnt.EvictedTotal != 0 || cnt.Runs != 0 || cnt.DryRuns != 1 {
		t.Fatalf("dry-run moved operational counters: %+v", cnt)
	}

	// Real run on an identical cache must delete exactly what the dry run reported.
	cReal := mk()
	eReal := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, cReal)
	real, err := eReal.Run(context.Background(), false)
	if err != nil {
		t.Fatalf("real Run: %v", err)
	}
	if !equalStrings(evictedKeys(dry), evictedKeys(real)) {
		t.Fatalf("dry-run preview %v != real eviction %v", evictedKeys(dry), evictedKeys(real))
	}
	if !equalStrings(sortedCopy(evictedKeys(dry)), sortedCopy(cReal.deleted)) {
		t.Fatalf("dry-run preview %v != actually-deleted %v", evictedKeys(dry), cReal.deleted)
	}
	if dry.BytesReclaimed != real.BytesReclaimed {
		t.Errorf("dry-run bytes %d != real bytes %d", dry.BytesReclaimed, real.BytesReclaimed)
	}
}

func TestRunToleratesAlreadyDeletedEntry(t *testing.T) {
	// A peer replica removed "d" already: Delete returns ErrNotFound, which the
	// engine must treat as a successful, idempotent reclaim (distributed-safe).
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	c.failDelete["d"] = cache.ErrNotFound
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	rep, err := e.Run(context.Background(), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Errors != 0 {
		t.Errorf("ErrNotFound should not count as an error, got %d", rep.Errors)
	}
	if rep.EvictedCount != 2 {
		t.Errorf("evicted=%d, want 2 (d counted as reclaimed)", rep.EvictedCount)
	}
}

func TestRunRecordsRealDeleteError(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	c.failDelete["d"] = errors.New("s3 unavailable")
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	rep, err := e.Run(context.Background(), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Errors != 1 {
		t.Fatalf("expected 1 delete error, got %d", rep.Errors)
	}
	// d's bytes were not reclaimed since its delete failed.
	if rep.BytesReclaimed != 250 || rep.EvictedCount != 1 {
		t.Errorf("after failed delete: evicted=%d bytes=%d, want 1/250", rep.EvictedCount, rep.BytesReclaimed)
	}
	if e.Snapshot().DeleteErrorsTotal != 1 {
		t.Errorf("DeleteErrorsTotal = %d, want 1", e.Snapshot().DeleteErrorsTotal)
	}
}

func TestHighWatermarkCallbackFires(t *testing.T) {
	// Everything is pinned, so a sweep cannot reduce below the high watermark and
	// the alert callback must fire.
	a := entry("a", 500, 100, 50, 1)
	b := entry("b", 500, 100, 40, 1)
	a.Metadata[cache.MetaPin] = "true"
	b.Metadata[cache.MetaPin] = "true"
	c := newFakeCache(a, b)

	var fired int
	var gotRep Report
	e, err := New(Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, Options{
		Sources:         []ReferenceSource{NewMetadataPinSource()},
		OnHighWatermark: func(_ context.Context, rep Report) { fired++; gotRep = rep },
		Now:             func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := e.Run(context.Background(), false)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.EvictedCount != 0 {
		t.Fatalf("nothing should be evictable, evicted %d", rep.EvictedCount)
	}
	if !rep.AboveHighWatermark {
		t.Fatal("expected AboveHighWatermark=true")
	}
	if fired != 1 {
		t.Fatalf("high-watermark callback fired %d times, want 1", fired)
	}
	if gotRep.UsedBytes != 1000 {
		t.Errorf("callback report UsedBytes = %d, want 1000", gotRep.UsedBytes)
	}
	if e.Snapshot().AboveHighWatermark != 1 || e.Snapshot().ConsecutiveAbove != 1 {
		t.Errorf("watermark counters = total:%d streak:%d", e.Snapshot().AboveHighWatermark, e.Snapshot().ConsecutiveAbove)
	}
}

func TestHighWatermarkCallbackNotFiredWhenReclaimed(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	var fired int
	e, err := New(Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c, Options{
		OnHighWatermark: func(_ context.Context, _ Report) { fired++ },
		Now:             func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Run(context.Background(), false); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fired != 0 {
		t.Fatalf("callback should not fire when the sweep brings the cache below the watermark")
	}
}

func TestTriggerInlineWhenNotStarted(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("d", 250, 100, 50, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	// Not Start()ed: Trigger must run inline rather than block.
	rep, err := e.Trigger(context.Background(), true)
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if !rep.DryRun {
		t.Error("expected a dry-run report")
	}
	if len(c.deleted) != 0 {
		t.Errorf("dry-run trigger deleted entries: %v", c.deleted)
	}
}

func TestTriggerViaRunningLoop(t *testing.T) {
	c := newFakeCache(
		entry("a", 250, 100, 10, 5),
		entry("b", 250, 100, 40, 5),
		entry("c", 250, 100, 30, 5),
		entry("d", 250, 100, 50, 5),
	)
	e := newEngine(t, Config{Enabled: true, CapacityBytes: 1000, Policy: PolicyLRU}, c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Start(ctx)
	defer e.Close()

	rep, err := e.Trigger(ctx, false)
	if err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if rep.EvictedCount != 2 {
		t.Fatalf("loop-driven run evicted %d, want 2", rep.EvictedCount)
	}
}

func TestDisabledEngineDoesNotStart(t *testing.T) {
	c := newFakeCache(entry("a", 100, 10, 10, 1))
	e := newEngine(t, Config{Enabled: false, DefaultTTL: time.Nanosecond}, c)
	e.Start(context.Background()) // no-op
	// Trigger still works (admin on-demand) and runs inline.
	if _, err := e.Trigger(context.Background(), true); err != nil {
		t.Fatalf("Trigger on disabled engine: %v", err)
	}
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
