package ratelimit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

func TestMemStoreAddCurrentAndRoll(t *testing.T) {
	clk := newFakeClock()
	s := newMemStore(clk.now)
	ctx := context.Background()
	const window = time.Minute

	total, err := s.Add(ctx, "k", 100, window)
	if err != nil || total != 100 {
		t.Fatalf("Add = %d, %v; want 100, nil", total, err)
	}
	total, _ = s.Add(ctx, "k", 50, window)
	if total != 150 {
		t.Fatalf("Add accumulate = %d, want 150", total)
	}
	if cur, _ := s.Current(ctx, "k", window); cur != 150 {
		t.Fatalf("Current = %d, want 150", cur)
	}

	// Window roll resets the counter.
	clk.advance(window)
	if cur, _ := s.Current(ctx, "k", window); cur != 0 {
		t.Fatalf("Current after window = %d, want 0", cur)
	}
	total, _ = s.Add(ctx, "k", 7, window)
	if total != 7 {
		t.Fatalf("Add after roll = %d, want 7", total)
	}
}

func TestCacheStoreRoundTripAndRoll(t *testing.T) {
	clk := newFakeClock()
	store, err := cache.NewFilesystemStore(filepath.Join(t.TempDir(), "rl"))
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	defer store.Close()

	cs := NewCacheStore(store, clk.now)
	ctx := context.Background()
	const window = time.Hour

	if total, err := cs.Add(ctx, byteKey("team-a"), 500, window); err != nil || total != 500 {
		t.Fatalf("Add = %d, %v; want 500, nil", total, err)
	}
	if total, err := cs.Add(ctx, byteKey("team-a"), 250, window); err != nil || total != 750 {
		t.Fatalf("Add accumulate = %d, %v; want 750, nil", total, err)
	}
	if cur, err := cs.Current(ctx, byteKey("team-a"), window); err != nil || cur != 750 {
		t.Fatalf("Current = %d, %v; want 750, nil", cur, err)
	}

	// A fresh adapter over the same store observes the persisted total (the
	// cross-replica coordination path).
	cs2 := NewCacheStore(store, clk.now)
	if cur, _ := cs2.Current(ctx, byteKey("team-a"), window); cur != 750 {
		t.Fatalf("second adapter Current = %d, want 750", cur)
	}

	// Window roll.
	clk.advance(window)
	if cur, _ := cs.Current(ctx, byteKey("team-a"), window); cur != 0 {
		t.Fatalf("Current after window = %d, want 0", cur)
	}
}

// TestLimiterWithCacheStore wires a CacheStore into a Limiter and verifies byte
// quota enforcement end-to-end against the shared backend.
func TestLimiterWithCacheStore(t *testing.T) {
	clk := newFakeClock()
	store, err := cache.NewFilesystemStore(filepath.Join(t.TempDir(), "rl"))
	if err != nil {
		t.Fatalf("NewFilesystemStore: %v", err)
	}
	defer store.Close()

	l := New(Options{
		Default: Policy{ByteQuota: 1024, Window: time.Hour},
		Store:   NewCacheStore(store, clk.now),
		Now:     clk.now,
	})
	ctx := context.Background()

	res, dec := l.Admit(ctx, "team-a")
	if !dec.Allowed {
		t.Fatal("first admit should succeed")
	}
	res.RecordBytes(1024)
	res.Release()

	if _, dec := l.Admit(ctx, "team-a"); dec.Allowed || dec.Type != LimitBytes {
		t.Fatalf("expected byte rejection via shared store, got allowed=%v type=%s", dec.Allowed, dec.Type)
	}
}
