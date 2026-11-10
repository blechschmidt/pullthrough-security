package keyrotation

import (
	"errors"
	"testing"
	"time"
)

func mustBegin(t *testing.T, s *OverlapState, key string, now time.Time) {
	t.Helper()
	if _, err := s.Begin(key, now); err != nil {
		t.Fatalf("Begin(%q) unexpected error: %v", key, err)
	}
}

func TestOverlapState_StableToOverlapToDrainingToStable(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", time.Hour)

	if got := s.Phase(t0); got != PhaseStable {
		t.Fatalf("fresh single-key slot: phase = %q, want stable", got)
	}
	if s.InOverlap(t0) {
		t.Fatal("fresh slot must not be in overlap")
	}

	// Rotate to k2: opens an overlap window of 1h.
	mustBegin(t, s, "k2", t0)
	if got := s.Phase(t0); got != PhaseOverlap {
		t.Fatalf("after rotation: phase = %q, want overlap", got)
	}
	if !s.InOverlap(t0) {
		t.Fatal("expected to be in overlap right after rotation")
	}
	if s.PrimaryKeyID != "k2" {
		t.Fatalf("primary = %q, want k2", s.PrimaryKeyID)
	}
	active := s.ActiveKeyIDs(t0)
	if len(active) != 2 || active[0] != "k2" || active[1] != "k1" {
		t.Fatalf("active keys = %v, want [k2 k1]", active)
	}

	// Still within the window at +59m.
	if !s.InOverlap(t0.Add(59 * time.Minute)) {
		t.Fatal("still expected overlap at +59m")
	}

	// At exactly +1h the window has elapsed (ExpiresAt is not After now): draining.
	tDrain := t0.Add(time.Hour)
	if s.InOverlap(tDrain) {
		t.Fatal("overlap window should be closed at +1h")
	}
	if got := s.Phase(tDrain); got != PhaseDraining {
		t.Fatalf("elapsed-but-unpruned: phase = %q, want draining", got)
	}
	if got := s.ActiveKeyIDs(tDrain); len(got) != 1 || got[0] != "k2" {
		t.Fatalf("active keys after window = %v, want [k2]", got)
	}

	// Prune retires the old key and returns to stable.
	pruned := s.Prune(tDrain)
	if len(pruned) != 1 || pruned[0] != "k1" {
		t.Fatalf("pruned = %v, want [k1]", pruned)
	}
	if got := s.Phase(tDrain); got != PhaseStable {
		t.Fatalf("after prune: phase = %q, want stable", got)
	}
}

func TestOverlapState_RefusesStackedRotation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", time.Hour)
	mustBegin(t, s, "k2", t0)

	// A second rotation while k1 is still within its overlap window must be refused
	// — the single-in-flight safety invariant.
	if s.CanBegin(t0.Add(30 * time.Minute)) {
		t.Fatal("CanBegin must be false during an open overlap window")
	}
	_, err := s.Begin("k3", t0.Add(30*time.Minute))
	if !errors.Is(err, ErrRotationInFlight) {
		t.Fatalf("stacked rotation error = %v, want ErrRotationInFlight", err)
	}
	// State must be unchanged: primary still k2, k1 still the only previous key.
	if s.PrimaryKeyID != "k2" {
		t.Fatalf("primary after refused rotation = %q, want k2", s.PrimaryKeyID)
	}
	if len(s.PreviousKeys) != 1 || s.PreviousKeys[0].KeyID != "k1" {
		t.Fatalf("previous keys after refused rotation = %+v, want just k1", s.PreviousKeys)
	}
}

func TestOverlapState_BeginAfterWindowAutoPrunes(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", time.Hour)
	mustBegin(t, s, "k2", t0)

	// After the window elapses a new rotation is allowed and auto-prunes k1.
	later := t0.Add(2 * time.Hour)
	if !s.CanBegin(later) {
		t.Fatal("CanBegin must be true after the overlap window elapses")
	}
	pruned, err := s.Begin("k3", later)
	if err != nil {
		t.Fatalf("Begin after window: unexpected error %v", err)
	}
	if len(pruned) != 1 || pruned[0] != "k1" {
		t.Fatalf("Begin should auto-prune k1; pruned = %v", pruned)
	}
	if s.PrimaryKeyID != "k3" {
		t.Fatalf("primary = %q, want k3", s.PrimaryKeyID)
	}
	// k2 is now the retiring key in a fresh overlap window.
	if !s.InOverlap(later) {
		t.Fatal("expected a fresh overlap window for k2")
	}
	if got := s.LivePreviousKeyIDs(later); len(got) != 1 || got[0] != "k2" {
		t.Fatalf("live previous keys = %v, want [k2]", got)
	}
}

func TestOverlapState_BeginValidation(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", time.Hour)

	if _, err := s.Begin("", t0); !errors.Is(err, ErrEmptyKeyID) {
		t.Fatalf("empty key id error = %v, want ErrEmptyKeyID", err)
	}
	if _, err := s.Begin("k1", t0); !errors.Is(err, ErrSameKey) {
		t.Fatalf("same-key rotation error = %v, want ErrSameKey", err)
	}
	// A no-op/same-key rotation must not consume an overlap slot.
	if s.InOverlap(t0) {
		t.Fatal("same-key rotation must not open an overlap window")
	}
}

func TestOverlapState_UninitializedSlot(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("", time.Hour)
	if got := s.Phase(t0); got != PhaseUninitialized {
		t.Fatalf("empty primary: phase = %q, want uninitialized", got)
	}
	if !s.CanBegin(t0) {
		t.Fatal("an uninitialized slot must allow Begin")
	}
	// The first rotation installs a primary with no previous key (nothing to retain).
	mustBegin(t, s, "k1", t0)
	if len(s.PreviousKeys) != 0 {
		t.Fatalf("first rotation should create no previous key, got %+v", s.PreviousKeys)
	}
	if got := s.Phase(t0); got != PhaseStable {
		t.Fatalf("phase after first install = %q, want stable", got)
	}
}

func TestOverlapState_ZeroWindowImmediate(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", 0)
	// With no overlap window, a rotation never enters overlap: k1 expires at t0.
	mustBegin(t, s, "k2", t0)
	if s.InOverlap(t0) {
		t.Fatal("zero window must not produce an overlap state")
	}
	// It is immediately draining until pruned, and a further rotation is allowed.
	if !s.CanBegin(t0) {
		t.Fatal("zero window must allow an immediate subsequent rotation")
	}
}

func TestOverlapState_PruneIdempotent(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := NewOverlapState("k1", time.Hour)
	mustBegin(t, s, "k2", t0)
	later := t0.Add(2 * time.Hour)
	if got := s.Prune(later); len(got) != 1 {
		t.Fatalf("first prune = %v, want one key", got)
	}
	if got := s.Prune(later); got != nil {
		t.Fatalf("second prune should be a no-op, got %v", got)
	}
}
