package lockdown

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestService(t *testing.T, opts ...Option) *Service {
	t.Helper()
	svc, err := New(Config{Enabled: true}, nil, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc == nil {
		t.Fatal("New returned nil for an enabled config")
	}
	return svc
}

func TestDisabledReturnsNil(t *testing.T) {
	svc, err := New(Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc != nil {
		t.Fatal("New should return nil when disabled")
	}
	// Every accessor must be nil-safe.
	if svc.Enabled() || svc.FreezeActive() || svc.StrictActive() || svc.Mode() != ModeOff {
		t.Fatal("nil service accessors must report inactive")
	}
	if d := svc.Check(Coordinate{Name: "x"}); d.Blocked {
		t.Fatal("nil service must not block")
	}
}

func TestEngageRequiresReasonAndIncident(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeFreeze, IncidentID: "INC-1"}); err == nil {
		t.Error("expected error for missing reason")
	}
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeFreeze, Reason: "r"}); err == nil {
		t.Error("expected error for missing incident ID")
	}
	if _, err := svc.Engage(ctx, EngageInput{Mode: "bogus", Reason: "r", IncidentID: "i"}); err == nil {
		t.Error("expected error for unknown mode")
	}
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeBlock, Reason: "r", IncidentID: "i"}); err == nil {
		t.Error("expected error for block mode without targets")
	}
}

func TestFreezeAndStrictModes(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeFreeze, Reason: "incident", IncidentID: "INC-1"}); err != nil {
		t.Fatalf("Engage freeze: %v", err)
	}
	if !svc.FreezeActive() {
		t.Error("FreezeActive should be true under a freeze")
	}
	if svc.StrictActive() {
		t.Error("StrictActive should be false under a freeze")
	}
	// A freeze never blocks a coordinate at the gate consult.
	if d := svc.Check(Coordinate{Ecosystem: "npm", Name: "left-pad", Version: "1.0.0"}); d.Blocked {
		t.Error("freeze must not block at the Check consult (it blocks at the fetch boundary)")
	}

	// Switching to strict.
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeStrict, Reason: "incident", IncidentID: "INC-1"}); err != nil {
		t.Fatalf("Engage strict: %v", err)
	}
	if !svc.StrictActive() || svc.FreezeActive() {
		t.Error("expected strict active, freeze inactive after switching modes")
	}
}

func TestTargetedBlock(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Engage(ctx, EngageInput{
		Mode:       ModeBlock,
		Reason:     "malware",
		IncidentID: "INC-9",
		Targets: []Coordinate{
			{Ecosystem: "npm", Name: "evil", Version: "1.2.3"}, // exact version
			{Ecosystem: "pip", Name: "wholepkg"},               // whole package
		},
	}); err != nil {
		t.Fatalf("Engage block: %v", err)
	}

	cases := []struct {
		coord Coordinate
		block bool
	}{
		{Coordinate{Ecosystem: "npm", Name: "evil", Version: "1.2.3"}, true},
		{Coordinate{Ecosystem: "npm", Name: "evil", Version: "9.9.9"}, false}, // wrong version
		{Coordinate{Ecosystem: "npm", Name: "good", Version: "1.2.3"}, false},
		{Coordinate{Ecosystem: "pip", Name: "wholepkg", Version: "0.1.0"}, true}, // any version
		{Coordinate{Ecosystem: "pip", Name: "wholepkg"}, true},
		{Coordinate{Ecosystem: "npm", Name: "wholepkg", Version: "1.0.0"}, false}, // wrong ecosystem
	}
	for _, c := range cases {
		d := svc.Check(c.coord)
		if d.Blocked != c.block {
			t.Errorf("Check(%+v).Blocked = %v, want %v", c.coord, d.Blocked, c.block)
		}
		if d.Blocked && (d.Code != CodeBlocked || d.IncidentID != "INC-9") {
			t.Errorf("Check(%+v) bad decision: %+v", c.coord, d)
		}
	}
}

func TestClearRequiresReasonAndLifts(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Engage(ctx, EngageInput{Mode: ModeStrict, Reason: "r", IncidentID: "i"}); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if _, err := svc.Clear(ctx, ClearInput{}); err == nil {
		t.Error("Clear should require a reason")
	}
	if _, err := svc.Clear(ctx, ClearInput{Reason: "all clear"}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if svc.Status().Active {
		t.Error("status should be inactive after Clear")
	}
	// Clearing when nothing is engaged is a no-op, not an error.
	if _, err := svc.Clear(ctx, ClearInput{Reason: "again"}); err != nil {
		t.Errorf("Clear with nothing engaged: %v", err)
	}
}

func TestTTLAutoExpiry(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := func() time.Time { return now }
	svc := newTestService(t, WithClock(clk))
	ctx := context.Background()
	if _, err := svc.Engage(ctx, EngageInput{
		Mode: ModeBlock, Reason: "r", IncidentID: "i", TTL: 30 * time.Minute,
		Targets: []Coordinate{{Name: "x"}},
	}); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if !svc.Status().Active {
		t.Fatal("should be active immediately after engage")
	}
	// Advance past the TTL.
	now = now.Add(31 * time.Minute)
	if svc.Status().Active {
		t.Error("lockdown should auto-expire past its TTL")
	}
	if svc.Mode() != ModeOff {
		t.Error("expired lockdown should report ModeOff")
	}
	if d := svc.Check(Coordinate{Name: "x"}); d.Blocked {
		t.Error("expired lockdown must not block")
	}
	if svc.Metrics().Expirations != 1 {
		t.Errorf("expirations = %d, want 1", svc.Metrics().Expirations)
	}
}

func TestMaxTTLCap(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	svc, err := New(Config{Enabled: true, MaxTTL: time.Hour}, nil, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	st, err := svc.Engage(context.Background(), EngageInput{Mode: ModeFreeze, Reason: "r", IncidentID: "i", TTL: 24 * time.Hour})
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if got := st.ExpiresAt.Sub(now); got != time.Hour {
		t.Errorf("TTL not capped: expiry in %s, want 1h", got)
	}
}

func TestDurablePersistenceAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lockdown.json")
	ctx := context.Background()

	svc1, err := New(Config{Enabled: true, StorePath: path}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := svc1.Engage(ctx, EngageInput{
		Mode: ModeBlock, Reason: "r", IncidentID: "INC-D",
		Targets: []Coordinate{{Ecosystem: "npm", Name: "evil"}},
	}); err != nil {
		t.Fatalf("Engage: %v", err)
	}

	// A "restart": a fresh service loads the persisted state.
	svc2, err := New(Config{Enabled: true, StorePath: path}, nil)
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	st := svc2.Status()
	if !st.Active || st.Mode != ModeBlock || st.IncidentID != "INC-D" {
		t.Fatalf("persisted state not restored: %+v", st)
	}
	if d := svc2.Check(Coordinate{Ecosystem: "npm", Name: "evil", Version: "1.0.0"}); !d.Blocked {
		t.Error("restored targeted block should still deny the coordinate")
	}

	// Clearing removes the persisted state.
	if _, err := svc2.Clear(ctx, ClearInput{Reason: "done"}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	svc3, err := New(Config{Enabled: true, StorePath: path}, nil)
	if err != nil {
		t.Fatalf("New (after clear): %v", err)
	}
	if svc3.Status().Active {
		t.Error("cleared state must not be restored as active")
	}
}

// fakeCoordinator drives the coord-guard integration: a follower (IsLeader false)
// must not persist the auto-expiry sweep, while a leader does.
type fakeCoordinator struct {
	leader bool
	token  uint64
}

func (f *fakeCoordinator) IsLeader() bool       { return f.leader }
func (f *fakeCoordinator) FencingToken() uint64 { return f.token }

func TestFencingTokenRecorded(t *testing.T) {
	co := &fakeCoordinator{leader: true, token: 7}
	svc := newTestService(t, WithCoordinator(co))
	st, err := svc.Engage(context.Background(), EngageInput{Mode: ModeStrict, Reason: "r", IncidentID: "i"})
	if err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if st.FencingToken != 7 {
		t.Errorf("fencing token = %d, want 7", st.FencingToken)
	}
}

func TestFollowerDoesNotPersistExpiry(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	co := &fakeCoordinator{leader: false}
	svc := newTestService(t, WithClock(func() time.Time { return now }), WithCoordinator(co))
	if _, err := svc.Engage(context.Background(), EngageInput{Mode: ModeFreeze, Reason: "r", IncidentID: "i", TTL: time.Minute}); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	now = now.Add(2 * time.Minute)
	// A follower still reports the effective (expired→inactive) state...
	if svc.Status().Active {
		t.Error("follower should compute the lockdown as expired/inactive")
	}
	// ...but does not count it as a persisted expiry transition (leader-only).
	if svc.Metrics().Expirations != 0 {
		t.Errorf("follower expirations = %d, want 0 (leader persists the sweep)", svc.Metrics().Expirations)
	}
}
