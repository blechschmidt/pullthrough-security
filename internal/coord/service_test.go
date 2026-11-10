package coord

import (
	"context"
	"testing"
	"time"
)

// newTestService builds an Enabled Service over a shared backend + fake clock,
// without starting its campaign goroutines, so tests can drive tick() by hand.
func newTestService(t *testing.T, id string, b backend, clk *fakeClock) *Service {
	t.Helper()
	s, err := New(Config{
		Enabled:       true,
		Mode:          "memory",
		NodeID:        id,
		LeaseTTL:      testTTL,
		RenewInterval: 10 * time.Second,
		RetryInterval: 10 * time.Second,
	}, nil, WithClock(clk.Now), withBackend(b))
	if err != nil {
		t.Fatalf("New(%s): %v", id, err)
	}
	return s
}

func TestServiceDisabledAlwaysLeader(t *testing.T) {
	s, err := New(Config{Enabled: false}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	g := s.Guard("backup")
	if !g.IsLeader() {
		t.Error("disabled coordination must report leader (single-node fallback)")
	}
	if s.Enabled() {
		t.Error("Enabled() should be false")
	}
	// Start/Close are no-ops when disabled.
	s.Start(context.Background())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestServiceSingleNodeBecomesLeader(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	s := newTestService(t, "node-a", b, clk)
	g := s.Guard("backup")

	if g.IsLeader() {
		t.Fatal("guard should not be leader before first tick")
	}
	s.tick(context.Background(), g)
	if !g.IsLeader() {
		t.Fatal("guard should be leader after acquiring")
	}
	if g.FencingToken() != 1 {
		t.Errorf("FencingToken = %d, want 1", g.FencingToken())
	}
	if got := g.stats.acquisitions.Load(); got != 1 {
		t.Errorf("acquisitions = %d, want 1", got)
	}
}

func TestServiceTwoNodesSingleLeader(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	sa := newTestService(t, "node-a", b, clk)
	sb := newTestService(t, "node-b", b, clk)
	ga := sa.Guard("j")
	gb := sb.Guard("j")
	ctx := context.Background()

	sa.tick(ctx, ga)
	sb.tick(ctx, gb)

	if !ga.IsLeader() {
		t.Error("node-a should be leader")
	}
	if gb.IsLeader() {
		t.Error("node-b should not be leader")
	}
	if got := gb.stats.acquireContended.Load(); got != 1 {
		t.Errorf("node-b acquireContended = %d, want 1", got)
	}

	// node-a heartbeats; node-b keeps trying and stays a follower.
	clk.Advance(10 * time.Second)
	sa.tick(ctx, ga)
	sb.tick(ctx, gb)
	if !ga.IsLeader() || gb.IsLeader() {
		t.Error("leadership should be stable on node-a across renewals")
	}
	if got := ga.stats.renewals.Load(); got != 1 {
		t.Errorf("node-a renewals = %d, want 1", got)
	}
}

func TestServiceFailoverOnLeaderStall(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	sa := newTestService(t, "node-a", b, clk)
	sb := newTestService(t, "node-b", b, clk)
	ga := sa.Guard("j")
	gb := sb.Guard("j")
	ctx := context.Background()

	sa.tick(ctx, ga) // node-a becomes leader
	if !ga.IsLeader() {
		t.Fatal("node-a should be leader")
	}

	// node-a stalls past the TTL; node-b takes over.
	clk.Advance(testTTL + time.Second)
	sb.tick(ctx, gb)
	if !gb.IsLeader() {
		t.Fatal("node-b should have taken over after node-a's lease expired")
	}
	if gb.FencingToken() <= ga.FencingToken() {
		t.Errorf("failover token %d not greater than %d", gb.FencingToken(), ga.FencingToken())
	}

	// node-a resumes, attempts to renew, and must step down.
	sa.tick(ctx, ga)
	if ga.IsLeader() {
		t.Error("stalled node-a must step down after losing the lease")
	}
	if got := ga.stats.losses.Load(); got != 1 {
		t.Errorf("node-a losses = %d, want 1", got)
	}
}

func TestServiceTimeAsLeaderAccounting(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	s := newTestService(t, "node-a", b, clk)
	g := s.Guard("j")
	ctx := context.Background()

	s.tick(ctx, g) // acquire at t0
	clk.Advance(20 * time.Second)
	st := g.status(clk.Now())
	if st.TimeAsLeaderSeconds < 20 {
		t.Errorf("TimeAsLeaderSeconds = %.1f, want >= 20", st.TimeAsLeaderSeconds)
	}
	if !st.IsLeader {
		t.Error("status should report leader")
	}
}

func TestServiceSnapshotAndLeaseholders(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	s := newTestService(t, "node-a", b, clk)
	g := s.Guard("backup")
	s.tick(context.Background(), g)

	snap := s.Snapshot()
	if !snap.Enabled || snap.NodeID != "node-a" {
		t.Fatalf("unexpected snapshot header: %+v", snap)
	}
	if len(snap.Jobs) != 1 || snap.Jobs[0].Job != "backup" || !snap.Jobs[0].IsLeader {
		t.Fatalf("unexpected jobs: %+v", snap.Jobs)
	}

	lhs := s.Leaseholders(context.Background())
	if len(lhs) != 1 || !lhs[0].Held || lhs[0].Holder != "node-a" || !lhs[0].Self {
		t.Fatalf("unexpected leaseholders: %+v", lhs)
	}
}

func TestServiceStartCloseLifecycle(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	s := newTestService(t, "node-a", b, clk)
	g := s.Guard("j")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	// The campaign goroutine acquires on its first immediate tick.
	deadline := time.Now().Add(2 * time.Second)
	for !g.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("guard never became leader after Start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After Close, the held lease was resigned, so a fresh node can acquire it.
	other := newNode(b, "node-z", clk)
	if _, err := other.AcquireLease(context.Background(), "j", testTTL); err != nil {
		t.Errorf("expected lease free after Close, got %v", err)
	}
}
