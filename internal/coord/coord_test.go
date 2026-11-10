package coord

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic lease-timing tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

const testTTL = 30 * time.Second

// newNode builds a coordinator with a distinct node ID over a shared backend and
// clock, modeling one replica in a simulated cluster.
func newNode(b backend, id string, clk *fakeClock) *coordinator {
	return newCoordinator(b, id, clk.Now)
}

func TestAcquireFreshLease(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	n := newNode(b, "node-a", clk)

	lease, err := n.AcquireLease(context.Background(), "backup", testTTL)
	if err != nil {
		t.Fatalf("AcquireLease: %v", err)
	}
	if lease.Holder != "node-a" {
		t.Errorf("Holder = %q, want node-a", lease.Holder)
	}
	if lease.FencingToken != 1 {
		t.Errorf("FencingToken = %d, want 1", lease.FencingToken)
	}
	if !n.IsLeader("backup") {
		t.Error("expected node-a to be leader")
	}
}

func TestSecondNodeBlockedWhileLeaseLive(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	a := newNode(b, "node-a", clk)
	bn := newNode(b, "node-b", clk)

	if _, err := a.AcquireLease(context.Background(), "j", testTTL); err != nil {
		t.Fatalf("node-a acquire: %v", err)
	}
	_, err := bn.AcquireLease(context.Background(), "j", testTTL)
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("node-b acquire err = %v, want ErrLeaseHeld", err)
	}
	if bn.IsLeader("j") {
		t.Error("node-b must not be leader while node-a holds a live lease")
	}
}

func TestRenewExtendsAndKeepsToken(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	a := newNode(b, "node-a", clk)

	lease, err := a.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	clk.Advance(10 * time.Second)
	renewed, err := a.RenewLease(context.Background(), lease, testTTL)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.FencingToken != lease.FencingToken {
		t.Errorf("renew changed token: %d -> %d", lease.FencingToken, renewed.FencingToken)
	}
	want := clk.Now().Add(testTTL)
	if !renewed.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", renewed.ExpiresAt, want)
	}
}

func TestExpiredLeaseStolenWithHigherToken(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	a := newNode(b, "node-a", clk)
	bn := newNode(b, "node-b", clk)

	aLease, err := a.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("node-a acquire: %v", err)
	}

	// node-a freezes (no renewals); the lease expires.
	clk.Advance(testTTL + time.Second)

	if a.IsLeader("j") {
		t.Error("node-a should not be leader after its lease expired")
	}

	bLease, err := bn.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("node-b steal: %v", err)
	}
	if bLease.Holder != "node-b" {
		t.Errorf("Holder = %q, want node-b", bLease.Holder)
	}
	if bLease.FencingToken <= aLease.FencingToken {
		t.Errorf("steal token %d not greater than original %d", bLease.FencingToken, aLease.FencingToken)
	}

	// node-a, resuming after its pause, must discover it lost the lease (fencing).
	if _, err := a.RenewLease(context.Background(), aLease, testTTL); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale node-a renew err = %v, want ErrLeaseLost", err)
	}
}

func TestResignReleasesImmediately(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	a := newNode(b, "node-a", clk)
	bn := newNode(b, "node-b", clk)

	aLease, err := a.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("node-a acquire: %v", err)
	}
	if err := a.Resign(context.Background(), aLease); err != nil {
		t.Fatalf("resign: %v", err)
	}
	if a.IsLeader("j") {
		t.Error("node-a still leader after resign")
	}
	// node-b can take over immediately without waiting for expiry.
	bLease, err := bn.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("node-b acquire after resign: %v", err)
	}
	if bLease.FencingToken != aLease.FencingToken+1 {
		t.Errorf("post-resign token = %d, want %d", bLease.FencingToken, aLease.FencingToken+1)
	}
}

func TestReacquireAfterResignSelf(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	a := newNode(b, "node-a", clk)

	l1, err := a.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Acquiring again while holding it just renews in place (same token).
	l2, err := a.AcquireLease(context.Background(), "j", testTTL)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if l2.FencingToken != l1.FencingToken {
		t.Errorf("re-acquire changed token %d -> %d", l1.FencingToken, l2.FencingToken)
	}
}

// TestSimulatedContention drives many nodes contending over a single lease across
// many rounds and asserts the core safety invariant: at every instant at most one
// node believes it is the leader.
func TestSimulatedContention(t *testing.T) {
	clk := newFakeClock()
	b := newMemoryBackend()
	const nodes = 5
	ns := make([]*coordinator, nodes)
	for i := range ns {
		ns[i] = newNode(b, nodeName(i), clk)
	}
	held := make([]*Lease, nodes)

	leaderCount := func() int {
		n := 0
		for i := range ns {
			if ns[i].IsLeader("j") {
				n++
			}
		}
		return n
	}

	for round := 0; round < 200; round++ {
		// Every node attempts to acquire or renew each round.
		for i := range ns {
			if held[i] != nil {
				l, err := ns[i].RenewLease(context.Background(), held[i], testTTL)
				if err != nil {
					held[i] = nil
					continue
				}
				held[i] = l
				continue
			}
			l, err := ns[i].AcquireLease(context.Background(), "j", testTTL)
			if err == nil {
				held[i] = l
			}
		}
		if c := leaderCount(); c > 1 {
			t.Fatalf("round %d: %d simultaneous leaders (split-brain)", round, c)
		}
		// Advance time by a fraction of the TTL; occasionally jump past it so the
		// current leader's lease lapses and another node can take over.
		if round%7 == 0 {
			clk.Advance(testTTL + time.Second)
			// The lapsed leader's local view must drop within the next round.
			for i := range ns {
				if held[i] != nil && held[i].expired(clk.Now()) {
					// Its renew next round will surface the loss.
				}
			}
		} else {
			clk.Advance(testTTL / 4)
		}
	}
}

func nodeName(i int) string {
	return "node-" + string(rune('a'+i))
}

func TestInvalidTTL(t *testing.T) {
	clk := newFakeClock()
	a := newNode(newMemoryBackend(), "node-a", clk)
	if _, err := a.AcquireLease(context.Background(), "j", 0); !errors.Is(err, ErrInvalidTTL) {
		t.Fatalf("err = %v, want ErrInvalidTTL", err)
	}
}
