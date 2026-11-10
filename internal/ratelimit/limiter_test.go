package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestAdmitNilLimiterAllows(t *testing.T) {
	var l *Limiter
	res, dec := l.Admit(context.Background(), "team-a")
	if !dec.Allowed {
		t.Fatal("nil limiter must admit everything")
	}
	res.Release() // must not panic
	res.RecordBytes(123)
}

func TestAdmitUnlimitedPolicyAllows(t *testing.T) {
	l := New(Options{})
	for i := 0; i < 1000; i++ {
		_, dec := l.Admit(context.Background(), "team-a")
		if !dec.Allowed {
			t.Fatalf("unlimited policy throttled at %d", i)
		}
	}
	if got := l.Metrics().Allowed; got != 1000 {
		t.Fatalf("allowed counter = %d, want 1000", got)
	}
}

func TestAdmitRPSBucket(t *testing.T) {
	clk := newFakeClock()
	l := New(Options{
		Default: Policy{RPS: 5, Burst: 3},
		Now:     clk.now,
	})
	ctx := context.Background()

	allowed := 0
	for i := 0; i < 10; i++ {
		if _, dec := l.Admit(ctx, "team-a"); dec.Allowed {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("burst allowed = %d, want 3", allowed)
	}

	// The next rejection should carry a Retry-After hint.
	_, dec := l.Admit(ctx, "team-a")
	if dec.Allowed || dec.Type != LimitRPS {
		t.Fatalf("expected rps rejection, got allowed=%v type=%s", dec.Allowed, dec.Type)
	}
	if dec.RetryAfter <= 0 {
		t.Fatalf("expected positive retry-after, got %v", dec.RetryAfter)
	}

	// After 1 second, 5 more tokens accrue (capped at burst 3).
	clk.advance(time.Second)
	allowed = 0
	for i := 0; i < 10; i++ {
		if _, dec := l.Admit(ctx, "team-a"); dec.Allowed {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("post-refill allowed = %d, want 3 (burst cap)", allowed)
	}
}

func TestAdmitConcurrencyCap(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 2}})
	ctx := context.Background()

	r1, d1 := l.Admit(ctx, "team-a")
	r2, d2 := l.Admit(ctx, "team-a")
	if !d1.Allowed || !d2.Allowed {
		t.Fatal("first two concurrent admits should succeed")
	}
	_, d3 := l.Admit(ctx, "team-a")
	if d3.Allowed || d3.Type != LimitConcurrency {
		t.Fatalf("third concurrent admit: allowed=%v type=%s, want rejected concurrency", d3.Allowed, d3.Type)
	}

	// Releasing one frees a slot.
	r1.Release()
	_, d4 := l.Admit(ctx, "team-a")
	if !d4.Allowed {
		t.Fatal("admit should succeed after a slot is released")
	}
	r2.Release()
}

func TestAdmitByteQuota(t *testing.T) {
	clk := newFakeClock()
	l := New(Options{
		Default: Policy{ByteQuota: 1000, Window: time.Minute},
		Now:     clk.now,
	})
	ctx := context.Background()

	// First request admitted; record 1000 bytes to exhaust the quota.
	res, dec := l.Admit(ctx, "team-a")
	if !dec.Allowed {
		t.Fatal("first request should be admitted")
	}
	res.RecordBytes(1000)
	res.Release()

	// Next request rejected: quota exhausted.
	_, dec = l.Admit(ctx, "team-a")
	if dec.Allowed || dec.Type != LimitBytes {
		t.Fatalf("expected byte-quota rejection, got allowed=%v type=%s", dec.Allowed, dec.Type)
	}

	// After the window elapses, the counter resets and admits again.
	clk.advance(time.Minute)
	if _, dec := l.Admit(ctx, "team-a"); !dec.Allowed {
		t.Fatal("expected admit after byte-quota window reset")
	}
}

func TestAdmitGlobalAndTenant(t *testing.T) {
	l := New(Options{
		Global:  Policy{MaxConcurrent: 1},
		Default: Policy{MaxConcurrent: 5},
	})
	ctx := context.Background()

	r1, d1 := l.Admit(ctx, "team-a")
	if !d1.Allowed {
		t.Fatal("first admit should succeed")
	}
	// Global cap of 1 blocks a different tenant even though its own cap is 5.
	_, d2 := l.Admit(ctx, "team-b")
	if d2.Allowed || d2.Type != LimitConcurrency {
		t.Fatalf("global cap should block team-b: allowed=%v type=%s", d2.Allowed, d2.Type)
	}
	r1.Release()
	if _, d3 := l.Admit(ctx, "team-b"); !d3.Allowed {
		t.Fatal("team-b should be admitted after global slot freed")
	}
}

// TestAdmitRejectionReleasesGlobalSlot verifies a per-tenant rejection does not
// leak the global concurrency slot acquired earlier in the same Admit.
func TestAdmitRejectionReleasesGlobalSlot(t *testing.T) {
	l := New(Options{
		Global:    Policy{MaxConcurrent: 10},
		PerTenant: map[string]Policy{"team-a": {MaxConcurrent: 1}},
	})
	ctx := context.Background()

	r1, d1 := l.Admit(ctx, "team-a")
	if !d1.Allowed {
		t.Fatal("first admit should succeed")
	}
	// team-a is at its cap; this Admit acquires the global slot then fails on the
	// tenant slot and must roll the global slot back.
	_, d2 := l.Admit(ctx, "team-a")
	if d2.Allowed {
		t.Fatal("expected team-a rejection at its concurrency cap")
	}
	r1.Release()

	// The global semaphore should now be empty (1 holder released, the rejected
	// attempt rolled back). Confirm via snapshot.
	if got := l.Metrics().Global.InFlight; got != 0 {
		t.Fatalf("global in-flight = %d after rollback, want 0", got)
	}
}

func TestSetPolicyRuntimeUpdate(t *testing.T) {
	clk := newFakeClock()
	l := New(Options{Default: Policy{RPS: 1, Burst: 1}, Now: clk.now})
	ctx := context.Background()

	if _, dec := l.Admit(ctx, "team-a"); !dec.Allowed {
		t.Fatal("first admit should succeed")
	}
	if _, dec := l.Admit(ctx, "team-a"); dec.Allowed {
		t.Fatal("second admit should be throttled at burst 1")
	}

	// Raise the tenant's rate/burst at runtime, then let a second elapse so the
	// reconfigured bucket refills under the new policy.
	if err := l.SetPolicy("team-a", Policy{RPS: 100, Burst: 5}); err != nil {
		t.Fatalf("SetPolicy: %v", err)
	}
	clk.advance(time.Second)
	allowed := 0
	for i := 0; i < 10; i++ {
		if _, dec := l.Admit(ctx, "team-a"); dec.Allowed {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("expected 5 admits (new burst) after raising the policy, got %d", allowed)
	}
}

func TestSetPolicyRejectsReservedKeyAndNegatives(t *testing.T) {
	l := New(Options{})
	if err := l.SetPolicy(GlobalKey, Policy{}); err == nil {
		t.Fatal("expected SetPolicy to reject the reserved global key")
	}
	if err := l.SetPolicy("team-a", Policy{RPS: -1}); err == nil {
		t.Fatal("expected SetPolicy to reject a negative rps")
	}
	if err := l.SetGlobalPolicy(Policy{MaxConcurrent: -1}); err == nil {
		t.Fatal("expected SetGlobalPolicy to reject a negative concurrency")
	}
}

func TestSnapshotReportsUsage(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 5, ByteQuota: 10_000, Window: time.Hour}})
	ctx := context.Background()
	r, _ := l.Admit(ctx, "team-a")
	r.RecordBytes(4096)

	snap := l.Metrics()
	if len(snap.Tenants) != 1 {
		t.Fatalf("expected 1 tenant row, got %d", len(snap.Tenants))
	}
	row := snap.Tenants[0]
	if row.Tenant != "team-a" {
		t.Fatalf("tenant = %q", row.Tenant)
	}
	if row.InFlight != 1 {
		t.Fatalf("in-flight = %d, want 1", row.InFlight)
	}
	if row.BytesUsed != 4096 {
		t.Fatalf("bytes used = %d, want 4096", row.BytesUsed)
	}
	if row.WindowEnds.IsZero() {
		t.Fatal("expected a non-zero window end for a windowed byte quota")
	}
	r.Release()
}

// TestAdmitConcurrentRace exercises the limiter under the race detector with many
// goroutines competing for a small concurrency budget, verifying slots are never
// over-committed and always released.
func TestAdmitConcurrentRace(t *testing.T) {
	const maxConc = 8
	l := New(Options{Default: Policy{MaxConcurrent: maxConc}})
	ctx := context.Background()

	var inFlight atomic.Int64
	var maxObserved atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, dec := l.Admit(ctx, "team-a")
			if !dec.Allowed {
				return
			}
			cur := inFlight.Add(1)
			for {
				m := maxObserved.Load()
				if cur <= m || maxObserved.CompareAndSwap(m, cur) {
					break
				}
			}
			inFlight.Add(-1)
			res.Release()
		}()
	}
	wg.Wait()

	if got := maxObserved.Load(); got > maxConc {
		t.Fatalf("observed %d concurrent holders, exceeds cap %d", got, maxConc)
	}
	if got := l.Metrics().Tenants; len(got) == 1 && got[0].InFlight != 0 {
		t.Fatalf("residual in-flight = %d after all released, want 0", got[0].InFlight)
	}
}
