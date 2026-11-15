package ratelimit

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// admitAsync starts an Admit in the background; the result arrives on the
// returned channel.
type admitResult struct {
	res Reservation
	dec Decision
}

func admitAsync(ctx context.Context, l *Limiter, tenant string) <-chan admitResult {
	ch := make(chan admitResult, 1)
	go func() {
		res, dec := l.Admit(ctx, tenant)
		ch <- admitResult{res, dec}
	}()
	return ch
}

// waitFor polls cond until it holds or the test's patience runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitingNow(l *Limiter) int64 { return l.Metrics().Waiting }

func TestAdmitWaitsForASlot(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}, MaxWait: 5 * time.Second})
	ctx := context.Background()
	r1, d1 := l.Admit(ctx, "team-a")
	if !d1.Allowed || d1.Waited != 0 {
		t.Fatalf("first admit: %+v", d1)
	}
	ch := admitAsync(ctx, l, "team-a")
	waitFor(t, "the second request to queue", func() bool { return waitingNow(l) == 1 })
	select {
	case got := <-ch:
		t.Fatalf("admitted while the only slot is held: %+v", got.dec)
	case <-time.After(20 * time.Millisecond):
	}
	r1.Release()
	got := <-ch
	if !got.dec.Allowed || got.dec.Waited <= 0 {
		t.Fatalf("queued request: %+v, want admitted after a wait", got.dec)
	}
	snap := l.Metrics()
	if snap.Delayed != 1 || snap.Waiting != 0 || snap.Throttled != 0 || snap.Tenants[0].Delayed != 1 {
		t.Fatalf("snapshot after a delayed admit: %+v", snap)
	}
	got.res.Release()
	if in := l.Metrics().Tenants[0].InFlight; in != 0 {
		t.Fatalf("in-flight %d after release", in)
	}
}

func TestAdmitWaitExpires(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}, MaxWait: 80 * time.Millisecond})
	ctx := context.Background()
	r1, _ := l.Admit(ctx, "team-a")
	defer r1.Release()
	start := time.Now()
	_, dec := l.Admit(ctx, "team-a")
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Fatalf("gave up after %v, before the 80ms wait", elapsed)
	}
	if dec.Allowed || dec.Type != LimitConcurrency || dec.RetryAfter != time.Second ||
		!strings.Contains(dec.Reason, "no slot came free within 80ms") {
		t.Fatalf("expired wait: %+v", dec)
	}
	snap := l.Metrics()
	if snap.Waiting != 0 || snap.Throttled != 1 || snap.ThrottledByReason[string(LimitConcurrency)] != 1 {
		t.Fatalf("snapshot after an expired wait: %+v", snap)
	}
}

func TestAdmitWithoutWaitRefusesAtOnceWithRetryAfter(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}})
	r1, _ := l.Admit(context.Background(), "team-a")
	defer r1.Release()
	_, dec := l.Admit(context.Background(), "team-a")
	if dec.Allowed || dec.Reason != "concurrency limit reached" || dec.RetryAfter != time.Second {
		t.Fatalf("refusal without a wait: %+v", dec)
	}
	if got := l.Metrics().MaxWait; got != "0s" {
		t.Fatalf("snapshot MaxWait = %q", got)
	}
}

func TestAdmitQueueIsBounded(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}, MaxWait: 5 * time.Second, MaxQueue: 2})
	ctx := context.Background()
	r1, _ := l.Admit(ctx, "team-a")
	a := admitAsync(ctx, l, "team-a")
	b := admitAsync(ctx, l, "team-a")
	waitFor(t, "two requests to queue", func() bool { return waitingNow(l) == 2 })

	start := time.Now()
	_, dec := l.Admit(ctx, "team-a")
	if dec.Allowed || !strings.Contains(dec.Reason, "too many requests are waiting") || dec.RetryAfter != time.Second {
		t.Fatalf("third waiter: %+v, want refused because the queue is full", dec)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a full queue refused only after %v", elapsed)
	}
	r1.Release()
	// The two waiters queued in either order; each releases as it gets in.
	for i := 0; i < 2; i++ {
		var got admitResult
		select {
		case got = <-a:
		case got = <-b:
		}
		if !got.dec.Allowed {
			t.Fatalf("queued request: %+v", got.dec)
		}
		got.res.Release()
	}
	if got := l.Metrics().MaxQueue; got != 2 {
		t.Fatalf("snapshot MaxQueue = %d", got)
	}
	if got := New(Options{}).Metrics().MaxQueue; got != DefaultMaxQueue {
		t.Fatalf("default MaxQueue = %d", got)
	}
}

func TestAdmitServesWaitersInOrder(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}, MaxWait: 5 * time.Second})
	ctx := context.Background()
	held, _ := l.Admit(ctx, "team-a")
	var order []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, dec := l.Admit(ctx, "team-a")
			if !dec.Allowed {
				t.Errorf("waiter %d refused: %+v", i, dec)
				return
			}
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			res.Release()
		}()
		// Queue them one after the other.
		waitFor(t, "the next waiter to queue", func() bool { return waitingNow(l) == int64(i+1) })
	}
	held.Release()
	wg.Wait()
	for i, got := range order {
		if got != i {
			t.Fatalf("served in order %v, want first come first served", order)
		}
	}
}

func TestAdmitClientGoneWhileWaiting(t *testing.T) {
	l := New(Options{Default: Policy{MaxConcurrent: 1}, MaxWait: 5 * time.Second})
	r1, _ := l.Admit(context.Background(), "team-a")
	ctx, cancel := context.WithCancel(context.Background())
	ch := admitAsync(ctx, l, "team-a")
	waitFor(t, "the request to queue", func() bool { return waitingNow(l) == 1 })
	cancel()
	got := <-ch
	if got.dec.Allowed || got.dec.RetryAfter != 0 || !strings.Contains(got.dec.Reason, "went away") {
		t.Fatalf("cancelled waiter: %+v", got.dec)
	}
	r1.Release()
	// Nothing leaked: the slot is free again and nobody waits.
	r2, d2 := l.Admit(context.Background(), "team-a")
	if !d2.Allowed || d2.Waited != 0 {
		t.Fatalf("after the cancelled waiter left: %+v", d2)
	}
	r2.Release()
	if snap := l.Metrics(); snap.Waiting != 0 || snap.Tenants[0].Waiting != 0 || snap.Tenants[0].InFlight != 0 {
		t.Fatalf("snapshot: %+v", snap)
	}
}

func TestAdmitWaitsForARateToken(t *testing.T) {
	// 20 tokens a second, burst 1: the second request is due 50ms later.
	l := New(Options{Default: Policy{RPS: 20, Burst: 1}, MaxWait: time.Second})
	ctx := context.Background()
	if _, d := l.Admit(ctx, "team-a"); !d.Allowed || d.Waited != 0 {
		t.Fatalf("first: %+v", d)
	}
	start := time.Now()
	_, d := l.Admit(ctx, "team-a")
	if !d.Allowed || d.Waited < 40*time.Millisecond || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("second: %+v after %v, want admitted after ~50ms", d, time.Since(start))
	}
	if snap := l.Metrics(); snap.Delayed != 1 || snap.Throttled != 0 {
		t.Fatalf("snapshot: %+v", snap)
	}
}

func TestAdmitRefusesARateTokenDueTooLate(t *testing.T) {
	clk := newFakeClock()
	// One token a second, a wait of 200ms: the next token is due too late.
	l := New(Options{Default: Policy{RPS: 1, Burst: 1}, MaxWait: 200 * time.Millisecond, Now: clk.now})
	ctx := context.Background()
	if _, d := l.Admit(ctx, "team-a"); !d.Allowed {
		t.Fatalf("first: %+v", d)
	}
	start := time.Now()
	_, d := l.Admit(ctx, "team-a")
	if d.Allowed || d.Type != LimitRPS || d.RetryAfter < 900*time.Millisecond {
		t.Fatalf("second: %+v, want refused with a ~1s Retry-After", d)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("a token due too late must be refused at once, not after waiting")
	}
	// The refusal borrowed nothing: a second later exactly one token is there.
	clk.advance(time.Second)
	if _, d := l.Admit(ctx, "team-a"); !d.Allowed || d.Waited != 0 {
		t.Fatalf("a second later: %+v", d)
	}
}

func TestAdmitBorrowedTokensPaceWaiters(t *testing.T) {
	clk := newFakeClock()
	// The clock stands still, so each waiter borrows one more token: the waits
	// grow by 1/rate each, and the one whose token is due beyond the wait is
	// refused.
	l := New(Options{Default: Policy{RPS: 100, Burst: 1}, MaxWait: 25 * time.Millisecond, Now: clk.now})
	ctx := context.Background()
	var waits []time.Duration
	for i := 0; i < 4; i++ {
		_, d := l.Admit(ctx, "team-a")
		if !d.Allowed {
			if i != 3 {
				t.Fatalf("request %d refused: %+v", i, d)
			}
			continue
		}
		waits = append(waits, d.Waited)
	}
	if len(waits) != 3 || waits[0] != 0 || waits[1] < 8*time.Millisecond || waits[2] < 18*time.Millisecond {
		t.Fatalf("waits %v, want 0, ~10ms, ~20ms and the fourth refused", waits)
	}
}

func TestAdmitRefundsTheTokenOfARefusedRequest(t *testing.T) {
	clk := newFakeClock()
	l := New(Options{Default: Policy{RPS: 1, Burst: 1, MaxConcurrent: 1}, Now: clk.now})
	ctx := context.Background()
	r1, d1 := l.Admit(ctx, "team-a")
	if !d1.Allowed {
		t.Fatalf("first: %+v", d1)
	}
	clk.advance(time.Second) // one token again
	if _, d := l.Admit(ctx, "team-a"); d.Allowed || d.Type != LimitConcurrency {
		t.Fatalf("second: %+v, want refused by concurrency", d)
	}
	r1.Release()
	// The refused request gave its token back.
	r3, d3 := l.Admit(ctx, "team-a")
	if !d3.Allowed {
		t.Fatalf("third: %+v, want the refunded token", d3)
	}
	r3.Release()
}

// TestAdmitTenantQueueHoldsNoGlobalSlot: requests queued behind their tenant's
// limit hold none of the global capacity, so other tenants are not held up.
func TestAdmitTenantQueueHoldsNoGlobalSlot(t *testing.T) {
	l := New(Options{
		Global:    Policy{MaxConcurrent: 2},
		PerTenant: map[string]Policy{"team-a": {MaxConcurrent: 1}},
		MaxWait:   5 * time.Second,
	})
	ctx := context.Background()
	ra, _ := l.Admit(ctx, "team-a")
	queued := admitAsync(ctx, l, "team-a")
	waitFor(t, "team-a's second request to queue", func() bool { return waitingNow(l) == 1 })
	if in := l.Metrics().Global.InFlight; in != 1 {
		t.Fatalf("global in-flight %d while team-a queues, want 1", in)
	}
	rb, db := l.Admit(ctx, "team-b")
	if !db.Allowed || db.Waited != 0 {
		t.Fatalf("team-b: %+v, want admitted at once", db)
	}
	rb.Release()
	ra.Release()
	got := <-queued
	if !got.dec.Allowed {
		t.Fatalf("team-a's queued request: %+v", got.dec)
	}
	got.res.Release()
	if in := l.Metrics().Global.InFlight; in != 0 {
		t.Fatalf("global in-flight %d at the end", in)
	}
}

// TestAdmitGlobalQueueReleasesTenantSlot: a request that waits for a global
// slot in vain gives its tenant slot back.
func TestAdmitGlobalQueueReleasesTenantSlot(t *testing.T) {
	l := New(Options{Global: Policy{MaxConcurrent: 1}, Default: Policy{MaxConcurrent: 5}, MaxWait: 50 * time.Millisecond})
	ctx := context.Background()
	ra, _ := l.Admit(ctx, "team-a")
	defer ra.Release()
	if _, d := l.Admit(ctx, "team-b"); d.Allowed || d.Type != LimitConcurrency {
		t.Fatalf("team-b: %+v, want refused by the global limit", d)
	}
	for _, row := range l.Metrics().Tenants {
		if row.Tenant == "team-b" && row.InFlight != 0 {
			t.Fatalf("team-b holds %d slots after its refusal", row.InFlight)
		}
	}
}

func TestSetPolicyLetsWaitersIn(t *testing.T) {
	for name, next := range map[string]Policy{"raised": {MaxConcurrent: 3}, "lifted": {}} {
		t.Run(name, func(t *testing.T) {
			l := New(Options{PerTenant: map[string]Policy{"team-a": {MaxConcurrent: 1}}, MaxWait: 5 * time.Second})
			ctx := context.Background()
			r1, _ := l.Admit(ctx, "team-a")
			defer r1.Release()
			ch := admitAsync(ctx, l, "team-a")
			waitFor(t, "the request to queue", func() bool { return waitingNow(l) == 1 })
			if err := l.SetPolicy("team-a", next); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-ch:
				if !got.dec.Allowed {
					t.Fatalf("waiter after the policy change: %+v", got.dec)
				}
				got.res.Release()
			case <-time.After(2 * time.Second):
				t.Fatal("the waiter was not let in when the limit went up")
			}
		})
	}
}

// TestAdmitWaitingUnderLoad: a burst far above the concurrency limit is
// served in full by queueing, never above the limit, and leaves nothing held.
func TestAdmitWaitingUnderLoad(t *testing.T) {
	const maxConc = 8
	l := New(Options{Default: Policy{MaxConcurrent: maxConc}, MaxWait: 10 * time.Second})
	ctx := context.Background()
	var inFlight, maxSeen, refused atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 400; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, dec := l.Admit(ctx, "team-a")
			if !dec.Allowed {
				refused.Add(1)
				return
			}
			cur := inFlight.Add(1)
			for {
				m := maxSeen.Load()
				if cur <= m || maxSeen.CompareAndSwap(m, cur) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			inFlight.Add(-1)
			res.Release()
		}()
	}
	wg.Wait()
	if refused.Load() != 0 {
		t.Fatalf("%d requests refused; the queue should absorb the burst", refused.Load())
	}
	if maxSeen.Load() > maxConc {
		t.Fatalf("%d in flight at once, above the limit %d", maxSeen.Load(), maxConc)
	}
	snap := l.Metrics()
	if snap.Tenants[0].InFlight != 0 || snap.Waiting != 0 || snap.Allowed != 400 {
		t.Fatalf("snapshot after the burst: %+v", snap)
	}
}

func TestSemaphoreAcquireWait(t *testing.T) {
	s := newSemaphore(1)
	ctx := context.Background()
	if waited, err := s.acquireWait(ctx, time.Second, 1); waited || err != nil {
		t.Fatalf("free slot: waited=%v err=%v", waited, err)
	}
	if _, err := s.acquireWait(ctx, 0, 1); err != errSlotsFull {
		t.Fatalf("no wait allowed: %v", err)
	}
	if _, err := s.acquireWait(ctx, time.Second, 0); err != errQueueFull {
		t.Fatalf("no queue allowed: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		waited, err := s.acquireWait(ctx, 5*time.Second, 1)
		if err == nil && !waited {
			err = errSlotsFull
		}
		done <- err
	}()
	waitFor(t, "the waiter to queue", func() bool { return s.queued() == 1 })
	// The queue is full now, and a newcomer may not jump it either.
	if _, err := s.acquireWait(ctx, time.Second, 1); err != errQueueFull {
		t.Fatalf("second waiter: %v", err)
	}
	s.release()
	if err := <-done; err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if s.inFlight() != 1 || s.queued() != 0 {
		t.Fatalf("in flight %d queued %d", s.inFlight(), s.queued())
	}
	if _, err := s.acquireWait(ctx, 20*time.Millisecond, 1); err != errWaitExpired {
		t.Fatalf("expired wait: %v", err)
	}
	if s.queued() != 0 {
		t.Fatalf("an expired waiter stayed queued")
	}
}

func TestTokenBucketReserveAndRefund(t *testing.T) {
	base := time.Unix(4_000_000, 0)
	b := newTokenBucket(10, 1)
	if wait, ok := b.reserve(base, 0); !ok || wait != 0 {
		t.Fatalf("first: wait=%v ok=%v", wait, ok)
	}
	wait, ok := b.reserve(base, time.Second)
	if !ok || wait < 99*time.Millisecond || wait > 101*time.Millisecond {
		t.Fatalf("borrowed: wait=%v ok=%v, want ~100ms", wait, ok)
	}
	wait, ok = b.reserve(base, 150*time.Millisecond)
	if ok || wait < 199*time.Millisecond {
		t.Fatalf("beyond the wait: wait=%v ok=%v, want refused with ~200ms", wait, ok)
	}
	b.refund()
	b.refund()
	b.refund() // more refunds than borrowings: capped at the burst
	if wait, ok := b.reserve(base, 0); !ok || wait != 0 {
		t.Fatalf("after refunds: wait=%v ok=%v", wait, ok)
	}
	if _, ok := b.reserve(base, 0); ok {
		t.Fatal("refunds must not lift the bucket above its burst")
	}
	free := newTokenBucket(0, 0)
	if wait, ok := free.reserve(base, 0); !ok || wait != 0 {
		t.Fatalf("rate 0: wait=%v ok=%v", wait, ok)
	}
}

// TestAdmitBoundsRateSleepers: a long wait cannot make a tenant's requests
// pile up asleep: beyond MaxQueue sleeping requests the next is refused at
// once, and its borrowed token is given back.
func TestAdmitBoundsRateSleepers(t *testing.T) {
	clk := newFakeClock()
	l := New(Options{Default: Policy{RPS: 1, Burst: 1}, MaxWait: time.Minute, MaxQueue: 1, Now: clk.now})
	ctx, cancel := context.WithCancel(context.Background())
	if _, d := l.Admit(ctx, "team-a"); !d.Allowed {
		t.Fatalf("first: %+v", d)
	}
	sleeper := admitAsync(ctx, l, "team-a") // borrows the token due in 1s
	waitFor(t, "the second request to sleep", func() bool { return waitingNow(l) == 1 })
	start := time.Now()
	_, d := l.Admit(context.Background(), "team-a")
	if d.Allowed || d.Type != LimitRPS || !strings.Contains(d.Reason, "too many requests are waiting") || d.RetryAfter < time.Second {
		t.Fatalf("third: %+v, want refused because a request already sleeps", d)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("the third request must be refused at once")
	}
	cancel()
	if got := <-sleeper; got.dec.Allowed || got.dec.Type != LimitRPS || !strings.Contains(got.dec.Reason, "went away") {
		t.Fatalf("cancelled sleeper: %+v", got.dec)
	}
	// Both refusals gave their borrowed tokens back, so the bucket owes
	// nothing: a second later a token is there (with either still borrowed the
	// request would have to wait).
	clk.advance(time.Second)
	if _, d := l.Admit(context.Background(), "team-a"); !d.Allowed || d.Waited != 0 {
		t.Fatalf("a second after the refunds: %+v", d)
	}
	if snap := l.Metrics(); snap.Waiting != 0 || snap.Tenants[0].Waiting != 0 {
		t.Fatalf("waiting after all left: %+v", snap)
	}
}
