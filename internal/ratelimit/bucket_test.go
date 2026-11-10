package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucketBurstThenRefill(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	b := newTokenBucket(2, 3) // 2 tokens/sec, capacity 3, starts full

	// Three immediate takes succeed (burst), the fourth fails.
	for i := 0; i < 3; i++ {
		if ok, _ := b.take(base); !ok {
			t.Fatalf("burst take %d: expected allowed", i)
		}
	}
	ok, retry := b.take(base)
	if ok {
		t.Fatal("expected 4th take to be throttled")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry-after, got %v", retry)
	}
	// At 2 tokens/sec, one token accrues in 0.5s.
	if want := 500 * time.Millisecond; retry > want+time.Millisecond {
		t.Fatalf("retry-after %v exceeds expected ~%v", retry, want)
	}

	// After 1 second, 2 tokens have refilled (capped at burst).
	later := base.Add(time.Second)
	for i := 0; i < 2; i++ {
		if ok, _ := b.take(later); !ok {
			t.Fatalf("post-refill take %d: expected allowed", i)
		}
	}
	if ok, _ := b.take(later); ok {
		t.Fatal("expected throttle after refilled tokens consumed")
	}
}

func TestTokenBucketRefillCapsAtBurst(t *testing.T) {
	base := time.Unix(2_000_000, 0)
	b := newTokenBucket(1, 2)
	// Drain.
	b.take(base)
	b.take(base)
	// Wait a long time; refill must cap at burst (2), not accumulate unbounded.
	later := base.Add(time.Hour)
	allowed := 0
	for i := 0; i < 5; i++ {
		if ok, _ := b.take(later); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("expected exactly 2 allowed after cap, got %d", allowed)
	}
}

func TestTokenBucketSetRateClampsTokens(t *testing.T) {
	base := time.Unix(3_000_000, 0)
	b := newTokenBucket(10, 10) // full: 10 tokens
	b.setRate(1, 2)             // shrink capacity to 2
	allowed := 0
	for i := 0; i < 5; i++ {
		if ok, _ := b.take(base); ok {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("expected tokens clamped to new burst 2, got %d allowed", allowed)
	}
}

func TestSemaphoreAcquireRelease(t *testing.T) {
	s := newSemaphore(2)
	if !s.acquire() || !s.acquire() {
		t.Fatal("expected first two acquisitions to succeed")
	}
	if s.acquire() {
		t.Fatal("expected third acquisition to fail at capacity")
	}
	if got := s.inFlight(); got != 2 {
		t.Fatalf("inFlight = %d, want 2", got)
	}
	s.release()
	if !s.acquire() {
		t.Fatal("expected acquisition to succeed after release")
	}
}

func TestSemaphoreSetMax(t *testing.T) {
	s := newSemaphore(1)
	if !s.acquire() {
		t.Fatal("acquire 1")
	}
	if s.acquire() {
		t.Fatal("expected full at max=1")
	}
	s.setMax(3)
	if !s.acquire() || !s.acquire() {
		t.Fatal("expected acquisitions after raising max")
	}
}

// TestSemaphoreConcurrent exercises the semaphore under the race detector.
func TestSemaphoreConcurrent(t *testing.T) {
	s := newSemaphore(4)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.acquire() {
				s.release()
			}
		}()
	}
	wg.Wait()
	if got := s.inFlight(); got != 0 {
		t.Fatalf("inFlight = %d after balanced acquire/release, want 0", got)
	}
}
