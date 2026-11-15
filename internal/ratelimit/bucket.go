package ratelimit

import (
	"container/list"
	"context"
	"errors"
	"sync"
	"time"
)

// tokenBucket is a classic token-bucket rate limiter: it refills at rate tokens
// per second up to a capacity of burst tokens, and a request is admitted when at
// least one token is available. It supports live reconfiguration (setRate) so a
// runtime policy change does not discard the bucket's accumulated state, and is
// safe for concurrent use.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // tokens added per second
	burst  float64 // maximum tokens held
	tokens float64 // current tokens
	last   time.Time
}

// newTokenBucket constructs a bucket that starts full (allowing an immediate
// burst). last is left zero and lazily initialized on the first take.
func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst}
}

// setRate reconfigures the bucket's sustained rate and burst capacity, clamping
// the current token count to the new capacity. Caller must not hold mu.
func (b *tokenBucket) setRate(rate, burst float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rate = rate
	b.burst = burst
	if b.tokens > burst {
		b.tokens = burst
	}
}

// take attempts to consume one token as of now. It returns whether a token was
// available and, when it was not, the duration the caller should wait before a
// token will have accrued (the Retry-After hint).
func (b *tokenBucket) take(now time.Time) (ok bool, retryAfter time.Duration) {
	wait, ok := b.reserve(now, 0)
	if ok {
		return true, 0
	}
	return false, wait
}

// reserve takes one token as of now. When none is left it borrows the next one
// to accrue, provided that one is due within maxWait: the bucket goes into
// debt, and the caller must wait the returned duration before it goes ahead.
// Each later reservation queues behind the debt, so waiting requests are let
// through at the sustained rate in the order they came. A token due later than
// maxWait is not borrowed: ok is false and wait says when one would be due (the
// Retry-After hint).
func (b *tokenBucket) reserve(now time.Time, maxWait time.Duration) (wait time.Duration, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rate <= 0 {
		// Rate disabled: always admit (the caller should not have created the
		// bucket, but be defensive).
		return 0, true
	}

	if b.last.IsZero() {
		b.last = now
	}
	// Refill based on elapsed time, capped at burst.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return 0, true
	}

	// Time until one full token accrues, behind any tokens already borrowed.
	needed := 1 - b.tokens
	wait = time.Duration(needed / b.rate * float64(time.Second))
	if wait <= 0 {
		wait = time.Millisecond
	}
	if wait > maxWait {
		return wait, false
	}
	b.tokens--
	return wait, true
}

// refund gives back a token reserve took, for a request that was refused after
// all: a request that is not served costs its tenant nothing.
func (b *tokenBucket) refund() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens++
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
}

// semaphore is a counting semaphore bounding the number of concurrently held
// slots, with a first-come-first-served queue of requests waiting for one. It
// supports live reconfiguration of its maximum and is safe for concurrent use. A
// max of zero means unbounded (acquire always succeeds), though the limiter
// avoids creating one in that case.
type semaphore struct {
	mu      sync.Mutex
	max     int
	cur     int
	waiters list.List // of chan struct{}, closed when the slot is granted; oldest first
}

func newSemaphore(max int) *semaphore { return &semaphore{max: max} }

// Reasons acquireWait gives up.
var (
	// errSlotsFull: every slot is held and the caller may not wait.
	errSlotsFull = errors.New("ratelimit: concurrency limit reached")
	// errQueueFull: every slot is held and the queue is at its bound.
	errQueueFull = errors.New("ratelimit: concurrency limit reached and its queue is full")
	// errWaitExpired: no slot came free within the wait.
	errWaitExpired = errors.New("ratelimit: no concurrency slot came free in time")
)

// setMax updates the capacity. Lowering it below the current in-flight count
// does not forcibly evict holders; new acquisitions simply wait until the count
// drains below the new max. Raising it (or lifting it with 0) hands the new
// slots to waiting requests at once.
func (s *semaphore) setMax(max int) {
	s.mu.Lock()
	s.max = max
	s.grantLocked()
	s.mu.Unlock()
}

// acquire reserves one slot, returning false when the semaphore is full or
// requests are already waiting for one.
func (s *semaphore) acquire() bool {
	_, err := s.acquireWait(context.Background(), 0, 0)
	return err == nil
}

// acquireWait reserves one slot. When none is free it joins the queue — unless
// wait is not positive or maxQueue requests are waiting already — and waits up
// to wait for its turn; it never takes a slot ahead of a request queued before
// it. waited reports that the slot came only after queueing. A slot granted
// just as the wait expired is kept; one granted after the caller went away
// (ctx done) is handed on to the next in line.
func (s *semaphore) acquireWait(ctx context.Context, wait time.Duration, maxQueue int) (waited bool, err error) {
	s.mu.Lock()
	if s.free() && s.waiters.Len() == 0 {
		s.cur++
		s.mu.Unlock()
		return false, nil
	}
	if wait <= 0 {
		s.mu.Unlock()
		return false, errSlotsFull
	}
	if s.waiters.Len() >= maxQueue {
		s.mu.Unlock()
		return false, errQueueFull
	}
	ready := make(chan struct{})
	elem := s.waiters.PushBack(ready)
	s.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	var cause error
	select {
	case <-ready:
		return true, nil
	case <-ctx.Done():
		cause = ctx.Err()
	case <-timer.C:
		cause = errWaitExpired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-ready:
		// The slot was granted as the wait ended.
		if cause == errWaitExpired {
			return true, nil
		}
		s.cur--
	default:
		s.waiters.Remove(elem)
	}
	// Leaving the queue (or handing back a slot) may let the next one in.
	s.grantLocked()
	return true, cause
}

// release returns one slot, handing it to the oldest waiting request if any.
func (s *semaphore) release() {
	s.mu.Lock()
	if s.cur > 0 {
		s.cur--
	}
	s.grantLocked()
	s.mu.Unlock()
}

// free reports whether a slot is free. Caller holds mu.
func (s *semaphore) free() bool { return s.max <= 0 || s.cur < s.max }

// grantLocked hands free slots to waiting requests, oldest first. Caller holds
// mu.
func (s *semaphore) grantLocked() {
	for s.waiters.Len() > 0 && s.free() {
		front := s.waiters.Front()
		s.waiters.Remove(front)
		s.cur++
		close(front.Value.(chan struct{}))
	}
}

// inFlight reports the number of slots currently held.
func (s *semaphore) inFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// queued reports the number of requests waiting for a slot.
func (s *semaphore) queued() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.waiters.Len()
}
