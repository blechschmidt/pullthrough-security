package ratelimit

import (
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
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rate <= 0 {
		// Rate disabled: always admit (the caller should not have created the
		// bucket, but be defensive).
		return true, 0
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
		return true, 0
	}

	// Time until one full token accrues.
	needed := 1 - b.tokens
	wait := time.Duration(needed / b.rate * float64(time.Second))
	if wait <= 0 {
		wait = time.Millisecond
	}
	return false, wait
}

// semaphore is a counting semaphore bounding the number of concurrently held
// slots. It supports live reconfiguration of its maximum and is safe for
// concurrent use. A max of zero means unbounded (acquire always succeeds and is
// not tracked), though the limiter avoids creating one in that case.
type semaphore struct {
	mu  sync.Mutex
	max int
	cur int
}

func newSemaphore(max int) *semaphore { return &semaphore{max: max} }

// setMax updates the capacity. Lowering it below the current in-flight count
// does not forcibly evict holders; new acquisitions simply block until the
// count drains below the new max.
func (s *semaphore) setMax(max int) {
	s.mu.Lock()
	s.max = max
	s.mu.Unlock()
}

// acquire reserves one slot, returning false when the semaphore is full.
func (s *semaphore) acquire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.max > 0 && s.cur >= s.max {
		return false
	}
	s.cur++
	return true
}

// release returns one slot.
func (s *semaphore) release() {
	s.mu.Lock()
	if s.cur > 0 {
		s.cur--
	}
	s.mu.Unlock()
}

// inFlight reports the number of slots currently held.
func (s *semaphore) inFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}
