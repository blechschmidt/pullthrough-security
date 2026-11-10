package cachefed

import (
	"sync"
	"time"
)

// state is the circuit-breaker state of a single peer. It mirrors the
// upstream-pool health-aware routing state machine (Task 38) so federation
// peers are shed and recovered with the same, well-understood semantics.
type state int

const (
	// stateClosed is the healthy steady state: requests flow to the peer and
	// failures are counted toward the trip threshold.
	stateClosed state = iota
	// stateOpen means the peer tripped: requests are not sent (the federation
	// skips it) until the open-timeout elapses, after which a bounded number of
	// trial probes are admitted (half-open).
	stateOpen
	// stateHalfOpen admits a bounded number of trial requests to probe recovery.
	// Enough consecutive successes close the circuit; any failure re-opens it.
	stateHalfOpen
)

func (s state) String() string {
	switch s {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// breakerParams holds the tunables that drive a peer's state machine.
type breakerParams struct {
	failureThreshold  int           // consecutive failures (while closed) that trip the breaker
	successThreshold  int           // consecutive successes (while half-open) that close it
	openTimeout       time.Duration // how long the breaker stays open before admitting a probe
	halfOpenMaxProbes int           // concurrent trial requests admitted while half-open
}

// breaker is a per-peer circuit breaker. All mutable state is guarded by mu so
// the read-through fan-out (which touches several peers concurrently) and the
// status snapshot can access it safely.
type breaker struct {
	params breakerParams
	now    func() time.Time

	mu                   sync.Mutex
	st                   state
	consecutiveFailures  int
	consecutiveSuccesses int
	openedAt             time.Time
	probesInFlight       int

	// cumulative counters for the status snapshot / metrics.
	totalSuccess int64
	totalFailure int64
	latencySum   float64
	latencyCount int64
	tripCount    int64
	lastErr      string
}

func newBreaker(params breakerParams, now func() time.Time) *breaker {
	if now == nil {
		now = time.Now
	}
	if params.failureThreshold <= 0 {
		params.failureThreshold = 3
	}
	if params.successThreshold <= 0 {
		params.successThreshold = 2
	}
	if params.openTimeout <= 0 {
		params.openTimeout = 30 * time.Second
	}
	if params.halfOpenMaxProbes <= 0 {
		params.halfOpenMaxProbes = 1
	}
	return &breaker{params: params, now: now, st: stateClosed}
}

// allow decides whether a request may be sent to the peer right now, advancing
// the breaker's time-based transitions. When allowed it returns whether the
// attempt is admitted as a half-open trial probe; the caller MUST subsequently
// call exactly one of success/failure/cancel with that same isProbe so the
// in-flight probe accounting stays balanced.
func (b *breaker) allow() (allowed, isProbe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	switch b.st {
	case stateClosed:
		return true, false
	case stateOpen:
		if now.Sub(b.openedAt) < b.params.openTimeout {
			return false, false
		}
		// Cooldown elapsed: move to half-open and admit this attempt as a probe.
		b.transition(stateHalfOpen, now)
		b.probesInFlight = 1
		return true, true
	case stateHalfOpen:
		if b.probesInFlight >= b.params.halfOpenMaxProbes {
			return false, false
		}
		b.probesInFlight++
		return true, true
	default:
		return false, false
	}
}

// peek reports whether the peer is currently eligible for selection without
// mutating any state. It is a cheap pre-filter; allow performs the authoritative
// (side-effecting) admission.
func (b *breaker) peek() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.st {
	case stateClosed, stateHalfOpen:
		return true
	case stateOpen:
		return b.now().Sub(b.openedAt) >= b.params.openTimeout
	default:
		return false
	}
}

// success records a successful attempt and advances recovery.
func (b *breaker) success(isProbe bool, latencySeconds float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if isProbe && b.probesInFlight > 0 {
		b.probesInFlight--
	}
	b.totalSuccess++
	b.latencySum += latencySeconds
	b.latencyCount++
	b.consecutiveFailures = 0
	switch b.st {
	case stateHalfOpen:
		b.consecutiveSuccesses++
		if b.consecutiveSuccesses >= b.params.successThreshold {
			b.transition(stateClosed, b.now())
		}
	case stateOpen:
		// A late success while open nudges toward recovery without closing outright.
		b.transition(stateHalfOpen, b.now())
	}
}

// failure records a failed attempt and advances the trip transitions.
func (b *breaker) failure(isProbe bool, latencySeconds float64, errMsg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if isProbe && b.probesInFlight > 0 {
		b.probesInFlight--
	}
	b.totalFailure++
	b.latencySum += latencySeconds
	b.latencyCount++
	b.consecutiveSuccesses = 0
	if errMsg != "" {
		b.lastErr = errMsg
	}
	now := b.now()
	switch b.st {
	case stateClosed:
		b.consecutiveFailures++
		if b.consecutiveFailures >= b.params.failureThreshold {
			b.transition(stateOpen, now)
			b.openedAt = now
			b.tripCount++
		}
	case stateHalfOpen:
		b.transition(stateOpen, now)
		b.openedAt = now
		b.tripCount++
	case stateOpen:
		b.openedAt = now
	}
}

// cancel neutrally releases a probe slot for an attempt that was abandoned
// (e.g. a hedged request cancelled once another peer answered first). It counts
// as neither a success nor a failure, so a healthy peer that merely lost a race
// is not penalized toward tripping its breaker.
func (b *breaker) cancel(isProbe bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if isProbe && b.probesInFlight > 0 {
		b.probesInFlight--
	}
}

// transition sets the state and resets the counters scoped to the new state.
// The caller holds mu.
func (b *breaker) transition(to state, _ time.Time) {
	if b.st == to {
		return
	}
	b.st = to
	switch to {
	case stateClosed:
		b.consecutiveFailures = 0
		b.consecutiveSuccesses = 0
		b.probesInFlight = 0
	case stateHalfOpen:
		b.consecutiveSuccesses = 0
	case stateOpen:
		b.probesInFlight = 0
	}
}

// snapshot returns a consistent copy of the breaker's observable counters.
func (b *breaker) snapshot() (st string, totalSuccess, totalFailure, latencyCount int64, latencySum float64, lastErr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st.String(), b.totalSuccess, b.totalFailure, b.latencyCount, b.latencySum, b.lastErr
}
