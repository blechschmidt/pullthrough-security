package upstreampool

import (
	"net/url"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// State is the circuit-breaker state of a single mirror endpoint.
type State int

const (
	// StateClosed is the healthy steady state: requests flow to the endpoint and
	// failures are counted toward the trip threshold.
	StateClosed State = iota
	// StateOpen means the endpoint tripped: requests are not sent (the pool fails
	// over to the next endpoint) until the open-timeout elapses, at which point a
	// limited number of trial requests are admitted (half-open).
	StateOpen
	// StateHalfOpen admits a bounded number of trial requests to probe recovery.
	// Enough consecutive successes close the circuit; any failure re-opens it.
	StateHalfOpen
)

// String renders the state as a stable, lowercase identifier suitable for metric
// labels and JSON.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// breakerParams holds the tunables that drive an endpoint's state machine.
type breakerParams struct {
	failureThreshold  int           // consecutive failures (while closed) that trip the breaker
	successThreshold  int           // consecutive successes (while half-open) that close it
	openTimeout       time.Duration // how long the breaker stays open before admitting a probe
	halfOpenMaxProbes int           // concurrent trial requests admitted while half-open
}

// endpoint is one mirror in a pool: its target base URL, optional dedicated
// credentials/client, and its live circuit-breaker state and counters. All
// mutable state is guarded by mu so the pool, the active prober, and the admin
// API can touch it concurrently.
type endpoint struct {
	id      string
	base    *url.URL
	primary bool

	// creds, when set, override the request credentials for this endpoint so a
	// mirror can authenticate with its own account while preserving the
	// auth-passthrough model. hasCreds distinguishes "no override" from "empty".
	creds    upstream.Credentials
	hasCreds bool
	// client, when non-nil, is a dedicated request executor for this endpoint
	// (e.g. a mirror behind an internal CA needs its own TLS policy). When nil
	// the pool's shared client is used.
	client upstream.Doer

	params breakerParams

	mu                   sync.Mutex
	state                State
	consecutiveFailures  int
	consecutiveSuccesses int
	openedAt             time.Time
	probesInFlight       int
	drained              bool // operator force-drain: never selected until cleared
	lastChange           time.Time

	// cumulative counters (atomic-equivalent under mu) for metrics and admin.
	totalSuccess int64
	totalFailure int64
	totalProbes  int64
	latencySum   float64
	latencyCount int64
	lastErr      string
	lastErrAt    time.Time
	tripCount    int64 // number of times this endpoint tripped to open
}

// acquire decides whether a request (live or probe) may be sent to the endpoint
// right now, advancing the breaker's time-based transitions. It returns allowed
// and, when allowed, whether the attempt is a half-open trial probe (isProbe),
// which the caller must echo back to release so the in-flight probe accounting
// stays balanced.
//
// The transition Open→HalfOpen happens lazily here when the open-timeout has
// elapsed, so recovery does not require a background ticker (though the optional
// active prober drives it sooner).
func (e *endpoint) acquire(now time.Time) (allowed, isProbe bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.drained {
		return false, false
	}

	switch e.state {
	case StateClosed:
		return true, false
	case StateOpen:
		if now.Sub(e.openedAt) < e.params.openTimeout {
			return false, false
		}
		// Cooldown elapsed: move to half-open and admit this attempt as a probe.
		e.transition(StateHalfOpen, now)
		e.probesInFlight = 1
		return true, true
	case StateHalfOpen:
		if e.probesInFlight >= e.params.halfOpenMaxProbes {
			return false, false
		}
		e.probesInFlight++
		return true, true
	default:
		return false, false
	}
}

// release records the outcome of an attempt and advances the breaker's
// outcome-driven transitions. opened reports whether this call tripped the
// breaker closed→open (or half-open→open), so the caller can emit a
// circuit-open notification exactly once per trip.
func (e *endpoint) release(now time.Time, isProbe, success bool, latencySeconds float64, errMsg string) (opened bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if isProbe && e.probesInFlight > 0 {
		e.probesInFlight--
	}
	if isProbe {
		e.totalProbes++
	}
	e.latencySum += latencySeconds
	e.latencyCount++

	if success {
		e.totalSuccess++
		e.consecutiveFailures = 0
		switch e.state {
		case StateHalfOpen:
			e.consecutiveSuccesses++
			if e.consecutiveSuccesses >= e.params.successThreshold {
				e.transition(StateClosed, now)
			}
		case StateOpen:
			// A late success arriving while open (e.g. a slow probe) nudges toward
			// recovery without immediately closing; require a clean half-open pass.
			e.transition(StateHalfOpen, now)
		}
		return false
	}

	// Failure.
	e.totalFailure++
	e.consecutiveSuccesses = 0
	if errMsg != "" {
		e.lastErr = errMsg
		e.lastErrAt = now
	}
	switch e.state {
	case StateClosed:
		e.consecutiveFailures++
		if e.consecutiveFailures >= e.params.failureThreshold {
			e.transition(StateOpen, now)
			e.openedAt = now
			e.tripCount++
			return true
		}
	case StateHalfOpen:
		// A failed trial immediately re-opens the breaker for another cooldown.
		e.transition(StateOpen, now)
		e.openedAt = now
		e.tripCount++
		return true
	case StateOpen:
		// Extend the cooldown window on a fresh failure.
		e.openedAt = now
	}
	return false
}

// transition sets the state and resets the counters that are scoped to the new
// state, recording the change time. The caller holds mu.
func (e *endpoint) transition(to State, now time.Time) {
	if e.state == to {
		return
	}
	e.state = to
	e.lastChange = now
	switch to {
	case StateClosed:
		e.consecutiveFailures = 0
		e.consecutiveSuccesses = 0
		e.probesInFlight = 0
	case StateHalfOpen:
		e.consecutiveSuccesses = 0
		e.probesInFlight = 0
	case StateOpen:
		e.probesInFlight = 0
	}
}

// snapshot returns a consistent, lock-free copy of the endpoint's observable
// state for metrics and the admin API.
func (e *endpoint) snapshot() EndpointStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := EndpointStatus{
		ID:                   e.id,
		URL:                  e.base.String(),
		Primary:              e.primary,
		State:                e.state.String(),
		Drained:              e.drained,
		ConsecutiveFailures:  e.consecutiveFailures,
		ConsecutiveSuccesses: e.consecutiveSuccesses,
		ProbesInFlight:       e.probesInFlight,
		TotalSuccess:         e.totalSuccess,
		TotalFailure:         e.totalFailure,
		TotalProbes:          e.totalProbes,
		TripCount:            e.tripCount,
		LatencySum:           e.latencySum,
		LatencyCount:         e.latencyCount,
		LastError:            e.lastErr,
	}
	if !e.openedAt.IsZero() && e.state != StateClosed {
		st.OpenedAt = e.openedAt
	}
	if !e.lastChange.IsZero() {
		st.LastChange = e.lastChange
	}
	if !e.lastErrAt.IsZero() {
		st.LastErrorAt = e.lastErrAt
	}
	return st
}

// setDrained sets or clears the operator force-drain flag. Draining removes the
// endpoint from selection without altering its circuit state; undraining makes
// it eligible again from its current state.
func (e *endpoint) setDrained(drained bool, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.drained = drained
	e.lastChange = now
}

// reset forces the breaker closed and clears the failure/probe counters, used by
// the admin "clear circuit" override. It does not change the drain flag.
func (e *endpoint) reset(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.transition(StateClosed, now)
	e.consecutiveFailures = 0
	e.consecutiveSuccesses = 0
	e.openedAt = time.Time{}
}

// forceOpen trips the breaker open immediately, used by the admin override to
// take an endpoint out of rotation for the cooldown window.
func (e *endpoint) forceOpen(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != StateOpen {
		e.tripCount++
	}
	e.transition(StateOpen, now)
	e.openedAt = now
}
