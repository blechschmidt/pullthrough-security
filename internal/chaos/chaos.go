// Package chaos is a deterministic fault-injection test harness for the
// pull-through proxy's upstream and storage dependencies (Task 98).
//
// A pull-through supply-chain proxy sits on the critical path of every build:
// its resilience under degraded conditions is a first-class security property,
// not an afterthought. A proxy that fails unpredictably when an upstream mirror
// is slow, an object-store backend times out, or the LLM commit-scanner API is
// unavailable will either (a) stall every build behind it, or (b) silently
// fail open and admit unscanned content. Neither is acceptable, so each
// dependency's degraded-mode behavior must be an explicit, tested contract.
//
// This package provides two things:
//
//   - Reusable fault-injection primitives (this file and storage.go/gates.go):
//     a scriptable upstream [FaultyDoer], a [FaultyCache] wrapper that injects
//     storage errors/latency/corruption, fault-injecting [FaultyScanner] /
//     [FaultyAssessmentSource] / [FaultyProvider] implementations, a
//     deterministic [ManualClock], and a fault-injecting upstream HTTP server
//     ([FaultyUpstream]) for end-to-end gateway scenarios.
//
//   - A machine-checkable catalog of resilience guarantees (guarantees.go):
//     one [Guarantee] per (dependency, degraded condition) pair, each with a
//     deterministic verifier. [Run] executes the whole catalog and renders a
//     resilience matrix (JSON/Markdown) — the documented contract referenced by
//     docs/resilience.md. The table-driven tests drive the same catalog.
//
// Everything here is deterministic: faults are injected through explicit seams
// (the upstream.Doer interface, the cache.Cache interface, the policy
// AssessmentSource / commit Provider interfaces), time is driven by a
// [ManualClock] rather than the wall clock, and concurrency is sequenced with
// channels — so the suite never sleeps on real time and never flakes.
//
// This is a test harness, not a production component: nothing here runs on the
// live pull path.
package chaos

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// ManualClock is a race-safe, injectable clock. It is the deterministic time
// source for circuit-breaker cooldowns and negative-cache TTLs: tests advance
// it explicitly instead of sleeping, so open→half-open→closed transitions and
// TTL expiry are exercised without wall-clock waits.
type ManualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewManualClock seeds a clock at a fixed, nonzero instant (far from the zero
// time so durations never underflow).
func NewManualClock() *ManualClock {
	return &ManualClock{now: time.Unix(1_700_000_000, 0)}
}

// Now returns the current simulated time.
func (c *ManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *ManualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// DoerFunc adapts a function to the upstream.Doer interface.
type DoerFunc func(ctx context.Context, r upstream.Request) (*upstream.Response, error)

// Do implements upstream.Doer.
func (f DoerFunc) Do(ctx context.Context, r upstream.Request) (*upstream.Response, error) {
	return f(ctx, r)
}

// FaultyDoer is a scriptable upstream.Doer for injecting upstream faults at the
// request level (the seam a health-aware mirror pool wraps). It records every
// requested URL so a test can assert which mirror a request reached, and drives
// its response from Handler. It is safe for concurrent use.
//
// FaultyDoer is the primitive behind the multi-mirror failover and
// circuit-breaking scenarios: give each pool endpoint its own FaultyDoer (via
// upstreampool.EndpointConfig.Client) and script healthy vs. failing behavior.
type FaultyDoer struct {
	// Handler produces the response (or transport error) for each request.
	// Required. Use the Respond* / Fail* constructors for common cases.
	Handler DoerFunc

	mu       sync.Mutex
	requests []string
}

var _ upstream.Doer = (*FaultyDoer)(nil)

// Do implements upstream.Doer, recording the requested URL and delegating to
// Handler.
func (d *FaultyDoer) Do(ctx context.Context, r upstream.Request) (*upstream.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, r.URL)
	d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return d.Handler(ctx, r)
}

// Requests returns a copy of the URLs this Doer has been asked to fetch, in
// order.
func (d *FaultyDoer) Requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.requests))
	copy(out, d.requests)
	return out
}

// Count returns how many requests this Doer has received.
func (d *FaultyDoer) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.requests)
}

// HealthyDoer returns a FaultyDoer that answers every request 200 with body.
func HealthyDoer(body string) *FaultyDoer {
	return &FaultyDoer{Handler: func(_ context.Context, _ upstream.Request) (*upstream.Response, error) {
		return statusResponse(200, body), nil
	}}
}

// StatusDoer returns a FaultyDoer that answers every request with the given
// HTTP status and body. Use it to simulate a 5xx/429 (retryable) or a 404/401
// (terminal, non-failover) upstream.
func StatusDoer(status int, body string) *FaultyDoer {
	return &FaultyDoer{Handler: func(_ context.Context, _ upstream.Request) (*upstream.Response, error) {
		return statusResponse(status, body), nil
	}}
}

// TransportFailDoer returns a FaultyDoer whose every request fails with a
// transport-level error (simulating DNS failure, a refused dial, a dropped
// connection, or a TLS handshake error — all of which surface from
// upstream.Client.Do as a non-nil error with a nil response).
func TransportFailDoer(err error) *FaultyDoer {
	return &FaultyDoer{Handler: func(_ context.Context, _ upstream.Request) (*upstream.Response, error) {
		return nil, err
	}}
}

// FlakyDoer returns a FaultyDoer that fails its first failN requests with err
// (transport error) and then answers 200 with body. It is the primitive for
// "recovering upstream" scenarios driven past a circuit-breaker's open timeout.
func FlakyDoer(failN int, err error, body string) *FaultyDoer {
	var n int
	var mu sync.Mutex
	return &FaultyDoer{Handler: func(_ context.Context, _ upstream.Request) (*upstream.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if n < failN {
			n++
			return nil, err
		}
		return statusResponse(200, body), nil
	}}
}

// statusResponse builds a minimal upstream.Response with a readable,
// closeable body (the mirror pool drains and closes discarded responses).
func statusResponse(status int, body string) *upstream.Response {
	return &upstream.Response{
		Status:        status,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}
