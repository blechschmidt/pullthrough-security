// Package ratelimit implements enforceable per-tenant and global rate limiting,
// byte quotas, and upstream-concurrency caps for the pull-through proxy.
//
// The package is deliberately decoupled from the proxy and auth layers: it
// operates on an opaque tenant string (resolved by the caller from the
// authenticated principal's team) and exposes a single admission entry point,
// Limiter.Admit, plus a runtime-tunable policy surface for the admin API and a
// metrics snapshot for Prometheus.
//
// Enforcement combines three independent dimensions, each disabled when its
// policy field is zero:
//
//   - Request rate: a token bucket (sustained RPS with a burst capacity).
//     Enforced per replica (in-memory); under horizontal scaling each replica
//     admits up to its configured rate.
//   - Upstream concurrency: a counting semaphore bounding simultaneous in-flight
//     pulls per tenant. Also per replica.
//   - Byte quota: a windowed cumulative byte cap (e.g. a monthly egress budget).
//     Coordinated across replicas through a pluggable Store, so a multi-replica
//     deployment shares one budget rather than N independent ones.
//
// Both a per-tenant policy and a process-wide global policy are applied to every
// request; a request must satisfy both to be admitted.
package ratelimit

import (
	"fmt"
	"time"
)

// GlobalKey is the reserved tenant key under which the process-wide (global)
// policy and its live state are tracked. It cannot be used as a real tenant
// name; SetPolicy rejects it.
const GlobalKey = "__global__"

// defaultByteWindow is the byte-quota window applied when a policy sets a byte
// quota but leaves Window zero (a calendar-month-ish egress budget).
const defaultByteWindow = 30 * 24 * time.Hour

// Policy is the limit set applied to a tenant (or globally). A zero value on any
// dimension disables that dimension, so the zero Policy imposes no limits at
// all.
type Policy struct {
	// RPS is the sustained request rate in requests per second (0 = unlimited).
	RPS float64
	// Burst is the token-bucket capacity: the maximum number of requests that may
	// be admitted in an instantaneous burst before the sustained rate applies.
	// When zero and RPS > 0 it defaults to ceil(RPS) (at least 1).
	Burst int
	// MaxConcurrent caps simultaneous in-flight pulls for the tenant (0 =
	// unlimited).
	MaxConcurrent int
	// ByteQuota caps bytes served within Window (0 = unlimited).
	ByteQuota int64
	// Window is the rolling period over which ByteQuota accumulates before it
	// resets. Zero with ByteQuota > 0 defaults to defaultByteWindow.
	Window time.Duration
}

// unlimited reports whether the policy imposes no limits on any dimension.
func (p Policy) unlimited() bool {
	return p.RPS <= 0 && p.MaxConcurrent <= 0 && p.ByteQuota <= 0
}

// effectiveBurst returns the burst capacity to use, defaulting from RPS.
func (p Policy) effectiveBurst() float64 {
	if p.Burst > 0 {
		return float64(p.Burst)
	}
	if p.RPS > 0 {
		// Default the burst to one second's worth of tokens, at least one.
		b := p.RPS
		if b < 1 {
			b = 1
		}
		return b
	}
	return 0
}

// effectiveWindow returns the byte-quota window, defaulting when unset.
func (p Policy) effectiveWindow() time.Duration {
	if p.Window > 0 {
		return p.Window
	}
	return defaultByteWindow
}

// validate reports a configuration error for nonsensical policy values.
func (p Policy) validate() error {
	if p.RPS < 0 {
		return fmt.Errorf("ratelimit: rps must not be negative")
	}
	if p.Burst < 0 {
		return fmt.Errorf("ratelimit: burst must not be negative")
	}
	if p.MaxConcurrent < 0 {
		return fmt.Errorf("ratelimit: maxConcurrent must not be negative")
	}
	if p.ByteQuota < 0 {
		return fmt.Errorf("ratelimit: byteQuota must not be negative")
	}
	if p.Window < 0 {
		return fmt.Errorf("ratelimit: window must not be negative")
	}
	return nil
}

// LimitType identifies which dimension produced a throttling decision; it is the
// label value used for metrics and the machine-readable reason in responses.
type LimitType string

const (
	// LimitRPS denotes a request-rate (token-bucket) rejection.
	LimitRPS LimitType = "rps"
	// LimitConcurrency denotes an upstream-concurrency rejection.
	LimitConcurrency LimitType = "concurrency"
	// LimitBytes denotes a byte-quota-exhausted rejection.
	LimitBytes LimitType = "bytes"
)

// Decision is the outcome of an admission check. When Allowed is false, Type
// identifies the violated dimension, Reason is a human-readable explanation
// (safe to return to clients and log), and RetryAfter (when non-zero) is a hint
// for the client's Retry-After header.
type Decision struct {
	Allowed    bool
	Type       LimitType
	Reason     string
	RetryAfter time.Duration
}

// Reservation represents the resources held by an admitted request: any acquired
// concurrency slots (released by Release) and the byte-quota accounting hook
// (RecordBytes). The zero Reservation is a valid no-op, returned for an
// unlimited tenant or a nil limiter, so call sites never need a nil check.
type Reservation struct {
	release     func()
	recordBytes func(n int64)
}

// Release returns any concurrency slots held by the reservation. It is safe to
// call exactly once (typically via defer); a second call is a no-op.
func (r *Reservation) Release() {
	if r == nil || r.release == nil {
		return
	}
	rel := r.release
	r.release = nil
	rel()
}

// RecordBytes attributes n served bytes to the reservation's tenant (and the
// global budget). It is a no-op when no byte quota applies.
func (r *Reservation) RecordBytes(n int64) {
	if r == nil || r.recordBytes == nil || n <= 0 {
		return
	}
	r.recordBytes(n)
}
