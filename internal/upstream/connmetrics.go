package upstream

import (
	"context"
	"net"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"
)

// ConnMetrics accumulates outbound connection-pool lifecycle statistics across
// every Client that shares it. It is wired once per process — the client pool
// builds a single ConnMetrics and hands the same pointer to every
// upstream.Client it constructs — so the figures aggregate the whole pull/fetch
// path regardless of how many distinct per-TLS-policy clients (and their
// separate transports) exist underneath. The zero value is ready to use, and
// every method is safe for concurrent use.
//
// The counters answer the questions an operator tuning the transport for
// high-concurrency load actually asks:
//
//   - Dials / DialErrors / dial latency: how often a brand-new TCP+TLS
//     connection had to be established (the expensive path) and how long that
//     took. This is the raw connection-churn signal — a healthy, well-reusing
//     pool dials rarely relative to the number of requests it serves.
//   - Acquired / Reused: of every connection handed to a request, how many were
//     taken from the keep-alive pool rather than freshly dialed. Reused/Acquired
//     is the connection-reuse rate — the headline efficiency number the
//     connection-reuse benchmark and its perfguard baseline gate on.
//   - Open / Idle: point-in-time gauges of the pool's footprint (total live
//     connections, and of those how many are currently parked idle).
//   - Closed: connections torn down (idle-timeout eviction, server close, or
//     error) — the other half of the churn picture.
//
// Open and Closed are exact: every connection this process dials is wrapped so
// its Close is observed. Idle is a best-effort estimate derived from the
// transport's idle-pool put/get notifications; the net/http transport does not
// notify on an idle connection that it closes on IdleConnTimeout, so the gauge
// is clamped to be non-negative and should be read as "approximately how many
// connections are parked", not an exact count.
type ConnMetrics struct {
	dials      atomic.Int64
	dialErrors atomic.Int64
	dialNanos  atomic.Int64 // cumulative latency of successfully completed dials
	closed     atomic.Int64
	acquired   atomic.Int64
	reused     atomic.Int64
	open       atomic.Int64
	idle       atomic.Int64
}

// ConnStats is a point-in-time snapshot of a ConnMetrics. Counters are
// cumulative; Open and Idle are gauges.
type ConnStats struct {
	Dials       int64
	DialErrors  int64
	DialSeconds float64 // cumulative latency of successful dials
	DialCount   int64   // successful dials (== Dials - DialErrors); the denominator for average dial latency
	Closed      int64
	Acquired    int64
	Reused      int64
	Open        int64
	Idle        int64
}

// ReuseRatio is Reused/Acquired in [0,1] — the fraction of connection
// acquisitions satisfied from the keep-alive pool. It is 0 when no connection
// was acquired.
func (s ConnStats) ReuseRatio() float64 {
	if s.Acquired <= 0 {
		return 0
	}
	return float64(s.Reused) / float64(s.Acquired)
}

// Snapshot returns the current statistics.
func (m *ConnMetrics) Snapshot() ConnStats {
	if m == nil {
		return ConnStats{}
	}
	dials := m.dials.Load()
	dialErrs := m.dialErrors.Load()
	open := m.open.Load()
	if open < 0 {
		open = 0
	}
	idle := m.idle.Load()
	if idle < 0 {
		idle = 0
	}
	return ConnStats{
		Dials:       dials,
		DialErrors:  dialErrs,
		DialSeconds: float64(m.dialNanos.Load()) / float64(time.Second),
		DialCount:   dials - dialErrs,
		Closed:      m.closed.Load(),
		Acquired:    m.acquired.Load(),
		Reused:      m.reused.Load(),
		Open:        open,
		Idle:        idle,
	}
}

// observeDial records the outcome and latency of one dial attempt. On success
// the open-connection gauge is incremented; the matching decrement happens when
// the connection's Close is observed (see trackedConn).
func (m *ConnMetrics) observeDial(d time.Duration, err error) {
	m.dials.Add(1)
	if err != nil {
		m.dialErrors.Add(1)
		return
	}
	if d > 0 {
		m.dialNanos.Add(int64(d))
	}
	m.open.Add(1)
}

// onClose records that a dialed connection was torn down.
func (m *ConnMetrics) onClose() {
	m.closed.Add(1)
	m.open.Add(-1)
}

// onGotConn records a connection acquisition for a request.
func (m *ConnMetrics) onGotConn(info httptrace.GotConnInfo) {
	m.acquired.Add(1)
	if info.Reused {
		m.reused.Add(1)
	}
	if info.WasIdle {
		m.idle.Add(-1)
	}
}

// onPutIdle records a connection being returned to the idle pool.
func (m *ConnMetrics) onPutIdle(err error) {
	if err == nil {
		m.idle.Add(1)
	}
}

// trace is the per-request httptrace hook set that feeds the acquisition and
// idle-pool counters. It is stateless (it only closes over m), so one instance
// is built per Client and shared across all of that client's requests.
func (m *ConnMetrics) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn:     m.onGotConn,
		PutIdleConn: m.onPutIdle,
	}
}

// dialFunc is the signature of net.Dialer.DialContext.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// instrumentDial wraps a DialContext so every dial is timed and counted and the
// returned connection's Close is observed. It preserves the base dialer's
// behavior exactly, including any ControlContext hook (the egress/SSRF guard's
// post-DNS IP re-check), which runs inside base before it returns.
func (m *ConnMetrics) instrumentDial(base dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		conn, err := base(ctx, network, addr)
		m.observeDial(time.Since(start), err)
		if err != nil {
			return nil, err
		}
		return &trackedConn{Conn: conn, metrics: m}, nil
	}
}

// trackedConn decrements the open-connection gauge exactly once, when the
// underlying connection is first closed. The transport may call Close more than
// once (or concurrently); sync.Once makes the accounting idempotent.
type trackedConn struct {
	net.Conn
	metrics *ConnMetrics
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(c.metrics.onClose)
	return c.Conn.Close()
}
