package intercept

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Reasons a connection or request is refused, as reported in Metrics.
const (
	refusedUnmatchedHost = "unmatched_host" // the host is not configured for interception
	refusedNoServerName  = "no_server_name" // a NAT TLS connection without SNI
	refusedNotTLS        = "not_tls"        // a NAT TLS connection that did not start with a ClientHello
	refusedHandshake     = "handshake"      // the TLS handshake with the client failed
	refusedPlainHTTP     = "plain_http"     // an absolute-form http:// request while AllowPlainHTTP is off
)

// Metrics counts what the interception listeners do. The zero value is ready
// to use and safe for concurrent use.
type Metrics struct {
	mu          sync.Mutex
	connections map[Mode]*atomic.Uint64
	intercepts  map[Mode]*atomic.Uint64
	requests    map[Mode]*atomic.Uint64
	passed      map[Mode]*atomic.Uint64
	noRoute     map[Mode]*atomic.Uint64
	refusals    map[refusalKey]*atomic.Uint64
}

type refusalKey struct {
	mode   Mode
	reason string
}

// MetricsSnapshot is a point-in-time copy of the counters.
type MetricsSnapshot struct {
	// Connections counts accepted client connections (and absolute-form
	// requests) per mode.
	Connections map[Mode]uint64
	// Intercepted counts connections whose TLS the proxy terminated per mode.
	Intercepted map[Mode]uint64
	// Requests counts requests dispatched into the pipeline per mode.
	Requests map[Mode]uint64
	// Passthrough counts connections passed on undecrypted per mode.
	Passthrough map[Mode]uint64
	// Unrouted counts requests for an intercepted host's path no rule covers.
	Unrouted map[Mode]uint64
	// Refused counts refused connections per mode and reason.
	Refused []Refusal
}

// Refusal is one refused-connection counter.
type Refusal struct {
	Mode   Mode
	Reason string
	Count  uint64
}

func (m *Metrics) counter(table *map[Mode]*atomic.Uint64, mode Mode) *atomic.Uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if *table == nil {
		*table = map[Mode]*atomic.Uint64{}
	}
	c := (*table)[mode]
	if c == nil {
		c = new(atomic.Uint64)
		(*table)[mode] = c
	}
	return c
}

func (m *Metrics) connection(mode Mode)  { m.counter(&m.connections, mode).Add(1) }
func (m *Metrics) intercepted(mode Mode) { m.counter(&m.intercepts, mode).Add(1) }
func (m *Metrics) request(mode Mode)     { m.counter(&m.requests, mode).Add(1) }
func (m *Metrics) passthrough(mode Mode) { m.counter(&m.passed, mode).Add(1) }
func (m *Metrics) unrouted(mode Mode)    { m.counter(&m.noRoute, mode).Add(1) }

func (m *Metrics) refused(mode Mode, reason string) {
	m.mu.Lock()
	if m.refusals == nil {
		m.refusals = map[refusalKey]*atomic.Uint64{}
	}
	key := refusalKey{mode, reason}
	c := m.refusals[key]
	if c == nil {
		c = new(atomic.Uint64)
		m.refusals[key] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// Snapshot returns the current counter values.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	copyTable := func(t map[Mode]*atomic.Uint64) map[Mode]uint64 {
		out := make(map[Mode]uint64, len(t))
		for k, v := range t {
			out[k] = v.Load()
		}
		return out
	}
	s := MetricsSnapshot{
		Connections: copyTable(m.connections),
		Intercepted: copyTable(m.intercepts),
		Requests:    copyTable(m.requests),
		Passthrough: copyTable(m.passed),
		Unrouted:    copyTable(m.noRoute),
	}
	for k, v := range m.refusals {
		s.Refused = append(s.Refused, Refusal{Mode: k.mode, Reason: k.reason, Count: v.Load()})
	}
	sort.Slice(s.Refused, func(i, j int) bool {
		if s.Refused[i].Mode != s.Refused[j].Mode {
			return s.Refused[i].Mode < s.Refused[j].Mode
		}
		return s.Refused[i].Reason < s.Refused[j].Reason
	})
	return s
}

// Stats returns the proxy's counters.
func (p *Proxy) Stats() MetricsSnapshot { return p.metrics.Snapshot() }
