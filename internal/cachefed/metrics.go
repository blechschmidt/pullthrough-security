package cachefed

import "sync/atomic"

// Metrics holds the cache-federation subsystem's cumulative counters, shared by
// the read-through client path (a local miss served — or not — from a sibling
// peer) and the server path (answering a sibling's HEAD/GET). It is safe for
// concurrent use; a nil *Metrics is a valid no-op so call sites need no guards.
//
// The gateway constructs one instance and the observability layer binds
// scrape-time callbacks over its Snapshot, keeping these atomics the single
// source of truth for the pullthrough_cachefed_* series. Per-peer latency and
// circuit state are reported separately from the live peer registry (see
// Federation.PeerStatuses), mirroring the upstream-pool metrics split.
type Metrics struct {
	// Client (read-through) path.
	hits            atomic.Uint64 // local miss satisfied by a sibling peer
	misses          atomic.Uint64 // local miss that no healthy peer could satisfy
	peerErrors      atomic.Uint64 // peer requests that failed (network / non-2xx / timeout)
	verifyFailures  atomic.Uint64 // peer responses rejected because the bytes failed digest re-verification
	skippedNoDigest atomic.Uint64 // misses not offered to peers because no expected digest was known

	// Server path (answering siblings).
	served       atomic.Uint64 // sibling requests answered from the local cache
	servedMisses atomic.Uint64 // sibling requests for a key we did not hold
	servedRefuse atomic.Uint64 // sibling requests for an entry a serve guard refused
	unauthorized atomic.Uint64 // sibling requests rejected for a bad/missing auth token
}

// NewMetrics returns a fresh counter set.
func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) recordHit() {
	if m != nil {
		m.hits.Add(1)
	}
}

func (m *Metrics) recordMiss() {
	if m != nil {
		m.misses.Add(1)
	}
}

func (m *Metrics) recordPeerError() {
	if m != nil {
		m.peerErrors.Add(1)
	}
}

func (m *Metrics) recordVerifyFailure() {
	if m != nil {
		m.verifyFailures.Add(1)
	}
}

func (m *Metrics) recordSkippedNoDigest() {
	if m != nil {
		m.skippedNoDigest.Add(1)
	}
}

func (m *Metrics) recordServed() {
	if m != nil {
		m.served.Add(1)
	}
}

func (m *Metrics) recordServedMiss() {
	if m != nil {
		m.servedMisses.Add(1)
	}
}

func (m *Metrics) recordServedRefused() {
	if m != nil {
		m.servedRefuse.Add(1)
	}
}

func (m *Metrics) recordUnauthorized() {
	if m != nil {
		m.unauthorized.Add(1)
	}
}

// Snapshot is a point-in-time copy of the counters for the metrics layer.
type Snapshot struct {
	Hits            uint64
	Misses          uint64
	PeerErrors      uint64
	VerifyFailures  uint64
	SkippedNoDigest uint64
	Served          uint64
	ServedMisses    uint64
	// ServedRefused counts sibling requests for an entry this proxy holds but a
	// serve guard refused to hand out (an artifact it has a verdict against).
	ServedRefused uint64
	Unauthorized  uint64
}

// Snapshot reads the current counter values. A nil *Metrics reports zeros.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	return Snapshot{
		Hits:            m.hits.Load(),
		Misses:          m.misses.Load(),
		PeerErrors:      m.peerErrors.Load(),
		VerifyFailures:  m.verifyFailures.Load(),
		SkippedNoDigest: m.skippedNoDigest.Load(),
		Served:          m.served.Load(),
		ServedMisses:    m.servedMisses.Load(),
		ServedRefused:   m.servedRefuse.Load(),
		Unauthorized:    m.unauthorized.Load(),
	}
}
