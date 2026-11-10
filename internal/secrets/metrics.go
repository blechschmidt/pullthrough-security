package secrets

import "sync"

// Metrics accumulates counters for secret resolution and background refresh.
// The proxy bridges these into the Prometheus registry as scrape-time callbacks
// (pullthrough_secrets_*), so this struct is the single source of truth.
//
// Every counter is keyed only by non-sensitive dimensions — the reference
// scheme ("env", "file", "vault") — never by a secret value or even a full
// reference path. No method here ever accepts or stores a resolved secret.
type Metrics struct {
	mu sync.Mutex

	resolveSuccess map[string]uint64 // by scheme
	resolveFailure map[string]uint64 // by scheme
	refreshSuccess uint64            // Vault lease/secret refreshes that succeeded
	refreshFailure uint64            // Vault lease/secret refreshes that failed
	rotations      uint64            // refreshes that observed a changed secret value
}

// NewMetrics returns an initialized, ready-to-use Metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		resolveSuccess: make(map[string]uint64),
		resolveFailure: make(map[string]uint64),
	}
}

func (m *Metrics) recordResolve(scheme string, ok bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.resolveSuccess[scheme]++
	} else {
		m.resolveFailure[scheme]++
	}
}

func (m *Metrics) recordRefresh(ok bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.refreshSuccess++
	} else {
		m.refreshFailure++
	}
}

func (m *Metrics) recordRotation() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotations++
}

// Snapshot is an immutable copy of the counters for export.
type Snapshot struct {
	ResolveSuccess map[string]uint64
	ResolveFailure map[string]uint64
	RefreshSuccess uint64
	RefreshFailure uint64
	Rotations      uint64
}

// Snapshot returns a deep copy of the current counters.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{ResolveSuccess: map[string]uint64{}, ResolveFailure: map[string]uint64{}}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := func(in map[string]uint64) map[string]uint64 {
		out := make(map[string]uint64, len(in))
		for k, v := range in {
			out[k] = v
		}
		return out
	}
	return Snapshot{
		ResolveSuccess: cp(m.resolveSuccess),
		ResolveFailure: cp(m.resolveFailure),
		RefreshSuccess: m.refreshSuccess,
		RefreshFailure: m.refreshFailure,
		Rotations:      m.rotations,
	}
}
