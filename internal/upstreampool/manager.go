package upstreampool

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Manager owns the set of mirror pools, keyed by backend name. It is the surface
// the admin API and the metrics bridge talk to, and it fans the active prober
// start-up out to every pool. A nil *Manager is a valid no-op (no pooled
// backends), so callers need not nil-check before ranging its (empty) snapshot.
type Manager struct {
	mu    sync.RWMutex
	pools map[string]*Pool
	order []string
}

// NewManager returns an empty Manager.
func NewManager() *Manager {
	return &Manager{pools: make(map[string]*Pool)}
}

// Add registers a pool under its backend name. It returns an error on a
// duplicate backend so a misconfiguration surfaces at startup.
func (m *Manager) Add(p *Pool) error {
	if p == nil {
		return fmt.Errorf("upstreampool: nil pool")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.pools[p.backend]; dup {
		return fmt.Errorf("upstreampool: duplicate pool for backend %q", p.backend)
	}
	m.pools[p.backend] = p
	m.order = append(m.order, p.backend)
	sort.Strings(m.order)
	return nil
}

// Len reports the number of registered pools.
func (m *Manager) Len() int {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.pools)
}

// Pool returns the pool for a backend, if any.
func (m *Manager) Pool(backend string) (*Pool, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.pools[backend]
	return p, ok
}

// StartProbing starts the active prober on every pool that has it enabled.
func (m *Manager) StartProbing(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.RLock()
	pools := make([]*Pool, 0, len(m.pools))
	for _, p := range m.pools {
		pools = append(pools, p)
	}
	m.mu.RUnlock()
	for _, p := range pools {
		p.StartProbing(ctx)
	}
}

// Snapshots returns every pool's snapshot, ordered by backend name for stable
// output.
func (m *Manager) Snapshots() []Snapshot {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Snapshot, 0, len(m.order))
	for _, name := range m.order {
		if p, ok := m.pools[name]; ok {
			out = append(out, p.Snapshot())
		}
	}
	return out
}

// Snapshot returns one backend's snapshot.
func (m *Manager) Snapshot(backend string) (Snapshot, bool) {
	p, ok := m.Pool(backend)
	if !ok {
		return Snapshot{}, false
	}
	return p.Snapshot(), true
}

// SetDrained force-drains or undrains a mirror endpoint of a backend's pool.
func (m *Manager) SetDrained(backend, endpointID string, drained bool) error {
	p, ok := m.Pool(backend)
	if !ok {
		return fmt.Errorf("upstreampool: no pool for backend %q", backend)
	}
	return p.SetDrained(endpointID, drained)
}

// ResetCircuit forces a mirror endpoint's breaker closed (admin override).
func (m *Manager) ResetCircuit(backend, endpointID string) error {
	p, ok := m.Pool(backend)
	if !ok {
		return fmt.Errorf("upstreampool: no pool for backend %q", backend)
	}
	return p.ResetCircuit(endpointID)
}

// OpenCircuit trips a mirror endpoint's breaker open (admin override).
func (m *Manager) OpenCircuit(backend, endpointID string) error {
	p, ok := m.Pool(backend)
	if !ok {
		return fmt.Errorf("upstreampool: no pool for backend %q", backend)
	}
	return p.OpenCircuit(endpointID)
}
