package upstreampool

import (
	"fmt"
	"time"
)

// EndpointStatus is the observable state of one mirror endpoint, surfaced to the
// admin API and the metrics bridge.
type EndpointStatus struct {
	ID                   string    `json:"id"`
	URL                  string    `json:"url"`
	Primary              bool      `json:"primary"`
	State                string    `json:"state"`
	Drained              bool      `json:"drained"`
	ConsecutiveFailures  int       `json:"consecutiveFailures"`
	ConsecutiveSuccesses int       `json:"consecutiveSuccesses"`
	ProbesInFlight       int       `json:"probesInFlight"`
	TotalSuccess         int64     `json:"totalSuccess"`
	TotalFailure         int64     `json:"totalFailure"`
	TotalProbes          int64     `json:"totalProbes"`
	TripCount            int64     `json:"tripCount"`
	LatencySum           float64   `json:"latencySumSeconds"`
	LatencyCount         int64     `json:"latencyCount"`
	LastError            string    `json:"lastError,omitempty"`
	LastErrorAt          time.Time `json:"lastErrorAt,omitempty"`
	OpenedAt             time.Time `json:"openedAt,omitempty"`
	LastChange           time.Time `json:"lastChange,omitempty"`
}

// AvgLatencySeconds returns the mean observed request latency, or 0 when no
// requests have been recorded.
func (s EndpointStatus) AvgLatencySeconds() float64 {
	if s.LatencyCount == 0 {
		return 0
	}
	return s.LatencySum / float64(s.LatencyCount)
}

// StateValue maps a state string to the numeric gauge value exposed in metrics:
// 0 closed, 1 half-open, 2 open.
func (s EndpointStatus) StateValue() float64 {
	switch s.State {
	case StateOpen.String():
		return 2
	case StateHalfOpen.String():
		return 1
	default:
		return 0
	}
}

// Snapshot is a pool-level view: the backend name, its failover count, and the
// status of every endpoint in priority order.
type Snapshot struct {
	Backend       string           `json:"backend"`
	Ecosystem     string           `json:"ecosystem,omitempty"`
	FailoverTotal int64            `json:"failoverTotal"`
	Healthy       int              `json:"healthy"`
	Endpoints     []EndpointStatus `json:"endpoints"`
}

// Snapshot returns the pool's current observable state.
func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	failover := p.failoverTotal
	p.mu.Unlock()

	eps := make([]EndpointStatus, 0, len(p.endpoints))
	healthy := 0
	for _, ep := range p.endpoints {
		st := ep.snapshot()
		if !st.Drained && st.State != StateOpen.String() {
			healthy++
		}
		eps = append(eps, st)
	}
	return Snapshot{
		Backend:       p.backend,
		Ecosystem:     p.ecosystem,
		FailoverTotal: failover,
		Healthy:       healthy,
		Endpoints:     eps,
	}
}

// findEndpoint locates an endpoint by id.
func (p *Pool) findEndpoint(id string) (*endpoint, error) {
	for _, ep := range p.endpoints {
		if ep.id == id {
			return ep, nil
		}
	}
	return nil, fmt.Errorf("upstreampool %q: no endpoint with id %q", p.backend, id)
}

// SetDrained force-drains (or undrains) an endpoint so an operator can pull a
// mirror out of rotation for maintenance without changing its circuit state.
func (p *Pool) SetDrained(endpointID string, drained bool) error {
	ep, err := p.findEndpoint(endpointID)
	if err != nil {
		return err
	}
	ep.setDrained(drained, p.now())
	if p.logger != nil {
		p.logger.Info("upstream mirror drain state changed",
			"backend", p.backend, "mirror", endpointID, "drained", drained)
	}
	return nil
}

// ResetCircuit forces an endpoint's breaker closed, clearing accumulated
// failures so it is immediately eligible again (admin override).
func (p *Pool) ResetCircuit(endpointID string) error {
	ep, err := p.findEndpoint(endpointID)
	if err != nil {
		return err
	}
	ep.reset(p.now())
	if p.logger != nil {
		p.logger.Info("upstream mirror circuit reset", "backend", p.backend, "mirror", endpointID)
	}
	return nil
}

// OpenCircuit trips an endpoint's breaker open immediately (admin override),
// taking it out of rotation for the configured cooldown.
func (p *Pool) OpenCircuit(endpointID string) error {
	ep, err := p.findEndpoint(endpointID)
	if err != nil {
		return err
	}
	ep.forceOpen(p.now())
	if p.logger != nil {
		p.logger.Info("upstream mirror circuit force-opened", "backend", p.backend, "mirror", endpointID)
	}
	return nil
}
