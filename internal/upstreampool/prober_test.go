package upstreampool

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestActiveProbeRecoversOpenEndpoint(t *testing.T) {
	clock := newClock()
	healthy := false
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		if healthy {
			return resp(200, "ok"), nil
		}
		return resp(503, "down"), nil
	}}
	p, _ := New(Config{
		Backend:          "npm",
		Client:           doer,
		Now:              clock.now,
		FailureThreshold: 1,
		SuccessThreshold: 1,
		OpenTimeout:      30 * time.Second,
		Probe:            ProbeConfig{Enabled: true, Path: "/v2/"},
		Endpoints:        []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})

	// Trip open with live traffic.
	r, _ := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if r != nil {
		drainClose(r.Body)
	}
	if stateOf(p, "primary") != StateOpen.String() {
		t.Fatal("expected open")
	}

	// The upstream recovers. Once the cooldown elapses, an active probe (not live
	// traffic) drives the endpoint back to closed — no client request needed.
	healthy = true
	clock.advance(31 * time.Second)
	p.probeOnce(context.Background())
	if got := stateOf(p, "primary"); got != StateClosed.String() {
		t.Fatalf("state after recovering probe = %q, want closed", got)
	}
	// The probe issued a request to the configured health path.
	last := doer.requested()
	if got := last[len(last)-1]; got != "https://primary.test/v2/" {
		t.Errorf("probe URL = %q, want https://primary.test/v2/", got)
	}
}

func TestActiveProbeTripsFailingEndpoint(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(503, "down"), nil
	}}
	p, _ := New(Config{
		Backend:          "npm",
		Client:           doer,
		Now:              clock.now,
		FailureThreshold: 2,
		Probe:            ProbeConfig{Enabled: true},
		Endpoints:        []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})

	// Two failing probes (no live traffic at all) trip the breaker proactively.
	p.probeOnce(context.Background())
	if stateOf(p, "primary") != StateClosed.String() {
		t.Fatal("one probe should not yet trip with threshold 2")
	}
	p.probeOnce(context.Background())
	if got := stateOf(p, "primary"); got != StateOpen.String() {
		t.Fatalf("state after 2 failing probes = %q, want open", got)
	}
}

func TestStartProbingDisabledIsNoop(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) { return resp(200, "ok"), nil }}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})
	// Probe disabled: StartProbing must not panic and must not issue requests.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartProbing(ctx)
	if len(doer.requested()) != 0 {
		t.Error("disabled prober issued requests")
	}
}
