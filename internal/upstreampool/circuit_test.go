package upstreampool

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// recordingNotifier captures emitted events for assertions.
type recordingNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (n *recordingNotifier) Emit(_ context.Context, ev notify.Event) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, ev)
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.events)
}

func (n *recordingNotifier) last() notify.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.events[len(n.events)-1]
}

// stateOf returns the breaker state string for the named endpoint.
func stateOf(p *Pool, id string) string {
	for _, e := range p.Snapshot().Endpoints {
		if e.ID == id {
			return e.State
		}
	}
	return ""
}

func TestCircuitOpensAfterThreshold(t *testing.T) {
	clock := newClock()
	notifier := &recordingNotifier{}
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(503, "down"), nil
	}}
	p, _ := New(Config{
		Backend:          "npm",
		Client:           doer,
		Now:              clock.now,
		FailureThreshold: 3,
		OpenTimeout:      30 * time.Second,
		Notifier:         notifier,
		Endpoints:        []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})

	// Three failures trip the breaker. Each call returns the upstream 503.
	for i := 0; i < 3; i++ {
		r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
		if err != nil {
			t.Fatalf("call %d: unexpected err %v", i, err)
		}
		if r != nil {
			drainClose(r.Body)
		}
	}
	if got := stateOf(p, "primary"); got != StateOpen.String() {
		t.Fatalf("state after 3 failures = %q, want open", got)
	}
	if notifier.count() != 1 {
		t.Fatalf("circuit-open notifications = %d, want 1", notifier.count())
	}
	ev := notifier.last()
	if ev.Type != notify.EventUpstreamCircuitOpen || ev.Severity != notify.SeverityHigh {
		t.Errorf("event type/severity = %s/%s", ev.Type, ev.Severity)
	}
	if ev.Backend != "npm" || ev.Fields["mirror"] != "primary" {
		t.Errorf("event fields wrong: backend=%q mirror=%q", ev.Backend, ev.Fields["mirror"])
	}

	// While open (within the cooldown), the sole endpoint is skipped: no request
	// is attempted and the pool reports all endpoints unavailable.
	before := len(doer.requested())
	_, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	var unavail *AllUnavailableError
	if !asUnavailable(err, &unavail) {
		t.Fatalf("expected AllUnavailableError while open, got %v", err)
	}
	if after := len(doer.requested()); after != before {
		t.Errorf("open breaker still issued a request: before=%d after=%d", before, after)
	}
}

func TestHalfOpenRecovery(t *testing.T) {
	clock := newClock()
	notifier := &recordingNotifier{}
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
		FailureThreshold: 2,
		SuccessThreshold: 2,
		OpenTimeout:      30 * time.Second,
		Notifier:         notifier,
		Endpoints:        []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})

	// Trip it open.
	for i := 0; i < 2; i++ {
		r, _ := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
		if r != nil {
			drainClose(r.Body)
		}
	}
	if stateOf(p, "primary") != StateOpen.String() {
		t.Fatal("expected open")
	}

	// Before the cooldown elapses, the endpoint is still skipped.
	clock.advance(10 * time.Second)
	if _, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"}); err == nil {
		t.Fatal("expected unavailable before cooldown elapsed")
	}

	// After the cooldown the endpoint goes half-open and admits a trial. The
	// upstream is now healthy; one success is not enough (successThreshold=2).
	clock.advance(25 * time.Second)
	healthy = true
	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if err != nil {
		t.Fatalf("half-open trial: %v", err)
	}
	drainClose(r.Body)
	if got := stateOf(p, "primary"); got != StateHalfOpen.String() {
		t.Fatalf("state after 1 half-open success = %q, want half_open", got)
	}

	// A second consecutive success closes the breaker.
	r, err = p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if err != nil {
		t.Fatalf("second trial: %v", err)
	}
	drainClose(r.Body)
	if got := stateOf(p, "primary"); got != StateClosed.String() {
		t.Fatalf("state after 2 half-open successes = %q, want closed", got)
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	clock := newClock()
	notifier := &recordingNotifier{}
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(503, "down"), nil
	}}
	p, _ := New(Config{
		Backend:          "npm",
		Client:           doer,
		Now:              clock.now,
		FailureThreshold: 1,
		OpenTimeout:      30 * time.Second,
		Notifier:         notifier,
		Endpoints:        []EndpointConfig{{ID: "primary", URL: "https://primary.test"}},
	})

	r, _ := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if r != nil {
		drainClose(r.Body)
	}
	if stateOf(p, "primary") != StateOpen.String() {
		t.Fatal("expected open after first failure")
	}
	opensAfterTrip := notifier.count()

	// Cooldown elapses → half-open trial → still failing → re-open. The re-open
	// must emit another notification.
	clock.advance(31 * time.Second)
	r, _ = p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if r != nil {
		drainClose(r.Body)
	}
	if got := stateOf(p, "primary"); got != StateOpen.String() {
		t.Fatalf("state after failed half-open trial = %q, want open", got)
	}
	if notifier.count() <= opensAfterTrip {
		t.Errorf("expected another circuit-open notification on re-open")
	}
}

func TestDrainRemovesFromRotation(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})

	if err := p.SetDrained("primary", true); err != nil {
		t.Fatal(err)
	}
	r, err := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	if err != nil {
		t.Fatal(err)
	}
	drainClose(r.Body)
	got := doer.requested()
	// The drained primary is skipped; the mirror serves.
	if len(got) != 1 || hostOf(got[0]) != "https://mirror.test" {
		t.Fatalf("drained primary still used: %v", got)
	}

	// Undrain restores it to the front of rotation.
	if err := p.SetDrained("primary", false); err != nil {
		t.Fatal(err)
	}
	r, _ = p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	drainClose(r.Body)
	got = doer.requested()
	if hostOf(got[len(got)-1]) != "https://primary.test" {
		t.Fatalf("undrained primary not used: %v", got)
	}
}

func TestAdminCircuitOverrides(t *testing.T) {
	clock := newClock()
	doer := &fakeDoer{handler: func(r upstream.Request) (*upstream.Response, error) {
		return resp(200, "ok"), nil
	}}
	p, _ := New(Config{
		Backend: "npm", Client: doer, Now: clock.now, OpenTimeout: time.Hour,
		Endpoints: []EndpointConfig{
			{ID: "primary", URL: "https://primary.test"},
			{ID: "mirror", URL: "https://mirror.test"},
		},
	})

	// Force the primary open: traffic should fail over to the mirror.
	if err := p.OpenCircuit("primary"); err != nil {
		t.Fatal(err)
	}
	if stateOf(p, "primary") != StateOpen.String() {
		t.Fatal("OpenCircuit did not open the breaker")
	}
	r, _ := p.Do(context.Background(), upstream.Request{URL: "https://primary.test/x"})
	drainClose(r.Body)
	if hostOf(doer.requested()[0]) != "https://mirror.test" {
		t.Error("force-open primary still served traffic")
	}

	// Reset closes it again immediately.
	if err := p.ResetCircuit("primary"); err != nil {
		t.Fatal(err)
	}
	if stateOf(p, "primary") != StateClosed.String() {
		t.Fatalf("ResetCircuit did not close the breaker")
	}

	if err := p.OpenCircuit("nope"); err == nil {
		t.Error("expected error for unknown endpoint")
	}
}

// asUnavailable is a tiny errors.As helper kept local to avoid importing errors
// in every test.
func asUnavailable(err error, target **AllUnavailableError) bool {
	if err == nil {
		return false
	}
	u, ok := err.(*AllUnavailableError)
	if ok {
		*target = u
	}
	return ok
}
