package notify

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSink is a programmable in-memory Sink for deterministic dispatcher tests.
// It records delivered events and can be configured to fail a number of times
// (with a retryable or permanent error) before succeeding.
type fakeSink struct {
	name string
	kind string

	mu       sync.Mutex
	received []Event

	// failFirst causes the first failFirst attempts to return an error.
	failFirst   atomic.Int64
	retryable   bool
	alwaysFail  bool
	attempts    atomic.Int64
	deliveredCh chan struct{}
}

func newFakeSink(name string) *fakeSink {
	return &fakeSink{name: name, kind: "webhook", deliveredCh: make(chan struct{}, 1024)}
}

func (f *fakeSink) Name() string { return f.name }
func (f *fakeSink) Kind() string { return f.kind }

func (f *fakeSink) Deliver(_ context.Context, ev Event) error {
	f.attempts.Add(1)
	if f.alwaysFail {
		return &DeliveryError{Sink: f.name, Retryable: f.retryable, Status: 500}
	}
	if f.failFirst.Load() > 0 {
		f.failFirst.Add(-1)
		return &DeliveryError{Sink: f.name, Retryable: f.retryable, Status: 503}
	}
	f.mu.Lock()
	f.received = append(f.received, ev)
	f.mu.Unlock()
	select {
	case f.deliveredCh <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.received)
}

func (f *fakeSink) last() (Event, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.received) == 0 {
		return Event{}, false
	}
	return f.received[len(f.received)-1], true
}

// waitForDeliveries blocks until the sink has recorded at least n successful
// deliveries or the deadline elapses.
func waitForDeliveries(t *testing.T, f *fakeSink, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for f.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d deliveries to %q (got %d)", n, f.name, f.count())
		}
		select {
		case <-f.deliveredCh:
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// fastClock returns a fixed time so event timestamps are deterministic.
func fixedNow() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func TestEmitRoutesByEventType(t *testing.T) {
	vulnSink := newFakeSink("vuln-sink")
	policySink := newFakeSink("policy-sink")

	n := New(Options{
		Now:     fixedNow,
		Workers: 2,
		Routes: []RouteSpec{
			{Sinks: []Sink{vulnSink}, EventTypes: []EventType{EventVulnerability, EventQuarantine}},
			{Sinks: []Sink{policySink}, EventTypes: []EventType{EventPolicyBlock}},
		},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "CVE-1", "block", "bad"))
	n.Emit(context.Background(), PolicyBlockEvent("pip", "b", "y@2", "denylist", "nope"))

	waitForDeliveries(t, vulnSink, 1, time.Second)
	waitForDeliveries(t, policySink, 1, time.Second)

	if vulnSink.count() != 1 {
		t.Errorf("vuln sink got %d, want 1", vulnSink.count())
	}
	if policySink.count() != 1 {
		t.Errorf("policy sink got %d, want 1", policySink.count())
	}
	// The policy event must not reach the vuln-only sink.
	if ev, _ := vulnSink.last(); ev.Type != EventVulnerability {
		t.Errorf("vuln sink received wrong type %q", ev.Type)
	}
}

func TestEmitSeverityFilteringGlobalFloor(t *testing.T) {
	sink := newFakeSink("s")
	n := New(Options{
		Now:         fixedNow,
		MinSeverity: SeverityHigh,
		Routes:      []RouteSpec{{Sinks: []Sink{sink}}},
	})
	defer n.Close()

	// Below the floor: dropped before routing.
	n.Emit(context.Background(), VulnerabilityEvent(SeverityLow, "npm", "b", "x@1", "", "warn", "low"))
	n.Emit(context.Background(), VulnerabilityEvent(SeverityMedium, "npm", "b", "x@1", "", "warn", "med"))
	// At/above the floor: delivered.
	n.Emit(context.Background(), VulnerabilityEvent(SeverityCritical, "npm", "b", "x@1", "", "block", "crit"))

	waitForDeliveries(t, sink, 1, time.Second)
	// Give any erroneously-routed low/medium events a chance to (not) arrive.
	time.Sleep(50 * time.Millisecond)
	if sink.count() != 1 {
		t.Errorf("sink got %d deliveries, want exactly 1 (only the critical)", sink.count())
	}
	if ev, _ := sink.last(); ev.Severity != SeverityCritical {
		t.Errorf("delivered severity = %q, want critical", ev.Severity)
	}
}

// TestTapSeesAllEventsBelowFloor verifies that an in-process tap (the SecOps
// dashboard seam) observes every prepared event regardless of the global
// severity floor or sink routing — even when no sinks would deliver it.
func TestTapSeesAllEventsBelowFloor(t *testing.T) {
	n := New(Options{
		Now:         fixedNow,
		MinSeverity: SeverityHigh, // sinks only see high+; taps see everything
	})
	defer n.Close()

	var mu sync.Mutex
	var seen []Severity
	n.Tap(func(ev Event) {
		mu.Lock()
		seen = append(seen, ev.Severity)
		mu.Unlock()
	})

	n.Emit(context.Background(), VulnerabilityEvent(SeverityLow, "npm", "b", "x@1", "", "warn", "low"))
	n.Emit(context.Background(), VulnerabilityEvent(SeverityCritical, "npm", "b", "x@1", "", "block", "crit"))

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("tap saw %d events, want 2 (taps bypass the severity floor): %v", len(seen), seen)
	}
}

func TestEmitPerRouteSeverityFloor(t *testing.T) {
	high := newFakeSink("high-only")
	all := newFakeSink("all")
	n := New(Options{
		Now: fixedNow,
		Routes: []RouteSpec{
			{Sinks: []Sink{high}, MinSeverity: SeverityHigh},
			{Sinks: []Sink{all}, MinSeverity: SeverityInfo},
		},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityMedium, "npm", "b", "x@1", "", "warn", "med"))
	waitForDeliveries(t, all, 1, time.Second)
	time.Sleep(50 * time.Millisecond)

	if all.count() != 1 {
		t.Errorf("all sink got %d, want 1", all.count())
	}
	if high.count() != 0 {
		t.Errorf("high-only sink got %d, want 0 (medium below floor)", high.count())
	}
}

func TestEmitDeduplicatesAcrossRoutes(t *testing.T) {
	sink := newFakeSink("s")
	// Two routes both target the same sink and both match the event; the sink must
	// receive the event exactly once.
	n := New(Options{
		Now: fixedNow,
		Routes: []RouteSpec{
			{Sinks: []Sink{sink}, EventTypes: []EventType{EventVulnerability}},
			{Sinks: []Sink{sink}, EventTypes: []EventType{EventVulnerability, EventQuarantine}},
		},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "", "block", "bad"))
	waitForDeliveries(t, sink, 1, time.Second)
	time.Sleep(50 * time.Millisecond)
	if sink.count() != 1 {
		t.Errorf("sink got %d deliveries, want exactly 1 (deduplicated)", sink.count())
	}
}

func TestDeliveryRetriesThenSucceeds(t *testing.T) {
	sink := newFakeSink("s")
	sink.failFirst.Store(2) // fail twice (retryable), succeed on the third
	sink.retryable = true

	n := New(Options{
		Now:        fixedNow,
		Workers:    1,
		MaxRetries: 5,
		BaseDelay:  time.Millisecond, // keep the test fast
		MaxDelay:   5 * time.Millisecond,
		Routes:     []RouteSpec{{Sinks: []Sink{sink}}},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "", "block", "bad"))
	waitForDeliveries(t, sink, 1, 2*time.Second)

	if got := sink.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (2 failures + 1 success)", got)
	}
	snap := n.Metrics()
	m := snap.PerSink["s"]
	if m.Sent != 1 {
		t.Errorf("Sent = %d, want 1", m.Sent)
	}
	if m.Retries != 2 {
		t.Errorf("Retries = %d, want 2", m.Retries)
	}
	if m.Failed != 0 {
		t.Errorf("Failed = %d, want 0", m.Failed)
	}
}

func TestDeliveryGivesUpAfterMaxRetries(t *testing.T) {
	sink := newFakeSink("s")
	sink.alwaysFail = true
	sink.retryable = true

	n := New(Options{
		Now:        fixedNow,
		Workers:    1,
		MaxRetries: 2,
		BaseDelay:  time.Millisecond,
		MaxDelay:   3 * time.Millisecond,
		Routes:     []RouteSpec{{Sinks: []Sink{sink}}},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "", "block", "bad"))

	// Wait until the failure is recorded.
	deadline := time.Now().Add(2 * time.Second)
	for n.Metrics().PerSink["s"].Failed == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a failed delivery")
		}
		time.Sleep(2 * time.Millisecond)
	}
	m := n.Metrics().PerSink["s"]
	if m.Failed != 1 {
		t.Errorf("Failed = %d, want 1", m.Failed)
	}
	// 1 initial + 2 retries = 3 attempts.
	if got := sink.attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
	if m.Retries != 2 {
		t.Errorf("Retries = %d, want 2", m.Retries)
	}
}

func TestPermanentErrorNotRetried(t *testing.T) {
	sink := newFakeSink("s")
	sink.alwaysFail = true
	sink.retryable = false // a 4xx-style permanent failure

	n := New(Options{
		Now:        fixedNow,
		Workers:    1,
		MaxRetries: 5,
		BaseDelay:  time.Millisecond,
		Routes:     []RouteSpec{{Sinks: []Sink{sink}}},
	})
	defer n.Close()

	n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "", "block", "bad"))
	deadline := time.Now().Add(time.Second)
	for n.Metrics().PerSink["s"].Failed == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for failure")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := sink.attempts.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1 (no retry on permanent error)", got)
	}
	if r := n.Metrics().PerSink["s"].Retries; r != 0 {
		t.Errorf("Retries = %d, want 0", r)
	}
}

func TestEmitNeverBlocksWhenQueueFull(t *testing.T) {
	// A sink that blocks forever, a single worker, and a tiny queue: once the
	// worker is stuck and the queue is full, further Emits must drop, not block.
	release := make(chan struct{})
	blocking := &blockingSink{name: "blocked", release: release}

	n := New(Options{
		Now:       fixedNow,
		Workers:   1,
		QueueSize: 1,
		Routes:    []RouteSpec{{Sinks: []Sink{blocking}}},
	})
	defer func() {
		close(release)
		n.Close()
	}()

	// First Emit is picked up by the worker (which blocks). Second fills the queue.
	// Subsequent Emits must be dropped without blocking.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			n.Emit(context.Background(), VulnerabilityEvent(SeverityHigh, "npm", "b", "x@1", "", "block", "bad"))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked when the delivery queue was full")
	}

	// Some notifications must have been dropped and counted.
	deadline := time.Now().Add(time.Second)
	for n.Metrics().PerSink["blocked"].Dropped == 0 {
		if time.Now().After(deadline) {
			t.Fatal("expected at least one dropped notification")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// blockingSink blocks in Deliver until release is closed.
type blockingSink struct {
	name    string
	release chan struct{}
}

func (b *blockingSink) Name() string { return b.name }
func (b *blockingSink) Kind() string { return "webhook" }
func (b *blockingSink) Deliver(ctx context.Context, _ Event) error {
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestEmitRedactsSensitiveFields(t *testing.T) {
	sink := newFakeSink("s")
	n := New(Options{
		Now:      fixedNow,
		Redactor: NewRedactor([]string{"customsecret"}),
		Routes:   []RouteSpec{{Sinks: []Sink{sink}}},
	})
	defer n.Close()

	ev := PolicyBlockEvent("npm", "b", "x@1", "denylist", "blocked").
		WithField("authorization", "Bearer xyz").
		WithField("customsecret", "p@ss").
		WithField("package", "x")
	n.Emit(context.Background(), ev)
	waitForDeliveries(t, sink, 1, time.Second)

	got, _ := sink.last()
	if got.Fields["authorization"] != redactedPlaceholder {
		t.Errorf("authorization not redacted: %q", got.Fields["authorization"])
	}
	if got.Fields["customsecret"] != redactedPlaceholder {
		t.Errorf("custom sensitive field not redacted: %q", got.Fields["customsecret"])
	}
	if got.Fields["package"] != "x" {
		t.Errorf("non-sensitive field altered: %q", got.Fields["package"])
	}
}

func TestEmitStampsTimeAndNormalizesSeverity(t *testing.T) {
	sink := newFakeSink("s")
	n := New(Options{Now: fixedNow, Routes: []RouteSpec{{Sinks: []Sink{sink}}}})
	defer n.Close()

	// An event with no time and an odd-cased severity.
	n.Emit(context.Background(), Event{Type: EventQuarantine, Severity: "CRITICAL", Title: "q"})
	waitForDeliveries(t, sink, 1, time.Second)
	got, _ := sink.last()
	if !got.Time.Equal(fixedNow()) {
		t.Errorf("Time = %v, want %v", got.Time, fixedNow())
	}
	if got.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want critical", got.Severity)
	}
}

func TestTestEndpointDeliversAndReports(t *testing.T) {
	ok := newFakeSink("ok")
	bad := newFakeSink("bad")
	bad.alwaysFail = true
	bad.retryable = true

	n := New(Options{
		Now:    fixedNow,
		Routes: []RouteSpec{{Sinks: []Sink{ok, bad}}},
	})
	defer n.Close()

	results, err := n.Test(context.Background(), "")
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	byName := map[string]TestResult{}
	for _, r := range results {
		byName[r.Sink] = r
	}
	if !byName["ok"].OK {
		t.Errorf("ok sink should succeed: %+v", byName["ok"])
	}
	if byName["bad"].OK || byName["bad"].Error == "" {
		t.Errorf("bad sink should fail with an error: %+v", byName["bad"])
	}
	// The test endpoint performs no retries: exactly one attempt on the bad sink.
	if got := bad.attempts.Load(); got != 1 {
		t.Errorf("bad sink attempts = %d, want 1 (no retry on test)", got)
	}
	// The ok sink received the synthetic test event.
	if ev, present := ok.last(); !present || ev.Type != EventTest {
		t.Errorf("ok sink did not receive a test event: %+v", ev)
	}
}

func TestTestEndpointUnknownSink(t *testing.T) {
	n := New(Options{Now: fixedNow, Routes: []RouteSpec{{Sinks: []Sink{newFakeSink("s")}}}})
	defer n.Close()
	if _, err := n.Test(context.Background(), "missing"); err == nil {
		t.Error("expected an error for an unknown sink name")
	}
}

func TestNilNotifierIsNoop(t *testing.T) {
	var n *Notifier
	// None of these must panic.
	n.Emit(context.Background(), TestEvent())
	if err := n.Close(); err != nil {
		t.Errorf("Close on nil = %v", err)
	}
	if got := n.Sinks(); got != nil {
		t.Errorf("Sinks on nil = %v", got)
	}
	if _, err := n.Test(context.Background(), ""); err == nil {
		t.Error("Test on nil should error")
	}
	snap := n.Metrics()
	if len(snap.PerSink) != 0 {
		t.Errorf("Metrics on nil should be empty, got %+v", snap)
	}
}

func TestSinksAndMetricsIntrospection(t *testing.T) {
	a := newFakeSink("a")
	b := newFakeSink("b")
	b.kind = "slack"
	n := New(Options{Now: fixedNow, Routes: []RouteSpec{{Sinks: []Sink{a, b}}}})
	defer n.Close()

	sinks := n.Sinks()
	if len(sinks) != 2 {
		t.Fatalf("want 2 sinks, got %d", len(sinks))
	}
	if sinks[0].Name != "a" || sinks[0].Kind != "webhook" {
		t.Errorf("sinks[0] = %+v", sinks[0])
	}
	if sinks[1].Name != "b" || sinks[1].Kind != "slack" {
		t.Errorf("sinks[1] = %+v", sinks[1])
	}
	snap := n.Metrics()
	if _, ok := snap.PerSink["a"]; !ok {
		t.Error("metrics missing sink a")
	}
	if _, ok := snap.PerSink["b"]; !ok {
		t.Error("metrics missing sink b")
	}
}
