package siem

import (
	"context"
	"sync"
	"testing"
	"time"
)

// captureSink is a programmable in-memory Sink for deterministic dispatcher
// tests. It records delivered batches and can optionally fail or block.
type captureSink struct {
	name string
	kind string

	mu      sync.Mutex
	batches [][]Event
	events  []Event

	// failFirst makes the first n delivery attempts fail retryably.
	failFirst int
	attempts  int

	// gate, when non-nil, blocks the first DeliverBatch until released; started
	// is closed on entry to the first blocked call.
	gate     chan struct{}
	started  chan struct{}
	gateOnce sync.Once
}

func newCaptureSink(name string) *captureSink {
	return &captureSink{name: name, kind: "capture"}
}

func (s *captureSink) Name() string { return s.name }
func (s *captureSink) Kind() string { return s.kind }
func (s *captureSink) Close() error { return nil }

func (s *captureSink) DeliverBatch(ctx context.Context, batch []Event) error {
	if s.gate != nil {
		s.gateOnce.Do(func() {
			close(s.started)
			<-s.gate
		})
	}
	s.mu.Lock()
	s.attempts++
	if s.attempts <= s.failFirst {
		s.mu.Unlock()
		return &DeliveryError{Sink: s.name, Retryable: true, Err: context.DeadlineExceeded}
	}
	cp := make([]Event, len(batch))
	copy(cp, batch)
	s.batches = append(s.batches, cp)
	s.events = append(s.events, cp...)
	s.mu.Unlock()
	return nil
}

func (s *captureSink) eventCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

func (s *captureSink) batchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

// waitFor polls cond until it is true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %s", timeout)
	}
}

func sampleEvent(sev Severity) Event {
	return Event{
		Source:   SourceFinding,
		Time:     time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC),
		Severity: sev,
		Category: "vulnscan",
		Name:     "CVE-2026-0001",
		Outcome:  "error",
		Subject:  "team-a",
		Message:  "critical vulnerability",
		Fields:   map[string]string{"coordinate": "npm/lodash@1.0.0"},
	}
}

func TestForwarderDeliversAndBatches(t *testing.T) {
	sink := newCaptureSink("s1")
	f := New(Options{
		Sinks:        []Sink{sink},
		BatchSize:    10,
		BatchTimeout: 20 * time.Millisecond,
	})
	defer f.Close()

	for i := 0; i < 5; i++ {
		f.Emit(sampleEvent(SeverityHigh))
	}
	waitFor(t, time.Second, func() bool { return sink.eventCount() == 5 })

	if got := f.Metrics().Enqueued; got != 5 {
		t.Fatalf("enqueued = %d, want 5", got)
	}
	if got := f.Metrics().PerSink["s1"].Delivered; got != 5 {
		t.Fatalf("delivered = %d, want 5", got)
	}
	// All five arrived close together, so they should coalesce into one batch.
	if bc := sink.batchCount(); bc != 1 {
		t.Fatalf("batch count = %d, want 1 (events should coalesce)", bc)
	}
}

func TestForwarderMinSeverityFloor(t *testing.T) {
	sink := newCaptureSink("s1")
	f := New(Options{
		Sinks:       []Sink{sink},
		MinSeverity: SeverityHigh,
	})
	defer f.Close()

	f.Emit(sampleEvent(SeverityLow))    // below floor, dropped silently
	f.Emit(sampleEvent(SeverityMedium)) // below floor
	f.Emit(sampleEvent(SeverityHigh))   // at floor, forwarded

	waitFor(t, time.Second, func() bool { return sink.eventCount() == 1 })
	time.Sleep(20 * time.Millisecond) // give any erroneous extra deliveries a chance
	if got := sink.eventCount(); got != 1 {
		t.Fatalf("delivered = %d, want 1 (floor should drop low/medium)", got)
	}
	if got := f.Metrics().Enqueued; got != 1 {
		t.Fatalf("enqueued = %d, want 1 (below-floor events not counted)", got)
	}
}

func TestForwarderRetriesThenSucceeds(t *testing.T) {
	sink := newCaptureSink("s1")
	sink.failFirst = 2
	f := New(Options{
		Sinks:          []Sink{sink},
		MaxRetries:     3,
		RetryBaseDelay: time.Millisecond,
		RetryMaxDelay:  5 * time.Millisecond,
		BatchSize:      1,
	})
	defer f.Close()

	f.Emit(sampleEvent(SeverityHigh))
	waitFor(t, 2*time.Second, func() bool { return sink.eventCount() == 1 })

	m := f.Metrics().PerSink["s1"]
	if m.Delivered != 1 {
		t.Fatalf("delivered = %d, want 1", m.Delivered)
	}
	if m.Retries != 2 {
		t.Fatalf("retries = %d, want 2", m.Retries)
	}
	if m.Failed != 0 {
		t.Fatalf("failed = %d, want 0", m.Failed)
	}
}

func TestForwarderQueueFullDrops(t *testing.T) {
	sink := newCaptureSink("s1")
	sink.gate = make(chan struct{})
	sink.started = make(chan struct{})
	f := New(Options{
		Sinks:     []Sink{sink},
		QueueSize: 1,
		BatchSize: 1,
	})
	defer func() {
		close(sink.gate)
		f.Close()
	}()

	f.Emit(sampleEvent(SeverityHigh)) // drained by dispatcher, blocks in DeliverBatch
	<-sink.started                    // dispatcher is now blocked delivering ev1

	f.Emit(sampleEvent(SeverityHigh)) // fills the 1-slot queue
	f.Emit(sampleEvent(SeverityHigh)) // queue full, no spill -> dropped
	f.Emit(sampleEvent(SeverityHigh)) // dropped

	waitFor(t, time.Second, func() bool { return f.Metrics().Dropped >= 2 })
	if got := f.Metrics().Enqueued; got != 4 {
		t.Fatalf("enqueued = %d, want 4", got)
	}
}

func TestForwarderSpillOverflow(t *testing.T) {
	dir := t.TempDir()
	spill, err := openSpill(dir+"/spill.log", 0)
	if err != nil {
		t.Fatal(err)
	}
	sink := newCaptureSink("s1")
	sink.gate = make(chan struct{})
	sink.started = make(chan struct{})
	f := New(Options{
		Sinks:     []Sink{sink},
		QueueSize: 1,
		BatchSize: 10,
		Spill:     spill,
	})
	released := false
	defer func() {
		if !released {
			close(sink.gate)
		}
		f.Close()
	}()

	f.Emit(sampleEvent(SeverityHigh)) // drained, blocks
	<-sink.started

	// Queue holds 1; the next few overflow to spill rather than dropping.
	for i := 0; i < 5; i++ {
		f.Emit(sampleEvent(SeverityHigh))
	}
	waitFor(t, time.Second, func() bool { return f.Metrics().Spilled >= 1 })
	if got := f.Metrics().Dropped; got != 0 {
		t.Fatalf("dropped = %d, want 0 (spill should absorb overflow)", got)
	}

	// Release the sink; everything (queue + spill) should drain and deliver.
	close(sink.gate)
	released = true
	waitFor(t, 2*time.Second, func() bool { return sink.eventCount() == 6 })
}

func TestForwarderNilIsNoop(t *testing.T) {
	var f *Forwarder
	f.Emit(sampleEvent(SeverityHigh))
	f.ForwardFindings(context.Background(), sampleDocument())
	if got := f.Sinks(); got != 0 {
		t.Fatalf("nil forwarder Sinks() = %d, want 0", got)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("nil Close() = %v", err)
	}
}
