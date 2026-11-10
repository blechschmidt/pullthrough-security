package otlplog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *slog.Logger { return slog.New(discardHandler{}) }

func rec(body string) LogRecord {
	return LogRecord{Time: time.Unix(0, 1), SeverityNumber: severityInfo, SeverityText: "INFO", Body: body}
}

func TestForwarderDeliversAndFlushesOnClose(t *testing.T) {
	exp := &capturingExporter{}
	f := newForwarder(forwarderOptions{Exporter: exp, Logger: discardLogger(), BatchTimeout: time.Hour})
	for i := 0; i < 10; i++ {
		f.Enqueue(rec("r"))
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := len(exp.all()); got != 10 {
		t.Fatalf("delivered %d, want 10", got)
	}
	m := f.Metrics()
	if m.Enqueued != 10 || m.Delivered != 10 {
		t.Errorf("metrics enqueued=%d delivered=%d", m.Enqueued, m.Delivered)
	}
}

// blockingExporter blocks the first Export until released, so the test can fill
// the queue deterministically.
type blockingExporter struct {
	release chan struct{}
	once    sync.Once
	count   atomic.Int64
}

func (e *blockingExporter) Export(_ context.Context, records []LogRecord) error {
	e.once.Do(func() { <-e.release })
	e.count.Add(int64(len(records)))
	return nil
}
func (e *blockingExporter) Shutdown(context.Context) error { return nil }

func TestForwarderDropsOnOverflowWithoutSpill(t *testing.T) {
	exp := &blockingExporter{release: make(chan struct{})}
	f := newForwarder(forwarderOptions{
		Exporter: exp, Logger: discardLogger(),
		QueueSize: 4, BatchSize: 2, BatchTimeout: time.Hour,
	})
	// The dispatcher grabs a first batch and blocks inside Export; subsequent
	// enqueues fill the queue (cap 4) then drop.
	for i := 0; i < 50; i++ {
		f.Enqueue(rec("r"))
	}
	// Give the dispatcher a moment to pick up the first batch and block.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.Metrics().Dropped > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	m := f.Metrics()
	if m.Dropped == 0 {
		t.Fatalf("expected drops under overflow, got none (enqueued=%d)", m.Enqueued)
	}
	if m.Enqueued != 50 {
		t.Errorf("enqueued = %d, want 50", m.Enqueued)
	}
	close(exp.release)
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// flakyExporter fails the first n calls with a retryable error.
type flakyExporter struct {
	mu        sync.Mutex
	failsLeft int
	delivered int
}

func (e *flakyExporter) Export(_ context.Context, records []LogRecord) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failsLeft > 0 {
		e.failsLeft--
		return &httpError{status: 503, retryable: true}
	}
	e.delivered += len(records)
	return nil
}
func (e *flakyExporter) Shutdown(context.Context) error { return nil }

func TestForwarderRetriesTransientFailures(t *testing.T) {
	exp := &flakyExporter{failsLeft: 2}
	f := newForwarder(forwarderOptions{
		Exporter: exp, Logger: discardLogger(),
		BatchTimeout: time.Hour, MaxRetries: 5, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond,
	})
	f.Enqueue(rec("r"))
	// Wait for the record to be delivered (after two retried failures) before
	// closing, so Close's backoff-interrupt never races the retry sequence.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.Metrics().Delivered == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	exp.mu.Lock()
	defer exp.mu.Unlock()
	if exp.delivered != 1 {
		t.Errorf("delivered = %d, want 1", exp.delivered)
	}
	if got := f.Metrics().Retries; got != 2 {
		t.Errorf("retries = %d, want 2", got)
	}
	if got := f.Metrics().Failed; got != 0 {
		t.Errorf("failed = %d, want 0", got)
	}
}

// permanentExporter always fails with a non-retryable error.
type permanentExporter struct{ calls atomic.Int64 }

func (e *permanentExporter) Export(context.Context, []LogRecord) error {
	e.calls.Add(1)
	return &httpError{status: 400, retryable: false}
}
func (e *permanentExporter) Shutdown(context.Context) error { return nil }

func TestForwarderDoesNotRetryPermanentFailures(t *testing.T) {
	exp := &permanentExporter{}
	f := newForwarder(forwarderOptions{Exporter: exp, Logger: discardLogger(), BatchTimeout: time.Hour, MaxRetries: 5})
	f.Enqueue(rec("r"))
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := exp.calls.Load(); got != 1 {
		t.Errorf("export calls = %d, want 1 (no retries on 4xx)", got)
	}
	if got := f.Metrics().Failed; got != 1 {
		t.Errorf("failed = %d, want 1", got)
	}
}

func TestForwarderSpillAbsorbsOverflow(t *testing.T) {
	spill, err := openSpill(t.TempDir()+"/spill.ndjson", 0)
	if err != nil {
		t.Fatalf("open spill: %v", err)
	}
	exp := &blockingExporter{release: make(chan struct{})}
	f := newForwarder(forwarderOptions{
		Exporter: exp, Logger: discardLogger(),
		QueueSize: 2, BatchSize: 1, BatchTimeout: time.Hour, Spill: spill,
	})
	for i := 0; i < 20; i++ {
		f.Enqueue(rec("r"))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.Metrics().Spilled > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if f.Metrics().Spilled == 0 {
		t.Fatalf("expected records to spill, got none")
	}
	if f.Metrics().Dropped != 0 {
		t.Errorf("unexpected drops with uncapped spill: %d", f.Metrics().Dropped)
	}
	close(exp.release)
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Everything enqueued must ultimately be delivered (queue + spill drained).
	if got := exp.count.Load(); got != 20 {
		t.Errorf("delivered %d, want 20", got)
	}
}

func TestNilForwarderIsNoOp(t *testing.T) {
	var f *Forwarder
	f.Enqueue(rec("r")) // must not panic
	if f.Metrics() != (Metrics{}) {
		t.Errorf("nil forwarder metrics not zero")
	}
	if err := f.Close(); err != nil {
		t.Errorf("nil close: %v", err)
	}
}

func TestIsRetryable(t *testing.T) {
	if isRetryable(nil) {
		t.Error("nil should not be retryable")
	}
	if !isRetryable(errors.New("boom")) {
		t.Error("unknown transport error should be retryable")
	}
	if isRetryable(&httpError{status: 400, retryable: false}) {
		t.Error("4xx should not be retryable")
	}
	if !isRetryable(&httpError{status: 503, retryable: true}) {
		t.Error("5xx should be retryable")
	}
}
