package siem

import (
	"context"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

func TestWrapAuditSinkForwardsAndPreservesChain(t *testing.T) {
	capture := newCaptureSink("s1")
	fwd := New(Options{
		Sinks:        []Sink{capture},
		ForwardAudit: true,
		BatchSize:    10,
		BatchTimeout: 10 * time.Millisecond,
	})
	defer fwd.Close()

	inner := audit.NewMemorySink()
	wrapped := WrapAuditSink(inner, fwd)

	// The wrapper must preserve the inner sink's optional RecordReader capability
	// so the Merkle transparency layer can still resume across restarts.
	if _, ok := wrapped.(audit.RecordReader); !ok {
		t.Fatal("wrapped sink lost RecordReader capability")
	}

	key := []byte("test-hmac-key")
	logger, err := audit.NewLogger(context.Background(), audit.Options{Key: key, Sink: wrapped})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := logger.Log(context.Background(), audit.Event{
			Type:     audit.EventPolicy,
			Decision: audit.DecisionDeny,
			Reason:   "blocked",
		}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}

	// The hash chain must verify — forwarding is a read-only tap and must not
	// perturb the chain.
	recs, err := logger.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// VerifyChain returns (-1, nil) when the whole chain is intact.
	if bad, err := audit.VerifyChain(key, recs); err != nil {
		t.Fatalf("VerifyChain: %v (first bad record index %d)", err, bad)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3", len(recs))
	}

	// All three records should have been forwarded to the SIEM sink.
	waitFor(t, 2*time.Second, func() bool { return capture.eventCount() == 3 })
	for _, ev := range capture.events {
		if ev.Source != SourceAudit {
			t.Fatalf("forwarded event source = %q, want audit", ev.Source)
		}
	}
}

func TestWrapAuditSinkDisabledIsUnwrapped(t *testing.T) {
	inner := audit.NewMemorySink()

	// Nil forwarder: returned unchanged.
	if got := WrapAuditSink(inner, nil); got != audit.Sink(inner) {
		t.Fatal("nil forwarder should return the inner sink unchanged")
	}

	// Forwarder with audit forwarding disabled: returned unchanged.
	fwd := New(Options{ForwardAudit: false})
	defer fwd.Close()
	if got := WrapAuditSink(inner, fwd); got != audit.Sink(inner) {
		t.Fatal("audit-forwarding-off forwarder should return the inner sink unchanged")
	}
}

func TestWrapAuditSinkWithoutRecordReader(t *testing.T) {
	// A bare sink that is NOT a RecordReader must not gain a (broken) ReadAll.
	fwd := New(Options{Sinks: []Sink{newCaptureSink("s")}, ForwardAudit: true})
	defer fwd.Close()
	wrapped := WrapAuditSink(bareSink{}, fwd)
	if _, ok := wrapped.(audit.RecordReader); ok {
		t.Fatal("wrapper should not expose RecordReader when the inner sink lacks it")
	}
}

// bareSink is an audit.Sink that deliberately does not implement RecordReader.
type bareSink struct{}

func (bareSink) Append(context.Context, audit.Record) error       { return nil }
func (bareSink) Last(context.Context) (audit.Record, bool, error) { return audit.Record{}, false, nil }
func (bareSink) Close() error                                     { return nil }
