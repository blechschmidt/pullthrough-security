package audit

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

var testKey = []byte("test-hmac-key-do-not-use-in-prod")

func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestChainVerifies(t *testing.T) {
	sink := NewMemorySink()
	l, err := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Log(context.Background(), Event{Type: EventPull, Subject: "alice", Resource: "/v1/npm/x"}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	recs := sink.Records()
	if len(recs) != 5 {
		t.Fatalf("want 5 records, got %d", len(recs))
	}
	if idx, err := VerifyChain(testKey, recs); err != nil {
		t.Fatalf("verify failed at %d: %v", idx, err)
	}
	// Sequence numbers must be monotonic from 1.
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Fatalf("record %d has seq %d", i, r.Seq)
		}
	}
}

func TestTamperDetectedOnFieldEdit(t *testing.T) {
	sink := NewMemorySink()
	l, _ := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	for i := 0; i < 4; i++ {
		_ = l.Log(context.Background(), Event{Type: EventPull, Subject: "alice"})
	}
	recs := sink.Records()

	// Attacker edits a past event's subject without recomputing hashes.
	recs[1].Event.Subject = "mallory"
	idx, err := VerifyChain(testKey, recs)
	if err == nil {
		t.Fatalf("expected tamper detection")
	}
	if idx != 1 {
		t.Fatalf("expected break at index 1, got %d", idx)
	}
}

func TestTamperDetectedOnRemoval(t *testing.T) {
	sink := NewMemorySink()
	l, _ := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	for i := 0; i < 4; i++ {
		_ = l.Log(context.Background(), Event{Type: EventPull})
	}
	recs := sink.Records()

	// Remove the middle record; linkage and sequence break.
	spliced := append([]Record{recs[0], recs[1]}, recs[3])
	if idx, err := VerifyChain(testKey, spliced); err == nil {
		t.Fatalf("expected detection of removed record (idx=%d)", idx)
	}
}

func TestWrongKeyFailsVerification(t *testing.T) {
	sink := NewMemorySink()
	l, _ := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	_ = l.Log(context.Background(), Event{Type: EventPull})
	recs := sink.Records()
	if _, err := VerifyChain([]byte("a-different-key-entirely-here!!!"), recs); err == nil {
		t.Fatalf("verification must fail with the wrong key")
	}
}

func TestFileSinkRoundTripAndResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("file sink: %v", err)
	}
	l, err := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Log(context.Background(), Event{Type: EventCache, Detail: map[string]any{"i": i}}); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen and resume: new records must continue the chain.
	sink2, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	l2, err := NewLogger(context.Background(), Options{Key: testKey, Sink: sink2, Now: fixedClock()})
	if err != nil {
		t.Fatalf("resume logger: %v", err)
	}
	if err := l2.Log(context.Background(), Event{Type: EventPolicy}); err != nil {
		t.Fatalf("log after resume: %v", err)
	}
	_ = sink2.Close()

	recs, err := ReadAllRecords(path)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}
	if len(recs) != 4 {
		t.Fatalf("want 4 records across restart, got %d", len(recs))
	}
	if recs[3].Seq != 4 {
		t.Fatalf("resumed seq should be 4, got %d", recs[3].Seq)
	}
	if idx, err := VerifyChain(testKey, recs); err != nil {
		t.Fatalf("post-resume chain broken at %d: %v", idx, err)
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	if err := l.Log(context.Background(), Event{Type: EventPull}); err != nil {
		t.Fatalf("nil logger should be a no-op, got %v", err)
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	if _, err := NewLogger(context.Background(), Options{Sink: NewMemorySink()}); err == nil {
		t.Fatalf("empty key must be rejected")
	}
}
