package audit

import (
	"context"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// TestLogCorrelatesTraceContext proves Log stamps the active distributed-trace
// ids onto the record (Task 41), so an audited decision can be pivoted to its
// full latency trace.
func TestLogCorrelatesTraceContext(t *testing.T) {
	sink := NewMemorySink()
	l, err := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}

	sc := tracing.SpanContext{
		TraceID:    tracing.TraceID{0xab, 0xcd, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
		SpanID:     tracing.SpanID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		TraceFlags: tracing.FlagSampled,
	}
	ctx := tracing.ContextWithSpanContext(context.Background(), sc)

	if err := l.Log(ctx, Event{Type: EventPull, Subject: "alice"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	recs := sink.Records()
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	ev := recs[0].Event
	if ev.TraceID != "abcd0102030405060708090a0b0c0d0e" {
		t.Errorf("traceId = %q, want correlated trace id", ev.TraceID)
	}
	if ev.SpanID != "1122334455667788" {
		t.Errorf("spanId = %q, want correlated span id", ev.SpanID)
	}

	// The correlated ids are part of the hashed record, so the chain still
	// verifies cleanly.
	if idx, err := VerifyChain(testKey, recs); err != nil {
		t.Fatalf("verify failed at %d: %v", idx, err)
	}
}

// TestLogWithoutTraceLeavesIDsEmpty proves correlation is inert when no trace
// context is present (tracing disabled).
func TestLogWithoutTraceLeavesIDsEmpty(t *testing.T) {
	sink := NewMemorySink()
	l, _ := NewLogger(context.Background(), Options{Key: testKey, Sink: sink, Now: fixedClock()})
	if err := l.Log(context.Background(), Event{Type: EventPull}); err != nil {
		t.Fatalf("log: %v", err)
	}
	ev := sink.Records()[0].Event
	if ev.TraceID != "" || ev.SpanID != "" {
		t.Errorf("expected empty trace ids, got trace=%q span=%q", ev.TraceID, ev.SpanID)
	}
}
