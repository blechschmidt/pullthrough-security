package tracing

import (
	"context"
	"net/http"
	"testing"
)

func TestInjectExtractRoundTrip(t *testing.T) {
	p := NewProviderWithExporter(ProviderOptions{Exporter: &recordingExporter{}, Sampler: AlwaysSample(), IDReader: &seqReader{}})
	defer func() { _ = p.Shutdown(context.Background()) }()

	ctx, span := p.Tracer("t").Start(context.Background(), "root")
	defer span.End()

	carrier := HeaderCarrier(http.Header{})
	Inject(ctx, carrier)

	tp := carrier.Get("traceparent")
	if tp == "" {
		t.Fatalf("traceparent not injected")
	}

	// Extract into a fresh context and verify the ids match and Remote is set.
	got := Extract(context.Background(), carrier)
	sc := SpanContextFromContext(got)
	if !sc.Remote {
		t.Errorf("extracted context should be marked remote")
	}
	orig := span.SpanContext()
	if sc.TraceID != orig.TraceID {
		t.Errorf("trace id mismatch after round trip: %x != %x", sc.TraceID, orig.TraceID)
	}
	if sc.SpanID != orig.SpanID {
		t.Errorf("span id mismatch after round trip")
	}
	if !sc.IsSampled() {
		t.Errorf("sampled flag lost in round trip")
	}
}

func TestExtractValidTraceparent(t *testing.T) {
	carrier := MapCarrier{
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"tracestate":  "vendor=value",
	}
	sc := SpanContextFromContext(Extract(context.Background(), carrier))
	if !sc.IsValid() {
		t.Fatalf("expected valid span context")
	}
	if !sc.IsSampled() {
		t.Errorf("expected sampled")
	}
	if sc.TraceState != "vendor=value" {
		t.Errorf("tracestate = %q", sc.TraceState)
	}
	if encodeTraceID(sc.TraceID) != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %s", encodeTraceID(sc.TraceID))
	}
	if encodeSpanID(sc.SpanID) != "00f067aa0ba902b7" {
		t.Errorf("span id = %s", encodeSpanID(sc.SpanID))
	}
}

func TestExtractInvalidTraceparent(t *testing.T) {
	bad := []string{
		"",
		"garbage",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",    // missing flags
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace id
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero span id
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // invalid version
		"00-xyz92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // non-hex
	}
	for _, v := range bad {
		ctx := Extract(context.Background(), MapCarrier{"traceparent": v})
		if SpanContextFromContext(ctx).IsValid() {
			t.Errorf("traceparent %q should be rejected", v)
		}
	}
}

func TestExtractThenChildContinuesTrace(t *testing.T) {
	exp := &recordingExporter{}
	p := NewProviderWithExporter(ProviderOptions{Exporter: exp, Sampler: NewRatioSampler(1.0), IDReader: &seqReader{}})
	defer func() { _ = p.Shutdown(context.Background()) }()

	carrier := MapCarrier{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}
	ctx := Extract(context.Background(), carrier)
	_, span := p.Tracer("t").Start(ctx, "child")
	span.End()
	_ = p.Shutdown(context.Background())

	spans := exp.snapshot()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if encodeTraceID(spans[0].SpanContext.TraceID) != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("child did not continue extracted trace: %s", encodeTraceID(spans[0].SpanContext.TraceID))
	}
	if encodeSpanID(spans[0].Parent) != "00f067aa0ba902b7" {
		t.Errorf("child parent = %s, want extracted span id", encodeSpanID(spans[0].Parent))
	}
}

func TestParentBasedRespectsRemoteUnsampled(t *testing.T) {
	// Remote parent with sampled=0 must keep the whole trace unsampled even
	// under a ratio-1 root sampler.
	exp := &recordingExporter{}
	p := NewProviderWithExporter(ProviderOptions{Exporter: exp, Sampler: NewRatioSampler(1.0), IDReader: &seqReader{}})
	defer func() { _ = p.Shutdown(context.Background()) }()

	carrier := MapCarrier{"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"}
	ctx := Extract(context.Background(), carrier)
	_, span := p.Tracer("t").Start(ctx, "child")
	if span.IsRecording() {
		t.Errorf("child of an unsampled remote parent must not record")
	}
	span.End()
}
