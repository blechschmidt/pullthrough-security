package otlplog

import (
	"context"
	"log/slog"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

func TestSeverityNumberMapping(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  int
		text  string
	}{
		{slog.LevelDebug, severityDebug, "DEBUG"},
		{slog.LevelInfo, severityInfo, "INFO"},
		{slog.LevelWarn, severityWarn, "WARN"},
		{slog.LevelError, severityError, "ERROR"},
		{slog.LevelInfo + 2, severityInfo + 2, "INFO+2"},
		{slog.LevelError + 4, severityFatal, "ERROR+4"},
		// Extremes clamp into the valid [1,24] band.
		{slog.Level(-100), severityTrace, slog.Level(-100).String()},
		{slog.Level(100), severityMax, slog.Level(100).String()},
	}
	for _, c := range cases {
		if got := severityNumber(c.level); got != c.want {
			t.Errorf("severityNumber(%v) = %d, want %d", c.level, got, c.want)
		}
		if got := severityText(c.level); got != c.text {
			t.Errorf("severityText(%v) = %q, want %q", c.level, got, c.text)
		}
	}
}

// capturingExporter records every batch it is handed.
type capturingExporter struct {
	batches [][]LogRecord
}

func (e *capturingExporter) Export(_ context.Context, records []LogRecord) error {
	cp := make([]LogRecord, len(records))
	copy(cp, records)
	e.batches = append(e.batches, cp)
	return nil
}

func (e *capturingExporter) Shutdown(context.Context) error { return nil }

func (e *capturingExporter) all() []LogRecord {
	var out []LogRecord
	for _, b := range e.batches {
		out = append(out, b...)
	}
	return out
}

// discardHandler is an inner slog.Handler that drops everything but reports
// enabled at Info and above, so the tee's level delegation is exercised.
type discardHandler struct{ attrs int }

func (discardHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }
func (discardHandler) Handle(context.Context, slog.Record) error    { return nil }
func (h discardHandler) WithAttrs([]slog.Attr) slog.Handler         { return h }
func (h discardHandler) WithGroup(string) slog.Handler              { return h }

func newTestHandler(t *testing.T, exp Exporter, forwardLevel slog.Level) (*slog.Logger, *Forwarder) {
	t.Helper()
	fwd := newForwarder(forwarderOptions{Exporter: exp, Logger: slog.New(discardHandler{})})
	h := NewHandler(discardHandler{}, fwd, HandlerOptions{ForwardLevel: forwardLevel})
	return slog.New(h), fwd
}

func TestHandlerForwardsRecordsWithAttributes(t *testing.T) {
	exp := &capturingExporter{}
	logger, fwd := newTestHandler(t, exp, slog.LevelInfo)

	logger.Info("upstream fetch", "backend", "npm", "count", 3, "ok", true)
	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recs := exp.all()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Body != "upstream fetch" {
		t.Errorf("body = %q", r.Body)
	}
	if r.SeverityNumber != severityInfo || r.SeverityText != "INFO" {
		t.Errorf("severity = %d/%q", r.SeverityNumber, r.SeverityText)
	}
	got := map[string]any{}
	for _, a := range r.Attributes {
		got[a.Key] = a.Value
	}
	if got["backend"] != "npm" {
		t.Errorf("backend = %v", got["backend"])
	}
	if got["count"] != int64(3) {
		t.Errorf("count = %v (%T), want int64(3)", got["count"], got["count"])
	}
	if got["ok"] != true {
		t.Errorf("ok = %v", got["ok"])
	}
}

func TestHandlerForwardLevelFloor(t *testing.T) {
	exp := &capturingExporter{}
	logger, fwd := newTestHandler(t, exp, slog.LevelWarn)

	logger.Info("info line") // below forward floor -> not exported
	logger.Warn("warn line") // exported
	logger.Error("err line") // exported
	logger.Debug("dbg line") // inner handler disables debug entirely

	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	recs := exp.all()
	if len(recs) != 2 {
		t.Fatalf("expected 2 forwarded records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Body != "warn line" || recs[1].Body != "err line" {
		t.Errorf("unexpected bodies: %q, %q", recs[0].Body, recs[1].Body)
	}
}

func TestHandlerGroupFlattening(t *testing.T) {
	exp := &capturingExporter{}
	fwd := newForwarder(forwarderOptions{Exporter: exp, Logger: slog.New(discardHandler{})})
	base := NewHandler(discardHandler{}, fwd, HandlerOptions{ForwardLevel: slog.LevelInfo})
	logger := slog.New(base).With("tenant", "team-a").WithGroup("req").With("method", "GET")

	logger.Info("served", slog.Int("status", 200), slog.Group("cache", slog.Bool("hit", true)))
	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recs := exp.all()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	got := map[string]any{}
	for _, a := range recs[0].Attributes {
		got[a.Key] = a.Value
	}
	// "tenant" was added before any group; "req.method" via WithGroup+With;
	// the record's own attrs land under the open "req" group.
	want := map[string]any{
		"tenant":        "team-a",
		"req.method":    "GET",
		"req.status":    int64(200),
		"req.cache.hit": true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %q = %v (%T), want %v", k, got[k], got[k], v)
		}
	}
}

func TestHandlerCorrelatesTraceAndSpan(t *testing.T) {
	exp := &capturingExporter{}
	logger, fwd := newTestHandler(t, exp, slog.LevelInfo)

	// Build a real sampled span context and log under it.
	tp := tracing.NewProviderWithExporter(tracing.ProviderOptions{
		Exporter: noopSpanExporter{},
		Sampler:  tracing.AlwaysSample(),
	})
	defer func() { _ = tp.Shutdown(context.Background()) }()
	ctx, span := tp.Tracer("test").Start(context.Background(), "op")

	logger.InfoContext(ctx, "inside span")
	span.End()
	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recs := exp.all()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].TraceID != span.TraceID() || recs[0].TraceID == "" {
		t.Errorf("traceId = %q, want %q", recs[0].TraceID, span.TraceID())
	}
	if recs[0].SpanID != span.SpanID() || recs[0].SpanID == "" {
		t.Errorf("spanId = %q, want %q", recs[0].SpanID, span.SpanID())
	}
	if recs[0].Flags&uint32(tracing.FlagSampled) == 0 {
		t.Errorf("sampled flag not propagated: flags=%d", recs[0].Flags)
	}
}

func TestHandlerNoTraceLeavesIDsEmpty(t *testing.T) {
	exp := &capturingExporter{}
	logger, fwd := newTestHandler(t, exp, slog.LevelInfo)
	logger.Info("no span here")
	if err := fwd.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	recs := exp.all()
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].TraceID != "" || recs[0].SpanID != "" {
		t.Errorf("expected empty ids, got %q/%q", recs[0].TraceID, recs[0].SpanID)
	}
}

func TestNewHandlerNilForwarderReturnsInner(t *testing.T) {
	inner := discardHandler{}
	if got := NewHandler(inner, nil, HandlerOptions{}); got != slog.Handler(inner) {
		t.Errorf("NewHandler with nil forwarder should return inner unchanged")
	}
}

// noopSpanExporter satisfies tracing.SpanExporter for the correlation test.
type noopSpanExporter struct{}

func (noopSpanExporter) ExportSpans(context.Context, []tracing.SpanData) error { return nil }
func (noopSpanExporter) Shutdown(context.Context) error                        { return nil }
