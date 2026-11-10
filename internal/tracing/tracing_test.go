package tracing

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// recordingExporter captures exported spans for assertions.
type recordingExporter struct {
	mu    sync.Mutex
	spans []SpanData
	calls int
}

func (e *recordingExporter) ExportSpans(_ context.Context, spans []SpanData) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	e.spans = append(e.spans, spans...)
	return nil
}

func (e *recordingExporter) Shutdown(context.Context) error { return nil }

func (e *recordingExporter) snapshot() []SpanData {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]SpanData, len(e.spans))
	copy(out, e.spans)
	return out
}

// seqReader is a deterministic io.Reader so generated ids are reproducible.
type seqReader struct {
	mu sync.Mutex
	n  byte
}

func (r *seqReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range p {
		r.n++
		if r.n == 0 {
			r.n = 1
		}
		p[i] = r.n
	}
	return len(p), nil
}

func newTestProvider(t *testing.T, exp SpanExporter, sampler Sampler) *Provider {
	t.Helper()
	p := NewProviderWithExporter(ProviderOptions{
		Exporter:      exp,
		Sampler:       sampler,
		ServiceName:   "test-svc",
		FlushInterval: 20 * time.Millisecond,
		MaxBatchSize:  4,
		IDReader:      &seqReader{},
	})
	t.Cleanup(func() {
		_ = p.Shutdown(context.Background())
	})
	return p
}

func TestSpanEmissionAndAttributes(t *testing.T) {
	exp := &recordingExporter{}
	p := newTestProvider(t, exp, AlwaysSample())
	tr := p.Tracer("test")

	ctx, span := tr.Start(context.Background(), "pull",
		WithSpanKind(SpanKindServer),
		WithAttributes(String("tenant", "acme")))
	span.SetAttributes(Int("http.response.status_code", 200), Bool("cache.hit", true))
	span.SetStatus(StatusOK, "")
	_ = ctx
	span.End()

	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	spans := exp.snapshot()
	if len(spans) != 1 {
		t.Fatalf("expected 1 exported span, got %d", len(spans))
	}
	sd := spans[0]
	if sd.Name != "pull" {
		t.Errorf("name = %q, want pull", sd.Name)
	}
	if sd.Kind != SpanKindServer {
		t.Errorf("kind = %d, want server", sd.Kind)
	}
	if !sd.SpanContext.TraceID.IsValid() || !sd.SpanContext.SpanID.IsValid() {
		t.Errorf("span context ids must be valid")
	}
	want := map[string]any{"tenant": "acme", "http.response.status_code": int64(200), "cache.hit": true}
	got := map[string]any{}
	for _, a := range sd.Attributes {
		got[a.Key] = a.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attribute %q = %#v, want %#v", k, got[k], v)
		}
	}
	if sd.Status.Code != StatusOK {
		t.Errorf("status = %d, want OK", sd.Status.Code)
	}
}

func TestChildSpanInheritsTraceID(t *testing.T) {
	exp := &recordingExporter{}
	p := newTestProvider(t, exp, AlwaysSample())
	tr := p.Tracer("test")

	ctx, parent := tr.Start(context.Background(), "parent")
	ctx, child := tr.Start(ctx, "child")
	child.End()
	parent.End()
	_ = ctx

	_ = p.Shutdown(context.Background())

	spans := exp.snapshot()
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	byName := map[string]SpanData{}
	for _, s := range spans {
		byName[s.Name] = s
	}
	pp, cc := byName["parent"], byName["child"]
	if pp.SpanContext.TraceID != cc.SpanContext.TraceID {
		t.Errorf("child trace id %x != parent trace id %x", cc.SpanContext.TraceID, pp.SpanContext.TraceID)
	}
	if cc.Parent != pp.SpanContext.SpanID {
		t.Errorf("child.parent %x != parent.spanID %x", cc.Parent, pp.SpanContext.SpanID)
	}
}

func TestNeverSampleEmitsNothingButPropagates(t *testing.T) {
	exp := &recordingExporter{}
	p := newTestProvider(t, exp, NeverSample())
	tr := p.Tracer("test")

	ctx, span := tr.Start(context.Background(), "pull")
	if span.IsRecording() {
		t.Errorf("span should not be recording under NeverSample")
	}
	// Context must still carry a valid (unsampled) span context for propagation.
	sc := SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Errorf("span context should be valid even when unsampled")
	}
	if sc.IsSampled() {
		t.Errorf("sampled flag should be unset under NeverSample")
	}
	span.End()
	_ = p.Shutdown(context.Background())

	if got := exp.snapshot(); len(got) != 0 {
		t.Errorf("expected 0 exported spans, got %d", len(got))
	}
	if m := p.Metrics(); m.SpansStarted != 1 || m.SpansSampled != 0 {
		t.Errorf("metrics started=%d sampled=%d, want 1/0", m.SpansStarted, m.SpansSampled)
	}
}

func TestNilSafety(t *testing.T) {
	var p *Provider
	tr := p.Tracer("x") // nil tracer
	ctx, span := tr.Start(context.Background(), "noop")
	// All of these must be safe no-ops.
	span.SetAttributes(String("k", "v"))
	span.SetStatus(StatusError, "boom")
	span.RecordError(io.EOF)
	span.AddEvent("evt")
	span.End()
	if span.IsRecording() {
		t.Errorf("nil span should not be recording")
	}
	if span.TraceID() != "" {
		t.Errorf("nil span TraceID should be empty")
	}
	if ctx == nil {
		t.Errorf("ctx should pass through unchanged")
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Errorf("nil provider shutdown: %v", err)
	}
}

func TestQueueOverflowDropsSpans(t *testing.T) {
	// A blocking exporter keeps the batch loop busy so the queue fills.
	block := make(chan struct{})
	exp := &blockingExporter{release: block}
	p := NewProviderWithExporter(ProviderOptions{
		Exporter:     exp,
		Sampler:      AlwaysSample(),
		MaxQueueSize: 2,
		MaxBatchSize: 1,
		IDReader:     &seqReader{},
	})
	defer func() { close(block); _ = p.Shutdown(context.Background()) }()

	tr := p.Tracer("t")
	for i := 0; i < 20; i++ {
		_, s := tr.Start(context.Background(), "s")
		s.End()
	}
	// Some spans must have been dropped given the tiny bounded queue and the
	// stalled exporter.
	if m := p.Metrics(); m.SpansDropped == 0 {
		t.Errorf("expected some dropped spans with a full queue, got %d", m.SpansDropped)
	}
}

type blockingExporter struct {
	release chan struct{}
}

func (e *blockingExporter) ExportSpans(ctx context.Context, _ []SpanData) error {
	select {
	case <-e.release:
	case <-ctx.Done():
	}
	return nil
}
func (e *blockingExporter) Shutdown(context.Context) error { return nil }

func TestOTLPExporterWireFormat(t *testing.T) {
	var got bytes.Buffer
	var ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		_, _ = io.Copy(&got, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp, err := NewOTLPExporter(OTLPConfig{
		Endpoint: srv.URL,
		Insecure: true,
		Resource: []Attr{String("service.name", "pullthrough")},
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}

	var tid TraceID
	var sid, parent SpanID
	copy(tid[:], bytes.Repeat([]byte{0xab}, 16))
	copy(sid[:], bytes.Repeat([]byte{0x11}, 8))
	copy(parent[:], bytes.Repeat([]byte{0x22}, 8))
	sd := SpanData{
		Name:        "upstream.fetch",
		SpanContext: SpanContext{TraceID: tid, SpanID: sid, TraceFlags: FlagSampled},
		Parent:      parent,
		Kind:        SpanKindClient,
		StartTime:   time.Unix(0, 1500),
		EndTime:     time.Unix(0, 4500),
		Attributes:  []Attr{String("backend", "npm"), Int("count", 3)},
		Status:      SpanStatus{Code: StatusError, Message: "bad gateway"},
	}
	if err := exp.ExportSpans(context.Background(), []SpanData{sd}); err != nil {
		t.Fatalf("export: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}

	var req otlpExportRequest
	if err := json.Unmarshal(got.Bytes(), &req); err != nil {
		t.Fatalf("unmarshal payload: %v\n%s", err, got.String())
	}
	if len(req.ResourceSpans) != 1 || len(req.ResourceSpans[0].ScopeSpans) != 1 {
		t.Fatalf("unexpected payload shape: %+v", req)
	}
	spans := req.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	s := spans[0]
	if s.TraceID != hex.EncodeToString(tid[:]) {
		t.Errorf("traceId = %q, want %q", s.TraceID, hex.EncodeToString(tid[:]))
	}
	if s.ParentSpanID != hex.EncodeToString(parent[:]) {
		t.Errorf("parentSpanId = %q", s.ParentSpanID)
	}
	if s.StartTimeUnixNano != "1500" || s.EndTimeUnixNano != "4500" {
		t.Errorf("times = %s/%s, want 1500/4500", s.StartTimeUnixNano, s.EndTimeUnixNano)
	}
	if s.Status == nil || s.Status.Code != int(StatusError) {
		t.Errorf("status = %+v, want error", s.Status)
	}
	// int attribute must be a string per OTLP/JSON; verify "count":"3".
	var sawCount bool
	for _, a := range s.Attributes {
		if a.Key == "count" {
			sawCount = true
			if a.Value.IntValue == nil || *a.Value.IntValue != "3" {
				t.Errorf("count intValue = %+v, want \"3\"", a.Value.IntValue)
			}
		}
	}
	if !sawCount {
		t.Errorf("count attribute missing")
	}
}

func TestOTLPExporterReportsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	exp, err := NewOTLPExporter(OTLPConfig{Endpoint: srv.URL, Insecure: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, s := newTestProvider(t, &recordingExporter{}, AlwaysSample()).Tracer("t").Start(context.Background(), "s")
	s.End()
	err = exp.ExportSpans(context.Background(), []SpanData{{Name: "x", SpanContext: SpanContext{TraceID: TraceID{1}, SpanID: SpanID{1}}}})
	if err == nil {
		t.Errorf("expected error on 503 response")
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		insecure bool
		want     string
	}{
		{"http://c:4318", false, "http://c:4318/v1/traces"},
		{"http://c:4318/v1/traces", false, "http://c:4318/v1/traces"},
		{"collector:4318", true, "http://collector:4318/v1/traces"},
		{"collector:4318", false, "https://collector:4318/v1/traces"},
		{"https://c/custom/path", false, "https://c/custom/path"},
	}
	for _, c := range cases {
		got, err := normalizeTracesEndpoint(c.in, c.insecure)
		if err != nil {
			t.Errorf("normalize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("normalize(%q, insecure=%v) = %q, want %q", c.in, c.insecure, got, c.want)
		}
	}
	if _, err := normalizeTracesEndpoint("", false); err == nil {
		t.Errorf("empty endpoint should error")
	}
}

func TestConfigNewDisabled(t *testing.T) {
	p, err := New(Config{Enabled: false})
	if err != nil || p != nil {
		t.Errorf("disabled config should yield (nil,nil), got (%v,%v)", p, err)
	}
	p, err = New(Config{Enabled: true, Endpoint: ""})
	if err != nil || p != nil {
		t.Errorf("no endpoint should yield (nil,nil), got (%v,%v)", p, err)
	}
}
