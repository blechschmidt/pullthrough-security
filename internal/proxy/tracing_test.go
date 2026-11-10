package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// recordingExporter captures spans for assertions in proxy-level tracing tests.
type recordingExporter struct {
	mu    sync.Mutex
	spans []tracing.SpanData
}

func (e *recordingExporter) ExportSpans(_ context.Context, spans []tracing.SpanData) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, spans...)
	return nil
}
func (e *recordingExporter) Shutdown(context.Context) error { return nil }

func (e *recordingExporter) byName() map[string]tracing.SpanData {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]tracing.SpanData, len(e.spans))
	for _, s := range e.spans {
		out[s.Name] = s
	}
	return out
}

// newTracedGateway builds a gateway wired with a tracing provider exporting to
// exp, proxying baseURL through a fresh in-memory cache. It returns the provider
// so the test can flush it before asserting.
func newTracedGateway(t *testing.T, baseURL string, exp tracing.SpanExporter) (*Gateway, *tracing.Provider) {
	t.Helper()
	provider := tracing.NewProviderWithExporter(tracing.ProviderOptions{
		Exporter: exp,
		Sampler:  tracing.AlwaysSample(),
	})
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: registry,
		Tracer:   provider.Tracer("test"),
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, provider
}

// TestGatewayEmitsPullSpans proves a cacheable pull produces the expected span
// tree (server pull span with cache-fetch, upstream-fetch, and resolve
// children) and records the cache-miss outcome on the request-level span.
func TestGatewayEmitsPullSpans(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	exp := &recordingExporter{}
	g, provider := newTracedGateway(t, srv.URL, exp)

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body %q)", rr.Code, rr.Body.String())
	}

	// Shutting the provider down flushes the queue synchronously.
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("provider shutdown: %v", err)
	}
	spans := exp.byName()

	for _, want := range []string{"pull npm", "backend.resolve", "cache.fetch", "upstream.fetch"} {
		if _, ok := spans[want]; !ok {
			t.Errorf("missing span %q; got %v", want, keys(spans))
		}
	}

	server := spans["pull npm"]
	if server.Kind != tracing.SpanKindServer {
		t.Errorf("pull span kind = %d, want server", server.Kind)
	}
	if got := attr(server, "pullthrough.cache.status"); got != "MISS" {
		t.Errorf("pull span cache.status = %v, want MISS", got)
	}
	// All spans must share one trace id (the request's).
	tid := server.SpanContext.TraceID
	for name, s := range spans {
		if s.SpanContext.TraceID != tid {
			t.Errorf("span %q has trace id %x, want %x", name, s.SpanContext.TraceID, tid)
		}
	}
	if spans["upstream.fetch"].Kind != tracing.SpanKindClient {
		t.Errorf("upstream.fetch kind = %d, want client", spans["upstream.fetch"].Kind)
	}
}

// TestGatewayContinuesInboundTrace proves an inbound W3C traceparent is adopted:
// the request-level span shares the client's trace id and parents from the
// propagated span id.
func TestGatewayContinuesInboundTrace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "DATA")
	}))
	defer srv.Close()

	exp := &recordingExporter{}
	g, provider := newTracedGateway(t, srv.URL, exp)

	req := httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil)
	const inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req.Header.Set("traceparent", inbound)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("provider shutdown: %v", err)
	}
	spans := exp.byName()
	server, ok := spans["pull npm"]
	if !ok {
		t.Fatalf("missing pull span; got %v", keys(spans))
	}
	if got := traceHex(server.SpanContext.TraceID); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("did not continue inbound trace: trace id = %s", got)
	}
	if got := spanHex(server.Parent); got != "00f067aa0ba902b7" {
		t.Errorf("pull span parent = %s, want inbound span id 00f067aa0ba902b7", got)
	}
}

// TestGatewayNoTracerIsNoOp proves the pipeline serves normally when no tracer
// is configured (the disabled default).
func TestGatewayNoTracerIsNoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "OK")
	}))
	defer srv.Close()

	g := newGateway(t, srv.URL, upstream.Credentials{}) // no Tracer
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/x.tgz", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "OK" {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func attr(s tracing.SpanData, key string) any {
	for _, a := range s.Attributes {
		if a.Key == key {
			return a.Value
		}
	}
	return nil
}

func keys(m map[string]tracing.SpanData) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func traceHex(t tracing.TraceID) string { return hexBytes(t[:]) }
func spanHex(s tracing.SpanID) string   { return hexBytes(s[:]) }

func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
