package otlplog

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// TestPipelineEndToEnd exercises the production wiring: New builds the exporter +
// forwarder, Handler wraps an inner handler, a record logged under an active
// span is correlated, and Close flushes it to a real HTTP collector.
func TestPipelineEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pipe, err := New(Config{
		Enabled:        true,
		Endpoint:       srv.URL,
		Insecure:       true,
		ServiceName:    "pullthrough",
		ServiceVersion: "9.9.9",
		Tenant:         "team-a",
		MinLevel:       "info",
		Logger:         slog.New(discardHandler{}),
	})
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	if pipe == nil {
		t.Fatal("expected a live pipeline")
	}
	if pipe.Endpoint() != srv.URL+"/v1/logs" {
		t.Errorf("endpoint = %q", pipe.Endpoint())
	}

	logger := slog.New(pipe.Handler(discardHandler{}))

	tp := tracing.NewProviderWithExporter(tracing.ProviderOptions{Exporter: noopSpanExporter{}, Sampler: tracing.AlwaysSample()})
	defer func() { _ = tp.Shutdown(context.Background()) }()
	ctx, span := tp.Tracer("t").Start(context.Background(), "op")

	logger.InfoContext(ctx, "served request", "backend", "npm")
	logger.Debug("not forwarded: below stderr and forward level")
	span.End()

	// Close flushes the queue to the collector.
	if err := pipe.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("collector received no export")
	}
	// Decode the last body and assert the resource + record shape.
	var req otlpLogsRequest
	if err := json.Unmarshal(bodies[len(bodies)-1], &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(req.ResourceLogs) != 1 {
		t.Fatalf("resourceLogs = %d", len(req.ResourceLogs))
	}
	resAttrs := map[string]string{}
	for _, a := range req.ResourceLogs[0].Resource.Attributes {
		if a.Value.StringValue != nil {
			resAttrs[a.Key] = *a.Value.StringValue
		}
	}
	if resAttrs["service.name"] != "pullthrough" || resAttrs["service.version"] != "9.9.9" || resAttrs["tenant"] != "team-a" {
		t.Errorf("resource attrs = %+v", resAttrs)
	}
	recs := req.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (debug must be dropped)", len(recs))
	}
	if recs[0].Body == nil || *recs[0].Body.StringValue != "served request" {
		t.Errorf("body = %+v", recs[0].Body)
	}
	if recs[0].TraceID != span.TraceID() || recs[0].SpanID != span.SpanID() {
		t.Errorf("correlation ids = %q/%q, want %q/%q", recs[0].TraceID, recs[0].SpanID, span.TraceID(), span.SpanID())
	}
}

func TestNewDisabledReturnsNil(t *testing.T) {
	pipe, err := New(Config{Enabled: false, Endpoint: "http://c:4318"})
	if err != nil || pipe != nil {
		t.Fatalf("disabled New = (%v, %v), want (nil, nil)", pipe, err)
	}
	// A nil pipeline is a no-op for every method.
	if h := pipe.Handler(discardHandler{}); h != slog.Handler(discardHandler{}) {
		t.Error("nil pipeline Handler should return inner unchanged")
	}
	if pipe.Metrics() != (Metrics{}) || pipe.Endpoint() != "" {
		t.Error("nil pipeline accessors should be zero")
	}
	if err := pipe.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

func TestNewRejectsBadLevel(t *testing.T) {
	if _, err := New(Config{Enabled: true, Endpoint: "http://c:4318", MinLevel: "loud"}); err == nil {
		t.Fatal("expected error for bad MinLevel")
	}
}
