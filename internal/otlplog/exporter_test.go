package otlplog

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite golden fixtures")

// goldenRecords is the deterministic batch encoded in the golden fixture. It
// exercises every LogRecord field: timestamps, severity, body, scalar attribute
// types (string/int/bool/float), trace/span correlation, and the sampled flag.
func goldenRecords() []LogRecord {
	return []LogRecord{
		{
			Time:           time.Unix(0, 1700000000000000000).UTC(),
			ObservedTime:   time.Unix(0, 1700000000500000000).UTC(),
			SeverityNumber: severityError,
			SeverityText:   "ERROR",
			Body:           "upstream fetch failed",
			Attributes: []Attr{
				{Key: "backend", Value: "npm"},
				{Key: "status", Value: int64(502)},
				{Key: "retryable", Value: true},
				{Key: "latency_ms", Value: 12.5},
			},
			TraceID: "abababababababababababababababab",
			SpanID:  "1111111111111111",
			Flags:   1,
		},
		{
			Time:           time.Unix(0, 1700000001000000000).UTC(),
			ObservedTime:   time.Unix(0, 1700000001000000000).UTC(),
			SeverityNumber: severityInfo,
			SeverityText:   "INFO",
			Body:           "cache hit",
			Attributes: []Attr{
				{Key: "coordinate", Value: "npm:left-pad@1.3.0"},
			},
		},
	}
}

func TestOTLPExporterGoldenEncoding(t *testing.T) {
	exp, err := NewOTLPExporter(OTLPConfig{
		Endpoint:  "http://collector:4318",
		Insecure:  true,
		Resource:  []Attr{String("service.name", "pullthrough"), String("service.version", "1.2.3"), String("tenant", "team-a")},
		ScopeName: "github.com/blechschmidt/pullthrough-security/internal/otlplog",
	})
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}
	payload := exp.buildRequest(goldenRecords())
	got, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "golden", "export-request.json")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update-golden to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestOTLPExporterWireFormat(t *testing.T) {
	var got bytes.Buffer
	var ct, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		auth = r.Header.Get("Authorization")
		_, _ = got.ReadFrom(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exp, err := NewOTLPExporter(OTLPConfig{
		Endpoint: srv.URL,
		Insecure: true,
		Headers:  map[string]string{"Authorization": "Bearer tok"},
		Resource: []Attr{String("service.name", "pullthrough")},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := exp.Export(context.Background(), goldenRecords()); err != nil {
		t.Fatalf("export: %v", err)
	}
	if ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if auth != "Bearer tok" {
		t.Errorf("authorization = %q", auth)
	}

	var req otlpLogsRequest
	if err := json.Unmarshal(got.Bytes(), &req); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, got.String())
	}
	if len(req.ResourceLogs) != 1 || len(req.ResourceLogs[0].ScopeLogs) != 1 {
		t.Fatalf("unexpected shape: %+v", req)
	}
	rl := req.ResourceLogs[0]
	if len(rl.Resource.Attributes) != 1 || rl.Resource.Attributes[0].Key != "service.name" {
		t.Errorf("resource attrs = %+v", rl.Resource.Attributes)
	}
	recs := rl.ScopeLogs[0].LogRecords
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	r0 := recs[0]
	if r0.TimeUnixNano != "1700000000000000000" {
		t.Errorf("timeUnixNano = %q", r0.TimeUnixNano)
	}
	if r0.SeverityNumber != severityError || r0.SeverityText != "ERROR" {
		t.Errorf("severity = %d/%q", r0.SeverityNumber, r0.SeverityText)
	}
	if r0.Body == nil || r0.Body.StringValue == nil || *r0.Body.StringValue != "upstream fetch failed" {
		t.Errorf("body = %+v", r0.Body)
	}
	if r0.TraceID != "abababababababababababababababab" || r0.SpanID != "1111111111111111" {
		t.Errorf("ids = %q/%q", r0.TraceID, r0.SpanID)
	}
	if r0.Flags != 1 {
		t.Errorf("flags = %d", r0.Flags)
	}
	// int64 attributes must serialize as strings per OTLP/JSON.
	var sawStatus, sawLatency bool
	for _, a := range r0.Attributes {
		switch a.Key {
		case "status":
			sawStatus = true
			if a.Value.IntValue == nil || *a.Value.IntValue != "502" {
				t.Errorf("status intValue = %+v", a.Value.IntValue)
			}
		case "latency_ms":
			sawLatency = true
			if a.Value.DoubleValue == nil || *a.Value.DoubleValue != 12.5 {
				t.Errorf("latency doubleValue = %+v", a.Value.DoubleValue)
			}
		}
	}
	if !sawStatus || !sawLatency {
		t.Errorf("missing typed attributes: status=%v latency=%v", sawStatus, sawLatency)
	}
}

func TestOTLPExporterRetryClassification(t *testing.T) {
	cases := []struct {
		status    int
		retryable bool
	}{
		{http.StatusOK, false}, // handled as success, never reaches classifier
		{http.StatusBadRequest, false},
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusServiceUnavailable, true},
	}
	for _, c := range cases {
		if c.status == http.StatusOK {
			continue
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
		}))
		exp, err := NewOTLPExporter(OTLPConfig{Endpoint: srv.URL, Insecure: true})
		if err != nil {
			srv.Close()
			t.Fatalf("new: %v", err)
		}
		err = exp.Export(context.Background(), goldenRecords())
		srv.Close()
		if err == nil {
			t.Errorf("status %d: expected error", c.status)
			continue
		}
		if isRetryable(err) != c.retryable {
			t.Errorf("status %d: isRetryable = %v, want %v", c.status, isRetryable(err), c.retryable)
		}
	}
}

func TestNormalizeLogsEndpoint(t *testing.T) {
	cases := []struct {
		in       string
		insecure bool
		want     string
		wantErr  bool
	}{
		{"http://c:4318", false, "http://c:4318/v1/logs", false},
		{"https://c:4318/v1/logs", false, "https://c:4318/v1/logs", false},
		{"c:4318", true, "http://c:4318/v1/logs", false},
		{"c:4318", false, "https://c:4318/v1/logs", false},
		{"", false, "", true},
		{"://bad", false, "", true},
	}
	for _, c := range cases {
		got, err := normalizeLogsEndpoint(c.in, c.insecure)
		if (err != nil) != c.wantErr {
			t.Errorf("normalize(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
