package otlplog

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OTLPExporter is a vendored-thin OpenTelemetry logs exporter speaking OTLP over
// HTTP with the protobuf-JSON encoding the OpenTelemetry Collector accepts at
// /v1/logs. As with the traces exporter (internal/tracing), JSON (rather than
// the binary protobuf encoding or the gRPC transport) keeps the exporter
// dependency-free while remaining wire-compatible with the standard collector,
// Loki's OTLP receiver, and Grafana/Tempo log ingestion.
type OTLPExporter struct {
	client    *http.Client
	endpoint  string // fully-qualified logs URL, e.g. http://collector:4318/v1/logs
	headers   map[string]string
	resource  []Attr
	scopeName string
}

// OTLPConfig configures the OTLP/HTTP logs exporter.
type OTLPConfig struct {
	// Endpoint is the collector base URL or full logs URL. A base URL (no
	// /v1/logs path) has the standard signal path appended.
	Endpoint string
	// Insecure, when the endpoint has no scheme, selects http:// over https://.
	Insecure bool
	// Headers are sent on every export request (e.g. an ingest token).
	Headers map[string]string
	// Resource are the resource-level attributes (service.name, tenant, etc.).
	Resource []Attr
	// ScopeName names the instrumentation scope reported with every record.
	ScopeName string
	// Timeout bounds a single export request. Defaults to 10s.
	Timeout time.Duration
	// TLSSkipVerify disables server-certificate verification (test/dev only).
	TLSSkipVerify bool
}

const (
	defaultExportTimeout = 10 * time.Second
	defaultScopeName     = "github.com/blechschmidt/pullthrough-security/internal/otlplog"
)

// Exporter is the sink finished log records are delivered to. The OTLP exporter
// implements it; tests substitute a recording exporter.
type Exporter interface {
	// Export delivers a batch of log records. It must not retain the slice after
	// returning. A returned error is classified by the forwarder for retry.
	Export(ctx context.Context, records []LogRecord) error
	// Shutdown flushes and releases the exporter's resources.
	Shutdown(ctx context.Context) error
}

// NewOTLPExporter builds an OTLP/HTTP logs exporter, normalizing the endpoint
// into a full /v1/logs URL.
func NewOTLPExporter(cfg OTLPConfig) (*OTLPExporter, error) {
	endpoint, err := normalizeLogsEndpoint(cfg.Endpoint, cfg.Insecure)
	if err != nil {
		return nil, err
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultExportTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opt-in for self-signed collectors
	}
	scope := cfg.ScopeName
	if scope == "" {
		scope = defaultScopeName
	}
	return &OTLPExporter{
		client:    &http.Client{Timeout: timeout, Transport: transport},
		endpoint:  endpoint,
		headers:   cfg.Headers,
		resource:  cfg.Resource,
		scopeName: scope,
	}, nil
}

// normalizeLogsEndpoint resolves the configured endpoint to a full logs URL. A
// bare host:port or scheme-less host is given a scheme (http when insecure, else
// https); an endpoint without the OTLP signal path has /v1/logs appended.
func normalizeLogsEndpoint(endpoint string, insecure bool) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("otlplog: OTLP endpoint is empty")
	}
	if !strings.Contains(endpoint, "://") {
		scheme := "https"
		if insecure {
			scheme = "http"
		}
		endpoint = scheme + "://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("otlplog: invalid OTLP endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("otlplog: OTLP endpoint %q has no host", endpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/logs"
	}
	return u.String(), nil
}

// Endpoint returns the normalized logs URL (for status surfaces).
func (e *OTLPExporter) Endpoint() string {
	if e == nil {
		return ""
	}
	return e.endpoint
}

// httpError reports a non-2xx response so the forwarder can retry on transient
// (429/5xx) collector failures while giving up on permanent (4xx) ones.
type httpError struct {
	status    int
	retryable bool
}

func (e *httpError) Error() string {
	return fmt.Sprintf("otlplog: collector returned status %d", e.status)
}

// Retryable reports whether the forwarder should retry delivery after this error.
func (e *httpError) Retryable() bool { return e.retryable }

// Export marshals the batch into an OTLP/HTTP JSON request and POSTs it to the
// collector. A non-2xx response is an error so the forwarder can retry (429/5xx)
// or drop (other 4xx) the batch.
func (e *OTLPExporter) Export(ctx context.Context, records []LogRecord) error {
	if len(records) == 0 {
		return nil
	}
	payload := e.buildRequest(records)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlplog: marshaling OTLP payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlplog: building OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		// Transport-level failures (connection refused, timeout) are transient.
		return fmt.Errorf("otlplog: posting logs to %s: %w", e.endpoint, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode, retryable: isRetryableStatus(resp.StatusCode)}
	}
	return nil
}

// isRetryableStatus treats 408/429 and all 5xx as transient.
func isRetryableStatus(status int) bool {
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status <= 599
}

// Shutdown is a no-op for the stateless HTTP exporter; the forwarder owns the
// lifecycle and performs the final flush.
func (e *OTLPExporter) Shutdown(context.Context) error { return nil }

// buildRequest assembles the OTLP ExportLogsServiceRequest JSON structure.
func (e *OTLPExporter) buildRequest(records []LogRecord) otlpLogsRequest {
	otlpRecords := make([]otlpLogRecord, 0, len(records))
	for _, r := range records {
		otlpRecords = append(otlpRecords, encodeRecord(r))
	}
	return otlpLogsRequest{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: encodeAttrs(e.resource)},
			ScopeLogs: []otlpScopeLogs{{
				Scope:      otlpScope{Name: e.scopeName},
				LogRecords: otlpRecords,
			}},
		}},
	}
}

// --- OTLP/JSON wire structures (subset of logs.proto) ---

type otlpLogsRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpScope struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// otlpLogRecord is the OTLP LogRecord. Per the protobuf-JSON mapping,
// fixed64/uint64 nanos are encoded as decimal strings, trace/span ids are hex
// (not base64), and the severity number is the numeric enum value.
type otlpLogRecord struct {
	TimeUnixNano         string         `json:"timeUnixNano,omitempty"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano,omitempty"`
	SeverityNumber       int            `json:"severityNumber,omitempty"`
	SeverityText         string         `json:"severityText,omitempty"`
	Body                 *otlpAnyValue  `json:"body,omitempty"`
	Attributes           []otlpKeyValue `json:"attributes,omitempty"`
	TraceID              string         `json:"traceId,omitempty"`
	SpanID               string         `json:"spanId,omitempty"`
	Flags                uint32         `json:"flags,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue is the OTLP AnyValue union. Per the protobuf-JSON mapping, int64
// values are encoded as strings.
type otlpAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

func encodeRecord(r LogRecord) otlpLogRecord {
	rec := otlpLogRecord{
		SeverityNumber: r.SeverityNumber,
		SeverityText:   r.SeverityText,
		Attributes:     encodeAttrs(r.Attributes),
		TraceID:        r.TraceID,
		SpanID:         r.SpanID,
		Flags:          r.Flags,
	}
	if r.Body != "" {
		body := r.Body
		rec.Body = &otlpAnyValue{StringValue: &body}
	}
	if !r.Time.IsZero() {
		rec.TimeUnixNano = strconv.FormatInt(r.Time.UnixNano(), 10)
	}
	if !r.ObservedTime.IsZero() {
		rec.ObservedTimeUnixNano = strconv.FormatInt(r.ObservedTime.UnixNano(), 10)
	}
	return rec
}

func encodeAttrs(attrs []Attr) []otlpKeyValue {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]otlpKeyValue, 0, len(attrs))
	for _, a := range attrs {
		if a.Key == "" {
			continue
		}
		out = append(out, otlpKeyValue{Key: a.Key, Value: encodeValue(a.Value)})
	}
	return out
}

func encodeValue(v any) otlpAnyValue {
	switch t := v.(type) {
	case string:
		return otlpAnyValue{StringValue: &t}
	case bool:
		return otlpAnyValue{BoolValue: &t}
	case int:
		s := strconv.FormatInt(int64(t), 10)
		return otlpAnyValue{IntValue: &s}
	case int64:
		s := strconv.FormatInt(t, 10)
		return otlpAnyValue{IntValue: &s}
	case float64:
		return otlpAnyValue{DoubleValue: &t}
	default:
		s := fmt.Sprintf("%v", v)
		return otlpAnyValue{StringValue: &s}
	}
}
