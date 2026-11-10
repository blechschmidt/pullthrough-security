package tracing

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

// OTLPExporter is a vendored-thin OpenTelemetry exporter speaking OTLP over HTTP
// with the protobuf-JSON encoding the OpenTelemetry Collector accepts at
// /v1/traces. JSON (rather than the binary protobuf encoding or the gRPC
// transport) keeps the exporter dependency-free while remaining wire-compatible
// with the standard collector, Jaeger, and Tempo OTLP receivers.
type OTLPExporter struct {
	client    *http.Client
	endpoint  string // fully-qualified traces URL, e.g. http://collector:4318/v1/traces
	headers   map[string]string
	resource  []Attr
	scopeName string
}

// OTLPConfig configures the OTLP/HTTP exporter.
type OTLPConfig struct {
	// Endpoint is the collector base URL or full traces URL. A base URL (no
	// /v1/traces path) has the standard signal path appended.
	Endpoint string
	// Insecure, when the endpoint has no scheme, selects http:// over https://.
	Insecure bool
	// Headers are sent on every export request (e.g. authorization).
	Headers map[string]string
	// Resource are the resource-level attributes (service.name, etc.).
	Resource []Attr
	// ScopeName names the instrumentation scope reported with every span.
	ScopeName string
	// Timeout bounds a single export request. Defaults to 10s.
	Timeout time.Duration
	// TLSSkipVerify disables server-certificate verification (test/dev only).
	TLSSkipVerify bool
}

const defaultExportTimeout = 10 * time.Second

// NewOTLPExporter builds an OTLP/HTTP exporter, normalizing the endpoint into a
// full /v1/traces URL.
func NewOTLPExporter(cfg OTLPConfig) (*OTLPExporter, error) {
	endpoint, err := normalizeTracesEndpoint(cfg.Endpoint, cfg.Insecure)
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
		scope = "github.com/blechschmidt/pullthrough-security/internal/tracing"
	}
	return &OTLPExporter{
		client:    &http.Client{Timeout: timeout, Transport: transport},
		endpoint:  endpoint,
		headers:   cfg.Headers,
		resource:  cfg.Resource,
		scopeName: scope,
	}, nil
}

// normalizeTracesEndpoint resolves the configured endpoint to a full traces URL.
// A bare host:port or scheme-less host is given a scheme (http when insecure,
// else https); an endpoint without the OTLP signal path has /v1/traces appended.
func normalizeTracesEndpoint(endpoint string, insecure bool) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("tracing: OTLP endpoint is empty")
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
		return "", fmt.Errorf("tracing: invalid OTLP endpoint %q: %w", endpoint, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("tracing: OTLP endpoint %q has no host", endpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/traces"
	}
	return u.String(), nil
}

// ExportSpans marshals the batch into an OTLP/HTTP JSON request and POSTs it to
// the collector. A non-2xx response is an error so the Provider can count it.
func (e *OTLPExporter) ExportSpans(ctx context.Context, spans []SpanData) error {
	if len(spans) == 0 {
		return nil
	}
	payload := e.buildRequest(spans)
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("tracing: marshaling OTLP payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("tracing: building OTLP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("tracing: posting spans to %s: %w", e.endpoint, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("tracing: collector returned status %d", resp.StatusCode)
	}
	return nil
}

// Shutdown is a no-op for the stateless HTTP exporter.
func (e *OTLPExporter) Shutdown(context.Context) error { return nil }

// buildRequest assembles the OTLP ExportTraceServiceRequest JSON structure.
func (e *OTLPExporter) buildRequest(spans []SpanData) otlpExportRequest {
	otlpSpans := make([]otlpSpan, 0, len(spans))
	for _, sd := range spans {
		otlpSpans = append(otlpSpans, encodeSpan(sd))
	}
	return otlpExportRequest{
		ResourceSpans: []otlpResourceSpans{{
			Resource: otlpResource{Attributes: encodeAttrs(e.resource)},
			ScopeSpans: []otlpScopeSpans{{
				Scope: otlpScope{Name: e.scopeName},
				Spans: otlpSpans,
			}},
		}},
	}
}

// --- OTLP/JSON wire structures (subset of trace.proto) ---

type otlpExportRequest struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	Kind              int            `json:"kind"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Events            []otlpEvent    `json:"events,omitempty"`
	Status            *otlpStatus    `json:"status,omitempty"`
}

type otlpEvent struct {
	TimeUnixNano string         `json:"timeUnixNano"`
	Name         string         `json:"name"`
	Attributes   []otlpKeyValue `json:"attributes,omitempty"`
}

type otlpStatus struct {
	Message string `json:"message,omitempty"`
	Code    int    `json:"code,omitempty"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

// otlpAnyValue is the OTLP AnyValue union. Per the protobuf-JSON mapping, int64
// values are encoded as strings; trace/span ids are hex (not base64).
type otlpAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

func encodeSpan(sd SpanData) otlpSpan {
	s := otlpSpan{
		TraceID:           encodeTraceID(sd.SpanContext.TraceID),
		SpanID:            encodeSpanID(sd.SpanContext.SpanID),
		Name:              sd.Name,
		Kind:              int(sd.Kind),
		StartTimeUnixNano: strconv.FormatInt(sd.StartTime.UnixNano(), 10),
		EndTimeUnixNano:   strconv.FormatInt(sd.EndTime.UnixNano(), 10),
		Attributes:        encodeAttrs(sd.Attributes),
	}
	if sd.Parent.IsValid() {
		s.ParentSpanID = encodeSpanID(sd.Parent)
	}
	if sd.Status.Code != StatusUnset {
		s.Status = &otlpStatus{Code: int(sd.Status.Code), Message: sd.Status.Message}
	}
	for _, ev := range sd.Events {
		s.Events = append(s.Events, otlpEvent{
			TimeUnixNano: strconv.FormatInt(ev.Time.UnixNano(), 10),
			Name:         ev.Name,
			Attributes:   encodeAttrs(ev.Attributes),
		})
	}
	return s
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
