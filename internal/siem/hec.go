package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HECSink delivers events to a Splunk HTTP Event Collector endpoint. A batch is
// encoded as a stream of concatenated JSON event objects (Splunk's documented
// batched-event format), authenticated with the "Authorization: Splunk <token>"
// header.
type HECSink struct {
	name       string
	url        string
	token      string
	index      string
	source     string
	sourceType string
	host       string
	headers    map[string]string
	client     httpDoer
}

// HECOptions configures an HECSink.
type HECOptions struct {
	Name string
	// URL is the collector endpoint. A bare base URL (e.g. https://splunk:8088)
	// has the standard "/services/collector/event" path appended; a URL that
	// already names a path is used verbatim.
	URL string
	// Token authenticates to the collector; sent as "Authorization: Splunk ...".
	Token string
	// Index, Source, SourceType, Host populate the corresponding HEC envelope
	// fields when set; the collector's token defaults apply when empty.
	Index      string
	Source     string
	SourceType string
	Host       string
	// Headers are additional static headers (rarely needed).
	Headers map[string]string
	Timeout time.Duration
	TLS     TLSConfig
	// Client overrides the HTTP client (tests inject one); nil builds a default.
	Client httpDoer
}

// NewHECSink constructs a Splunk HEC sink.
func NewHECSink(opts HECOptions) (*HECSink, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("siem: hec sink requires a name")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("siem: hec sink %q requires a url", opts.Name)
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, fmt.Errorf("siem: hec sink %q requires a token", opts.Name)
	}
	client := opts.Client
	if client == nil {
		tlsCfg, err := opts.TLS.build()
		if err != nil {
			return nil, err
		}
		client = newHTTPClient(opts.Timeout, tlsCfg)
	}
	var headers map[string]string
	if len(opts.Headers) > 0 {
		headers = make(map[string]string, len(opts.Headers))
		for k, v := range opts.Headers {
			headers[k] = v
		}
	}
	sourceType := opts.SourceType
	if sourceType == "" {
		sourceType = "pullthrough:security"
	}
	return &HECSink{
		name:       opts.Name,
		url:        normalizeHECURL(opts.URL),
		token:      opts.Token,
		index:      opts.Index,
		source:     opts.Source,
		sourceType: sourceType,
		host:       opts.Host,
		headers:    headers,
		client:     client,
	}, nil
}

// normalizeHECURL appends the standard event path to a bare base URL.
func normalizeHECURL(raw string) string {
	trimmed := strings.TrimRight(raw, "/")
	if strings.Contains(strings.TrimPrefix(strings.TrimPrefix(trimmed, "https://"), "http://"), "/") {
		// The URL already carries a path component beyond the host.
		return raw
	}
	return trimmed + "/services/collector/event"
}

func (s *HECSink) Name() string { return s.name }
func (s *HECSink) Kind() string { return "splunk_hec" }
func (s *HECSink) Close() error { return nil }

// hecEnvelope is the per-event HEC document: Splunk metadata fields plus the
// structured event payload.
type hecEnvelope struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host,omitempty"`
	Source     string         `json:"source,omitempty"`
	SourceType string         `json:"sourcetype,omitempty"`
	Index      string         `json:"index,omitempty"`
	Event      map[string]any `json:"event"`
}

// DeliverBatch encodes the batch as concatenated HEC envelopes and posts them.
func (s *HECSink) DeliverBatch(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range batch {
		env := hecEnvelope{
			Time:       hecTime(ev.Time),
			Host:       s.host,
			Source:     s.source,
			SourceType: s.sourceType,
			Index:      s.index,
			Event:      hecEventPayload(ev),
		}
		if err := enc.Encode(env); err != nil {
			// A marshaling failure is a permanent (non-retryable) programming error.
			return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
		}
	}
	return s.post(ctx, buf.Bytes())
}

// hecEventPayload flattens an Event into the HEC "event" object.
func hecEventPayload(ev Event) map[string]any {
	payload := map[string]any{
		"source_stream": string(ev.Source),
		"severity":      string(ev.Severity),
		"category":      ev.Category,
		"name":          ev.Name,
		"timestamp":     ev.Time.UTC().Format(time.RFC3339Nano),
		"product":       "pullthrough-security",
	}
	if ev.Outcome != "" {
		payload["outcome"] = ev.Outcome
	}
	if ev.Subject != "" {
		payload["subject"] = ev.Subject
	}
	if ev.Message != "" {
		payload["message"] = ev.Message
	}
	if len(ev.Fields) > 0 {
		fields := make(map[string]any, len(ev.Fields))
		for k, v := range ev.Fields {
			fields[k] = v
		}
		payload["fields"] = fields
	}
	return payload
}

// hecTime renders a time as Splunk's fractional epoch seconds.
func hecTime(t time.Time) float64 {
	return float64(t.UTC().UnixNano()) / float64(time.Second)
}

func (s *HECSink) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Splunk "+s.token)
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return &DeliveryError{
		Sink:      s.name,
		Status:    resp.StatusCode,
		Retryable: retryable,
		Err:       fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))),
	}
}
