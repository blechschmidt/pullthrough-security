package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// OCSFSink delivers events to an OCSF-aware HTTP ingestion endpoint (an AWS
// Security Lake custom-source collector, a Snowflake ingestion REST endpoint, or
// any OCSF HTTP gateway). Each batch is encoded as newline-delimited JSON
// (NDJSON) — one OCSF object per line — which is the de-facto wire format such
// collectors accept. Delivery reuses the same batching/retry/disk-spill
// transport and chain-safe sink composition as the HEC and syslog sinks; only
// the on-the-wire encoding differs.
type OCSFSink struct {
	name       string
	url        string
	authValue  string // full Authorization header value, e.g. "Bearer <token>"
	authHeader string // header carrying authValue (default "Authorization")
	headers    map[string]string
	client     httpDoer
	encoder    *ocsfEncoder

	mu           sync.Mutex
	byClass      map[string]uint64
	encodeErrors atomic.Uint64
}

// OCSFOptions configures an OCSFSink.
type OCSFOptions struct {
	Name string
	// URL is the ingestion endpoint; it is used verbatim (unlike HEC there is no
	// well-known path to append).
	URL string
	// Token, when set, is sent as the Authorization header value "Bearer
	// <token>" unless AuthHeader/AuthScheme override the header/scheme. Endpoints
	// authenticated by mTLS or a custom header may omit it and use Headers.
	Token string
	// AuthHeader overrides the header that carries the token (default
	// "Authorization").
	AuthHeader string
	// AuthScheme overrides the token prefix (default "Bearer"); set it to "" to
	// send the bare token.
	AuthScheme string
	// Headers are additional static HTTP headers.
	Headers map[string]string
	Timeout time.Duration
	TLS     TLSConfig
	// Encoder is the shared OCSF encoder (required; built from siem.ocsf config).
	Encoder *ocsfEncoder
	// Client overrides the HTTP client (tests inject one); nil builds a default.
	Client httpDoer
}

// NewOCSFSink constructs an OCSF HTTP sink.
func NewOCSFSink(opts OCSFOptions) (*OCSFSink, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("siem: ocsf sink requires a name")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("siem: ocsf sink %q requires a url", opts.Name)
	}
	if opts.Encoder == nil {
		return nil, fmt.Errorf("siem: ocsf sink %q requires an encoder", opts.Name)
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
	authHeader := opts.AuthHeader
	if authHeader == "" {
		authHeader = "Authorization"
	}
	var authValue string
	if strings.TrimSpace(opts.Token) != "" {
		scheme := opts.AuthScheme
		if scheme == "" && opts.AuthHeader == "" {
			scheme = "Bearer"
		}
		if scheme != "" {
			authValue = scheme + " " + opts.Token
		} else {
			authValue = opts.Token
		}
	}
	return &OCSFSink{
		name:       opts.Name,
		url:        opts.URL,
		authValue:  authValue,
		authHeader: authHeader,
		headers:    headers,
		client:     client,
		encoder:    opts.Encoder,
		byClass:    make(map[string]uint64),
	}, nil
}

func (s *OCSFSink) Name() string { return s.name }
func (s *OCSFSink) Kind() string { return "ocsf" }
func (s *OCSFSink) Close() error { return nil }

// OCSFStats is a snapshot of an OCSF sink's encoding telemetry.
type OCSFStats struct {
	// ByClass counts OCSF objects encoded, keyed by OCSF class_name.
	ByClass map[string]uint64
	// EncodeErrors counts events that failed to marshal to OCSF JSON.
	EncodeErrors uint64
}

// OCSFStats returns a point-in-time snapshot of this sink's OCSF telemetry.
func (s *OCSFSink) OCSFStats() OCSFStats {
	s.mu.Lock()
	byClass := make(map[string]uint64, len(s.byClass))
	for k, v := range s.byClass {
		byClass[k] = v
	}
	s.mu.Unlock()
	return OCSFStats{ByClass: byClass, EncodeErrors: s.encodeErrors.Load()}
}

// DeliverBatch encodes the batch as NDJSON OCSF objects and posts them.
func (s *OCSFSink) DeliverBatch(ctx context.Context, batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	counts := make(map[string]uint64, 4)
	for _, ev := range batch {
		obj := s.encoder.encode(ev)
		if err := enc.Encode(obj); err != nil {
			// A marshaling failure is a permanent (non-retryable) programming error.
			s.encodeErrors.Add(1)
			return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
		}
		if className, ok := obj["class_name"].(string); ok {
			counts[className]++
		}
	}
	s.recordClasses(counts)
	return s.post(ctx, buf.Bytes())
}

// recordClasses folds a batch's per-class encode counts into the sink's running
// totals.
func (s *OCSFSink) recordClasses(counts map[string]uint64) {
	if len(counts) == 0 {
		return
	}
	s.mu.Lock()
	for k, v := range counts {
		s.byClass[k] += v
	}
	s.mu.Unlock()
}

func (s *OCSFSink) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Sink: s.name, Retryable: false, Err: err}
	}
	// OCSF NDJSON is served as application/x-ndjson by convention.
	req.Header.Set("Content-Type", "application/x-ndjson")
	if s.authValue != "" {
		req.Header.Set(s.authHeader, s.authValue)
	}
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
