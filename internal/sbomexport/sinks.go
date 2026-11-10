package sbomexport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Sink is one outbound destination for exported SBOM/finding documents. A sink
// delivers a single artifact's document; batching, retry, and backoff are the
// Service's responsibility. Implementations must be safe for concurrent use and
// must honor context cancellation.
type Sink interface {
	// Name is the operator-facing sink name (for logs and status).
	Name() string
	// Target is the stable metrics label identifying the sink kind
	// ("dependency-track" or "guac").
	Target() string
	// Upload delivers one artifact's document. It returns a retryable error
	// (wrapping *httpError with a 5xx/429 status, or a transport error) when the
	// Service should retry, and a non-retryable error otherwise.
	Upload(ctx context.Context, item ExportItem) error
}

// httpError records a non-2xx HTTP response so the retry predicate can decide
// whether the failure is transient.
type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	body := strings.TrimSpace(e.body)
	if len(body) > 256 {
		body = body[:256] + "…"
	}
	if body == "" {
		return fmt.Sprintf("http status %d", e.status)
	}
	return fmt.Sprintf("http status %d: %s", e.status, body)
}

// isRetryable reports whether a delivery error is worth retrying. HTTP 5xx and
// 429 are transient; other 4xx are permanent (a bad request / auth error will
// not fix itself). A transport-level error (no *httpError) is treated as
// transient.
func isRetryable(err error) bool {
	var he *httpError
	if errors.As(err, &he) {
		return he.status >= 500 || he.status == http.StatusTooManyRequests
	}
	return true
}

// newHTTPClient builds the outbound client the sinks share. The timeout bounds a
// single delivery attempt; retries are the Service's job.
func newHTTPClient(timeout time.Duration, skipVerify bool) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
	if skipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in for self-signed internal endpoints
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

// drainClose reads and discards a response body (bounded) then closes it, so the
// underlying connection can be reused.
func drainClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

// readBody reads a bounded prefix of a response body for error diagnostics.
func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return string(b)
}

// DependencyTrackConfig configures the OWASP Dependency-Track sink.
type DependencyTrackConfig struct {
	Name          string
	URL           string // base URL, e.g. https://dtrack.example.com
	APIKey        string
	AutoCreate    bool
	ParentProject string
	TLSSkipVerify bool
}

// DependencyTrackSink uploads CycloneDX BOMs to an OWASP Dependency-Track server
// via its PUT /api/v1/bom endpoint, with API-key auth and optional project
// auto-create. One BOM is uploaded per coordinate (project name/version).
type DependencyTrackSink struct {
	name       string
	endpoint   string
	apiKey     string
	autoCreate bool
	parent     string
	client     *http.Client
}

// NewDependencyTrackSink constructs a Dependency-Track sink. timeout bounds a
// single upload attempt.
func NewDependencyTrackSink(cfg DependencyTrackConfig, timeout time.Duration) *DependencyTrackSink {
	name := cfg.Name
	if strings.TrimSpace(name) == "" {
		name = "dependency-track"
	}
	return &DependencyTrackSink{
		name:       name,
		endpoint:   strings.TrimRight(cfg.URL, "/") + "/api/v1/bom",
		apiKey:     cfg.APIKey,
		autoCreate: cfg.AutoCreate,
		parent:     cfg.ParentProject,
		client:     newHTTPClient(timeout, cfg.TLSSkipVerify),
	}
}

func (s *DependencyTrackSink) Name() string   { return s.name }
func (s *DependencyTrackSink) Target() string { return "dependency-track" }

// dtRequest is the JSON body of the Dependency-Track BOM-upload API.
type dtRequest struct {
	ProjectName    string `json:"projectName"`
	ProjectVersion string `json:"projectVersion"`
	AutoCreate     bool   `json:"autoCreate"`
	ParentName     string `json:"parentName,omitempty"`
	BOM            string `json:"bom"`
}

func (s *DependencyTrackSink) Upload(ctx context.Context, item ExportItem) error {
	body := dtRequest{
		ProjectName:    item.ProjectName,
		ProjectVersion: item.ProjectVersion,
		AutoCreate:     s.autoCreate,
		ParentName:     s.parent,
		BOM:            base64.StdEncoding.EncodeToString(item.BOM),
	}
	enc, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("sbomexport: encoding dependency-track request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.endpoint, bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("sbomexport: building dependency-track request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if s.apiKey != "" {
		req.Header.Set("X-Api-Key", s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sbomexport: dependency-track upload: %w", err)
	}
	defer drainClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode, body: readBody(resp)}
	}
	return nil
}

// GUACConfig configures the GUAC ingestion sink.
type GUACConfig struct {
	Name          string
	URL           string // GUAC collector ingestion endpoint
	Token         string // optional bearer token
	DocumentType  string // "cyclonedx" (default) or "intoto"
	TLSSkipVerify bool
}

// GUACSink emits CycloneDX (or in-toto-wrapped) documents to a GUAC collector
// ingestion endpoint over HTTP. GUAC's collector accepts a document blob and
// infers the format; the sink posts the raw CycloneDX JSON (or, for the in-toto
// document type, an in-toto statement whose predicate is the BOM).
type GUACSink struct {
	name    string
	url     string
	token   string
	docType string
	client  *http.Client
}

// NewGUACSink constructs a GUAC ingestion sink. timeout bounds a single upload
// attempt.
func NewGUACSink(cfg GUACConfig, timeout time.Duration) *GUACSink {
	name := cfg.Name
	if strings.TrimSpace(name) == "" {
		name = "guac"
	}
	docType := strings.TrimSpace(cfg.DocumentType)
	if docType == "" {
		docType = "cyclonedx"
	}
	return &GUACSink{
		name:    name,
		url:     cfg.URL,
		token:   cfg.Token,
		docType: docType,
		client:  newHTTPClient(timeout, cfg.TLSSkipVerify),
	}
}

func (s *GUACSink) Name() string   { return s.name }
func (s *GUACSink) Target() string { return "guac" }

// guacDocument is the GUAC collector ingestion envelope: a document blob plus
// the source/collector provenance GUAC records for every ingested document.
type guacDocument struct {
	Blob      json.RawMessage `json:"blob"`
	Type      string          `json:"type"`
	Format    string          `json:"format"`
	Source    string          `json:"source"`
	Collector string          `json:"collector"`
}

// intotoStatement wraps a CycloneDX BOM as an in-toto predicate so GUAC can
// ingest it on the in-toto document path.
type intotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []intotoSubject `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type intotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest,omitempty"`
}

func (s *GUACSink) Upload(ctx context.Context, item ExportItem) error {
	var blob json.RawMessage
	docType := "CYCLONEDX"
	switch s.docType {
	case "intoto":
		stmt := intotoStatement{
			Type:          "https://in-toto.io/Statement/v1",
			PredicateType: "https://cyclonedx.org/bom",
			Subject:       []intotoSubject{{Name: item.ProjectName}},
			Predicate:     json.RawMessage(item.BOM),
		}
		if alg, digest, ok := splitDigest(item.Digest); ok {
			stmt.Subject[0].Digest = map[string]string{alg: digest}
		}
		enc, err := json.Marshal(stmt)
		if err != nil {
			return fmt.Errorf("sbomexport: encoding in-toto statement: %w", err)
		}
		blob = enc
		docType = "ITE6"
	default:
		blob = json.RawMessage(item.BOM)
	}

	env := guacDocument{
		Blob:      blob,
		Type:      docType,
		Format:    "JSON",
		Source:    "pullthrough-security",
		Collector: "pullthrough-security",
	}
	enc, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("sbomexport: encoding guac document: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(enc))
	if err != nil {
		return fmt.Errorf("sbomexport: building guac request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sbomexport: guac ingestion: %w", err)
	}
	defer drainClose(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode, body: readBody(resp)}
	}
	return nil
}

// splitDigest splits a "sha256:abc…" digest into algorithm and hex. It returns
// ok=false when the input is not in algo:hex form.
func splitDigest(d string) (algo, hex string, ok bool) {
	i := strings.IndexByte(d, ':')
	if i <= 0 || i == len(d)-1 {
		return "", "", false
	}
	return d[:i], d[i+1:], true
}
