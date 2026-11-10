package k8swebhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// HTTPSourceConfig configures a verdict source that reads the proxy's dossier
// over HTTP, for a split deployment where the webhook runs separately from the
// proxy. It reuses the proxy's existing admin dossier endpoint
// (GET <baseURL>/api/dossier) and its bearer-token / TLS conventions.
type HTTPSourceConfig struct {
	// BaseURL is the admin API base, e.g. "https://pullthrough.pullthrough.svc/admin".
	BaseURL string
	// Token is the admin bearer token (or an RBAC token with read capability).
	Token string
	// CACertFile pins the proxy's serving CA for the TLS connection. Empty uses
	// the system roots.
	CACertFile string
	// InsecureSkipVerify disables TLS verification (test/dev only).
	InsecureSkipVerify bool
	// Timeout bounds a single dossier request. 0 uses 5s.
	Timeout time.Duration
}

// HTTPSource resolves verdicts by calling the proxy's /api/dossier endpoint.
type HTTPSource struct {
	base   string
	token  string
	client *http.Client
}

// NewHTTPSource builds an HTTPSource from its config.
func NewHTTPSource(cfg HTTPSourceConfig) (*HTTPSource, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("k8swebhook: dossier source baseURL is required")
	}
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("k8swebhook: invalid dossier source baseURL %q: %w", base, err)
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // opt-in for dev
	if f := strings.TrimSpace(cfg.CACertFile); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("k8swebhook: reading dossier CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("k8swebhook: dossier CA file %q contained no certificates", f)
		}
		tlsCfg.RootCAs = pool
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &HTTPSource{
		base:  base,
		token: strings.TrimSpace(cfg.Token),
		client: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Verdict implements VerdictSource against the remote admin dossier endpoint.
func (s *HTTPSource) Verdict(ctx context.Context, tenant string, ref ImageRef, ecosystem string, stripRegistry bool) (Verdict, error) {
	name, version := ref.Coordinate(stripRegistry)
	q := url.Values{}
	q.Set("coordinate", name)
	if version != "" {
		q.Set("version", version)
	}
	if ecosystem != "" {
		q.Set("ecosystem", ecosystem)
	}
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	endpoint := s.base + "/api/dossier?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Verdict{}, fmt.Errorf("k8swebhook: building dossier request: %w", err)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("k8swebhook: dossier request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("k8swebhook: dossier endpoint returned %s", resp.Status)
	}
	var d dossier.Dossier
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Verdict{}, fmt.Errorf("k8swebhook: decoding dossier response: %w", err)
	}
	return verdictFromDossier(&d), nil
}
