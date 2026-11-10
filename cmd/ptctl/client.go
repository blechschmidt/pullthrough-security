package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client is a thin, dependency-light HTTP client for the pull-through proxy. It
// targets two surfaces: the public gateway (mounted at /v1/<name>/...) used by
// the connectivity self-test, and the read-only admin API (mounted under the
// admin prefix, default /admin) used to retrieve findings and attestations. It
// is deliberately small so the binary reads like a reference SDK an integrator
// could lift into their own tooling.
type client struct {
	baseURL     string // normalized, no trailing slash
	adminPrefix string // normalized, leading slash, no trailing slash
	token       string
	tenant      string
	http        *http.Client
}

// newClient builds a client from the resolved global flags, returning a clear
// error when the proxy URL is missing or malformed (the single most common
// onboarding mistake).
func newClient(g globalFlags) (*client, error) {
	raw := strings.TrimSpace(g.url)
	if raw == "" {
		return nil, fmt.Errorf("the proxy URL is required: pass --url https://proxy.example.com or set PULLTHROUGH_URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", g.url, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL %q: missing host", g.url)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid proxy URL %q: scheme must be http or https", g.url)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if g.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via --insecure for self-signed dev proxies
	}
	timeout := g.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	base := strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/")
	prefix := "/" + strings.Trim(g.adminPrefix, "/")
	if prefix == "/" {
		prefix = "/admin"
	}

	return &client{
		baseURL:     base,
		adminPrefix: prefix,
		token:       strings.TrimSpace(g.token),
		tenant:      strings.TrimSpace(g.tenant),
		http:        &http.Client{Timeout: timeout, Transport: transport},
	}, nil
}

// gatewayURL builds an absolute URL into the public gateway for a path that
// already includes the /v1/<name>/ prefix.
func (c *client) gatewayURL(path string) string {
	return c.baseURL + "/" + strings.TrimLeft(path, "/")
}

// adminURL builds an absolute URL into the admin API, appending the supplied
// query parameters (skipping empty values so callers need not pre-filter).
func (c *client) adminURL(apiPath string, query map[string]string) string {
	u := c.baseURL + c.adminPrefix + "/" + strings.TrimLeft(apiPath, "/")
	if len(query) == 0 {
		return u
	}
	q := url.Values{}
	for k, v := range query {
		if v != "" {
			q.Set(k, v)
		}
	}
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	return u
}

// apiError carries an HTTP status and the server's message for a failed admin
// API call, so callers can special-case (e.g.) 404 without string matching.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("admin API rejected the request (HTTP %d): %s — pass a read-capable --token or set PULLTHROUGH_TOKEN", e.Status, msg)
	case http.StatusNotFound:
		return fmt.Sprintf("not found (HTTP %d): %s", e.Status, msg)
	default:
		return fmt.Sprintf("admin API error (HTTP %d): %s", e.Status, msg)
	}
}

// getJSON performs a GET against an absolute admin URL and decodes a JSON body
// into out. Non-2xx responses are surfaced as *apiError, extracting the admin
// API's {"error": "..."} envelope when present.
func (c *client) getJSON(u string, out any) error {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{Status: resp.StatusCode, Body: extractErrorMessage(body)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", u, err)
	}
	return nil
}

// postJSON performs a POST with a JSON body against an absolute admin URL and
// decodes the JSON response into out. Non-2xx responses are surfaced as
// *apiError carrying the server's message (and, for the query API, its stable
// error code is included in that message body).
func (c *client) postJSON(u string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("encoding request body: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &apiError{Status: resp.StatusCode, Body: extractErrorMessage(body)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", u, err)
	}
	return nil
}

// getText performs a GET against an absolute admin URL and returns the response
// body verbatim (for non-JSON surfaces such as the Markdown drift report).
// Non-2xx responses are surfaced as *apiError.
func (c *client) getText(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &apiError{Status: resp.StatusCode, Body: extractErrorMessage(body)}
	}
	return string(body), nil
}

// getRaw performs a GET against an absolute admin URL and returns the response
// body bytes verbatim along with the response headers (for binary/document
// surfaces such as the VEX export, whose detached signature travels in headers).
// Non-2xx responses are surfaced as *apiError.
func (c *client) getRaw(u string) ([]byte, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, &apiError{Status: resp.StatusCode, Body: extractErrorMessage(body)}
	}
	return body, resp.Header, nil
}

// authorize attaches the bearer token (when set) to a request. The same scheme
// works for both the gateway access-control layer and the admin API.
func (c *client) authorize(req *http.Request) {
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// extractErrorMessage pulls the message out of the admin API's standard
// {"error": "..."} body, falling back to the raw (trimmed) body.
func extractErrorMessage(body []byte) string {
	var env struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && env.Error != "" {
		return env.Error
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
