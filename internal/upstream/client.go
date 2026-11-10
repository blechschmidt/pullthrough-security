// Package upstream provides the shared outbound HTTP substrate used by every
// HTTP-based package backend (pip, npm, cargo, Go modules, NuGet, Docker/OCI,
// Git-over-HTTPS). It centralizes connection pooling, outbound TLS
// configuration, credential injection, conditional requests, and a small,
// proxy-friendly response abstraction so individual backends do not each
// re-implement HTTP plumbing.
//
// A Client is safe for concurrent use and should be shared across requests to
// the same upstream so its connection pool is reused.
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"syscall"
	"time"
)

// DefaultUserAgent is sent when Options.UserAgent is empty.
const DefaultUserAgent = "pullthrough-security/1"

// TLSOptions configures outbound TLS for upstream connections.
type TLSOptions struct {
	// CACertFile, when set, is a PEM bundle of additional root CAs trusted for
	// verifying upstream certificates (in addition to the system pool).
	CACertFile string
	// InsecureSkipVerify disables upstream certificate verification. It is unsafe
	// and intended only for testing against self-signed endpoints.
	InsecureSkipVerify bool
	// MinVersion is the minimum acceptable TLS version: "1.0", "1.1", "1.2", or
	// "1.3". Defaults to "1.2".
	MinVersion string
	// VerifyConnection, when non-nil, is installed as tls.Config.VerifyConnection
	// and runs on every completed handshake, in addition to the standard chain
	// verification. It is the seam through which the per-upstream certificate/CA
	// pinning guard (internal/tlspin, Task 128) enforces that a served artifact is
	// never fetched over a connection whose certificate chain does not satisfy the
	// configured pin: a non-nil error aborts the handshake fail-closed.
	VerifyConnection func(cs tls.ConnectionState) error
}

// Options configures a Client.
type Options struct {
	TLS TLSOptions
	// DialTimeout bounds establishing a TCP connection. Defaults to 15s.
	DialTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for upstream response headers after
	// the request is written. Zero means no specific limit (the request context
	// still applies). Defaults to 30s.
	ResponseHeaderTimeout time.Duration
	// IdleConnTimeout bounds how long an idle keep-alive connection is retained.
	// Defaults to 90s.
	IdleConnTimeout time.Duration
	// TLSHandshakeTimeout bounds the TLS handshake. Defaults to 10s.
	TLSHandshakeTimeout time.Duration
	// MaxIdleConns and MaxIdleConnsPerHost bound the connection pool. Defaults to
	// 100 and 16 respectively.
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	// MaxConnsPerHost bounds the total connections (active + idle) per upstream
	// host. Zero (the default) means unlimited, so a slow upstream rather than a
	// client-side cap governs throughput; a positive value protects a fragile
	// upstream from connection storms under high client concurrency.
	MaxConnsPerHost int
	// KeepAlive is the TCP keep-alive probe interval for outbound connections.
	// Zero uses the built-in default (30s); a negative value disables keep-alive
	// probes. It does not disable connection reuse (see DisableKeepAlives).
	KeepAlive time.Duration
	// ExpectContinueTimeout bounds waiting for an upstream's 100-continue after
	// request headers are written with an Expect: 100-continue. Defaults to 1s.
	ExpectContinueTimeout time.Duration
	// DisableKeepAlives, when true, prevents connection reuse: a fresh connection
	// is dialed for every request and closed after it. It defeats the pool and is
	// intended only for debugging or a broken upstream.
	DisableKeepAlives bool
	// DisableHTTP2, when true, suppresses the opportunistic HTTP/2 upgrade on TLS
	// upstreams (the transport otherwise sets ForceAttemptHTTP2). Use only to work
	// around an upstream whose HTTP/2 implementation is broken.
	DisableHTTP2 bool
	// UserAgent is sent on every request. Defaults to DefaultUserAgent.
	UserAgent string

	// ConnMetrics, when non-nil, accumulates connection-pool lifecycle statistics
	// (dials, dial latency, reuse, open/idle pool size, closes) for this client.
	// A single ConnMetrics is typically shared across every client the process
	// builds so the figures aggregate the whole fetch path.
	ConnMetrics *ConnMetrics

	// The hooks below are the seam through which the egress/SSRF guard
	// (internal/egress) interposes uniformly on every backend. They are optional;
	// nil leaves the transport unguarded (the historical behavior).

	// WrapTransport, when non-nil, wraps the *http.Transport this Client builds and
	// returns the RoundTripper actually used. The egress guard installs a wrapper
	// that re-validates the destination URL's scheme and host on the initial
	// request and on every redirect hop (each hop is a fresh RoundTrip).
	WrapTransport func(base http.RoundTripper) http.RoundTripper
	// DialControl, when non-nil, is installed as the dialer's ControlContext hook.
	// It is invoked with the *resolved* network and IP:port immediately before each
	// TCP connect, so the egress guard can re-validate the destination IP after DNS
	// resolution and defeat DNS-rebinding. A non-nil error aborts the connection
	// (fail-closed).
	DialControl func(ctx context.Context, network, address string) error
	// CheckRedirect, when non-nil, overrides the HTTP client's redirect policy so
	// the guard can re-check each hop and cap the redirect chain.
	CheckRedirect func(req *http.Request, via []*http.Request) error
}

// Credentials authenticates the proxy to an upstream. The proxy injects its own
// configured credentials on outbound requests; it never forwards a client's
// inbound credentials. Token takes precedence over Username/Password when both
// are supplied.
type Credentials struct {
	Username string
	Password string
	// Token is a bearer token. When set it is sent as "Authorization: Bearer
	// <token>" and Username/Password are ignored.
	Token string
}

// apply injects the credentials onto an outbound request, unless an Authorization
// header is already present.
func (c Credentials) apply(req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		return
	}
	switch {
	case c.Token != "":
		req.Header.Set("Authorization", "Bearer "+c.Token)
	case c.Username != "" || c.Password != "":
		req.SetBasicAuth(c.Username, c.Password)
	}
}

// IsZero reports whether no credentials are configured.
func (c Credentials) IsZero() bool {
	return c.Username == "" && c.Password == "" && c.Token == ""
}

// Doer performs an upstream request. *Client is the concrete implementation;
// the interface is the seam that lets a health-aware multi-mirror pool
// (internal/upstreampool) wrap the client transparently so backends fail over
// across equivalent mirror endpoints without knowing the pool exists.
type Doer interface {
	Do(ctx context.Context, r Request) (*Response, error)
}

// Client is a configured HTTP client for fetching from a single upstream class.
type Client struct {
	hc        *http.Client
	userAgent string
	// connTrace, when non-nil, is attached to every request's context so the
	// shared ConnMetrics observes connection acquisition and idle-pool activity.
	// It is immutable after construction and safe to share across requests.
	connTrace *httptrace.ClientTrace
}

var _ Doer = (*Client)(nil)

// New constructs a Client from opts, building an *http.Transport with the
// requested TLS configuration and connection-pool bounds.
func New(opts Options) (*Client, error) {
	tlsCfg, err := buildTLSConfig(opts.TLS)
	if err != nil {
		return nil, err
	}

	dialTimeout := orDuration(opts.DialTimeout, 15*time.Second)
	keepAlive := 30 * time.Second
	if opts.KeepAlive != 0 {
		// A negative value is meaningful here (disable probes), so only a literal
		// zero falls back to the default — unlike the orDuration knobs.
		keepAlive = opts.KeepAlive
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}
	if opts.DialControl != nil {
		dialControl := opts.DialControl
		dialer.ControlContext = func(ctx context.Context, network, address string, _ syscall.RawConn) error {
			return dialControl(ctx, network, address)
		}
	}
	// Instrument the dial so new-connection count, dial latency, and open/closed
	// pool size are observed. The wrapper preserves the ControlContext hook above
	// (it runs inside the base DialContext), so the egress guard is unaffected.
	dial := dialer.DialContext
	if opts.ConnMetrics != nil {
		dial = opts.ConnMetrics.instrumentDial(dial)
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial,
		ForceAttemptHTTP2:     !opts.DisableHTTP2,
		DisableKeepAlives:     opts.DisableKeepAlives,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   orDuration(opts.TLSHandshakeTimeout, 10*time.Second),
		ResponseHeaderTimeout: orDuration(opts.ResponseHeaderTimeout, 30*time.Second),
		IdleConnTimeout:       orDuration(opts.IdleConnTimeout, 90*time.Second),
		MaxIdleConns:          orInt(opts.MaxIdleConns, 100),
		MaxIdleConnsPerHost:   orInt(opts.MaxIdleConnsPerHost, 16),
		MaxConnsPerHost:       opts.MaxConnsPerHost, // 0 == unlimited (Go default)
		ExpectContinueTimeout: orDuration(opts.ExpectContinueTimeout, 1*time.Second),
	}

	ua := opts.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}

	// Interpose the egress guard's RoundTripper (URL-level scheme/host checks on
	// every request and redirect hop) when configured.
	var rt http.RoundTripper = transport
	if opts.WrapTransport != nil {
		rt = opts.WrapTransport(transport)
	}

	var connTrace *httptrace.ClientTrace
	if opts.ConnMetrics != nil {
		connTrace = opts.ConnMetrics.trace()
	}

	return &Client{
		hc: &http.Client{
			Transport: rt,
			// CheckRedirect, when supplied, lets the egress guard cap the redirect
			// chain and re-check each hop.
			CheckRedirect: opts.CheckRedirect,
			// No client-level timeout: streaming large artifacts can legitimately
			// run long. Cancellation is driven by the request context instead.
		},
		userAgent: ua,
		connTrace: connTrace,
	}, nil
}

// NewWithHTTPClient wraps a pre-built *http.Client. It is primarily a testing
// seam (e.g. to inject an httptest server's client) but is also useful for
// callers that need full control over the transport.
func NewWithHTTPClient(hc *http.Client, userAgent string) *Client {
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	return &Client{hc: hc, userAgent: userAgent}
}

// Request describes a single upstream fetch.
type Request struct {
	// URL is the absolute upstream URL.
	URL string
	// Method defaults to GET when empty.
	Method string
	// Header carries additional request headers to send (e.g. Accept). Hop-by-hop
	// headers are ignored.
	Header http.Header
	// Creds, when non-zero, authenticates the request to the upstream.
	Creds Credentials
	// IfNoneMatch, when non-empty, makes the request conditional; a matching
	// upstream responds 304 and Response.NotModified is set.
	IfNoneMatch string
	// IfModifiedSince, when non-zero, adds an If-Modified-Since validator.
	IfModifiedSince time.Time
	// Body is the request body for non-GET methods; nil otherwise.
	Body io.Reader
}

// Response is a proxy-oriented view of an upstream HTTP response. Body is the
// caller's to Close, except when NotModified is true (Body is nil) or when an
// error is returned.
type Response struct {
	Status        int
	Header        http.Header
	Body          io.ReadCloser
	ContentLength int64
	ContentType   string
	ETag          string
	LastModified  string
	NotModified   bool
}

// IsSuccess reports a 2xx status.
func (r *Response) IsSuccess() bool { return r.Status >= 200 && r.Status < 300 }

// Do performs the request. It returns an error only for transport-level
// failures (DNS, connection, TLS, context cancellation); any HTTP status,
// including 4xx/5xx, is returned as a Response for the caller to interpret. A
// 304 response is normalized into Response.NotModified with a closed, nil Body.
func (c *Client) Do(ctx context.Context, r Request) (*Response, error) {
	if strings.TrimSpace(r.URL) == "" {
		return nil, errors.New("upstream: request URL is required")
	}
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}

	// Attach the connection-pool trace so acquisition/reuse and idle-pool activity
	// are recorded. httptrace propagates through redirect follow-ups, and the
	// trace lives in the request context so it survives the egress guard's
	// RoundTripper wrapping.
	if c.connTrace != nil {
		ctx = httptrace.WithClientTrace(ctx, c.connTrace)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.URL, r.Body)
	if err != nil {
		return nil, fmt.Errorf("upstream: building request: %w", err)
	}

	for k, vs := range r.Header {
		if isHopByHop(k) {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if r.IfNoneMatch != "" {
		req.Header.Set("If-None-Match", r.IfNoneMatch)
	}
	if !r.IfModifiedSince.IsZero() {
		req.Header.Set("If-Modified-Since", r.IfModifiedSince.UTC().Format(http.TimeFormat))
	}
	r.Creds.apply(req)

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream: fetching %s: %w", r.URL, err)
	}

	out := &Response{
		Status:        resp.StatusCode,
		Header:        resp.Header,
		ContentLength: resp.ContentLength,
		ContentType:   resp.Header.Get("Content-Type"),
		ETag:          resp.Header.Get("ETag"),
		LastModified:  resp.Header.Get("Last-Modified"),
	}

	if resp.StatusCode == http.StatusNotModified {
		// Drain and close: there is no body to stream to the caller.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		out.NotModified = true
		return out, nil
	}

	out.Body = resp.Body
	return out, nil
}

// buildTLSConfig translates TLSOptions into a *tls.Config.
func buildTLSConfig(opts TLSOptions) (*tls.Config, error) {
	minVersion, err := parseTLSVersion(opts.MinVersion)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:         minVersion,
		InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // opt-in for self-signed test upstreams
	}
	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("upstream: reading CA bundle %q: %w", opts.CACertFile, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream: no certificates found in CA bundle %q", opts.CACertFile)
		}
		cfg.RootCAs = pool
	}
	// Certificate/CA pinning (Task 128): an additional constraint applied after
	// the standard chain verification (or in place of it, when InsecureSkipVerify
	// replaces the system trust with a pin). A non-nil error aborts the handshake.
	if opts.VerifyConnection != nil {
		cfg.VerifyConnection = opts.VerifyConnection
	}
	return cfg, nil
}

func parseTLSVersion(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.0":
		return tls.VersionTLS10, nil
	default:
		return 0, fmt.Errorf("upstream: unsupported TLS minVersion %q", v)
	}
}

// hopByHop holds the connection-management headers that must not be forwarded
// between the proxy and either peer (RFC 7230 §6.1).
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func isHopByHop(h string) bool { return hopByHop[strings.ToLower(h)] }

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
