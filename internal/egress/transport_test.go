package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newGuardedClient builds an upstream.Client wired with the guard's transport
// hooks exactly as the production client pool does.
func newGuardedClient(t *testing.T, g *Guard) *upstream.Client {
	t.Helper()
	c, err := upstream.New(upstream.Options{
		WrapTransport: g.WrapRoundTripper,
		DialControl:   g.DialControl,
		CheckRedirect: g.CheckRedirect,
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return c
}

// localhostURL returns u with its host rewritten to "localhost" (preserving the
// port), so a request reaches the loopback test server via a *hostname* that the
// URL-level allowlist can permit while DNS still resolves it to 127.0.0.1.
func localhostURL(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	u.Host = "localhost:" + u.Port()
	return u.String()
}

// TestEndToEndAllowedFetch verifies the guard does not break a legitimate fetch:
// with the loopback test server explicitly excepted, the request succeeds.
func TestEndToEndAllowedFetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	g := mustGuard(t, Config{
		AllowedSchemes:          []string{"http"},
		BlockPrivateNetworks:    true,
		AllowedDestinationCIDRs: []string{"127.0.0.0/8"},
	}, Options{})

	c := newGuardedClient(t, g)
	resp, err := c.Do(context.Background(), upstream.Request{URL: ts.URL})
	if err != nil {
		t.Fatalf("expected success through the guard, got %v", err)
	}
	defer resp.Body.Close()
	if resp.Status != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.Status)
	}
}

// TestEndToEndRedirectToInternal proves the redirect policy re-checks every hop:
// the first hop (the test server) is permitted, but its 302 to the cloud-metadata
// service is refused on the redirected RoundTrip.
func TestEndToEndRedirectToInternal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer ts.Close()

	g := mustGuard(t, Config{
		AllowedSchemes:          []string{"http"},
		BlockPrivateNetworks:    true,
		AllowedDestinationCIDRs: []string{"127.0.0.0/8"}, // reach the test server only
		FollowRedirects:         true,
		MaxRedirects:            5,
	}, Options{})

	c := newGuardedClient(t, g)
	_, err := c.Do(context.Background(), upstream.Request{URL: ts.URL})
	if err == nil {
		t.Fatal("expected the redirect to the metadata service to be blocked")
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockedError, got %v", err)
	}
	if be.Reason != ReasonMetadata {
		t.Fatalf("reason=%q, want metadata", be.Reason)
	}
}

// TestEndToEndDNSRebinding proves the dial-time re-validation: a hostname that
// passes the URL-level allowlist but resolves to a loopback address is refused at
// connect, with no window between the policy check and the TCP connect.
func TestEndToEndDNSRebinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// "localhost" is on the allowlist (so the URL check passes) but resolves to
	// 127.0.0.1, which the IP-range floor blocks at dial — no exception configured.
	g := mustGuard(t, Config{
		AllowedSchemes:       []string{"http"},
		Allowlist:            []string{"localhost"},
		BlockPrivateNetworks: true,
	}, Options{})

	c := newGuardedClient(t, g)
	target := localhostURL(t, ts.URL)
	_, err := c.Do(context.Background(), upstream.Request{URL: target})
	if err == nil {
		t.Fatalf("expected the rebinding to loopback (%s) to be blocked at dial", target)
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockedError, got %v", err)
	}
	if be.Reason != ReasonLoopback {
		t.Fatalf("reason=%q, want loopback", be.Reason)
	}
}

// TestEndToEndMaxRedirectCap proves the redirect chain is capped: a server that
// redirects to itself forever is stopped at the configured hop limit.
func TestEndToEndMaxRedirectCap(t *testing.T) {
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always redirect back to localhost (allowlisted, excepted) to loop.
		http.Redirect(w, r, localhostURL(t, ts.URL)+"/next", http.StatusFound)
	}))
	defer ts.Close()

	g := mustGuard(t, Config{
		AllowedSchemes:          []string{"http"},
		Allowlist:               []string{"localhost"},
		BlockPrivateNetworks:    true,
		AllowedDestinationCIDRs: []string{"127.0.0.0/8"},
		FollowRedirects:         true,
		MaxRedirects:            3,
	}, Options{})

	c := newGuardedClient(t, g)
	_, err := c.Do(context.Background(), upstream.Request{URL: localhostURL(t, ts.URL)})
	if err == nil {
		t.Fatal("expected the redirect loop to be capped")
	}
	var be *BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("expected *BlockedError, got %v", err)
	}
	if be.Reason != ReasonTooManyRedirects {
		t.Fatalf("reason=%q, want too_many_redirects", be.Reason)
	}
}

// TestEndToEndNoFollowRedirects verifies that with following disabled the
// redirect response is surfaced to the caller rather than followed.
func TestEndToEndNoFollowRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer ts.Close()

	g := mustGuard(t, Config{
		AllowedSchemes:          []string{"http"},
		BlockPrivateNetworks:    true,
		AllowedDestinationCIDRs: []string{"127.0.0.0/8"},
		FollowRedirects:         false,
	}, Options{})

	c := newGuardedClient(t, g)
	resp, err := c.Do(context.Background(), upstream.Request{URL: ts.URL})
	if err != nil {
		t.Fatalf("expected the 302 to be returned unfollowed, got %v", err)
	}
	defer resp.Body.Close()
	if resp.Status != http.StatusFound {
		t.Fatalf("status=%d, want 302 (unfollowed)", resp.Status)
	}
}
