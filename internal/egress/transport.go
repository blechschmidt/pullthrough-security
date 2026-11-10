package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// CheckURL validates the scheme and host of u under the policy for the tenant
// resolved from ctx, plus — when the host is an IP literal — the private-network
// floor. It returns nil when the request is permitted, otherwise a *BlockedError
// that has already been recorded (counter + notification + audit). It is invoked
// on the initial request and again on every redirect hop.
func (g *Guard) CheckURL(ctx context.Context, u *url.URL) *BlockedError {
	if !g.Enabled() {
		return nil
	}
	if u == nil {
		be := &BlockedError{Reason: ReasonInvalidURL, Detail: "nil request URL"}
		g.recordBlock(ctx, "", be, "")
		return be
	}
	tenant := g.tenantFor(ctx)

	g.mu.RLock()
	tr := g.tenants[tenant]
	g.mu.RUnlock()
	var tenantHTTPSOnly *bool
	if tr != nil {
		tenantHTTPSOnly = tr.httpsOnly
	}

	if !g.schemeAllowed(u.Scheme, tenantHTTPSOnly) {
		be := &BlockedError{
			Reason: ReasonSchemeNotAllowed,
			Host:   u.Hostname(),
			Detail: fmt.Sprintf("scheme %q is not permitted", u.Scheme),
		}
		g.recordBlock(ctx, tenant, be, u.String())
		return be
	}

	host := u.Hostname()
	if host == "" {
		be := &BlockedError{Reason: ReasonInvalidURL, Detail: "request URL has no host"}
		g.recordBlock(ctx, tenant, be, u.String())
		return be
	}

	if !g.hostAllowed(tr, host) {
		be := &BlockedError{
			Reason: ReasonHostNotAllowed,
			Host:   host,
			Detail: "host is not in the egress allowlist",
		}
		g.recordBlock(ctx, tenant, be, u.String())
		return be
	}

	// An IP-literal destination can be judged here immediately; a hostname is
	// re-validated after DNS resolution by the dial control (defeating rebinding).
	if g.blockPrivate {
		if ip := net.ParseIP(host); ip != nil {
			if reason, blocked := classifyIP(ip); blocked && !g.inExceptions(ip) {
				be := &BlockedError{
					Reason: reason,
					Host:   host,
					Detail: "destination IP is in a blocked range",
				}
				g.recordBlock(ctx, tenant, be, u.String())
				return be
			}
		}
	}

	g.recordAllow()
	return nil
}

// hostAllowed reports whether host passes the host allowlist. The semantics are
// additive and deny-by-default-once-enforced:
//
//   - an empty (unenforced) global allowlist permits any host (only the scheme
//     and IP-range floors apply);
//   - a non-empty global allowlist denies by default, permitting a host that
//     matches the global list or the calling tenant's additive list.
//
// A tenant allowlist can only *extend* the permitted set; it never restricts a
// caller below an open (unenforced) global allowlist.
func (g *Guard) hostAllowed(tr *tenantRules, host string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if !g.global.enforced() {
		return true
	}
	if g.global.matchHost(host) {
		return true
	}
	if tr != nil && tr.rules.enforced() && tr.rules.matchHost(host) {
		return true
	}
	return false
}

// CheckDialAddress re-validates the resolved destination of an outbound
// connection immediately before connect. address is the host:port the dialer is
// about to connect to, with host already an IP literal (the resolver ran). This
// is the DNS-rebinding defense: the IP validated here is the exact IP connected
// to, with no window for re-resolution.
func (g *Guard) CheckDialAddress(ctx context.Context, address string) *BlockedError {
	if !g.Enabled() || !g.blockPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		be := &BlockedError{
			Reason: ReasonResolveError,
			Host:   host,
			Detail: "dial destination is not an IP literal",
		}
		g.recordBlock(ctx, g.tenantFor(ctx), be, address)
		return be
	}
	if reason, blocked := classifyIP(ip); blocked && !g.inExceptions(ip) {
		be := &BlockedError{
			Reason: reason,
			Host:   host,
			Detail: "resolved destination IP is in a blocked range",
		}
		g.recordBlock(ctx, g.tenantFor(ctx), be, address)
		return be
	}
	g.recordAllow()
	return nil
}

// DialControl is the net.Dialer ControlContext adapter. It returns a non-nil
// error (the *BlockedError) to abort the connection fail-closed.
func (g *Guard) DialControl(ctx context.Context, network, address string) error {
	if be := g.CheckDialAddress(ctx, address); be != nil {
		return be
	}
	return nil
}

// roundTripper enforces the URL-level policy (scheme + host allowlist) on the
// initial request and on every redirect hop (each hop is a fresh RoundTrip).
type roundTripper struct {
	base  http.RoundTripper
	guard *Guard
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if be := rt.guard.CheckURL(req.Context(), req.URL); be != nil {
		return nil, be
	}
	return rt.base.RoundTrip(req)
}

// WrapRoundTripper wraps base so every request (and redirect hop) is URL-checked.
// A disabled guard returns base unchanged.
func (g *Guard) WrapRoundTripper(base http.RoundTripper) http.RoundTripper {
	if !g.Enabled() {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &roundTripper{base: base, guard: g}
}

// CheckRedirect is the http.Client.CheckRedirect policy: it enforces the
// follow/no-follow choice and the max-redirect cap. The per-hop URL and resolved
// IP are re-validated by the RoundTripper and the dial control respectively, so
// this only owns the chain-length and follow policy.
func (g *Guard) CheckRedirect(req *http.Request, via []*http.Request) error {
	if !g.Enabled() {
		if len(via) >= 10 { // mirror net/http's default cap
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	if !g.followRedirects {
		return http.ErrUseLastResponse
	}
	if len(via) >= g.maxRedirects {
		be := &BlockedError{
			Reason: ReasonTooManyRedirects,
			Host:   req.URL.Hostname(),
			Detail: fmt.Sprintf("redirect chain exceeded the %d-hop cap", g.maxRedirects),
		}
		g.recordBlock(req.Context(), g.tenantFor(req.Context()), be, req.URL.String())
		return be
	}
	return nil
}
