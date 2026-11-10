package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Docker Registry v2 (OCI distribution) authentication.
//
// Registries such as Docker Hub and GHCR guard the /v2 API with a token
// handshake (RFC 6750 bearer, the "Docker Registry v2 token" scheme):
//
//  1. The proxy requests a resource and receives 401 with a challenge header:
//     WWW-Authenticate: Bearer realm="https://auth.docker.io/token",
//     service="registry.docker.io",scope="repository:library/nginx:pull"
//  2. The proxy GETs realm?service=...&scope=..., authenticating with the
//     operator-configured credentials (or anonymously for public images), and
//     receives a short-lived bearer token.
//  3. The proxy retries the original request with Authorization: Bearer <token>.
//
// Tokens are scoped per repository and expire, so they are cached by scope and
// reused (and proactively attached) until they near expiry. Some registries
// answer with a plain "Basic" challenge instead; those are satisfied by
// applying the configured username/password directly.

// tokenSafetyMargin retires a cached token this long before its declared
// expiry, so an in-flight request does not race the upstream's clock.
const tokenSafetyMargin = 10 * time.Second

// defaultTokenTTL is assumed when the token endpoint omits expires_in.
const defaultTokenTTL = 60 * time.Second

// maxTokenResponseBytes bounds how much of a token endpoint response we read, so
// a hostile or misconfigured auth server cannot make us buffer unbounded data.
const maxTokenResponseBytes = 1 << 20 // 1 MiB

// authChallenge is a parsed WWW-Authenticate header.
type authChallenge struct {
	scheme  string // lowercased: "bearer" or "basic"
	realm   string
	service string
	scope   string
}

// tokenResponse is the JSON body returned by a registry token endpoint. Both
// "token" and "access_token" are in use across registries.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func (t tokenResponse) value() string {
	if t.Token != "" {
		return t.Token
	}
	return t.AccessToken
}

type cachedToken struct {
	value  string
	expiry time.Time
}

// authenticator performs the registry token handshake and caches the resulting
// bearer tokens by scope. It is safe for concurrent use.
type authenticator struct {
	client upstream.Doer
	creds  upstream.Credentials
	now    func() time.Time

	mu     sync.Mutex
	tokens map[string]cachedToken // keyed by scope
}

func newAuthenticator(client upstream.Doer, creds upstream.Credentials) *authenticator {
	return &authenticator{
		client: client,
		creds:  creds,
		now:    time.Now,
		tokens: make(map[string]cachedToken),
	}
}

// do executes req against the upstream, transparently performing the token
// handshake on a 401. scope is the repository scope derived from the request
// (e.g. "repository:library/nginx:pull"), used to look up and store cached
// tokens; it may be empty for endpoints without a natural scope (the challenge's
// own scope is then authoritative). The returned Response is the caller's to
// close unless NotModified.
func (a *authenticator) do(ctx context.Context, req upstream.Request, scope string) (*upstream.Response, error) {
	// Proactively attach a still-valid cached token for this scope so steady-state
	// traffic to a repository avoids a 401 round-trip per request.
	if tok, ok := a.cachedToken(scope); ok {
		req.Header = withAuthorization(req.Header, "Bearer "+tok)
	}

	resp, err := a.client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusUnauthorized {
		return resp, nil
	}

	// Authentication required (or our cached token was rejected): parse the
	// challenge, obtain fresh authorization, and retry exactly once.
	challenge, ok := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	drainClose(resp.Body)
	if !ok {
		// No actionable challenge; return the original 401 for the caller to relay.
		return a.client.Do(ctx, stripAuthorization(req))
	}

	authzValue, err := a.authorize(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}

	retry := req
	retry.Header = withAuthorization(req.Header, authzValue)
	// Credentials are conveyed via the explicit Authorization header; clear Creds
	// so the client does not also try to apply them.
	retry.Creds = upstream.Credentials{}
	return a.client.Do(ctx, retry)
}

// authorize satisfies a challenge, returning the Authorization header value to
// send on the retry. For Bearer it fetches (and caches) a token; for Basic it
// formats the configured credentials.
func (a *authenticator) authorize(ctx context.Context, c authChallenge, scope string) (string, error) {
	switch c.scheme {
	case "bearer":
		// Prefer the scope advertised by the challenge (authoritative); fall back
		// to the request-derived scope.
		tokenScope := c.scope
		if tokenScope == "" {
			tokenScope = scope
		}
		tok, err := a.fetchToken(ctx, c, tokenScope)
		if err != nil {
			return "", err
		}
		return "Bearer " + tok, nil
	case "basic":
		if a.creds.Username == "" && a.creds.Password == "" {
			return "", fmt.Errorf("docker: upstream requires Basic auth but no credentials are configured")
		}
		return "Basic " + basicAuthValue(a.creds.Username, a.creds.Password), nil
	default:
		return "", fmt.Errorf("docker: unsupported auth scheme %q", c.scheme)
	}
}

// fetchToken retrieves a bearer token from the challenge's realm, caching it
// under cacheScope for reuse until it nears expiry.
func (a *authenticator) fetchToken(ctx context.Context, c authChallenge, cacheScope string) (string, error) {
	if tok, ok := a.cachedToken(cacheScope); ok {
		return tok, nil
	}

	tokenURL, err := buildTokenURL(c)
	if err != nil {
		return "", err
	}

	resp, err := a.client.Do(ctx, upstream.Request{
		URL:    tokenURL,
		Method: http.MethodGet,
		Header: http.Header{"Accept": {"application/json"}},
		// The token endpoint authenticates the operator's account (or is
		// anonymous for public images). Credentials.apply sends a bearer Token if
		// configured, else Basic username/password.
		Creds: a.creds,
	})
	if err != nil {
		return "", fmt.Errorf("docker: requesting token from %s: %w", c.realm, err)
	}
	defer drainClose(resp.Body)

	if !resp.IsSuccess() {
		return "", fmt.Errorf("docker: token endpoint %s returned status %d", c.realm, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", fmt.Errorf("docker: reading token response: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("docker: decoding token response: %w", err)
	}
	value := tr.value()
	if value == "" {
		return "", fmt.Errorf("docker: token endpoint %s returned an empty token", c.realm)
	}

	a.storeToken(cacheScope, value, tr.ExpiresIn)
	return value, nil
}

func (a *authenticator) cachedToken(scope string) (string, bool) {
	if scope == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tok, ok := a.tokens[scope]
	if !ok || !a.now().Before(tok.expiry) {
		return "", false
	}
	return tok.value, true
}

func (a *authenticator) storeToken(scope, value string, expiresIn int) {
	if scope == "" {
		return // unscoped tokens are not safely reusable across repositories
	}
	ttl := time.Duration(expiresIn) * time.Second
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	ttl -= tokenSafetyMargin
	if ttl <= 0 {
		ttl = time.Second
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[scope] = cachedToken{value: value, expiry: a.now().Add(ttl)}
}

// buildTokenURL composes the realm with service and scope query parameters.
// SECURITY: the realm originates from the operator-configured upstream's
// challenge; we still constrain it to http(s) so a compromised or misconfigured
// upstream cannot redirect token requests to a non-HTTP locator.
func buildTokenURL(c authChallenge) (string, error) {
	if c.realm == "" {
		return "", fmt.Errorf("docker: auth challenge missing realm")
	}
	u, err := url.Parse(c.realm)
	if err != nil {
		return "", fmt.Errorf("docker: invalid token realm %q: %w", c.realm, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("docker: token realm must be http(s), got %q", u.Scheme)
	}
	q := u.Query()
	if c.service != "" {
		q.Set("service", c.service)
	}
	if c.scope != "" {
		q.Set("scope", c.scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// parseChallenge parses a WWW-Authenticate header value into an authChallenge.
// It understands the "Bearer" and "Basic" schemes and the comma-separated,
// optionally quoted key=value parameter list (RFC 7235 §4.1).
func parseChallenge(header string) (authChallenge, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return authChallenge{}, false
	}
	scheme, rest, _ := strings.Cut(header, " ")
	c := authChallenge{scheme: strings.ToLower(strings.TrimSpace(scheme))}
	if c.scheme != "bearer" && c.scheme != "basic" {
		return authChallenge{}, false
	}
	for _, kv := range splitParams(rest) {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch key {
		case "realm":
			c.realm = val
		case "service":
			c.service = val
		case "scope":
			c.scope = val
		}
	}
	return c, true
}

// splitParams splits a parameter list on commas that are not inside a quoted
// string, so a quoted value containing a comma (e.g. a multi-resource scope) is
// preserved intact.
func splitParams(s string) []string {
	var parts []string
	var b strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			b.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, strings.TrimSpace(b.String()))
	}
	return parts
}

// withAuthorization returns a copy of h with the Authorization header set to
// value, leaving the caller's header untouched.
func withAuthorization(h http.Header, value string) http.Header {
	out := cloneHeader(h)
	out.Set("Authorization", value)
	return out
}

// stripAuthorization returns a copy of req with any Authorization header and
// credentials removed, used to relay an unauthenticated request when no
// actionable challenge was offered.
func stripAuthorization(req upstream.Request) upstream.Request {
	out := req
	out.Header = cloneHeader(req.Header)
	out.Header.Del("Authorization")
	out.Creds = upstream.Credentials{}
	return out
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h)+1)
	for k, vs := range h {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func basicAuthValue(user, pass string) string {
	req := &http.Request{Header: make(http.Header)}
	req.SetBasicAuth(user, pass)
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
}

func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
