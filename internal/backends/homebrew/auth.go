package homebrew

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

// GitHub Packages (ghcr.io) guards the OCI /v2 blob API with the Docker
// Registry v2 token handshake (RFC 6750 bearer):
//
//  1. The proxy GETs a bottle blob and receives 401 with a challenge:
//     WWW-Authenticate: Bearer realm="https://ghcr.io/token",
//     service="ghcr.io",scope="repository:homebrew/core/wget:pull"
//  2. The proxy GETs realm?service=...&scope=... (anonymously for public
//     Homebrew bottles, or with operator credentials for a private tap) and
//     receives a short-lived bearer token.
//  3. The proxy retries the blob request with Authorization: Bearer <token>.
//
// Tokens are scoped per repository and expire, so they are cached by scope and
// reused (and proactively attached) until they near expiry. A redirect from the
// blob endpoint to blob storage carries its own signed query auth; Go's client
// strips the Authorization header on a cross-host redirect, so the bearer token
// is never leaked to the storage host.

const (
	// tokenSafetyMargin retires a cached token this long before its declared
	// expiry so an in-flight request does not race the upstream's clock.
	tokenSafetyMargin = 10 * time.Second
	// defaultTokenTTL is assumed when the token endpoint omits expires_in.
	defaultTokenTTL = 60 * time.Second
	// maxTokenResponseBytes bounds how much of a token response we read so a
	// hostile or misconfigured auth server cannot make us buffer unbounded data.
	maxTokenResponseBytes = 1 << 20 // 1 MiB
)

// authChallenge is a parsed WWW-Authenticate header.
type authChallenge struct {
	scheme  string // lowercased: "bearer" or "basic"
	realm   string
	service string
	scope   string
}

// tokenResponse is the JSON body a registry token endpoint returns. Both
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

// authenticator performs the ghcr token handshake and caches bearer tokens by
// scope. It is safe for concurrent use; the zero fields are set by newAuthenticator.
type authenticator struct {
	client upstream.Doer
	creds  upstream.Credentials
	now    func() time.Time

	mu     sync.Mutex
	tokens map[string]cachedToken // keyed by scope
	// onToken, when non-nil, fires once per successful token fetch (telemetry).
	onToken func()
}

func newAuthenticator(client upstream.Doer, creds upstream.Credentials, onToken func()) *authenticator {
	return &authenticator{
		client:  client,
		creds:   creds,
		now:     time.Now,
		tokens:  make(map[string]cachedToken),
		onToken: onToken,
	}
}

// do executes req against the upstream, transparently performing the token
// handshake on a 401. scope is the repository scope derived from the request
// ("repository:<repo>:pull"), used to look up and store cached tokens. The
// returned Response is the caller's to close unless NotModified.
func (a *authenticator) do(ctx context.Context, req upstream.Request, scope string) (*upstream.Response, error) {
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

	// Authentication required (or the cached token was rejected): parse the
	// challenge, obtain fresh authorization, and retry exactly once.
	challenge, ok := parseChallenge(resp.Header.Get("WWW-Authenticate"))
	drainClose(resp.Body)
	if !ok {
		return a.client.Do(ctx, stripAuthorization(req))
	}

	authzValue, err := a.authorize(ctx, challenge, scope)
	if err != nil {
		return nil, err
	}

	retry := req
	retry.Header = withAuthorization(req.Header, authzValue)
	// Authorization is conveyed via the explicit header; clear Creds so the
	// client does not also try to apply them.
	retry.Creds = upstream.Credentials{}
	return a.client.Do(ctx, retry)
}

// authorize satisfies a challenge, returning the Authorization header value to
// send on the retry.
func (a *authenticator) authorize(ctx context.Context, c authChallenge, scope string) (string, error) {
	switch c.scheme {
	case "bearer":
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
			return "", fmt.Errorf("homebrew: bottle registry requires Basic auth but no credentials are configured")
		}
		return "Basic " + basicAuthValue(a.creds.Username, a.creds.Password), nil
	default:
		return "", fmt.Errorf("homebrew: unsupported auth scheme %q", c.scheme)
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
		// The token endpoint authenticates the operator's account (or is anonymous
		// for public bottles).
		Creds: a.creds,
	})
	if err != nil {
		return "", fmt.Errorf("homebrew: requesting token from %s: %w", c.realm, err)
	}
	defer drainClose(resp.Body)

	if !resp.IsSuccess() {
		return "", fmt.Errorf("homebrew: token endpoint %s returned status %d", c.realm, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes))
	if err != nil {
		return "", fmt.Errorf("homebrew: reading token response: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("homebrew: decoding token response: %w", err)
	}
	value := tr.value()
	if value == "" {
		return "", fmt.Errorf("homebrew: token endpoint %s returned an empty token", c.realm)
	}

	a.storeToken(cacheScope, value, tr.ExpiresIn)
	if a.onToken != nil {
		a.onToken()
	}
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
// SECURITY: the realm originates from the configured upstream's challenge; it is
// still constrained to http(s) so a compromised or misconfigured upstream cannot
// redirect token requests to a non-HTTP locator.
func buildTokenURL(c authChallenge) (string, error) {
	if c.realm == "" {
		return "", fmt.Errorf("homebrew: auth challenge missing realm")
	}
	u, err := url.Parse(c.realm)
	if err != nil {
		return "", fmt.Errorf("homebrew: invalid token realm %q: %w", c.realm, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("homebrew: token realm must be http(s), got %q", u.Scheme)
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

// parseChallenge parses a WWW-Authenticate header value. It understands the
// "Bearer" and "Basic" schemes and the comma-separated, optionally quoted
// key=value parameter list (RFC 7235 §4.1).
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
// string, so a quoted value containing a comma is preserved intact.
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

func withAuthorization(h http.Header, value string) http.Header {
	out := cloneHeader(h)
	out.Set("Authorization", value)
	return out
}

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
