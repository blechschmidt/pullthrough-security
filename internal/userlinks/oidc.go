package userlinks

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// OIDCConfig configures the identity provider cache users sign in at.
type OIDCConfig struct {
	// Issuer is the provider's issuer URL, exactly as it appears in the "iss"
	// claim of the tokens it issues. Required.
	Issuer string
	// ClientID is the OAuth2 client the proxy is registered as. Required.
	ClientID string
	// ClientSecret authenticates a confidential client at the token endpoint.
	// Empty makes the proxy a public client, which relies on PKCE alone.
	ClientSecret string
	// RedirectURL is where the provider sends the browser back to: the proxy's
	// externally reachable callback URL, "<public URL><ui path>/callback". It
	// must be registered with the provider, character for character. Required.
	RedirectURL string
	// Scopes are requested at sign-in. Empty means "openid profile email".
	Scopes []string

	// DiscoveryURL overrides where the provider's metadata is read from
	// (default: "<issuer>/.well-known/openid-configuration"). When
	// AuthorizationEndpoint, TokenEndpoint and a key source (JWKSURL or JWKS)
	// are all set, no discovery takes place at all — for a provider without a
	// reachable discovery document, and for pinning.
	DiscoveryURL          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURL               string
	// JWKS is an inline JWK Set document: the provider's signing keys, pinned.
	JWKS string

	// JWKSCacheTTL bounds how long fetched signing keys are cached (default 15m);
	// Leeway is the clock skew tolerated on a token's validity (default 60s).
	JWKSCacheTTL time.Duration
	Leeway       time.Duration

	// HTTPClient talks to the provider. Nil means a client with a 10s timeout.
	HTTPClient *http.Client
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// discoveryRetry is how long a failed discovery is remembered before the next
// sign-in attempt tries again. A provider that is down is not helped by a
// request per click.
const discoveryRetry = 10 * time.Second

// maxProviderResponse bounds what is read of a provider's response.
const maxProviderResponse = 1 << 20

// oidcClient is the relying party: it sends a browser to the provider, swaps
// the code that comes back for an ID token, and verifies that token.
//
// The provider's endpoints are resolved on first use, not at start-up, and a
// failure is retried. A proxy that refused to start — or to serve packages —
// because the identity provider was unreachable at that moment would turn an
// outage of sign-in into an outage of the cache.
type oidcClient struct {
	cfg  OIDCConfig
	http *http.Client
	now  func() time.Time

	mu       sync.Mutex
	resolved *oidcEndpoints
	failedAt time.Time
	failure  error
}

// oidcEndpoints is what is known about the provider once resolved.
type oidcEndpoints struct {
	authorization string
	token         string
	verifier      *auth.OIDCAuthenticator
}

func newOIDCClient(cfg OIDCConfig) (*oidcClient, error) {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.RedirectURL = strings.TrimSpace(cfg.RedirectURL)
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("userlinks: oidc issuer is required")
	case cfg.ClientID == "":
		return nil, errors.New("userlinks: oidc clientId is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("userlinks: oidc redirectUrl is required")
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	c := &oidcClient{cfg: cfg, http: cfg.HTTPClient, now: cfg.Now}
	if c.http == nil {
		c.http = &http.Client{Timeout: 10 * time.Second}
	}
	if c.now == nil {
		c.now = time.Now
	}
	return c, nil
}

// discoveryDocument is the part of the provider metadata that is used.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// discoveryTimeout bounds one attempt to learn the provider's endpoints.
const discoveryTimeout = 15 * time.Second

// endpoints returns the provider's endpoints, resolving them on first use.
func (c *oidcClient) endpoints(ctx context.Context) (*oidcEndpoints, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resolved != nil {
		return c.resolved, nil
	}
	if c.failure != nil && c.now().Sub(c.failedAt) < discoveryRetry {
		return nil, c.failure
	}
	// Discovery is the provider's answer, not the asking request's: a sign-in
	// whose browser gave up does not cancel it, and its failure is not cached
	// as the provider's for everyone else.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
	defer cancel()
	ep, err := c.resolve(rctx)
	if err != nil {
		c.failure, c.failedAt = err, c.now()
		return nil, err
	}
	c.resolved, c.failure = ep, nil
	return ep, nil
}

func (c *oidcClient) resolve(ctx context.Context) (*oidcEndpoints, error) {
	authz := strings.TrimSpace(c.cfg.AuthorizationEndpoint)
	token := strings.TrimSpace(c.cfg.TokenEndpoint)
	jwksURL := strings.TrimSpace(c.cfg.JWKSURL)
	jwks := strings.TrimSpace(c.cfg.JWKS)

	if authz == "" || token == "" || (jwksURL == "" && jwks == "") {
		doc, err := c.discover(ctx)
		if err != nil {
			return nil, err
		}
		if authz == "" {
			authz = doc.AuthorizationEndpoint
		}
		if token == "" {
			token = doc.TokenEndpoint
		}
		if jwksURL == "" && jwks == "" {
			jwksURL = doc.JWKSURI
		}
	}
	if authz == "" || token == "" {
		return nil, errors.New("userlinks: the identity provider's authorization or token endpoint is not known")
	}
	if jwksURL == "" && jwks == "" {
		return nil, errors.New("userlinks: the identity provider's signing keys are not known (no jwks_uri)")
	}
	verifier, err := auth.NewOIDCAuthenticator(auth.OIDCOptions{
		Issuer:       c.cfg.Issuer,
		Audience:     c.cfg.ClientID,
		JWKSURL:      jwksURL,
		StaticJWKS:   []byte(jwks),
		HTTPClient:   c.http,
		JWKSCacheTTL: c.cfg.JWKSCacheTTL,
		Leeway:       c.cfg.Leeway,
		Now:          c.now,
	})
	if err != nil {
		return nil, fmt.Errorf("userlinks: oidc token verifier: %w", err)
	}
	return &oidcEndpoints{authorization: authz, token: token, verifier: verifier}, nil
}

func (c *oidcClient) discover(ctx context.Context) (*discoveryDocument, error) {
	u := strings.TrimSpace(c.cfg.DiscoveryURL)
	if u == "" {
		u = strings.TrimRight(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("userlinks: oidc discovery: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userlinks: oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userlinks: oidc discovery: %s answered %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
	if err != nil {
		return nil, fmt.Errorf("userlinks: oidc discovery: %w", err)
	}
	var doc discoveryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("userlinks: oidc discovery: the document is not valid JSON: %w", err)
	}
	// The document must speak for the issuer that was configured. One that
	// names another could direct sign-ins to endpoints of someone else's choice.
	if doc.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("userlinks: oidc discovery: the document is for issuer %q, not the configured %q",
			doc.Issuer, c.cfg.Issuer)
	}
	return &doc, nil
}

// authCodeURL returns the URL at the provider a browser is sent to in order to
// sign in.
func (c *oidcClient) authCodeURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	ep, err := c.endpoints(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("scope", strings.Join(c.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(ep.authorization, "?") {
		sep = "&"
	}
	return ep.authorization + sep + q.Encode(), nil
}

// exchange swaps an authorization code, together with the PKCE verifier of the
// sign-in it belongs to, for the ID token.
func (c *oidcClient) exchange(ctx context.Context, code, verifier string) (string, error) {
	ep, err := c.endpoints(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	form.Set("code_verifier", verifier)
	form.Set("client_id", c.cfg.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("userlinks: token exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.cfg.ClientSecret != "" {
		// A confidential client authenticates with HTTP Basic; its id and secret
		// are form-encoded first (RFC 6749 §2.3.1).
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("userlinks: token exchange: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponse))
	if err != nil {
		return "", fmt.Errorf("userlinks: token exchange: %w", err)
	}
	var tr struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(data, &tr); err != nil {
		return "", fmt.Errorf("userlinks: token exchange: the token endpoint answered %d with a body that is not JSON", resp.StatusCode)
	}
	if tr.Error != "" {
		return "", fmt.Errorf("userlinks: token exchange: the token endpoint refused: %s %s",
			cleanText(tr.Error, 64), cleanText(tr.ErrorDescription, 256))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userlinks: token exchange: the token endpoint answered %d", resp.StatusCode)
	}
	if strings.TrimSpace(tr.IDToken) == "" {
		return "", errors.New("userlinks: token exchange: the response carries no id_token (is the openid scope granted?)")
	}
	return tr.IDToken, nil
}

// verifyIDToken verifies an ID token — its signature against the provider's
// keys, its issuer, its audience, its validity period — and that it answers
// this sign-in and no other (the nonce). It returns the token's claims.
func (c *oidcClient) verifyIDToken(ctx context.Context, idToken, nonce string) (map[string]any, error) {
	ep, err := c.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+idToken)
	if _, err := ep.verifier.Authenticate(ctx, req); err != nil {
		return nil, fmt.Errorf("userlinks: the id token did not verify: %w", err)
	}

	// The signature is good; the payload can now be believed.
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("userlinks: the id token is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("userlinks: the id token is malformed")
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("userlinks: the id token is malformed")
	}

	got, _ := claims["nonce"].(string)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return nil, errors.New("userlinks: the id token does not belong to this sign-in (nonce mismatch)")
	}
	// A token issued to several audiences names the one party it was issued
	// for in "azp"; when it does, that party must be this client.
	if azp, ok := claims["azp"].(string); ok && azp != "" && azp != c.cfg.ClientID {
		return nil, errors.New("userlinks: the id token was issued to another client (azp)")
	}
	return claims, nil
}

// newPKCE returns a code verifier and its S256 challenge.
func newPKCE() (verifier, challenge string, err error) {
	if verifier, err = randomString(32); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// randomString returns n random bytes in base64url.
func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("userlinks: generating randomness: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// claimString returns a claim that is a string.
func claimString(claims map[string]any, name string) string {
	if name == "" {
		return ""
	}
	s, _ := claims[name].(string)
	return strings.TrimSpace(s)
}

// claimStrings returns a claim that lists strings: an array, or one string
// with the entries separated by spaces or commas.
func claimStrings(claims map[string]any, name string) []string {
	if name == "" {
		return nil
	}
	switch v := claims[name].(type) {
	case string:
		// One group. (Some providers send a single group as a string.) It is
		// not split into words: a group named "Cache admin requests" is not a
		// member of "admin" — and a group named like a role grants that role.
		if v = strings.TrimSpace(v); v != "" {
			return []string{v}
		}
		return nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}
