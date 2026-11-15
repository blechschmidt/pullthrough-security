package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

// OIDCConfig configures the OIDC/OAuth2 integration for the admin surface.
type OIDCConfig struct {
	// Issuer is the IdP issuer URL ("iss" claim). Required.
	Issuer string
	// ClientID is the registered OAuth2 client id. Required.
	ClientID string
	// ClientSecret authenticates a confidential client at the token endpoint.
	// Empty selects a public client (PKCE only).
	ClientSecret string
	// RedirectURL is this proxy's externally reachable callback URL, as
	// registered with the provider: "https://proxy.example.com/admin/auth/callback"
	// is served by the admin surface itself; any other path is served by the
	// gateway (see Service.CallbackRoute). Required.
	RedirectURL string
	// Scopes requested at login (default "openid profile email groups").
	Scopes []string
	// Audience is the expected "aud" for admin *API* bearer JWTs. Defaults to
	// ClientID (the audience of the ID token).
	Audience string

	// Explicit endpoints. When all of AuthorizationEndpoint/TokenEndpoint and a
	// key source (JWKSURL or inline JWKS) are set, discovery is skipped — the
	// supported offline-ish path for IdPs without a reachable discovery document.
	DiscoveryURL          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	EndSessionEndpoint    string
	JWKSURL               string
	JWKS                  string // inline JWK Set (air-gapped key pinning)

	// Claim names.
	SubjectClaim string // default "sub"
	GroupsClaim  string // default "groups"
	// TenantClaim names the claim carrying the caller's tenant/team. It scopes the
	// self-service portal. Default "team" (matching the pull-path auth team claim).
	TenantClaim string

	JWKSCacheTTL time.Duration // default 15m
	Leeway       time.Duration // default 60s

	// HTTPClient performs discovery and token exchange (default 10s client).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// oidcProvider performs the authorization-code+PKCE login flow and validates
// admin API bearer JWTs. ID-token and bearer signature/claim validation reuse
// internal/auth's JWKS-backed verifier (caching, rotation, clock-skew leeway).
//
// The provider's endpoints are resolved on first use, not when the proxy
// starts, and a failure is retried (after discoveryRetry). An identity
// provider that cannot be reached at start-up must not keep the admin surface
// from being built: the service would be left out, and with it the static
// tokens, and a surface without its authentication is not one to fall back on.
// Until the provider answers, SSO sign-ins fail and OIDC bearer tokens are
// refused; static tokens keep working.
type oidcProvider struct {
	cfg       OIDCConfig
	client    *http.Client
	now       func() time.Time
	subjectCl string
	groupsCl  string
	tenantCl  string
	scopes    []string
	redeemer  *auth.CodeRedeemer
	// callbackPath is the path of the redirect URL: where the browser comes
	// back to, and so the path the login-flow cookie is scoped to.
	callbackPath string

	mu       sync.Mutex
	resolved *oidcEndpoints
	failedAt time.Time
	failure  error
}

// oidcEndpoints is what is known about the provider once resolved.
type oidcEndpoints struct {
	authzURL   string
	tokenURL   string
	endSession string
	idAuth     *auth.OIDCAuthenticator // validates ID tokens (aud = clientID)
	bearerAuth *auth.OIDCAuthenticator // validates API bearer JWTs (aud = Audience)
}

// discoveryRetry is how long a failed resolution is remembered before the
// next request that needs the provider tries again; discoveryTimeout bounds
// one attempt.
const (
	discoveryRetry   = 10 * time.Second
	discoveryTimeout = 15 * time.Second
)

// errIdPUnavailable marks a failure to resolve the provider's endpoints.
var errIdPUnavailable = errors.New("adminauth: the identity provider cannot be used at the moment")

// discoveryDocument is the subset of the OIDC discovery metadata we consume.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// newOIDCProvider checks the configuration. It does not contact the provider.
func newOIDCProvider(cfg OIDCConfig) (*oidcProvider, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, fmt.Errorf("adminauth: oidc issuer is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, fmt.Errorf("adminauth: oidc clientId is required")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, fmt.Errorf("adminauth: oidc redirectUrl is required")
	}
	cfg.RedirectURL = strings.TrimSpace(cfg.RedirectURL)
	callbackPath, err := CallbackPathOf(cfg.RedirectURL)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	p := &oidcProvider{
		cfg:          cfg,
		client:       client,
		now:          now,
		subjectCl:    orElse(cfg.SubjectClaim, "sub"),
		groupsCl:     orElse(cfg.GroupsClaim, "groups"),
		tenantCl:     orElse(cfg.TenantClaim, "team"),
		redeemer:     &auth.CodeRedeemer{Client: client},
		callbackPath: callbackPath,
	}
	p.scopes = cfg.Scopes
	if len(p.scopes) == 0 {
		p.scopes = []string{"openid", "profile", "email", "groups"}
	}
	if strings.TrimSpace(cfg.JWKS) != "" {
		// An inline key set is parsed now: a broken one is a configuration
		// error, not an outage.
		if _, err := p.verifier(cfg.ClientID, ""); err != nil {
			return nil, fmt.Errorf("adminauth: oidc id-token verifier: %w", err)
		}
	}
	return p, nil
}

// CallbackPathOf returns the path of a redirect URL: where the identity
// provider sends the browser back to. It must be an absolute http(s) URL with
// a path other than "/".
func CallbackPathOf(redirectURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(redirectURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("adminauth: oidc redirectUrl %q is not an absolute http(s) URL", redirectURL)
	}
	p := u.EscapedPath()
	if p == "" || p == "/" {
		return "", fmt.Errorf("adminauth: oidc redirectUrl %q names no callback path", redirectURL)
	}
	return p, nil
}

// verifier builds a JWKS-backed verifier for the given audience.
func (p *oidcProvider) verifier(audience, jwksURL string) (*auth.OIDCAuthenticator, error) {
	return auth.NewOIDCAuthenticator(auth.OIDCOptions{
		Issuer:       p.cfg.Issuer,
		Audience:     audience,
		JWKSURL:      jwksURL,
		StaticJWKS:   []byte(strings.TrimSpace(p.cfg.JWKS)),
		HTTPClient:   p.client,
		JWKSCacheTTL: p.cfg.JWKSCacheTTL,
		Leeway:       p.cfg.Leeway,
		SubjectClaim: p.subjectCl,
		TeamClaim:    p.tenantCl, // expose the tenant/team claim as Principal.Team
		RolesClaim:   p.groupsCl, // expose IdP groups as Principal.Roles
		Now:          p.now,
	})
}

// endpoints returns the provider's endpoints and verifiers, resolving them on
// first use. A failure is remembered for discoveryRetry, so a provider that is
// down is asked once per interval, not once per request.
func (p *oidcProvider) endpoints(ctx context.Context) (*oidcEndpoints, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolved != nil {
		return p.resolved, nil
	}
	if p.failure != nil && p.now().Sub(p.failedAt) < discoveryRetry {
		return nil, p.failure
	}
	// The provider's answer is not the asking request's: a request that gives
	// up does not cancel the resolution for everyone else.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
	defer cancel()
	ep, err := p.resolve(rctx)
	if err != nil {
		p.failure, p.failedAt = fmt.Errorf("%w: %v", errIdPUnavailable, err), p.now()
		return nil, p.failure
	}
	p.resolved, p.failure = ep, nil
	return ep, nil
}

// resolve discovers what the configuration does not pin, and builds the
// verifiers.
func (p *oidcProvider) resolve(ctx context.Context) (*oidcEndpoints, error) {
	ep := &oidcEndpoints{
		authzURL:   strings.TrimSpace(p.cfg.AuthorizationEndpoint),
		tokenURL:   strings.TrimSpace(p.cfg.TokenEndpoint),
		endSession: strings.TrimSpace(p.cfg.EndSessionEndpoint),
	}
	jwksURL := strings.TrimSpace(p.cfg.JWKSURL)
	haveKeys := jwksURL != "" || strings.TrimSpace(p.cfg.JWKS) != ""

	// Discover endpoints unless everything required is already pinned (offline).
	if ep.authzURL == "" || ep.tokenURL == "" || !haveKeys {
		doc, err := p.discover(ctx)
		if err != nil {
			return nil, err
		}
		if ep.authzURL == "" {
			ep.authzURL = doc.AuthorizationEndpoint
		}
		if ep.tokenURL == "" {
			ep.tokenURL = doc.TokenEndpoint
		}
		if ep.endSession == "" {
			ep.endSession = doc.EndSessionEndpoint
		}
		if !haveKeys {
			jwksURL = doc.JWKSURI
		}
	}
	if ep.authzURL == "" || ep.tokenURL == "" {
		return nil, fmt.Errorf("adminauth: oidc authorization/token endpoint unresolved")
	}
	if jwksURL == "" && strings.TrimSpace(p.cfg.JWKS) == "" {
		return nil, fmt.Errorf("adminauth: oidc signing keys unresolved (no jwks_uri)")
	}

	// The ID-token and API-bearer verifiers differ only in the expected
	// audience.
	var err error
	if ep.idAuth, err = p.verifier(p.cfg.ClientID, jwksURL); err != nil {
		return nil, fmt.Errorf("adminauth: oidc id-token verifier: %w", err)
	}
	if ep.bearerAuth, err = p.verifier(orElse(p.cfg.Audience, p.cfg.ClientID), jwksURL); err != nil {
		return nil, fmt.Errorf("adminauth: oidc bearer verifier: %w", err)
	}
	return ep, nil
}

// discover fetches the OIDC discovery document.
func (p *oidcProvider) discover(ctx context.Context) (*discoveryDocument, error) {
	u := strings.TrimSpace(p.cfg.DiscoveryURL)
	if u == "" {
		u = strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("adminauth: oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("adminauth: oidc discovery: %s answered %d", u, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("adminauth: reading oidc discovery: %w", err)
	}
	var doc discoveryDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("adminauth: parsing oidc discovery: %w", err)
	}
	if doc.Issuer != "" && doc.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("adminauth: oidc discovery: %w", auth.IssuerMismatch(u, doc.Issuer, p.cfg.Issuer))
	}
	return &doc, nil
}

// authCodeURL builds the IdP authorization-endpoint URL for the given PKCE
// challenge, state, and nonce.
func (p *oidcProvider) authCodeURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	ep, err := p.endpoints(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(ep.authzURL, "?") {
		sep = "&"
	}
	return ep.authzURL + sep + q.Encode(), nil
}

// tokenResponse is the subset of the OAuth2 token-endpoint response we consume.
type tokenResponse struct {
	AccessToken string
	IDToken     string
}

// exchange swaps an authorization code (with its PKCE verifier) for tokens.
func (p *oidcProvider) exchange(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	ep, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	tr, err := p.redeemer.Redeem(ctx, auth.CodeRedemption{
		TokenEndpoint: ep.tokenURL,
		Code:          code,
		Verifier:      verifier,
		RedirectURL:   p.cfg.RedirectURL,
		ClientID:      p.cfg.ClientID,
		ClientSecret:  p.cfg.ClientSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("adminauth: token exchange: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("adminauth: token endpoint error %q: %s", tr.Error, tr.ErrorDescription)
	}
	if tr.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("adminauth: token endpoint returned %d", tr.StatusCode)
	}
	if strings.TrimSpace(tr.IDToken) == "" {
		return nil, fmt.Errorf("adminauth: token response carried no id_token")
	}
	return &tokenResponse{AccessToken: tr.AccessToken, IDToken: tr.IDToken}, nil
}

// claims is the result of validating an ID token or bearer JWT: the subject, the
// IdP groups, the issuer, and the tenant/team. Role mapping happens in the
// Service.
type claims struct {
	subject string
	groups  []string
	issuer  string
	tenant  string
}

// validateIDToken verifies an ID token's signature and registered claims, and
// checks the OIDC nonce binds the token to this login flow.
func (p *oidcProvider) validateIDToken(ctx context.Context, idToken, wantNonce string) (*claims, error) {
	ep, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	prin, err := ep.idAuth.Authenticate(ctx, bearerRequest(idToken))
	if err != nil {
		return nil, err
	}
	// Signature/exp/iss/aud are verified; the nonce lives in the (now trusted)
	// payload, which we read back to bind the token to this flow.
	raw, err := unverifiedPayload(idToken)
	if err != nil {
		return nil, err
	}
	if wantNonce != "" {
		gotNonce, _ := raw["nonce"].(string)
		if gotNonce != wantNonce {
			return nil, fmt.Errorf("adminauth: id_token nonce mismatch")
		}
	}
	return &claims{subject: prin.Subject, groups: prin.Roles, issuer: prin.Attributes["issuer"], tenant: prin.Team}, nil
}

// validateBearer verifies an admin API bearer JWT and extracts its claims.
func (p *oidcProvider) validateBearer(ctx context.Context, r *http.Request) (*claims, error) {
	ep, err := p.endpoints(ctx)
	if err != nil {
		return nil, err
	}
	prin, err := ep.bearerAuth.Authenticate(ctx, r)
	if err != nil {
		return nil, err
	}
	return &claims{subject: prin.Subject, groups: prin.Roles, issuer: prin.Attributes["issuer"], tenant: prin.Team}, nil
}

// --- PKCE helpers -----------------------------------------------------------

// newPKCE returns a high-entropy code verifier and its S256 challenge.
func newPKCE() (verifier, challenge string, err error) {
	verifier, err = randToken(32)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// randToken returns n cryptographically random bytes as a base64url string.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("adminauth: generating random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// bearerRequest builds a synthetic request carrying the token as a bearer
// credential, so the internal/auth verifier (which reads from a request) can be
// reused for raw token strings.
func bearerRequest(token string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// unverifiedPayload base64-decodes a JWT's claims segment WITHOUT verifying the
// signature. It is only used to read additional claims (the nonce) from a token
// whose signature was already verified by the auth verifier.
func unverifiedPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("adminauth: malformed jwt")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("adminauth: decoding jwt payload: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("adminauth: parsing jwt payload: %w", err)
	}
	return m, nil
}

func orElse(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
