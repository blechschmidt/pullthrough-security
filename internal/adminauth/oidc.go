package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	// RedirectURL is this proxy's externally reachable callback URL,
	// e.g. "https://proxy.example.com/admin/auth/callback". Required.
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
type oidcProvider struct {
	cfg        OIDCConfig
	client     *http.Client
	now        func() time.Time
	subjectCl  string
	groupsCl   string
	tenantCl   string
	authzURL   string
	tokenURL   string
	endSession string
	scopes     []string
	idAuth     *auth.OIDCAuthenticator // validates ID tokens (aud = clientID)
	bearerAuth *auth.OIDCAuthenticator // validates API bearer JWTs (aud = Audience)
}

// discoveryDocument is the subset of the OIDC discovery metadata we consume.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// tokenResponse is the subset of the OAuth2 token-endpoint response we consume.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

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
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	p := &oidcProvider{
		cfg:        cfg,
		client:     client,
		now:        now,
		subjectCl:  orElse(cfg.SubjectClaim, "sub"),
		groupsCl:   orElse(cfg.GroupsClaim, "groups"),
		tenantCl:   orElse(cfg.TenantClaim, "team"),
		authzURL:   strings.TrimSpace(cfg.AuthorizationEndpoint),
		tokenURL:   strings.TrimSpace(cfg.TokenEndpoint),
		endSession: strings.TrimSpace(cfg.EndSessionEndpoint),
	}
	p.scopes = cfg.Scopes
	if len(p.scopes) == 0 {
		p.scopes = []string{"openid", "profile", "email", "groups"}
	}

	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	haveKeys := jwksURL != "" || strings.TrimSpace(cfg.JWKS) != ""

	// Discover endpoints unless everything required is already pinned (offline).
	if p.authzURL == "" || p.tokenURL == "" || !haveKeys {
		doc, err := p.discover(context.Background())
		if err != nil {
			return nil, err
		}
		if p.authzURL == "" {
			p.authzURL = doc.AuthorizationEndpoint
		}
		if p.tokenURL == "" {
			p.tokenURL = doc.TokenEndpoint
		}
		if p.endSession == "" {
			p.endSession = doc.EndSessionEndpoint
		}
		if jwksURL == "" && strings.TrimSpace(cfg.JWKS) == "" {
			jwksURL = doc.JWKSURI
		}
	}
	if p.authzURL == "" || p.tokenURL == "" {
		return nil, fmt.Errorf("adminauth: oidc authorization/token endpoint unresolved")
	}

	// Build the JWKS-backed verifiers (ID token + API bearer). They differ only
	// in the expected audience.
	mkAuth := func(aud string) (*auth.OIDCAuthenticator, error) {
		return auth.NewOIDCAuthenticator(auth.OIDCOptions{
			Issuer:       cfg.Issuer,
			Audience:     aud,
			JWKSURL:      jwksURL,
			StaticJWKS:   []byte(strings.TrimSpace(cfg.JWKS)),
			HTTPClient:   client,
			JWKSCacheTTL: cfg.JWKSCacheTTL,
			Leeway:       cfg.Leeway,
			SubjectClaim: p.subjectCl,
			TeamClaim:    p.tenantCl, // expose the tenant/team claim as Principal.Team
			RolesClaim:   p.groupsCl, // expose IdP groups as Principal.Roles
			Now:          now,
		})
	}
	idAuth, err := mkAuth(cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("adminauth: oidc id-token verifier: %w", err)
	}
	bearerAud := orElse(cfg.Audience, cfg.ClientID)
	bearerAuth, err := mkAuth(bearerAud)
	if err != nil {
		return nil, fmt.Errorf("adminauth: oidc bearer verifier: %w", err)
	}
	p.idAuth = idAuth
	p.bearerAuth = bearerAuth
	return p, nil
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
		return nil, fmt.Errorf("adminauth: oidc discovery returned %d", resp.StatusCode)
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
		return nil, fmt.Errorf("adminauth: oidc discovery issuer %q does not match configured issuer %q", doc.Issuer, p.cfg.Issuer)
	}
	return &doc, nil
}

// authCodeURL builds the IdP authorization-endpoint URL for the given PKCE
// challenge, state, and nonce.
func (p *oidcProvider) authCodeURL(state, nonce, challenge string) string {
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
	if strings.Contains(p.authzURL, "?") {
		sep = "&"
	}
	return p.authzURL + sep + q.Encode()
}

// exchange swaps an authorization code (with its PKCE verifier) for tokens.
func (p *oidcProvider) exchange(ctx context.Context, code, verifier string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("code_verifier", verifier)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientSecret == "" {
		// Public client: client_id in the body is sufficient.
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientSecret != "" {
		// Confidential client: HTTP Basic per RFC 6749 §2.3.1.
		req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("adminauth: token exchange: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("adminauth: reading token response: %w", err)
	}
	var tr tokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("adminauth: parsing token response: %w", err)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("adminauth: token endpoint error %q: %s", tr.Error, tr.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("adminauth: token endpoint returned %d", resp.StatusCode)
	}
	if strings.TrimSpace(tr.IDToken) == "" {
		return nil, fmt.Errorf("adminauth: token response carried no id_token")
	}
	return &tr, nil
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
	prin, err := p.idAuth.Authenticate(ctx, bearerRequest(idToken))
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
	prin, err := p.bearerAuth.Authenticate(ctx, r)
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
