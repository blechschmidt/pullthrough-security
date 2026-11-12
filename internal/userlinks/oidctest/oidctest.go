// Package oidctest is a small OpenID Connect identity provider for tests: the
// part of one that an authorization-code sign-in with PKCE touches — discovery,
// the authorization endpoint, the token endpoint and the signing keys.
//
// It signs real ID tokens (RS256) with a key generated per provider, checks
// what a real provider checks (the client, the redirect URI, the client's
// secret, the PKCE verifier, that a code is used once), and "signs in" whoever
// the test says is sitting at the browser — there is no log-in form. It can
// also misbehave on request, to hold a relying party to what it must not
// accept: a token for another audience, an expired one, one signed with a
// foreign key, one that answers a different sign-in.
//
// It is used by the unit tests of internal/userlinks and by the integration
// suite that runs the real proxy binary (internal/e2e/userlinks).
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// User is who signs in at the provider: the claims of the ID token.
type User struct {
	// Subject is the provider's own identifier of the user ("sub").
	Subject string
	// Email, when set, is released as "email"; EmailVerified as
	// "email_verified" when non-nil.
	Email         string
	EmailVerified *bool
	// Name is released as "name"; Username as "preferred_username".
	Name     string
	Username string
	// Groups is released as "groups"; Team as "team".
	Groups []string
	Team   string
	// Extra holds any further claims.
	Extra map[string]any
}

// Fault makes the provider issue an ID token a relying party must refuse.
type Fault string

const (
	// FaultNone: a correct token.
	FaultNone Fault = ""
	// FaultWrongAudience: the token is for another client.
	FaultWrongAudience Fault = "wrong-audience"
	// FaultWrongIssuer: the token names another issuer.
	FaultWrongIssuer Fault = "wrong-issuer"
	// FaultExpired: the token expired an hour ago.
	FaultExpired Fault = "expired"
	// FaultWrongKey: the token is signed with a key the provider does not
	// publish.
	FaultWrongKey Fault = "wrong-key"
	// FaultWrongNonce: the token repeats a nonce the relying party did not send.
	FaultWrongNonce Fault = "wrong-nonce"
	// FaultUnsigned: the token claims alg "none" and carries no signature.
	FaultUnsigned Fault = "unsigned"
	// FaultNoIDToken: the token endpoint answers without an id_token.
	FaultNoIDToken Fault = "no-id-token"
	// FaultOtherAzp: the token names another client as its authorized party.
	FaultOtherAzp Fault = "other-azp"
)

// Provider is a running test identity provider.
type Provider struct {
	listener net.Listener
	server   *http.Server
	issuer   string

	clientID     string
	clientSecret string

	key      *rsa.PrivateKey
	otherKey *rsa.PrivateKey
	kid      string

	mu sync.Mutex
	// redirects are the redirect URIs registered for the client. Empty accepts
	// any, which is what a test that does not care wants.
	redirects []string
	user      *User
	deny      string
	fault     Fault
	codes     map[string]grant
	// requests counts the requests per endpoint.
	requests map[string]int
	// down makes every endpoint answer 503.
	down bool
}

type grant struct {
	nonce       string
	challenge   string
	redirectURI string
	user        User
}

// Start starts a provider on a loopback port for the given client. Close it
// when done.
func Start(clientID, clientSecret string) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Provider{
		listener:     ln,
		issuer:       "http://" + ln.Addr().String(),
		clientID:     clientID,
		clientSecret: clientSecret,
		key:          key,
		otherKey:     other,
		kid:          "test-key-1",
		codes:        map[string]grant{},
		requests:     map[string]int{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.count("discovery", p.handleDiscovery))
	mux.HandleFunc("/authorize", p.count("authorize", p.handleAuthorize))
	mux.HandleFunc("/token", p.count("token", p.handleToken))
	mux.HandleFunc("/jwks", p.count("jwks", p.handleJWKS))
	p.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = p.server.Serve(ln) }()
	return p, nil
}

// Close stops the provider.
func (p *Provider) Close() { _ = p.server.Close() }

// Issuer returns the provider's issuer URL.
func (p *Provider) Issuer() string { return p.issuer }

// ClientID returns the client the provider was started for.
func (p *Provider) ClientID() string { return p.clientID }

// ClientSecret returns the client's secret.
func (p *Provider) ClientSecret() string { return p.clientSecret }

// SignInAs sets who signs in at the next authorization request.
func (p *Provider) SignInAs(u User) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user, p.deny = &u, ""
}

// Deny makes the next authorization request come back with the given OAuth
// error ("access_denied") instead of a code.
func (p *Provider) Deny(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deny = code
}

// SetFault makes the token endpoint misbehave in the given way until reset.
func (p *Provider) SetFault(f Fault) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fault = f
}

// SetDown makes every endpoint answer 503, as an unreachable provider would
// behind a gateway.
func (p *Provider) SetDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
}

// AllowRedirect registers a redirect URI for the client. Once one is
// registered, any other is refused.
func (p *Provider) AllowRedirect(uri string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirects = append(p.redirects, uri)
}

// Requests returns how many requests an endpoint ("discovery", "authorize",
// "token", "jwks") has received.
func (p *Provider) Requests(endpoint string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[endpoint]
}

func (p *Provider) count(name string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.requests[name]++
		down := p.down
		p.mu.Unlock()
		if down {
			http.Error(w, "the provider is down", http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/token",
		"jwks_uri":                              p.issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (p *Provider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// handleAuthorize is the authorization endpoint. There is no log-in form: the
// user set with SignInAs is signed in at once and the browser is sent back with
// a code.
func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	p.mu.Lock()
	user, deny, redirects := p.user, p.deny, append([]string(nil), p.redirects...)
	p.mu.Unlock()

	// What a provider refuses without redirecting: an unknown client, a
	// redirect URI that is not registered.
	if q.Get("client_id") != p.clientID {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if len(redirects) > 0 {
		registered := false
		for _, uri := range redirects {
			registered = registered || uri == redirectURI
		}
		if !registered {
			http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
			return
		}
	}
	target, err := url.Parse(redirectURI)
	if err != nil || target.Host == "" {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	back := target.Query()
	back.Set("state", q.Get("state"))

	switch {
	case q.Get("response_type") != "code":
		back.Set("error", "unsupported_response_type")
	case !strings.Contains(" "+q.Get("scope")+" ", " openid "):
		back.Set("error", "invalid_scope")
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		back.Set("error", "invalid_request")
		back.Set("error_description", "PKCE with S256 is required")
	case deny != "":
		back.Set("error", deny)
	case user == nil:
		back.Set("error", "login_required")
	default:
		code := randomString()
		p.mu.Lock()
		p.codes[code] = grant{
			nonce:       q.Get("nonce"),
			challenge:   q.Get("code_challenge"),
			redirectURI: redirectURI,
			user:        *user,
		}
		p.mu.Unlock()
		back.Set("code", code)
	}
	target.RawQuery = back.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "")
		return
	}
	// A confidential client authenticates with HTTP Basic (form-encoded id and
	// secret); a public one names itself in the body.
	if p.clientSecret != "" {
		user, pass, ok := r.BasicAuth()
		id, _ := url.QueryUnescape(user)
		secret, _ := url.QueryUnescape(pass)
		if !ok || id != p.clientID || secret != p.clientSecret {
			tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}
	} else if r.PostForm.Get("client_id") != p.clientID {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
		return
	}

	code := r.PostForm.Get("code")
	p.mu.Lock()
	g, ok := p.codes[code]
	delete(p.codes, code) // a code is good for one exchange
	fault := p.fault
	p.mu.Unlock()
	if !ok {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown or already used code")
		return
	}
	if g.redirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	if fault == FaultNoIDToken {
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "at-" + randomString(), "token_type": "Bearer"})
		return
	}
	idToken, err := p.IDToken(g.user, g.nonce, fault)
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": "at-" + randomString(),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

// IDToken signs an ID token for u that answers the sign-in with the given
// nonce — or, with a fault, one that must be refused.
func (p *Provider) IDToken(u User, nonce string, fault Fault) (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss":   p.issuer,
		"aud":   p.clientID,
		"sub":   u.Subject,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
		"nonce": nonce,
	}
	if u.Email != "" {
		claims["email"] = u.Email
	}
	if u.EmailVerified != nil {
		claims["email_verified"] = *u.EmailVerified
	}
	if u.Name != "" {
		claims["name"] = u.Name
	}
	if u.Username != "" {
		claims["preferred_username"] = u.Username
	}
	if u.Groups != nil {
		claims["groups"] = u.Groups
	}
	if u.Team != "" {
		claims["team"] = u.Team
	}
	for k, v := range u.Extra {
		claims[k] = v
	}

	key, alg := p.key, "RS256"
	switch fault {
	case FaultWrongAudience:
		claims["aud"] = "some-other-client"
	case FaultWrongIssuer:
		claims["iss"] = "https://another-issuer.example"
	case FaultExpired:
		claims["iat"] = now.Add(-2 * time.Hour).Unix()
		claims["exp"] = now.Add(-time.Hour).Unix()
	case FaultWrongKey:
		key = p.otherKey
	case FaultWrongNonce:
		claims["nonce"] = "not-the-nonce-that-was-sent"
	case FaultUnsigned:
		alg = "none"
	case FaultOtherAzp:
		claims["aud"] = []string{p.clientID, "some-other-client"}
		claims["azp"] = "some-other-client"
	}

	header, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": p.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	if alg == "none" {
		return signingInput + ".", nil
	}
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func tokenError(w http.ResponseWriter, status int, code, description string) {
	body := map[string]any{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("oidctest: no randomness: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
