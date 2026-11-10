package adminauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// --- test crypto/JWT helpers ------------------------------------------------

const testKID = "test-key-1"

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return k
}

// jwksJSON renders a single-RSA-key JWK Set for the given public key.
func jwksJSON(pub *rsa.PublicKey, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]any{
		"keys": []map[string]any{
			{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n, "e": e},
		},
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

// signJWT signs claims as an RS256 compact JWS.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(hdr) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// --- static-token RBAC ------------------------------------------------------

func TestStaticTokenRolesAndCapabilities(t *testing.T) {
	svc, err := New(Options{
		Prefix: "/admin",
		StaticTokens: []StaticToken{
			{Name: "ci-viewer", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
			{Name: "ci-operator", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"},
			{Name: "ci-approver", Roles: []string{"approver"}, Secret: "approver-token-abcdef0123456789"},
			{Name: "ci-admin", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc == nil {
		t.Fatal("expected a service")
	}

	cases := []struct {
		token     string
		subject   string
		canRead   bool
		canOper   bool
		canApprov bool
		canAdmin  bool
	}{
		{"viewer-token-abcdef0123456789", "ci-viewer", true, false, false, false},
		{"operator-token-abcdef0123456789", "ci-operator", true, true, false, false},
		{"approver-token-abcdef0123456789", "ci-approver", true, false, true, false},
		{"admin-token-abcdef0123456789xyz", "ci-admin", true, true, true, true},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
		r.Header.Set("Authorization", "Bearer "+tc.token)
		id, err := svc.Authenticate(context.Background(), r)
		if err != nil {
			t.Fatalf("authenticate %s: %v", tc.subject, err)
		}
		if id.Subject != tc.subject {
			t.Errorf("subject = %q, want %q", id.Subject, tc.subject)
		}
		if id.Can(CapRead) != tc.canRead || id.Can(CapOperate) != tc.canOper ||
			id.Can(CapApprove) != tc.canApprov || id.Can(CapAdminister) != tc.canAdmin {
			t.Errorf("%s caps = read:%v oper:%v approve:%v admin:%v; want %v %v %v %v",
				tc.subject, id.Can(CapRead), id.Can(CapOperate), id.Can(CapApprove), id.Can(CapAdminister),
				tc.canRead, tc.canOper, tc.canApprov, tc.canAdmin)
		}
	}
}

func TestUnknownTokenDenied(t *testing.T) {
	svc, _ := New(Options{
		Prefix:       "/admin",
		StaticTokens: []StaticToken{{Name: "a", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"}},
	})
	r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r.Header.Set("Authorization", "Bearer not-a-valid-token-aaaaaaaaaaa")
	if _, err := svc.Authenticate(context.Background(), r); err != auth.ErrUnauthenticated {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
}

func TestLegacyAdminTokenGrantsAdmin(t *testing.T) {
	svc, err := New(Options{Prefix: "/admin", LegacyAdminToken: "legacy-secret"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r.Header.Set("Authorization", "Bearer legacy-secret")
	id, err := svc.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !id.Can(CapAdminister) || id.Method != "static-legacy" {
		t.Fatalf("legacy token should grant admin via static-legacy, got method=%q caps-admin=%v", id.Method, id.Can(CapAdminister))
	}
}

func TestStaticTokenRejectsUnknownRole(t *testing.T) {
	_, err := New(Options{
		Prefix:       "/admin",
		StaticTokens: []StaticToken{{Name: "x", Roles: []string{"superuser"}, Secret: "x-token-abcdef0123456789xyz"}},
	})
	if err == nil {
		t.Fatal("expected error for unknown role")
	}
}

// --- session codec ----------------------------------------------------------

func TestSessionCodecRoundTripTamperExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	codec := newSessionCodec([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	id := newIdentity("alice", "oidc-session", "https://idp", "acme", []Role{RoleOperator})

	val, err := codec.encodeSession(id, time.Hour)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := codec.decodeSession(val)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Subject != "alice" || !got.Can(CapOperate) {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Tenant != "acme" {
		t.Fatalf("tenant did not round-trip: got %q, want %q", got.Tenant, "acme")
	}

	// Tamper with the payload: flip a character.
	bad := "A" + val[1:]
	if _, err := codec.decodeSession(bad); err == nil {
		t.Fatal("expected tampered cookie to be rejected")
	}

	// Expiry.
	future := newSessionCodec([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now.Add(2 * time.Hour) })
	if _, err := future.decodeSession(val); err == nil {
		t.Fatal("expected expired cookie to be rejected")
	}
}

// --- role mapping -----------------------------------------------------------

func TestMapGroupsBindingsAndDefault(t *testing.T) {
	svc, err := New(Options{
		Prefix: "/admin",
		// Need at least one mechanism to construct; a legacy token suffices.
		LegacyAdminToken: "x",
		RoleBindings: map[string]string{
			"platform-admins": "admin",
			"sre":             "operator",
		},
		DefaultRole: "viewer",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := svc.mapGroups([]string{"platform-admins"}); len(got) != 1 || got[0] != RoleAdmin {
		t.Errorf("platform-admins -> %v, want [admin]", got)
	}
	// A canonical role name passes through without a binding.
	if got := svc.mapGroups([]string{"approver"}); len(got) != 1 || got[0] != RoleApprover {
		t.Errorf("approver -> %v, want [approver]", got)
	}
	// Unknown group with default role.
	if got := svc.mapGroups([]string{"random-group"}); len(got) != 1 || got[0] != RoleViewer {
		t.Errorf("unknown -> %v, want [viewer] (default)", got)
	}
	// Multiple bindings union & sort.
	if got := svc.mapGroups([]string{"sre", "platform-admins"}); len(got) != 2 {
		t.Errorf("union -> %v, want 2 roles", got)
	}
}

// --- mock OIDC provider -----------------------------------------------------

type mockIdP struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	issuer   string
	clientID string
	// idToken is returned by the token endpoint on the next exchange.
	idToken string
}

func newMockIdP(t *testing.T, clientID string) *mockIdP {
	t.Helper()
	m := &mockIdP{key: newRSAKey(t), clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                 m.issuer,
			"authorization_endpoint": m.issuer + "/authorize",
			"token_endpoint":         m.issuer + "/token",
			"jwks_uri":               m.issuer + "/jwks",
			"end_session_endpoint":   m.issuer + "/logout",
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwksJSON(&m.key.PublicKey, testKID)))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at",
			"id_token":     m.idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIdP) signToken(t *testing.T, now time.Time, extra map[string]any) string {
	claims := map[string]any{
		"iss": m.issuer,
		"aud": m.clientID,
		"sub": "alice@example.com",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signJWT(t, m.key, testKID, claims)
}

func newOIDCService(t *testing.T, idp *mockIdP, now time.Time) *Service {
	t.Helper()
	svc, err := New(Options{
		Prefix:        "/admin",
		SessionKey:    []byte("0123456789abcdef0123456789abcdef"),
		SecureCookies: false,
		RoleBindings:  map[string]string{"platform-admins": "admin"},
		OIDC: &OIDCConfig{
			Issuer:      idp.issuer,
			ClientID:    idp.clientID,
			RedirectURL: "https://proxy.example.com/admin/auth/callback",
			JWKSURL:     idp.issuer + "/jwks",
			Now:         func() time.Time { return now },
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New oidc service: %v", err)
	}
	return svc
}

func TestOIDCLoginFlow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idp := newMockIdP(t, "pullthrough-admin")
	svc := newOIDCService(t, idp, now)

	// 1) Start login.
	loginReq := httptest.NewRequest(http.MethodGet, "/admin/auth/login?return=/admin/cache", nil)
	loginRec := httptest.NewRecorder()
	svc.HandleLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302", loginRec.Code)
	}
	loc, err := url.Parse(loginRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state := loc.Query().Get("state")
	nonce := loc.Query().Get("nonce")
	if state == "" || nonce == "" || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize URL missing PKCE/state/nonce: %s", loc.String())
	}
	var flowCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == svc.flowCookieName {
			flowCookie = c
		}
	}
	if flowCookie == nil {
		t.Fatal("no flow cookie set")
	}

	// 2) IdP issues a token with the matching nonce and a group that maps to admin.
	idp.idToken = idp.signToken(t, now, map[string]any{
		"nonce":  nonce,
		"groups": []string{"platform-admins"},
	})

	// 3) Callback.
	cbReq := httptest.NewRequest(http.MethodGet, "/admin/auth/callback?code=abc&state="+url.QueryEscape(state), nil)
	cbReq.AddCookie(flowCookie)
	cbRec := httptest.NewRecorder()
	svc.HandleCallback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, want 302 (body: %s)", cbRec.Code, cbRec.Body.String())
	}
	if got := cbRec.Header().Get("Location"); got != "/admin/cache" {
		t.Fatalf("post-login redirect = %q, want /admin/cache", got)
	}
	var sessionCookie *http.Cookie
	for _, c := range cbRec.Result().Cookies() {
		if c.Name == svc.cookieName && c.Value != "" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie set after callback")
	}

	// 4) Authenticate with the session cookie.
	apiReq := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	apiReq.AddCookie(sessionCookie)
	id, err := svc.Authenticate(context.Background(), apiReq)
	if err != nil {
		t.Fatalf("authenticate via session: %v", err)
	}
	if id.Subject != "alice@example.com" || !id.Can(CapAdminister) || id.Method != "oidc-session" {
		t.Fatalf("session identity wrong: %+v can-admin=%v", id, id.Can(CapAdminister))
	}
}

func TestOIDCCallbackStateMismatch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idp := newMockIdP(t, "pullthrough-admin")
	svc := newOIDCService(t, idp, now)

	loginRec := httptest.NewRecorder()
	svc.HandleLogin(loginRec, httptest.NewRequest(http.MethodGet, "/admin/auth/login", nil))
	var flowCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == svc.flowCookieName {
			flowCookie = c
		}
	}

	cbReq := httptest.NewRequest(http.MethodGet, "/admin/auth/callback?code=abc&state=WRONG", nil)
	cbReq.AddCookie(flowCookie)
	cbRec := httptest.NewRecorder()
	svc.HandleCallback(cbRec, cbReq)
	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch status = %d, want 400", cbRec.Code)
	}
}

func TestOIDCBearerValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idp := newMockIdP(t, "pullthrough-admin")
	svc := newOIDCService(t, idp, now)

	// Valid bearer with a group → operator.
	token := idp.signToken(t, now, map[string]any{"groups": []string{"operator"}})
	r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	id, err := svc.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("bearer authenticate: %v", err)
	}
	if id.Method != "oidc-bearer" || !id.Can(CapOperate) || id.Can(CapAdminister) {
		t.Fatalf("bearer identity wrong: %+v", id)
	}

	// Expired token is rejected.
	past := time.Unix(1_600_000_000, 0)
	expired := idp.signToken(t, past, map[string]any{"exp": past.Add(time.Hour).Unix(), "groups": []string{"admin"}})
	r2 := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r2.Header.Set("Authorization", "Bearer "+expired)
	if _, err := svc.Authenticate(context.Background(), r2); err != auth.ErrUnauthenticated {
		t.Fatalf("expired token: want ErrUnauthenticated, got %v", err)
	}

	// A token whose groups map to no role is denied (no roles assigned).
	noRole := idp.signToken(t, now, map[string]any{"groups": []string{"random"}})
	r3 := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r3.Header.Set("Authorization", "Bearer "+noRole)
	if _, err := svc.Authenticate(context.Background(), r3); err != auth.ErrUnauthenticated {
		t.Fatalf("no-role token: want ErrUnauthenticated, got %v", err)
	}
}

func TestOIDCDiscovery(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idp := newMockIdP(t, "pullthrough-admin")
	// No explicit endpoints / JWKS: must be discovered from the well-known doc.
	svc, err := New(Options{
		Prefix:        "/admin",
		SessionKey:    []byte("0123456789abcdef0123456789abcdef"),
		SecureCookies: false,
		OIDC: &OIDCConfig{
			Issuer:      idp.issuer,
			ClientID:    idp.clientID,
			RedirectURL: "https://proxy.example.com/admin/auth/callback",
			Now:         func() time.Time { return now },
		},
	})
	if err != nil {
		t.Fatalf("New with discovery: %v", err)
	}
	if got := svc.oidc.authzURL; got != idp.issuer+"/authorize" {
		t.Fatalf("discovered authz endpoint = %q", got)
	}
	if got := svc.oidc.tokenURL; got != idp.issuer+"/token" {
		t.Fatalf("discovered token endpoint = %q", got)
	}
	token := idp.signToken(t, now, map[string]any{"groups": []string{"admin"}})
	r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	if _, err := svc.Authenticate(context.Background(), r); err != nil {
		t.Fatalf("authenticate after discovery: %v", err)
	}
}

func TestMetricsRecorded(t *testing.T) {
	svc, _ := New(Options{
		Prefix:       "/admin",
		StaticTokens: []StaticToken{{Name: "a", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"}},
	})
	ok := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	ok.Header.Set("Authorization", "Bearer viewer-token-abcdef0123456789")
	if _, err := svc.Authenticate(context.Background(), ok); err != nil {
		t.Fatalf("auth: %v", err)
	}
	bad := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	_, _ = svc.Authenticate(context.Background(), bad)

	snap := svc.Metrics().Snapshot()
	if snap.AuthSuccessByRole["viewer"] != 1 {
		t.Errorf("auth success by role viewer = %d, want 1", snap.AuthSuccessByRole["viewer"])
	}
	if snap.AuthFailureByReason["no_credential"] != 1 {
		t.Errorf("auth failure no_credential = %d, want 1", snap.AuthFailureByReason["no_credential"])
	}

	id := newIdentity("a", "static", "", "", []Role{RoleViewer})
	if svc.Authorize(id, CapOperate) {
		t.Error("viewer should not have operate")
	}
	if !svc.Authorize(id, CapRead) {
		t.Error("viewer should have read")
	}
	snap = svc.Metrics().Snapshot()
	if snap.AuthzDenyByCap["operate"] != 1 || snap.AuthzAllowByCap["read"] != 1 {
		t.Errorf("authz metrics wrong: %+v", snap)
	}
}

func TestSanitizeReturn(t *testing.T) {
	svc, _ := New(Options{Prefix: "/admin", LegacyAdminToken: "x"})
	cases := map[string]string{
		"/admin/cache":             "/admin/cache",
		"/admin":                   "/admin",
		"https://evil.example.com": "",
		"//evil.example.com":       "",
		"/other/path":              "",
		"":                         "",
	}
	for in, want := range cases {
		if got := svc.sanitizeReturn(in); got != want {
			t.Errorf("sanitizeReturn(%q) = %q, want %q", in, got, want)
		}
	}
}
