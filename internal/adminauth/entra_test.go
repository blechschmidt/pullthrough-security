package adminauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/signin"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

// A signed-in user is bound to a role by the value of the subject claim — an
// e-mail-like subject ASCII case-insensitively, any other exactly — and holds
// the roles of their groups as well.
func TestSubjectBindings(t *testing.T) {
	svc, err := New(Options{
		Prefix:     "/admin",
		SessionKey: []byte("0123456789abcdef0123456789abcdef"),
		OIDC: &OIDCConfig{
			Issuer: "https://idp.example.com", ClientID: "c", RedirectURL: "https://proxy.example.com/admin/auth/callback",
		},
		RoleBindings: map[string]string{"ops": "operator"},
		SubjectBindings: map[string]string{
			"Alice@Contoso.Example": "admin",
			"kelvin@example.com":    "admin",
			"XTDg-pairwise":         "viewer",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		subject string
		groups  []string
		want    string
	}{
		{"alice@contoso.example", nil, "admin"},
		{"ALICE@CONTOSO.EXAMPLE", nil, "admin"},
		{" alice@contoso.example ", nil, "admin"},
		{"Kelvin@example.com", nil, ""}, // the Kelvin sign is not a "k"
		{"XTDg-pairwise", nil, "viewer"},
		{"xtdg-pairwise", nil, ""}, // not e-mail-like: exact
		{"someone@example.com", []string{"ops"}, "operator"},
		{"alice@contoso.example", []string{"ops"}, "admin,operator"},
		{"someone@example.com", nil, ""},
		{"", []string{"admin"}, "admin"},
	}
	for _, tc := range cases {
		var got []string
		for _, r := range svc.rolesFor(tc.subject, tc.groups) {
			got = append(got, string(r))
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("rolesFor(%q, %v) = %v, want %q", tc.subject, tc.groups, got, tc.want)
		}
	}

	for name, opts := range map[string]Options{
		"unknown role":  {SubjectBindings: map[string]string{"a@example.com": "root"}},
		"empty subject": {SubjectBindings: map[string]string{"  ": "admin"}},
	} {
		opts.Prefix = "/admin"
		opts.StaticTokens = []StaticToken{{Name: "t", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"}}
		if _, err := New(opts); err == nil {
			t.Errorf("%s: New accepted %v", name, opts.SubjectBindings)
		}
	}
}

// entraSetup is an identity provider that behaves like Microsoft Entra ID for
// the console's sign-in: its metadata is published under an alias of its
// issuer, the redirect URI is registered as a single-page application, and the
// ID token names the user in preferred_username and carries no groups.
type entraSetup struct {
	idp         *oidctest.Provider
	svc         *Service
	redirectURL string
}

const entraRedirect = "https://proxy.example.com:8889/auth/oidc"

func newEntraSetup(t *testing.T, mutate func(*Options)) *entraSetup {
	t.Helper()
	idp, err := oidctest.Start("entra-app-client", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)
	idp.AllowSPARedirect(entraRedirect)
	opts := Options{
		Prefix:        "/admin",
		SessionKey:    []byte("0123456789abcdef0123456789abcdef"),
		SecureCookies: true,
		OIDC: &OIDCConfig{
			Issuer:       idp.Issuer(),
			DiscoveryURL: idp.AliasIssuer() + "/.well-known/openid-configuration",
			ClientID:     idp.ClientID(),
			RedirectURL:  entraRedirect,
			Scopes:       []string{"openid", "profile", "email"},
			SubjectClaim: "preferred_username",
			Audience:     "urn:pullthrough:admin-api",
		},
		SubjectBindings: map[string]string{"alice@contoso.example": "admin"},
	}
	if mutate != nil {
		mutate(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &entraSetup{idp: idp, svc: svc, redirectURL: entraRedirect}
}

// signIn runs the browser's part of a sign-in: it starts it at the console,
// lets the provider sign the current user in, and returns the response of the
// callback — through the dispatcher the gateway mounts, when the service has a
// route of its own.
func (e *entraSetup) signIn(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	e.svc.HandleLogin(rr, httptest.NewRequest(http.MethodGet, "/admin/auth/login?return=/admin/%23downloads", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rr.Code, rr.Body)
	}
	var flow *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == e.svc.flowCookieName {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("no login-flow cookie")
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(back, e.redirectURL+"?") {
		t.Fatalf("the provider answered %d → %q", resp.StatusCode, back)
	}
	cb := httptest.NewRequest(http.MethodGet, back, nil)
	cb.AddCookie(flow)
	out := httptest.NewRecorder()
	h, ok := signin.Routes(e.svc)[e.svc.CallbackRoute()]
	if !ok {
		h = http.HandlerFunc(e.svc.HandleCallback)
	}
	h.ServeHTTP(out, cb)
	return out
}

func sessionCookieOf(t *testing.T, svc *Service, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == svc.cookieName && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie (status %d, body %q)", rr.Code, rr.Body.String())
	return nil
}

// The console signs in through a provider shaped like Microsoft Entra ID, at a
// callback path of its own, and the bound user is an admin.
func TestEntraShapedSignIn(t *testing.T) {
	e := newEntraSetup(t, nil)
	if got := e.svc.CallbackRoute(); got != "/auth/oidc" {
		t.Fatalf("CallbackRoute = %q", got)
	}
	e.idp.SignInAs(oidctest.User{
		Subject:  "aPairwiseSubjectPerApplication-0123456789A", // pairwise, per application
		Username: "Alice@Contoso.Example",
		Name:     "Alice",
		Extra:    map[string]any{"oid": "11111111-2222-3333-4444-555555555555", "tid": "00000000-1111"},
	})
	rr := e.signIn(t)
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/admin/#downloads" {
		t.Fatalf("callback: %d → %q (%s)", rr.Code, rr.Header().Get("Location"), rr.Body)
	}
	// Entra refused the redemption without an Origin; the second attempt
	// carried the redirect URI's origin.
	if got := e.idp.TokenOrigins(); len(got) != 2 || got[0] != "" || got[1] != "https://proxy.example.com:8889" {
		t.Fatalf("token request origins = %q", got)
	}
	session := sessionCookieOf(t, e.svc, rr)
	if session.Path != "/admin" || !session.Secure || !session.HttpOnly {
		t.Fatalf("session cookie = %+v", session)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	r.AddCookie(session)
	id, err := e.svc.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "Alice@Contoso.Example" || !id.Can(CapAdminister) || id.Method != "oidc-session" {
		t.Fatalf("identity = %+v", id)
	}

	// An ID token the provider issued to the same client is not an API bearer
	// token: the admin API expects another audience.
	tok, err := e.idp.IDToken(oidctest.User{Subject: "s", Username: "alice@contoso.example"}, "n", oidctest.FaultNone)
	if err != nil {
		t.Fatal(err)
	}
	br := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	br.Header.Set("Authorization", "Bearer "+tok)
	if _, err := e.svc.Authenticate(context.Background(), br); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("an ID token as API bearer: err = %v", err)
	}

	// Anyone else in the tenant signs in at the provider, and is refused here.
	e.idp.SignInAs(oidctest.User{Subject: "other", Username: "guest@example.com"})
	if rr := e.signIn(t); rr.Code != http.StatusForbidden {
		t.Fatalf("an unbound user: %d %s", rr.Code, rr.Body)
	}
}

// Microsoft Entra ID's discovery document for the tenant's domain declares the
// tenant-ID issuer. Configured as the issuer, the domain form is refused — the
// tokens would not carry it — with an error that says what to configure.
func TestEntraAliasIssuer(t *testing.T) {
	idp, err := oidctest.Start("entra-app-client", "")
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	svc, err := New(Options{
		Prefix:     "/admin",
		SessionKey: []byte("0123456789abcdef0123456789abcdef"),
		OIDC:       &OIDCConfig{Issuer: idp.AliasIssuer(), ClientID: idp.ClientID(), RedirectURL: entraRedirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	svc.HandleLogin(rr, httptest.NewRequest(http.MethodGet, "/admin/auth/login", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("login with the alias as issuer: %d", rr.Code)
	}
	_, err = svc.oidc.endpoints(context.Background())
	if err == nil || !strings.Contains(err.Error(), `set issuer to "`+idp.Issuer()+`"`) {
		t.Fatalf("resolution error = %v", err)
	}
}

// The provider is not contacted when the service is built. While it cannot be
// reached, sign-ins answer 503 and OIDC bearer tokens are refused, static
// tokens keep working, and the provider is asked again once the retry interval
// has passed.
func TestProviderUnreachable(t *testing.T) {
	idp, err := oidctest.Start("client", "")
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()
	idp.SetDown(true)

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	svc, err := New(Options{
		Prefix:       "/admin",
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		StaticTokens: []StaticToken{{Name: "owner", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"}},
		OIDC:         &OIDCConfig{Issuer: idp.Issuer(), ClientID: "client", RedirectURL: "https://proxy.example.com/admin/auth/callback", Now: clock},
		Now:          clock,
	})
	if err != nil {
		t.Fatalf("New with the provider down: %v", err)
	}
	if n := idp.Requests("discovery"); n != 0 {
		t.Fatalf("New asked the provider %d times", n)
	}

	login := func() int {
		rr := httptest.NewRecorder()
		svc.HandleLogin(rr, httptest.NewRequest(http.MethodGet, "/admin/auth/login", nil))
		return rr.Code
	}
	if code := login(); code != http.StatusServiceUnavailable {
		t.Fatalf("login with the provider down: %d", code)
	}
	tok, _ := idp.IDToken(oidctest.User{Subject: "admin"}, "", oidctest.FaultNone)
	bearer := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	bearer.Header.Set("Authorization", "Bearer "+tok)
	if _, err := svc.Authenticate(context.Background(), bearer); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("bearer with the provider down: %v", err)
	}
	static := httptest.NewRequest(http.MethodGet, "/admin/api/overview", nil)
	static.Header.Set("Authorization", "Bearer admin-token-abcdef0123456789xyz")
	if id, err := svc.Authenticate(context.Background(), static); err != nil || !id.Can(CapAdminister) {
		t.Fatalf("static token with the provider down: %+v %v", id, err)
	}

	idp.SetDown(false)
	asked := idp.Requests("discovery")
	if code := login(); code != http.StatusServiceUnavailable || idp.Requests("discovery") != asked {
		t.Fatalf("a failure is remembered for the retry interval: %d, %d requests", code, idp.Requests("discovery")-asked)
	}
	mu.Lock()
	now = now.Add(discoveryRetry + time.Second)
	mu.Unlock()
	if code := login(); code != http.StatusFound {
		t.Fatalf("login once the provider is back: %d", code)
	}
}

// The login-flow cookie is scoped to the path the provider sends the browser
// back to; CallbackState tells a callback of this flow from any other.
func TestCallbackRouteAndState(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	idp := newMockIdP(t, "pullthrough-admin")
	svc := newOIDCService(t, idp, now) // redirect URL: the console's own callback
	if got := svc.CallbackRoute(); got != "" {
		t.Fatalf("CallbackRoute with the default callback = %q", got)
	}
	rr := httptest.NewRecorder()
	svc.HandleLogin(rr, httptest.NewRequest(http.MethodGet, "/admin/auth/login", nil))
	loc, _ := url.Parse(rr.Header().Get("Location"))
	state := loc.Query().Get("state")
	var flow *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == svc.flowCookieName {
			flow = c
		}
	}
	if flow == nil || flow.Path != "/admin/auth/callback" {
		t.Fatalf("flow cookie = %+v", flow)
	}

	req := func(state string, cookie *http.Cookie) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/admin/auth/callback?code=c&state="+url.QueryEscape(state), nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		return r
	}
	tampered := *flow
	tampered.Value = flow.Value[:len(flow.Value)-2] + "xx"
	for name, tc := range map[string]struct {
		r    *http.Request
		want signin.State
	}{
		"no cookie":       {req(state, nil), signin.Absent},
		"matching":        {req(state, flow), signin.Matches},
		"other state":     {req("another", flow), signin.Foreign},
		"tampered cookie": {req(state, &tampered), signin.Foreign},
	} {
		if got := svc.CallbackState(tc.r); got != tc.want {
			t.Errorf("%s: CallbackState = %v, want %v", name, got, tc.want)
		}
	}

	// Static-only mode has no sign-in.
	static, _ := New(Options{Prefix: "/admin", StaticTokens: []StaticToken{{Name: "t", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"}}})
	if static.CallbackRoute() != "" || static.CallbackState(req(state, flow)) != signin.Absent {
		t.Fatal("a service without OIDC claims a callback")
	}
}

// A state-changing request authenticated only by the session cookie must show
// that the console sent it; a read, or a request with a token, need not.
func TestSessionCookieMutationsNeedTheCSRFHeader(t *testing.T) {
	svc, err := New(Options{
		Prefix:       "/admin",
		SessionKey:   []byte("0123456789abcdef0123456789abcdef"),
		StaticTokens: []StaticToken{{Name: "ci", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"}},
		OIDC:         &OIDCConfig{Issuer: "https://idp.example.com", ClientID: "c", RedirectURL: "https://proxy.example.com/admin/auth/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := svc.codec.encodeSession(newIdentity("alice@example.com", "oidc-session", "https://idp.example.com", "", []Role{RoleAdmin}), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: svc.cookieName, Value: value}

	call := func(method string, header, token bool) (*Identity, error) {
		r := httptest.NewRequest(method, "/admin/api/lockdown", nil)
		r.AddCookie(session)
		if header {
			r.Header.Set(CSRFHeader, "1")
		}
		if token {
			r.Header.Set("Authorization", "Bearer operator-token-abcdef0123456789")
		}
		return svc.Authenticate(context.Background(), r)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if _, err := call(method, false, false); !errors.Is(err, ErrCrossSiteRequest) || !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("%s with the cookie alone: err = %v", method, err)
		}
		if id, err := call(method, true, false); err != nil || id.Subject != "alice@example.com" {
			t.Errorf("%s with the header: %+v %v", method, id, err)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if id, err := call(method, false, false); err != nil || id.Subject != "alice@example.com" {
			t.Errorf("%s with the cookie alone: %+v %v", method, id, err)
		}
	}
	// The token authenticates the request; the cookie is not what lets it in.
	if id, err := call(http.MethodPost, false, true); err != nil || id.Subject != "ci" {
		t.Errorf("POST with cookie and token: %+v %v", id, err)
	}
}
