package userlinks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/signin"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

func TestCallbackPaths(t *testing.T) {
	for _, tc := range []struct {
		redirect, public string
		cookie, route    string
		bad              bool
	}{
		{"https://p.example.com/links/callback", "https://p.example.com", "/links/callback", "/links/callback", false},
		{"https://p.example.com/auth/oidc", "https://p.example.com", "/auth/oidc", "/auth/oidc", false},
		{"https://p.example.com:8889/auth/oidc", "https://p.example.com:8889/", "/auth/oidc", "/auth/oidc", false},
		// Behind a reverse proxy that serves the proxy under /pt and takes the
		// prefix off: the browser comes back to /pt/…, the gateway sees /….
		{"https://p.example.com/pt/auth/oidc", "https://p.example.com/pt", "/pt/auth/oidc", "/auth/oidc", false},
		{"https://p.example.com/ptx/auth/oidc", "https://p.example.com/pt", "/ptx/auth/oidc", "/ptx/auth/oidc", false},
		{"https://p.example.com/", "https://p.example.com", "", "", true},
		{"https://p.example.com", "https://p.example.com", "", "", true},
		{"/auth/oidc", "https://p.example.com", "", "", true},
		{"ftp://p.example.com/cb", "https://p.example.com", "", "", true},
	} {
		cookie, route, err := CallbackPaths(tc.redirect, tc.public)
		if (err != nil) != tc.bad || cookie != tc.cookie || route != tc.route {
			t.Errorf("CallbackPaths(%q, %q) = %q, %q, %v", tc.redirect, tc.public, cookie, route, err)
		}
	}
}

// The page's sign-in comes back at a redirect URI of the identity provider's
// registration rather than at its own <uiPath>/callback: the gateway serves
// that path (internal/signin), the login-flow cookie is scoped to it, and the
// sign-in completes there. The provider is shaped like Microsoft Entra ID: the
// redirect URI is a single-page application's, so the code is redeemed
// cross-origin, and the user is named by preferred_username.
func TestSignInAtACallbackOfItsOwn(t *testing.T) {
	idp, err := oidctest.Start("entra-app-client", "")
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()

	var svc *Service
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	redirect := srv.URL + "/auth/oidc"
	idp.AllowSPARedirect(redirect)

	svc, err = New(Config{
		PublicURL:       srv.URL,
		Store:           NewMemoryStore(),
		SessionKey:      sessionKey,
		InsecureCookies: true,
		SubjectClaim:    "preferred_username",
		DefaultRoles:    []string{"reader"},
		OIDC: &OIDCConfig{
			Issuer:       idp.Issuer(),
			DiscoveryURL: idp.AliasIssuer() + "/.well-known/openid-configuration",
			ClientID:     idp.ClientID(),
			RedirectURL:  redirect,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if got := svc.CallbackRoute(); got != "/auth/oidc" {
		t.Fatalf("CallbackRoute = %q", got)
	}
	mux.Handle(svc.UIPath(), svc.Handler())
	mux.Handle(svc.UIPath()+"/", svc.Handler())
	routes := signin.Routes(svc)
	for path, h := range routes {
		mux.Handle("GET "+path, h)
	}
	if len(routes) != 1 {
		t.Fatalf("routes = %v", routes)
	}

	// The login-flow cookie is set for the callback path.
	rr := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, srv.URL+"/links/login", nil))
	var flow *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == flowCookie {
			flow = c
		}
	}
	if flow == nil || flow.Path != "/auth/oidc" {
		t.Fatalf("flow cookie = %+v", flow)
	}

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	idp.SignInAs(oidctest.User{Subject: "pairwise-1", Username: "Alice@Contoso.Example", Name: "Alice"})
	resp, err := browser.Get(srv.URL + "/links/login")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/links/" {
		t.Fatalf("the browser ended on %d %s", resp.StatusCode, resp.Request.URL)
	}
	if got := idp.TokenOrigins(); len(got) != 2 || got[0] != "" || got[1] != srv.URL {
		t.Fatalf("token request origins = %q", got)
	}
	// The flow cookie is spent; the session is the page's.
	u, _ := url.Parse(srv.URL + "/auth/oidc")
	for _, c := range jar.Cookies(u) {
		if c.Name == flowCookie {
			t.Fatalf("the flow cookie outlived the sign-in: %+v", c)
		}
	}
	resp, err = browser.Get(srv.URL + "/links/api/session")
	if err != nil {
		t.Fatal(err)
	}
	var session map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&session)
	resp.Body.Close()
	user, _ := session["user"].(map[string]any)
	if user == nil || !strings.EqualFold(asString(user["subject"]), "alice@contoso.example") {
		t.Fatalf("session = %v", session)
	}

	// A request at the callback without a sign-in started here is refused.
	resp, err = http.Get(srv.URL + "/auth/oidc?code=forged&state=forged")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a forged callback: %d", resp.StatusCode)
	}
}

func asString(v any) string { s, _ := v.(string); return s }
