package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

// When adminAuth is enabled but cannot be built, the admin surface is served
// only behind the legacy admin token, if one is configured and allowed; else it
// is not served at all — never without authentication.
func TestBuildAdminAuthOrClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := false
	broken := func(c *config.Config) {
		c.AdminAuth.Enabled = true
		c.AdminAuth.SessionKey = "0123456789abcdef0123456789abcdef"
		c.AdminAuth.OIDC = config.AdminOIDCConfig{
			Enabled: true, Issuer: "https://idp.example.com", ClientID: "c",
			RedirectURL: "https://proxy.example.com/admin/auth/callback",
			JWKS:        "this is not a JWK set",
		}
	}
	for name, tc := range map[string]struct {
		mutate     func(*config.Config)
		wantSvc    bool
		wantClosed bool
	}{
		"disabled": {func(c *config.Config) {}, false, false},
		"static tokens": {func(c *config.Config) {
			c.AdminAuth.Enabled = true
			c.AdminAuth.StaticTokens = []config.AdminStaticTokenConfig{{Name: "owner", Roles: []string{"admin"}, Token: "admin-token-abcdef0123456789xyz"}}
		}, true, false},
		"broken, no legacy token": {broken, false, true},
		"broken, legacy token": {func(c *config.Config) {
			broken(c)
			c.Observability.AdminToken = "legacy-admin-token-0123456789"
		}, false, false},
		"broken, legacy token not allowed": {func(c *config.Config) {
			broken(c)
			c.Observability.AdminToken = "legacy-admin-token-0123456789"
			c.AdminAuth.AllowLegacyToken = &f
		}, false, true},
	} {
		cfg := config.Default()
		tc.mutate(&cfg)
		svc, closed := buildAdminAuthOrClose(&cfg, logger)
		if (svc != nil) != tc.wantSvc || closed != tc.wantClosed {
			t.Errorf("%s: service %v, closed %v; want service %v, closed %v", name, svc != nil, closed, tc.wantSvc, tc.wantClosed)
		}
	}
}

// The hosted instance's set-up, end to end through the gateway: the console
// and the personal-links page both sign users in at an identity provider
// shaped like Microsoft Entra ID — metadata under an alias of the issuer, a
// single-page-application redirect URI redeemed cross-origin, the user named
// in preferred_username, no groups — through the one redirect URI
// <origin>/auth/oidc, which both share. The user bound in
// adminAuth.subjectBindings is an admin; the console's cookie session refuses
// a state-changing request that lacks the CSRF header.
func TestEntraSignInThroughTheGateway(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	idp, err := oidctest.Start("entra-app-client", "")
	if err != nil {
		t.Fatal(err)
	}
	defer idp.Close()

	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer srv.Close()
	callback := srv.URL + "/auth/oidc"
	idp.AllowSPARedirect(callback)

	cfg := config.Default()
	cfg.Server.PublicURL = srv.URL
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(t.TempDir(), "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{"npm": {Type: "npm", URL: "https://registry.npmjs.org"}}
	cfg.Observability.Admin = true
	cfg.AdminAuth = config.AdminAuthConfig{
		Enabled:         true,
		SessionKey:      "0123456789abcdef0123456789abcdef",
		InsecureCookies: true, // the test server speaks plain HTTP
		SubjectBindings: map[string]string{"alice@contoso.example": "admin"},
		OIDC: config.AdminOIDCConfig{
			Enabled:      true,
			Issuer:       idp.Issuer(),
			DiscoveryURL: idp.AliasIssuer() + "/.well-known/openid-configuration",
			ClientID:     idp.ClientID(),
			RedirectURL:  callback,
			Scopes:       []string{"openid", "profile", "email"},
			SubjectClaim: "preferred_username",
			Audience:     "urn:pullthrough:admin-api",
		},
	}
	cfg.UserLinks.Enabled = true
	cfg.UserLinks.SessionKey = "0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.UserLinks.InsecureCookies = true
	cfg.UserLinks.Store.Backend = "memory"
	cfg.UserLinks.OIDC = config.UserLinksOIDCConfig{
		Enabled:      true,
		Issuer:       idp.Issuer(),
		DiscoveryURL: idp.AliasIssuer() + "/.well-known/openid-configuration",
		ClientID:     idp.ClientID(),
		RedirectURL:  callback,
		SubjectClaim: "preferred_username",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the configuration is not valid: %v", err)
	}

	adminSvc, closed := buildAdminAuthOrClose(&cfg, logger)
	if adminSvc == nil || closed {
		t.Fatalf("admin auth: %v, closed %v", adminSvc, closed)
	}
	links, err := buildUserLinks(&cfg, nil, mustResolver(t), logger)
	if err != nil {
		t.Fatal(err)
	}
	defer links.Close()
	adminSrv, err := admin.New(admin.Options{Logger: logger, PathPrefix: "/admin", Cache: cache.NewMemoryCache(), AdminAuth: adminSvc})
	if err != nil {
		t.Fatal(err)
	}
	callbacks := signInCallbacks(adminSvc, links)
	if len(callbacks) != 1 || callbacks["/auth/oidc"] == nil {
		t.Fatalf("sign-in callbacks = %v", callbacks)
	}
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cache.NewMemoryCache(), Backends: backends.NewRegistry(),
		AdminHandler: adminSrv.Handler(), UserLinks: links, SignInCallbacks: callbacks,
	}, proxy.Options{HTTPAddr: ":0", AdminPrefix: "/admin", PublicURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	handler = gw.Handler()

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	get := func(path string) (int, string, string) {
		t.Helper()
		resp, err := browser.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Request.URL.Path, string(body)
	}

	// The console.
	idp.SignInAs(oidctest.User{Subject: "pairwise-a", Username: "Alice@Contoso.Example", Name: "Alice"})
	if code, at, body := get("/admin/auth/login"); code != http.StatusOK || at != "/admin/" {
		t.Fatalf("console sign-in ended on %d %s: %.200s", code, at, body)
	}
	code, _, body := get("/admin/auth/userinfo")
	var who struct {
		Authenticated bool     `json:"authenticated"`
		Subject       string   `json:"subject"`
		Roles         []string `json:"roles"`
		Method        string   `json:"method"`
	}
	if err := json.Unmarshal([]byte(body), &who); err != nil || code != http.StatusOK {
		t.Fatalf("userinfo: %d %s", code, body)
	}
	if !who.Authenticated || who.Subject != "Alice@Contoso.Example" || strings.Join(who.Roles, ",") != "admin" || who.Method != "oidc-session" {
		t.Fatalf("signed in as %+v", who)
	}
	if code, _, body := get("/admin/api/overview"); code != http.StatusOK {
		t.Fatalf("overview with the session: %d %s", code, body)
	}

	post := func(header bool) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/admin/api/upstreams/drain", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		if header {
			req.Header.Set(adminauth.CSRFHeader, "1")
		}
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := post(false); code != http.StatusForbidden || !strings.Contains(body, "cross-site request refused") {
		t.Fatalf("a POST with the cookie alone: %d %s", code, body)
	}
	if code, body := post(true); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("a POST the console sends: %d %s", code, body)
	}

	// The personal-links page, through the same callback path.
	idp.SignInAs(oidctest.User{Subject: "pairwise-b", Username: "Alice@Contoso.Example", Name: "Alice"})
	if code, at, body := get("/links/login"); code != http.StatusOK || at != "/links/" {
		t.Fatalf("links sign-in ended on %d %s: %.200s", code, at, body)
	}
	code, _, body = get("/links/api/session")
	if code != http.StatusOK || !strings.Contains(body, `"alice@contoso.example"`) {
		t.Fatalf("links session: %d %s", code, body)
	}

	// Each redemption was refused without an Origin header first, then made
	// cross-origin.
	if got := idp.TokenOrigins(); len(got) != 4 || got[0] != "" || got[1] != srv.URL || got[2] != "" || got[3] != srv.URL {
		t.Fatalf("token request origins = %q", got)
	}

	// Someone else of the tenant signs in at the provider, and is no admin.
	jar2, _ := cookiejar.New(nil)
	browser.Jar = jar2
	idp.SignInAs(oidctest.User{Subject: "pairwise-c", Username: "guest@example.com"})
	if code, _, body := get("/admin/auth/login"); code != http.StatusForbidden || !strings.Contains(body, "no admin roles") {
		t.Fatalf("an unbound user: %d %s", code, body)
	}
}
