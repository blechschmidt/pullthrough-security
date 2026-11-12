package userlinks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/uiaudit"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

// memAudit collects audit events.
type memAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memAudit) Log(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memAudit) reasons() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.events))
	for i, ev := range m.events {
		out[i] = string(ev.Decision) + " " + ev.Reason
	}
	return out
}

func (m *memAudit) find(reasonPrefix string) (audit.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.events) - 1; i >= 0; i-- {
		if strings.HasPrefix(m.events[i].Reason, reasonPrefix) {
			return m.events[i], true
		}
	}
	return audit.Event{}, false
}

// env is a personal-links service behind an HTTP server, with an identity
// provider to sign in at.
type env struct {
	t     *testing.T
	idp   *oidctest.Provider
	svc   *Service
	srv   *httptest.Server
	audit *memAudit
	store Store
}

var sessionKey = []byte("0123456789abcdef0123456789abcdef-test-key")

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	idp, err := oidctest.Start("pullthrough-cache", "s3cr3t/with:odd chars")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(idp.Close)

	e := &env{t: t, idp: idp, audit: &memAudit{}, store: NewMemoryStore()}
	// The service needs to know its public URL, which is the server's; the
	// server therefore starts first and looks the service up per request.
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.svc.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)

	cfg := Config{
		PublicURL:       e.srv.URL,
		Store:           e.store,
		SessionKey:      sessionKey,
		InsecureCookies: true, // the test server speaks plain HTTP
		OIDC: &OIDCConfig{
			Issuer:       idp.Issuer(),
			ClientID:     idp.ClientID(),
			ClientSecret: idp.ClientSecret(),
		},
		Backends: []onboard.Backend{
			{Name: "pypi", Type: "pip", URL: "https://pypi.org"},
			{Name: "npm", Type: "npm", URL: "https://registry.npmjs.org"},
			{Name: "dockerhub", Type: "docker", URL: "https://registry-1.docker.io"},
		},
		Audit:    e.audit,
		ClientIP: func(r *http.Request) string { return "203.0.113.9" },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	e.svc, err = New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	idp.AllowRedirect(e.srv.URL + e.svc.UIPath() + "/callback")
	return e
}

// browser returns an HTTP client that behaves like one: it keeps cookies and
// follows redirects.
func (e *env) browser() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 20 * time.Second}
}

func (e *env) url(path string) string { return e.srv.URL + e.svc.UIPath() + path }

// signIn drives a sign-in through the identity provider as the given user and
// returns the page the browser ends up on.
func (e *env) signIn(c *http.Client, u oidctest.User) (int, string) {
	e.t.Helper()
	e.idp.SignInAs(u)
	resp, err := c.Get(e.url("/login"))
	if err != nil {
		e.t.Fatalf("sign-in: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// call makes an API request the way the page's script does.
func (e *env) call(c *http.Client, method, path string, body any, mutate func(*http.Request)) (int, map[string]any) {
	e.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, e.url(path), reader)
	if err != nil {
		e.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set(csrfHeader, "1")
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			e.t.Fatalf("%s %s answered %d with a body that is not JSON: %s", method, path, resp.StatusCode, data)
		}
	}
	return resp.StatusCode, out
}

var aliceAtIdP = oidctest.User{
	Subject: "idp-sub-0001", Email: "Alice@Example.com", Name: "Alice Example",
	Groups: []string{"engineering", "dev"}, Team: "platform",
}

func TestSignInAndManageLinks(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.DefaultRoles = []string{"reader"}
		c.RoleMap = map[string]string{"engineering": "builder"}
		c.KnownRoles = []string{"reader", "builder", "dev"}
		c.TokenSnippets = true
	})
	c := e.browser()

	// Not signed in: the page says so, and its API refuses.
	status, session := e.call(c, "GET", "/api/session", nil, nil)
	if status != 200 || session["authenticated"] != false || session["signInEnabled"] != true || session["signInUrl"] != "/links/login" {
		t.Fatalf("session before sign-in = %d %v", status, session)
	}
	if ups, _ := session["upstreams"].([]any); len(ups) != 0 {
		t.Fatalf("the upstreams are listed to someone who is not signed in: %v", ups)
	}
	if status, _ := e.call(c, "GET", "/api/links", nil, nil); status != 401 {
		t.Fatalf("listing links without a session: %d, want 401", status)
	}
	if status, _ := e.call(c, "POST", "/api/links", map[string]any{"label": "x"}, nil); status != 401 {
		t.Fatalf("creating a link without a session: %d, want 401", status)
	}

	// Sign in through the identity provider.
	status, page := e.signIn(c, aliceAtIdP)
	if status != 200 || !strings.Contains(page, "<title>Personal cache links</title>") {
		t.Fatalf("after sign-in the browser is on: %d %.200s", status, page)
	}
	status, session = e.call(c, "GET", "/api/session", nil, nil)
	user, _ := session["user"].(map[string]any)
	if status != 200 || session["authenticated"] != true || user == nil {
		t.Fatalf("session after sign-in = %d %v", status, session)
	}
	// The e-mail address is the subject, in lower case; the provider's own
	// identifier is kept next to it; roles are the defaults, the mapped groups
	// and the groups that are role names.
	if user["subject"] != "alice@example.com" || user["oidcSubject"] != "idp-sub-0001" || user["team"] != "platform" ||
		user["name"] != "Alice Example" || user["issuer"] != e.idp.Issuer() {
		t.Fatalf("user = %v", user)
	}
	if roles, _ := json.Marshal(user["roles"]); string(roles) != `["builder","dev","reader"]` {
		t.Fatalf("roles = %s", roles)
	}
	if ups, _ := session["upstreams"].([]any); len(ups) != 3 {
		t.Fatalf("upstreams = %v", session["upstreams"])
	}

	// Create a link. This is the one response with a token in it.
	status, created := e.call(c, "POST", "/api/links", map[string]any{"label": "laptop", "ttlDays": 7}, nil)
	if status != 201 {
		t.Fatalf("creating a link: %d %v", status, created)
	}
	token, _ := created["token"].(string)
	if !WellFormed(token) {
		t.Fatalf("the response carries no token: %v", created)
	}
	base := e.srv.URL + "/u/" + token
	if created["baseUrl"] != base {
		t.Fatalf("baseUrl = %v, want %s", created["baseUrl"], base)
	}
	link, _ := created["link"].(map[string]any)
	if link["label"] != "laptop" || link["state"] != "active" || link["subject"] != "alice@example.com" || link["createdFrom"] != "203.0.113.9" {
		t.Fatalf("link = %v", link)
	}
	exp, _ := time.Parse(time.RFC3339, link["expiresAt"].(string))
	if d := time.Until(exp); d < 6*24*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("the link expires in %v, want seven days", d)
	}
	ups, _ := created["upstreams"].([]any)
	if len(ups) != 3 {
		t.Fatalf("upstreams of a new link = %v", ups)
	}
	byName := map[string]map[string]any{}
	for _, raw := range ups {
		up := raw.(map[string]any)
		byName[up["name"].(string)] = up
	}
	if byName["npm"]["url"] != base+"/v1/npm/" || byName["pypi"]["url"] != base+"/v1/pypi/" {
		t.Fatalf("personal URLs = %v / %v", byName["npm"]["url"], byName["pypi"]["url"])
	}
	npmSnippet := byName["npm"]["snippets"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(npmSnippet, "registry="+base+"/v1/npm/") || strings.Contains(npmSnippet, "_authToken") ||
		!strings.Contains(npmSnippet, "omit-lockfile-registry-resolved=true") {
		t.Fatalf("npm snippet for a personal link:\n%s", npmSnippet)
	}
	pipSnippet := byName["pypi"]["snippets"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(pipSnippet, "index-url = "+base+"/v1/pypi/simple/") {
		t.Fatalf("pip snippet for a personal link:\n%s", pipSnippet)
	}
	dockerSnippet := byName["dockerhub"]["snippets"].([]any)[0].(map[string]any)["body"].(string)
	host := strings.TrimPrefix(e.srv.URL, "http://")
	if !strings.Contains(dockerSnippet, "docker pull "+host+"/u/"+token+"/dockerhub/library/alpine:latest") {
		t.Fatalf("docker snippet for a personal link:\n%s", dockerSnippet)
	}
	// The same link as a credential, where the proxy asks clients to authenticate.
	tokenSnippet := byName["npm"]["tokenSnippets"].([]any)[0].(map[string]any)["body"].(string)
	if !strings.Contains(tokenSnippet, "registry="+e.srv.URL+"/v1/npm/") || !strings.Contains(tokenSnippet, ":_authToken="+token) {
		t.Fatalf("npm snippet for the link as a credential:\n%s", tokenSnippet)
	}

	// The link resolves, and the listing shows it — without the token, ever.
	resolved, err := e.svc.Registry().Resolve(context.Background(), token)
	if err != nil || resolved.Subject != "alice@example.com" || resolved.Team != "platform" {
		t.Fatalf("the created link does not resolve: %+v, %v", resolved, err)
	}
	status, listing := e.call(c, "GET", "/api/links", nil, nil)
	links, _ := listing["links"].([]any)
	if status != 200 || len(links) != 1 {
		t.Fatalf("listing = %d %v", status, listing)
	}
	raw, _ := json.Marshal(listing)
	if strings.Contains(string(raw), token) || strings.Contains(string(raw), "tokenHash") {
		t.Fatalf("the listing leaks the token or its hash: %s", raw)
	}
	id := links[0].(map[string]any)["id"].(string)

	// Revoke it.
	status, revoked := e.call(c, "POST", "/api/links/revoke", map[string]any{"id": id}, nil)
	if status != 200 || revoked["link"].(map[string]any)["state"] != "revoked" {
		t.Fatalf("revoking: %d %v", status, revoked)
	}
	if _, err := e.svc.Registry().Resolve(context.Background(), token); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("the revoked link resolves: %v", err)
	}

	// Sign out: the session is gone, the browser has to sign in again.
	if status, _ := e.call(c, "POST", "/logout", nil, nil); status != 204 {
		t.Fatalf("logout: %d", status)
	}
	if status, session := e.call(c, "GET", "/api/session", nil, nil); status != 200 || session["authenticated"] != false {
		t.Fatalf("session after sign-out = %v", session)
	}

	// Everything that happened is in the audit trail, attributed and addressed;
	// no event carries the token.
	want := []string{"allow userlinks: sign-in", "allow userlinks: link issued", "allow userlinks: link revoked"}
	got := e.audit.reasons()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("audit trail = %q, want %q", got, want)
	}
	for _, ev := range e.audit.events {
		if ev.Type != audit.EventAuth || ev.Subject != "alice@example.com" || ev.RemoteAddr != "203.0.113.9" {
			t.Fatalf("audit event = %+v", ev)
		}
		if data, _ := json.Marshal(ev); strings.Contains(string(data), token) {
			t.Fatalf("an audit event contains the token: %s", data)
		}
	}
	issued, _ := e.audit.find("userlinks: link issued")
	if issued.Detail["link"] != id || issued.Detail["label"] != "laptop" {
		t.Fatalf("the audit event of the issue does not name the link: %v", issued.Detail)
	}
	m := e.svc.Metrics()
	if m.SignInsStarted != 1 || m.SignInsCompleted != 1 || m.SignInsFailed != 0 || m.Registry.Issued != 1 || m.Registry.RevokedTotal != 1 {
		t.Fatalf("metrics = %+v", m)
	}
}

// A user manages their own links and nobody else's — and cannot find out
// whether someone else's exist.
func TestUsersAreIsolated(t *testing.T) {
	e := newEnv(t, nil)
	aliceBrowser, bobBrowser := e.browser(), e.browser()
	e.signIn(aliceBrowser, aliceAtIdP)
	e.signIn(bobBrowser, oidctest.User{Subject: "idp-sub-0002", Email: "bob@example.com"})

	_, created := e.call(aliceBrowser, "POST", "/api/links", map[string]any{"label": "alice's"}, nil)
	aliceToken := created["token"].(string)
	aliceID := created["link"].(map[string]any)["id"].(string)

	_, listing := e.call(bobBrowser, "GET", "/api/links", nil, nil)
	if links, _ := listing["links"].([]any); len(links) != 0 {
		t.Fatalf("bob sees links that are not his: %v", links)
	}
	status, body := e.call(bobBrowser, "POST", "/api/links/revoke", map[string]any{"id": aliceID}, nil)
	if status != 404 {
		t.Fatalf("bob revoking alice's link: %d %v, want 404", status, body)
	}
	statusUnknown, bodyUnknown := e.call(bobBrowser, "POST", "/api/links/revoke", map[string]any{"id": strings.Repeat("0", 16)}, nil)
	if statusUnknown != status || bodyUnknown["error"] != body["error"] {
		t.Fatalf("the answer tells someone else's link (%d %v) from one that does not exist (%d %v)", status, body, statusUnknown, bodyUnknown)
	}
	if _, err := e.svc.Registry().Resolve(context.Background(), aliceToken); err != nil {
		t.Fatalf("alice's link was affected: %v", err)
	}
}

// A request that changes something must come from the page itself.
func TestWritesNeedTheCSRFHeader(t *testing.T) {
	e := newEnv(t, nil)
	c := e.browser()
	e.signIn(c, aliceAtIdP)

	cases := map[string]func(*http.Request){
		"no header":           func(r *http.Request) { r.Header.Del(csrfHeader) },
		"cross-site":          func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"same-site, not same": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
		"another origin":      func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") },
		"an origin look-alike": func(r *http.Request) {
			r.Header.Set("Origin", e.srv.URL+".evil.example")
		},
	}
	for name, mutate := range cases {
		for _, path := range []string{"/api/links", "/api/links/revoke", "/logout"} {
			status, body := e.call(c, "POST", path, map[string]any{"label": "x"}, mutate)
			if status != 403 {
				t.Errorf("%s: POST %s = %d %v, want 403", name, path, status, body)
			}
		}
	}
	if n := len(e.svc.Links(Filter{})); n != 0 {
		t.Fatalf("%d links were created by forged requests", n)
	}
	// The page's own requests pass: with the header, same-origin, its own origin.
	status, _ := e.call(c, "POST", "/api/links", map[string]any{"label": "ok"}, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Origin", e.srv.URL)
	})
	if status != 201 {
		t.Fatalf("the page's own request was refused: %d", status)
	}
	// A GET never changes anything, with or without a session.
	for _, path := range []string{"/api/links/revoke", "/logout"} {
		resp, err := c.Get(e.url(path))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s = %d, want 405", path, resp.StatusCode)
		}
	}
}

func TestCreateLinkLimits(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxLinksPerUser = 2 })
	c := e.browser()
	e.signIn(c, aliceAtIdP)

	for _, bad := range []map[string]any{{"ttlDays": -1}, {"ttlDays": 100000}} {
		if status, body := e.call(c, "POST", "/api/links", bad, nil); status != 400 {
			t.Errorf("creating a link with %v: %d %v, want 400", bad, status, body)
		}
	}
	// A body that is not JSON, and one that is far too large.
	for name, body := range map[string]string{"not json": "{{{", "too large": `{"label":"` + strings.Repeat("x", maxRequestBody) + `"}`} {
		req, _ := http.NewRequest("POST", e.url("/api/links"), strings.NewReader(body))
		req.Header.Set(csrfHeader, "1")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}

	for i := 0; i < 2; i++ {
		if status, body := e.call(c, "POST", "/api/links", map[string]any{"label": "l"}, nil); status != 201 {
			t.Fatalf("link %d: %d %v", i, status, body)
		}
	}
	if status, body := e.call(c, "POST", "/api/links", map[string]any{"label": "one too many"}, nil); status != 409 {
		t.Fatalf("a third link with a limit of two: %d %v, want 409", status, body)
	}

	// The rate of creation is bounded as well, whatever is revoked in between.
	e2 := newEnv(t, func(c *Config) { c.MaxLinksPerUser = -1 })
	c2 := e2.browser()
	e2.signIn(c2, aliceAtIdP)
	created, limited := 0, 0
	for i := 0; i < creationsPerHour+5; i++ {
		switch status, _ := e2.call(c2, "POST", "/api/links", map[string]any{"label": "l"}, nil); status {
		case 201:
			created++
		case 429:
			limited++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if created != creationsPerHour || limited != 5 {
		t.Fatalf("%d links were created and %d requests limited, want %d and 5", created, limited, creationsPerHour)
	}
}

// Whatever the identity provider — or someone pretending to be it — does wrong,
// nobody is signed in.
func TestSignInRefusesWhatItCannotVerify(t *testing.T) {
	for _, fault := range []oidctest.Fault{
		oidctest.FaultWrongAudience, oidctest.FaultWrongIssuer, oidctest.FaultExpired, oidctest.FaultWrongKey,
		oidctest.FaultWrongNonce, oidctest.FaultUnsigned, oidctest.FaultNoIDToken, oidctest.FaultOtherAzp,
	} {
		t.Run(string(fault), func(t *testing.T) {
			e := newEnv(t, nil)
			e.idp.SetFault(fault)
			c := e.browser()
			status, page := e.signIn(c, aliceAtIdP)
			if status != http.StatusBadGateway || !strings.Contains(page, "Sign-in failed") {
				t.Fatalf("sign-in with a %s token: %d %.300s", fault, status, page)
			}
			if _, session := e.call(c, "GET", "/api/session", nil, nil); session["authenticated"] != false {
				t.Fatalf("a %s token signed someone in", fault)
			}
			if m := e.svc.Metrics(); m.SignInsFailed != 1 || m.SignInsCompleted != 0 {
				t.Fatalf("metrics = %+v", m)
			}
			// The failure page says nothing about the token or the provider's
			// internals, and is not cacheable.
			if strings.Contains(page, "eyJ") || strings.Contains(page, e.idp.Issuer()) {
				t.Fatalf("the failure page leaks details: %s", page)
			}
		})
	}
}

func TestSignInFlowIsBoundToTheBrowserThatStartedIt(t *testing.T) {
	e := newEnv(t, nil)
	e.idp.SignInAs(aliceAtIdP)

	// The victim's browser starts a sign-in but does not follow the redirect.
	victim := e.browser()
	victim.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := victim.Get(e.url("/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authURL := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(authURL, e.idp.Issuer()+"/authorize?") {
		t.Fatalf("login = %d → %q", resp.StatusCode, authURL)
	}
	q, _ := url.Parse(authURL)
	params := q.Query()
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(params.Get(name)) < 20 {
			t.Fatalf("the authorization request has a weak %s: %q", name, params.Get(name))
		}
	}
	if params.Get("code_challenge_method") != "S256" || params.Get("response_type") != "code" ||
		params.Get("redirect_uri") != e.url("/callback") || !strings.Contains(params.Get("scope"), "openid") {
		t.Fatalf("authorization request = %v", params)
	}
	// The flow cookie is the browser's half of the sign-in: private to the page,
	// unreadable to scripts.
	var flow *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == flowCookie {
			flow = c
		}
	}
	if flow == nil || !flow.HttpOnly || flow.SameSite != http.SameSiteLaxMode || flow.Path != "/links" || flow.MaxAge <= 0 {
		t.Fatalf("flow cookie = %+v", flow)
	}
	if strings.Contains(flow.Value, params.Get("state")) {
		// The value is signed, not encrypted — but base64, so a plain search
		// would not find it anyway. What matters is tested below: it cannot be
		// forged or replayed.
		t.Log("the state is visible in the cookie value")
	}

	// An attacker completes the authorization in their own browser and gets a
	// callback URL with a code for *their* account.
	attacker := e.browser()
	attacker.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	e.idp.SignInAs(oidctest.User{Subject: "attacker", Email: "attacker@example.com"})
	aresp, err := attacker.Get(e.url("/login"))
	if err != nil {
		t.Fatal(err)
	}
	aresp.Body.Close()
	aresp2, err := attacker.Get(aresp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	aresp2.Body.Close()
	attackerCallback := aresp2.Header.Get("Location")
	if !strings.Contains(attackerCallback, "code=") {
		t.Fatalf("the provider did not answer with a code: %q", attackerCallback)
	}

	// The victim's browser is made to open the attacker's callback URL (login
	// CSRF). Its flow cookie carries another state: the sign-in is refused, and
	// the victim does not end up signed in as the attacker.
	vresp, err := victim.Get(attackerCallback)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(vresp.Body)
	vresp.Body.Close()
	if vresp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "does not belong to the sign-in you started") {
		t.Fatalf("the victim's browser with the attacker's callback: %d %.300s", vresp.StatusCode, body)
	}
	if _, session := e.call(victim, "GET", "/api/session", nil, nil); session["authenticated"] != false {
		t.Fatal("login CSRF: the victim is signed in as the attacker")
	}
	// The refused callback spent the victim's flow cookie.
	for _, c := range vresp.Cookies() {
		if c.Name == flowCookie && c.MaxAge >= 0 {
			t.Fatalf("the flow cookie survived a refused callback: %+v", c)
		}
	}

	// A callback without any flow cookie, and one that is replayed.
	fresh := e.browser()
	fresh.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fresp, _ := fresh.Get(attackerCallback)
	fresp.Body.Close()
	if fresp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a callback without a started sign-in: %d", fresp.StatusCode)
	}
	done := e.browser()
	if status, _ := e.signIn(done, aliceAtIdP); status != 200 {
		t.Fatal("sign-in failed")
	}
	// The identity provider refusing, or the user cancelling.
	denied := e.browser()
	e.idp.Deny("access_denied")
	dresp, err := denied.Get(e.url("/login"))
	if err != nil {
		t.Fatal(err)
	}
	dbody, _ := io.ReadAll(dresp.Body)
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusBadRequest || !strings.Contains(string(dbody), "access_denied") {
		t.Fatalf("a denied authorization: %d %.300s", dresp.StatusCode, dbody)
	}
}

// What comes back in the query string of the callback is shown on a page, and
// anyone can build such a URL.
func TestCallbackEscapesWhatItShows(t *testing.T) {
	e := newEnv(t, nil)
	c := e.browser()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Get(e.url("/login"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	auth, _ := url.Parse(resp.Header.Get("Location"))
	state := auth.Query().Get("state")

	evil := `<script>alert(1)</script>"><img src=x onerror=alert(2)>`
	cb := e.url("/callback") + "?state=" + url.QueryEscape(state) + "&error=" + url.QueryEscape(evil)
	resp, err = c.Get(cb)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "<script>alert") || strings.Contains(string(body), "<img src=x") {
		t.Fatalf("the callback page reflects markup from the query string:\n%s", body)
	}
	if !strings.Contains(string(body), "&lt;script&gt;") {
		t.Fatalf("the provider's error is not shown (escaped): %s", body)
	}
	for name, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	} {
		if got := resp.Header.Get(name); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", name, got, want)
		}
	}
}

func TestSignInRestrictions(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		name   string
		config func(*Config)
		user   oidctest.User
		// subject is who the user is signed in as; empty means refused.
		subject string
		why     string
	}{
		{name: "e-mail as subject, lower-cased", user: oidctest.User{Subject: "s1", Email: "Carol@EXAMPLE.com", EmailVerified: &yes}, subject: "carol@example.com"},
		{name: "unverified e-mail is refused", user: oidctest.User{Subject: "s1", Email: "carol@example.com", EmailVerified: &no}, why: "not verified"},
		{name: "unverified e-mail, allowed by configuration", config: func(c *Config) { c.AllowUnverifiedEmail = true },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", EmailVerified: &no}, subject: "carol@example.com"},
		{name: "no e-mail released: the provider's identifier", user: oidctest.User{Subject: "sub-only"}, subject: "sub-only"},
		{name: "another subject claim", config: func(c *Config) { c.SubjectClaim = "preferred_username" },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", Username: "carol"}, subject: "carol"},
		{name: "subject claim sub ignores an unverified e-mail", config: func(c *Config) { c.SubjectClaim = "sub" },
			user: oidctest.User{Subject: "s1", Email: "x@example.com", EmailVerified: &no}, subject: "s1"},
		{name: "allowed domain", config: func(c *Config) { c.AllowedEmailDomains = []string{"@Example.com"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com"}, subject: "carol@example.com"},
		{name: "another domain", config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"} },
			user: oidctest.User{Subject: "s1", Email: "carol@evil.example"}, why: "domain"},
		{name: "a look-alike domain", config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com.evil.example"}, why: "domain"},
		{name: "domain restriction without an e-mail", config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"} },
			user: oidctest.User{Subject: "s1"}, why: "domain"},
		{name: "domain restriction, unverified e-mail, other subject claim",
			config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"}; c.SubjectClaim = "sub" },
			user:   oidctest.User{Subject: "s1", Email: "carol@example.com", EmailVerified: &no}, why: "not verified"},
		{name: "member of an allowed group", config: func(c *Config) { c.AllowedGroups = []string{"cache-users"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", Groups: []string{"x", "cache-users"}}, subject: "carol@example.com"},
		{name: "member of no allowed group", config: func(c *Config) { c.AllowedGroups = []string{"cache-users"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", Groups: []string{"cache-users-admin"}}, why: "group"},
		{name: "a subject that is not printable", config: func(c *Config) { c.SubjectClaim = "preferred_username" },
			user: oidctest.User{Subject: "s1", Username: "carol‮admin"}, why: "cannot be used"},
		// Only ASCII letters are folded: U+212A KELVIN SIGN would become "k"
		// under Unicode case mapping — another account's address.
		{name: "case folding is ASCII only", config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"} },
			user: oidctest.User{Subject: "s2", Email: "\u212Aaren@Example.com"}, subject: "\u212Aaren@example.com"},
		{name: "a domain spelled with a look-alike letter", config: func(c *Config) { c.AllowedEmailDomains = []string{"example.com"} },
			user: oidctest.User{Subject: "s2", Email: "karen@exa\u212Aple.com"}, why: "domain"},
		// A group sent as a string is one group, not a list of words.
		{name: "a group given as a string", config: func(c *Config) { c.GroupsClaim = "grp"; c.AllowedGroups = []string{"cache users"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", Extra: map[string]any{"grp": "cache users"}}, subject: "carol@example.com"},
		{name: "a word of a group given as a string", config: func(c *Config) { c.GroupsClaim = "grp"; c.AllowedGroups = []string{"admin"} },
			user: oidctest.User{Subject: "s1", Email: "carol@example.com", Extra: map[string]any{"grp": "Cache admin requests"}}, why: "group"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.config)
			c := e.browser()
			status, page := e.signIn(c, tc.user)
			_, session := e.call(c, "GET", "/api/session", nil, nil)
			if tc.subject == "" {
				if status != http.StatusForbidden || !strings.Contains(page, tc.why) {
					t.Fatalf("status %d, page %.300s; want 403 mentioning %q", status, page, tc.why)
				}
				if session["authenticated"] != false {
					t.Fatal("a refused user is signed in")
				}
				if ev, ok := e.audit.find("userlinks: sign-in refused"); !ok || ev.Decision != audit.DecisionDeny {
					t.Fatalf("the refusal is not in the audit trail: %v", e.audit.reasons())
				}
				if m := e.svc.Metrics(); m.SignInsDenied != 1 {
					t.Fatalf("metrics = %+v", m)
				}
				return
			}
			if status != 200 || session["authenticated"] != true {
				t.Fatalf("status %d, session %v", status, session)
			}
			if got := session["user"].(map[string]any)["subject"]; got != tc.subject {
				t.Fatalf("subject = %v, want %q", got, tc.subject)
			}
		})
	}
}

// The proxy starts and serves — and existing links work — while the identity
// provider is down; sign-in works again when it is back.
func TestIdentityProviderOutage(t *testing.T) {
	e := newEnv(t, nil)
	c := e.browser()
	e.signIn(c, aliceAtIdP)
	_, created := e.call(c, "POST", "/api/links", map[string]any{"label": "before"}, nil)
	token := created["token"].(string)

	// A second service, started while the provider is down.
	e.idp.SetDown(true)
	e2 := &env{t: t, idp: e.idp, audit: &memAudit{}, store: e.store}
	e2.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e2.svc.Handler().ServeHTTP(w, r) }))
	t.Cleanup(e2.srv.Close)
	svc, err := New(Config{
		PublicURL: e2.srv.URL, Store: e.store, SessionKey: sessionKey, InsecureCookies: true,
		OIDC: &OIDCConfig{Issuer: e.idp.Issuer(), ClientID: e.idp.ClientID(), ClientSecret: e.idp.ClientSecret()},
	})
	if err != nil {
		t.Fatalf("the service does not start while the identity provider is down: %v", err)
	}
	e2.svc = svc
	if _, err := svc.Registry().Resolve(context.Background(), token); err != nil {
		t.Fatalf("an existing link does not work while the identity provider is down: %v", err)
	}
	c2 := e2.browser()
	status, page := e2.signIn(c2, aliceAtIdP)
	if status != http.StatusServiceUnavailable || !strings.Contains(page, "Sign-in is unavailable") {
		t.Fatalf("sign-in during the outage: %d %.200s", status, page)
	}
	// A provider that is down is not asked again on every click.
	before := e.idp.Requests("discovery")
	for i := 0; i < 5; i++ {
		e2.signIn(c2, aliceAtIdP)
	}
	if got := e.idp.Requests("discovery"); got != before {
		t.Fatalf("%d discovery requests during the retry pause, want none", got-before)
	}

	e.idp.SetDown(false)
	e.idp.AllowRedirect(e2.srv.URL + "/links/callback")
	svc.oidc.mu.Lock()
	svc.oidc.failedAt = time.Time{} // the pause is over
	svc.oidc.mu.Unlock()
	if status, _ := e2.signIn(c2, aliceAtIdP); status != 200 {
		t.Fatalf("sign-in after the provider came back: %d", status)
	}
}

// The session is a signed cookie: it cannot be forged, repurposed or outlived.
func TestSessionCookie(t *testing.T) {
	c := newClock()
	codec := newCookieCodec(sessionKey, c.Now)
	value, err := codec.encodeSession(alice, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id, issuedAt, err := codec.decodeSession(value)
	if err != nil || id.Subject != alice.Subject || id.Team != alice.Team || !issuedAt.Equal(c.Now()) {
		t.Fatalf("round trip = %+v, %v, %v", id, issuedAt, err)
	}

	body, mac, _ := strings.Cut(value, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(body)
	forged := base64.RawURLEncoding.EncodeToString(bytes.Replace(payload, []byte("alice@example.com"), []byte("admin@example.com"), 1))
	flow, _ := codec.encodeFlow(flowClaims{State: "s", Verifier: "v", Nonce: "n"}, time.Hour)
	otherKey, _ := newCookieCodec([]byte("another-key-another-key-another-key!!"), c.Now).encodeSession(alice, time.Hour)
	for name, bad := range map[string]string{
		"empty":                    "",
		"no signature":             body,
		"altered payload":          forged + "." + mac,
		"altered signature":        body + "." + mac[:len(mac)-2] + "AA",
		"signed with another key":  otherKey,
		"a flow cookie":            flow,
		"garbage":                  "!!!.???",
		"enormous":                 strings.Repeat("A", maxCookieValue+1) + "." + mac,
		"payload that is not JSON": base64.RawURLEncoding.EncodeToString([]byte("nope")) + "." + sign(codec.sessionKey, base64.RawURLEncoding.EncodeToString([]byte("nope"))),
	} {
		if _, _, err := codec.decodeSession(bad); !errors.Is(err, errBadCookie) {
			t.Errorf("%s: decodeSession = %v, want errBadCookie", name, err)
		}
	}
	// A session cookie is not a flow cookie either.
	if _, err := codec.decodeFlow(value); !errors.Is(err, errBadCookie) {
		t.Errorf("a session cookie was accepted as a flow cookie: %v", err)
	}
	// Expiry.
	c.Advance(time.Hour - time.Second)
	if _, _, err := codec.decodeSession(value); err != nil {
		t.Fatalf("a second before its expiry: %v", err)
	}
	c.Advance(time.Second)
	if _, _, err := codec.decodeSession(value); !errors.Is(err, errBadCookie) {
		t.Fatalf("at its expiry: %v", err)
	}
	if _, err := codec.decodeFlow(flow); !errors.Is(err, errBadCookie) {
		t.Fatalf("an expired flow cookie: %v", err)
	}
}

// "Revoke everything of this user" also ends their session on the page.
func TestRevokeUserEndsSessions(t *testing.T) {
	e := newEnv(t, nil)
	c := e.browser()
	e.signIn(c, aliceAtIdP)
	_, created := e.call(c, "POST", "/api/links", map[string]any{"label": "laptop"}, nil)
	token := created["token"].(string)

	time.Sleep(1100 * time.Millisecond) // sessions are dated to the second
	n, _, err := e.svc.RevokeUser(context.Background(), "alice@example.com", "ops@example.com", "offboarding", "198.51.100.1")
	if err != nil || n != 1 {
		t.Fatalf("RevokeUser = %d, %v", n, err)
	}
	if _, session := e.call(c, "GET", "/api/session", nil, nil); session["authenticated"] != false {
		t.Fatal("the user's session survived the revocation")
	}
	if status, _ := e.call(c, "POST", "/api/links", map[string]any{"label": "again"}, nil); status != 401 {
		t.Fatalf("the user created a link with the old session: %d", status)
	}
	if _, err := e.svc.Registry().Resolve(context.Background(), token); reasonOf(t, err) != ReasonRevoked {
		t.Fatalf("the user's link survived: %v", err)
	}
	ev, ok := e.audit.find("userlinks: all links revoked")
	if !ok || ev.Subject != "alice@example.com" || ev.Detail["by"] != "ops@example.com" || ev.RemoteAddr != "198.51.100.1" {
		t.Fatalf("audit event = %+v", ev)
	}
	// They can sign in again and start over: it is a watermark, not a ban.
	time.Sleep(1100 * time.Millisecond)
	if status, _ := e.signIn(c, aliceAtIdP); status != 200 {
		t.Fatal("the user cannot sign in again")
	}
	if status, _ := e.call(c, "POST", "/api/links", map[string]any{"label": "new"}, nil); status != 201 {
		t.Fatalf("the user cannot create a link after signing in again: %d", status)
	}
}

func TestAuthenticate(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	token, base, info, err := e.svc.Issue(ctx, Identity{Subject: "ci-bot", Team: "platform", Roles: []string{"reader"}},
		IssueOptions{Label: "pipeline", IssuedBy: "ops@example.com", From: "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if base != e.srv.URL+"/u/"+token || info.IssuedBy != "ops@example.com" {
		t.Fatalf("Issue = %q, %+v", base, info)
	}
	if ev, ok := e.audit.find("userlinks: link issued"); !ok || ev.Detail["issuedBy"] != "ops@example.com" || ev.Subject != "ci-bot" {
		t.Fatalf("audit event of an administrator's issue = %+v", ev)
	}

	request := func(mutate func(*http.Request)) *http.Request {
		r := httptest.NewRequest("GET", "/v1/npm/lodash", nil)
		if mutate != nil {
			mutate(r)
		}
		return r
	}
	check := func(name string, p *auth.Principal, err error, via string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Subject != "ci-bot" || p.Team != "platform" || p.Method != MethodPersonalLink || len(p.Roles) != 1 || p.Roles[0] != "reader" ||
			p.Attributes[AttrLink] != info.ID || p.Attributes[AttrVia] != via {
			t.Fatalf("%s: principal = %+v", name, p)
		}
	}

	// In the path.
	p, err := e.svc.Authenticate(WithPathToken(ctx, token), request(nil))
	check("path", p, err, ViaPath)

	// As a credential, in every place a package manager puts one.
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	for name, mutate := range map[string]func(*http.Request){
		"bearer":          func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) },
		"token scheme":    func(r *http.Request) { r.Header.Set("Authorization", "token "+token) },
		"basic password":  func(r *http.Request) { r.Header.Set("Authorization", basic("anything", token)) },
		"basic user name": func(r *http.Request) { r.Header.Set("Authorization", basic(token, "x-oauth-basic")) },
		"x-api-token":     func(r *http.Request) { r.Header.Set("X-Api-Token", token) },
		"with other header": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer not-a-link")
			r.Header.Set("X-Auth-Token", token)
		},
	} {
		p, err := e.svc.Authenticate(ctx, request(mutate))
		check(name, p, err, ViaCredential)
	}

	// A request that carries no link is not this authenticator's: whatever
	// credential it has belongs to another one.
	//
	// (The mistyped link, refused below, changes a character of the random part
	// to a different one. Changing the last character to a fixed letter is not a
	// change for every token: the last character of the checksum carries only
	// two bits, so a quarter of all tokens end in "a".)
	mistyped := []byte(token)
	if i := len(TokenPrefix); mistyped[i] == 'a' {
		mistyped[i] = 'b'
	} else {
		mistyped[i] = 'a'
	}
	for name, mutate := range map[string]func(*http.Request){
		"nothing":            nil,
		"a static token":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer some-static-api-token-0123456789") },
		"a JWT":              func(r *http.Request) { r.Header.Set("Authorization", "Bearer aaa.bbb.ccc") },
		"basic, no link":     func(r *http.Request) { r.Header.Set("Authorization", basic("user", "password")) },
		"token in the query": func(r *http.Request) { r.URL.RawQuery = "token=" + token },
	} {
		if _, err := e.svc.Authenticate(ctx, request(mutate)); !errors.Is(err, auth.ErrUnauthenticated) {
			t.Errorf("%s: Authenticate = %v, want ErrUnauthenticated", name, err)
		}
	}

	// A link that is presented but not good refuses the request. It is never
	// "unauthenticated", which a caller would read as "carry on anonymously".
	unknown, _ := NewToken()
	_, expInfo, _ := e.svc.Registry().Issue(ctx, Identity{Subject: "ci-bot"}, IssueOptions{TTL: time.Nanosecond})
	_ = expInfo
	revTok, revInfo, _ := e.svc.Registry().Issue(ctx, Identity{Subject: "ci-bot"}, IssueOptions{})
	if _, err := e.svc.Revoke(ctx, revInfo.ID, "ops", "test", ""); err != nil {
		t.Fatal(err)
	}
	type refusal struct {
		ctx    context.Context
		req    *http.Request
		reason Reason
		status int
		known  bool
	}
	bearer := func(tok string) *http.Request {
		return request(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) })
	}
	for name, tc := range map[string]refusal{
		"unknown, in the path":      {WithPathToken(ctx, unknown), request(nil), ReasonUnknown, 403, false},
		"malformed, in the path":    {WithPathToken(ctx, "not-a-link"), request(nil), ReasonMalformed, 403, false},
		"empty, in the path":        {WithPathToken(ctx, ""), request(nil), ReasonMalformed, 403, false},
		"revoked, in the path":      {WithPathToken(ctx, revTok), request(nil), ReasonRevoked, 403, true},
		"unknown, as a credential":  {ctx, bearer(unknown), ReasonUnknown, 401, false},
		"revoked, as a credential":  {ctx, bearer(revTok), ReasonRevoked, 401, true},
		"mistyped, as a credential": {ctx, bearer(string(mistyped)), ReasonMalformed, 401, false},
		"cut short, as a credential": {ctx, request(func(r *http.Request) {
			r.Header.Set("Authorization", basic("pullthrough", token[:len(token)-3]))
		}), ReasonMalformed, 401, false},
		"path wins over credential": {WithPathToken(ctx, unknown), bearer(token), ReasonUnknown, 403, false},
	} {
		_, err := e.svc.Authenticate(tc.ctx, tc.req)
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("%s: Authenticate = %v, want an *AuthError", name, err)
		}
		if errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("%s: the refusal reads as \"unauthenticated\"", name)
		}
		if ae.Reason != tc.reason || ae.Status() != tc.status || (ae.Link != nil) != tc.known {
			t.Errorf("%s: reason %v status %d link %v; want %v %d known=%v", name, ae.Reason, ae.Status(), ae.Link, tc.reason, tc.status, tc.known)
		}
		// The message tells the user where to get a new link, and never repeats
		// the token.
		if !strings.Contains(ae.Error(), e.srv.URL+"/links/") || strings.Contains(ae.Error(), unknown) || strings.Contains(ae.Error(), revTok) {
			t.Errorf("%s: message = %q", name, ae.Error())
		}
	}

	// A registry that cannot be consulted: 503, retry — not "get a new link".
	down := newSpyStore(NewMemoryStore())
	down.set(func(s *spyStore) { s.failList = errors.New("down") })
	svc, err := New(Config{PublicURL: "https://proxy.example.com", Store: down})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Authenticate(WithPathToken(ctx, token), request(nil))
	var ae *AuthError
	if !errors.As(err, &ae) || ae.Reason != ReasonUnavailable || ae.Status() != http.StatusServiceUnavailable ||
		strings.Contains(ae.Error(), "create a new one") {
		t.Fatalf("with the registry unavailable: %v", err)
	}

	// Counted by how the link came and what became of it.
	counts := map[string]uint64{}
	for _, r := range e.svc.Metrics().Resolved {
		counts[r.Via+"/"+r.Outcome] = r.Count
	}
	if counts["path/ok"] != 1 || counts["credential/ok"] != 6 || counts["path/unknown"] != 2 || counts["path/malformed"] != 2 ||
		counts["path/revoked"] != 1 || counts["credential/unknown"] != 1 || counts["credential/revoked"] != 1 {
		t.Fatalf("counts = %v", counts)
	}

	// Touch records the use against the link.
	e.svc.Touch(p, "10.20.30.40", "npm/10.9.2 node/v22")
	if got, _ := e.svc.Registry().Get(info.ID); got.LastUsedAt == nil || got.LastAddr != "10.20.30.40" || got.LastAgent != "npm/10.9.2 node/v22" {
		t.Fatalf("usage after Touch = %+v", got)
	}
	e.svc.Touch(&auth.Principal{Subject: "x", Method: "token"}, "1.1.1.1", "x") // not a link: ignored
	e.svc.Touch(nil, "1.1.1.1", "x")
}

// A nil service is the feature switched off.
func TestNilService(t *testing.T) {
	var s *Service
	if s.Enabled() || s.SignInEnabled() || s.PathPrefix() != "" || s.UIPath() != "" || s.PageURL() != "" || s.Registry() != nil {
		t.Fatal("a nil service reports something")
	}
	if _, err := s.Authenticate(context.Background(), httptest.NewRequest("GET", "/", nil)); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("Authenticate on a nil service = %v", err)
	}
	s.Touch(&auth.Principal{Method: MethodPersonalLink}, "", "")
	s.Run(context.Background())
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Links(Filter{}) != nil || len(s.Metrics().Resolved) != 0 {
		t.Fatal("a nil service lists something")
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/links/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("the page of a nil service: %d", rec.Code)
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	ok := func() Config {
		return Config{PublicURL: "https://proxy.example.com", Store: NewMemoryStore(), SessionKey: sessionKey,
			OIDC: &OIDCConfig{Issuer: "https://idp.example.com", ClientID: "c"}}
	}
	if _, err := New(ok()); err != nil {
		t.Fatalf("a valid configuration is refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no public URL":             func(c *Config) { c.PublicURL = "" },
		"a relative public URL":     func(c *Config) { c.PublicURL = "/proxy" },
		"a non-HTTP public URL":     func(c *Config) { c.PublicURL = "ftp://proxy.example.com" },
		"no store":                  func(c *Config) { c.Store = nil },
		"a short session key":       func(c *Config) { c.SessionKey = []byte("short") },
		"no issuer":                 func(c *Config) { c.OIDC.Issuer = " " },
		"no client":                 func(c *Config) { c.OIDC.ClientID = "" },
		"a prefix with a slash":     func(c *Config) { c.PathPrefix = "/a/b" },
		"an upper-case prefix":      func(c *Config) { c.PathPrefix = "/U" },
		"a prefix with a dot":       func(c *Config) { c.PathPrefix = "/u.x" },
		"a prefix ending in a dash": func(c *Config) { c.PathPrefix = "/u-" },
		"a relative page path":      func(c *Config) { c.UIPath = "links" },
		"a page path with a query":  func(c *Config) { c.UIPath = "/links?x=1" },
		"a page path with dot-dot":  func(c *Config) { c.UIPath = "/a/../b" },
	} {
		cfg := ok()
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Without an identity provider no session key is needed: links are then
	// issued by an administrator only.
	svc, err := New(Config{PublicURL: "http://proxy.example.com:8080/", Store: NewMemoryStore(), PathPrefix: "me", UIPath: "/account/links/"})
	if err != nil {
		t.Fatal(err)
	}
	if svc.SignInEnabled() || svc.PathPrefix() != "/me" || svc.UIPath() != "/account/links" ||
		svc.PageURL() != "http://proxy.example.com:8080/account/links/" || svc.PersonalBase("tok") != "http://proxy.example.com:8080/me/tok" {
		t.Fatalf("service = %q %q %q", svc.PathPrefix(), svc.UIPath(), svc.PageURL())
	}
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/account/links/login", nil))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Sign-in is not configured") {
		t.Fatalf("login without an identity provider: %d %s", rec.Code, rec.Body)
	}
}

func TestPageAssets(t *testing.T) {
	e := newEnv(t, nil)
	c := e.browser()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for path, contentType := range map[string]string{"/": "text/html", "/app.js": "text/javascript", "/styles.css": "text/css"} {
		resp, err := c.Get(e.url(path))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), contentType) || len(body) == 0 {
			t.Errorf("GET %s = %d %q (%d bytes)", path, resp.StatusCode, resp.Header.Get("Content-Type"), len(body))
		}
		// The policy that keeps a script out of a page that shows a credential.
		csp := resp.Header.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("GET %s: Content-Security-Policy %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("GET %s: the policy allows inline script or style: %q", path, csp)
		}
	}
	// The bare path redirects to the page; unknown paths are not the page.
	resp, _ := c.Get(e.srv.URL + "/links")
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "/links/" {
		t.Errorf("GET /links = %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, path := range []string{"/nope", "/api/nope", "/../admin", "/api/links/extra"} {
		resp, err := c.Get(e.url(path))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Errorf("GET %s = 200", path)
		}
	}
	// The page itself has no inline script or style for the policy to block.
	html, _ := uiFS.Open("index.html")
	data, _ := io.ReadAll(html)
	html.Close()
	for _, forbidden := range []string{"<script>", "onclick=", "onload=", " style=", "<style", "javascript:"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("index.html contains %q, which the page's own policy forbids", forbidden)
		}
	}
}

// The page meets the same accessibility baseline as the admin console and the
// tenant portal. See docs/accessibility.md.
func TestPageAccessibility(t *testing.T) {
	findings, err := uiaudit.Audit(uiFS)
	if err != nil {
		t.Fatalf("auditing the embedded page: %v", err)
	}
	for _, f := range uiaudit.Errors(findings) {
		t.Errorf("accessibility: %s: %s (%s)", f.File, f.Detail, f.Rule)
	}
}

// Discovering the provider's endpoints is not the business of the request
// that happens to need them first: a browser that gives up on /links/login
// must not leave a "context canceled" behind for everyone's next sign-in.
func TestDiscoveryOutlivesTheRequestThatStartedIt(t *testing.T) {
	e := newEnv(t, nil)
	e.svc.oidc.mu.Lock()
	e.svc.oidc.resolved, e.svc.oidc.failure = nil, nil
	e.svc.oidc.mu.Unlock()
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.svc.oidc.endpoints(gone); err != nil {
		t.Fatalf("discovery started by a cancelled request: %v", err)
	}
	c := e.browser()
	if status, page := e.signIn(c, aliceAtIdP); status != http.StatusOK {
		t.Fatalf("the next sign-in: %d %.200s", status, page)
	}
}

// Behind a reverse proxy that serves the proxy under a path of its own, the
// browser sees the page at <that path>/links: the cookies are scoped to it and
// the redirects lead there. Served over HTTPS, the cookies carry the __Secure-
// prefix, which no sibling host or plain-HTTP response can set.
func TestPageBehindAPublicPath(t *testing.T) {
	e := newEnv(t, nil)
	svc, err := New(Config{
		PublicURL: "https://proxy.example.com/pt/", Store: NewMemoryStore(), SessionKey: sessionKey,
		OIDC: &OIDCConfig{Issuer: e.idp.Issuer(), ClientID: e.idp.ClientID(), ClientSecret: e.idp.ClientSecret()},
	})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "https://proxy.example.com/links/login", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("login: %d %s", rr.Code, rr.Body)
	}
	var flow *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "__Secure-"+flowCookie {
			flow = c
		}
	}
	if flow == nil || flow.Path != "/pt/links" || !flow.Secure || !flow.HttpOnly {
		t.Fatalf("the sign-in cookie: %+v (all: %v)", flow, rr.Result().Cookies())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || loc.Query().Get("redirect_uri") != "https://proxy.example.com/pt/links/callback" {
		t.Fatalf("redirect_uri in %q", rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "https://proxy.example.com/links", nil))
	if rr.Header().Get("Location") != "/pt/links/" {
		t.Fatalf("the page's own redirect: %d %q", rr.Code, rr.Header().Get("Location"))
	}
	rr = httptest.NewRecorder()
	svc.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "https://proxy.example.com/links/api/session", nil))
	var session map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &session); err != nil || session["signInUrl"] != "/pt/links/login" {
		t.Fatalf("session: %s (%v)", rr.Body, err)
	}
}
