package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRBACDenyByDefault(t *testing.T) {
	az, err := NewAuthorizer([]Role{
		{Name: "npm-reader", Ecosystems: []string{"npm"}, Upstreams: []string{"*"}},
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}

	// Principal with no roles is denied.
	if ok, _ := az.Authorize(&Principal{Subject: "a"}, "public-npm", "npm"); ok {
		t.Fatalf("principal with no roles must be denied")
	}
	// Holding the role grants npm.
	p := &Principal{Subject: "a", Roles: []string{"npm-reader"}}
	if ok, _ := az.Authorize(p, "public-npm", "npm"); !ok {
		t.Fatalf("npm-reader must be allowed to pull npm")
	}
	// But not pip (ecosystem not granted).
	if ok, _ := az.Authorize(p, "public-pip", "pip"); ok {
		t.Fatalf("npm-reader must not pull pip")
	}
}

func TestRBACUpstreamScoping(t *testing.T) {
	az, _ := NewAuthorizer([]Role{
		{Name: "corp-only", Ecosystems: []string{"*"}, Upstreams: []string{"corp-mirror"}},
	})
	p := &Principal{Roles: []string{"corp-only"}}
	if ok, _ := az.Authorize(p, "corp-mirror", "npm"); !ok {
		t.Fatalf("must allow the named upstream")
	}
	if ok, _ := az.Authorize(p, "public-npm", "npm"); ok {
		t.Fatalf("must deny a non-listed upstream even within an allowed ecosystem")
	}
}

func TestRBACEmptyListMatchesNothing(t *testing.T) {
	az, _ := NewAuthorizer([]Role{{Name: "broken", Ecosystems: nil, Upstreams: []string{"*"}}})
	p := &Principal{Roles: []string{"broken"}}
	if ok, _ := az.Authorize(p, "x", "npm"); ok {
		t.Fatalf("empty ecosystem list must grant nothing (least privilege)")
	}
}

func TestRBACWildcardAll(t *testing.T) {
	az, _ := NewAuthorizer([]Role{{Name: "admin", Ecosystems: []string{"*"}, Upstreams: []string{"*"}}})
	p := &Principal{Roles: []string{"admin"}}
	for _, eco := range []string{"npm", "pip", "docker", "git"} {
		if ok, _ := az.Authorize(p, "anything", eco); !ok {
			t.Fatalf("admin must pull %s", eco)
		}
	}
}

func TestTokenAuthentication(t *testing.T) {
	const secret = "abcdef0123456789-token-value"
	ta, err := NewTokenAuthenticator([]TokenEntry{
		{Name: "ci-bot", Team: "platform", Roles: []string{"npm-reader"}, Secret: secret},
	})
	if err != nil {
		t.Fatalf("token auth: %v", err)
	}

	// Bearer header.
	r := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	p, err := ta.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatalf("authenticate bearer: %v", err)
	}
	if p.Subject != "ci-bot" || p.Team != "platform" {
		t.Fatalf("wrong principal: %+v", p)
	}

	// Basic auth (token as password) must also work.
	r2 := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	r2.SetBasicAuth("unused", secret)
	if _, err := ta.Authenticate(context.Background(), r2); err != nil {
		t.Fatalf("authenticate basic: %v", err)
	}

	// Wrong token rejected.
	r3 := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
	r3.Header.Set("Authorization", "Bearer wrong-token-value-here")
	if _, err := ta.Authenticate(context.Background(), r3); err != ErrUnauthenticated {
		t.Fatalf("want ErrUnauthenticated, got %v", err)
	}
}

func TestTokenAuthByHash(t *testing.T) {
	const secret = "another-secret-token-value-here"
	ta, err := NewTokenAuthenticator([]TokenEntry{
		{Name: "by-hash", Hash: "sha256:" + HashToken(secret)},
	})
	if err != nil {
		t.Fatalf("token auth: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+secret)
	if _, err := ta.Authenticate(context.Background(), r); err != nil {
		t.Fatalf("authenticate by hash: %v", err)
	}
}

func TestTokenRejectsShortSecret(t *testing.T) {
	if _, err := NewTokenAuthenticator([]TokenEntry{{Name: "x", Secret: "short"}}); err == nil {
		t.Fatalf("short secret must be rejected")
	}
}

func TestQuotaRequestLimit(t *testing.T) {
	qm := NewQuotaManager(QuotaOptions{
		PerTeam: map[string]Quota{"t": {MaxRequests: 2}},
	})
	if ok, _ := qm.Reserve("t"); !ok {
		t.Fatalf("first request should be admitted")
	}
	if ok, _ := qm.Reserve("t"); !ok {
		t.Fatalf("second request should be admitted")
	}
	if ok, reason := qm.Reserve("t"); ok {
		t.Fatalf("third request should be denied")
	} else if reason == "" {
		t.Fatalf("denial should carry a reason")
	}
}

func TestQuotaByteLimit(t *testing.T) {
	qm := NewQuotaManager(QuotaOptions{PerTeam: map[string]Quota{"t": {MaxBytes: 100}}})
	if ok, _ := qm.Reserve("t"); !ok {
		t.Fatalf("first request admitted")
	}
	qm.RecordBytes("t", 150)
	if ok, _ := qm.Reserve("t"); ok {
		t.Fatalf("request after byte quota exhausted must be denied")
	}
}

func TestQuotaWindowReset(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	qm := NewQuotaManager(QuotaOptions{
		PerTeam: map[string]Quota{"t": {MaxRequests: 1, Window: time.Minute}},
		Now:     clock,
	})
	if ok, _ := qm.Reserve("t"); !ok {
		t.Fatalf("first admitted")
	}
	if ok, _ := qm.Reserve("t"); ok {
		t.Fatalf("second denied within window")
	}
	now = now.Add(2 * time.Minute) // advance past the window
	if ok, _ := qm.Reserve("t"); !ok {
		t.Fatalf("request after window reset must be admitted")
	}
}

func TestQuotaUnlimitedTeam(t *testing.T) {
	qm := NewQuotaManager(QuotaOptions{}) // default unlimited
	for i := 0; i < 1000; i++ {
		if ok, _ := qm.Reserve("anyteam"); !ok {
			t.Fatalf("unlimited quota must admit all")
		}
	}
}

func TestEnforcerFullFlow(t *testing.T) {
	az, _ := NewAuthorizer([]Role{{Name: "npm", Ecosystems: []string{"npm"}, Upstreams: []string{"*"}}})
	ta, _ := NewTokenAuthenticator([]TokenEntry{
		{Name: "bot", Team: "team-a", Roles: []string{"npm"}, Secret: "the-secret-token-value-x"},
	})
	qm := NewQuotaManager(QuotaOptions{PerTeam: map[string]Quota{"team-a": {MaxRequests: 1}}})
	e, err := NewEnforcer(EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: qm})
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}

	authd := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/v1/npm/lodash", nil)
		r.Header.Set("Authorization", "Bearer the-secret-token-value-x")
		return r
	}

	// Unauthenticated → 401.
	res := e.Check(context.Background(), httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil), "pub-npm", "npm")
	if res.Allowed || res.Status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %+v", res)
	}

	// Authenticated but wrong ecosystem → 403.
	res = e.Check(context.Background(), authd(), "pub-pip", "pip")
	if res.Allowed || res.Status != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed ecosystem, got %+v", res)
	}

	// Authorized → 200 (consumes the one allowed request).
	res = e.Check(context.Background(), authd(), "pub-npm", "npm")
	if !res.Allowed {
		t.Fatalf("expected allow, got %+v", res)
	}

	// Quota now exhausted → 429.
	res = e.Check(context.Background(), authd(), "pub-npm", "npm")
	if res.Allowed || res.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %+v", res)
	}
}

func TestEnforcerAnonymous(t *testing.T) {
	az, _ := NewAuthorizer([]Role{{Name: "pub", Ecosystems: []string{"*"}, Upstreams: []string{"*"}}})
	e, err := NewEnforcer(EnforcerOptions{
		Authorizer:     az,
		AllowAnonymous: true,
		Anonymous:      &Principal{Subject: "anonymous", Team: "public", Roles: []string{"pub"}},
	})
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}
	res := e.Check(context.Background(), httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil), "pub-npm", "npm")
	if !res.Allowed {
		t.Fatalf("anonymous with wildcard role must be allowed, got %+v", res)
	}
	if res.Principal.Subject != "anonymous" {
		t.Fatalf("expected anonymous principal, got %+v", res.Principal)
	}
}

func TestNilEnforcerAllowsAnonymous(t *testing.T) {
	var e *Enforcer
	res := e.Check(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil), "x", "npm")
	if !res.Allowed {
		t.Fatalf("nil enforcer must allow (access control disabled)")
	}
}

func TestTeamNamespaceSanitization(t *testing.T) {
	cases := map[string]string{
		"":            "_shared",
		"Team A":      "team_a",
		"../etc":      "___etc",
		"corp/secret": "corp_secret",
	}
	for in, want := range cases {
		if got := TeamNamespace(in); got != want {
			t.Fatalf("TeamNamespace(%q) = %q, want %q", in, got, want)
		}
	}
}
