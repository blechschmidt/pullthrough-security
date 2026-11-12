package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

const testToken = "integration-token-abcdef123456"

// newSecuredGateway builds a gateway with auth + audit enabled. The single
// backend "npm" (ecosystem npm) proxies baseURL. The token grants the
// "npm-reader" role bound to team "team-a".
func newSecuredGateway(t *testing.T, baseURL string, opts Options) (*Gateway, *audit.MemorySink) {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	_ = registry.Register(b)

	az, err := auth.NewAuthorizer([]auth.Role{
		{Name: "npm-reader", Ecosystems: []string{"npm"}, Upstreams: []string{"*"}},
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{
		{Name: "ci", Team: "team-a", Roles: []string{"npm-reader"}, Secret: testToken},
	})
	if err != nil {
		t.Fatalf("token auth: %v", err)
	}
	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{})})
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}

	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("test-key"), Sink: sink})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}

	opts.HTTPAddr = ":0"
	g, err := New(Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Enforcer:   enforcer,
		Audit:      auditLog,
		Ecosystems: map[string]string{"npm": "npm"},
	}, opts)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return g, sink
}

func upstreamArtifact(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
}

func TestAccessControlRejectsUnauthenticated(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	g, sink := newSecuredGateway(t, srv.URL, Options{})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("401 should carry WWW-Authenticate")
	}
	// The denial must be audited.
	recs := sink.Records()
	if len(recs) != 1 || recs[0].Event.Decision != audit.DecisionDeny {
		t.Fatalf("expected one deny audit record, got %+v", recs)
	}
}

func TestAccessControlAllowsAuthorized(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	g, sink := newSecuredGateway(t, srv.URL, Options{})

	req := httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body %q), want 200", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "ARTIFACT" {
		t.Errorf("body = %q", rr.Body.String())
	}

	// The pull must be audited with subject, team, and cache result.
	recs := sink.Records()
	if len(recs) != 1 {
		t.Fatalf("want 1 audit record, got %d", len(recs))
	}
	ev := recs[0].Event
	if ev.Type != audit.EventPull || ev.Decision != audit.DecisionAllow {
		t.Errorf("unexpected event: %+v", ev)
	}
	if ev.Subject != "ci" || ev.Team != "team-a" {
		t.Errorf("identity not audited: %+v", ev)
	}
	if ev.Detail["cache"] != "MISS" {
		t.Errorf("cache result not audited: %v", ev.Detail["cache"])
	}
	// Audit chain stays valid.
	if idx, err := audit.VerifyChain([]byte("test-key"), recs); err != nil {
		t.Fatalf("audit chain broken at %d: %v", idx, err)
	}
}

func TestAccessControlForbidsWrongEcosystem(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	// Register a second backend "pip" that the token's role does not grant.
	g, _ := newSecuredGateway(t, srv.URL, Options{})
	pip, _ := httpbackend.New(httpbackend.Options{
		Name: "pip", BaseURL: srv.URL,
		Client: upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	_ = g.deps.Backends.Register(pip)
	g.deps.Ecosystems["pip"] = "pip"

	req := httptest.NewRequest(http.MethodGet, "/v1/pip/pkg.whl", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for ungranted ecosystem", rr.Code)
	}
}

func TestCacheNamespacingIsolatesTenants(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	g, _ := newSecuredGateway(t, srv.URL, Options{CacheNamespacing: true})

	req := httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}

	// The cache key must be namespaced by the team ("team-a") so other tenants
	// cannot observe it.
	stats, err := g.deps.Cache.(interface {
		Entries(context.Context) ([]cache.Stat, error)
	}).Entries(context.Background())
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("want 1 cache entry, got %d", len(stats))
	}
	if got := stats[0].Key; got == "" || got[:len("team-a/")] != "team-a/" {
		t.Errorf("cache key %q is not namespaced by team", got)
	}
}

// A 401 names a way of presenting the token that the client at hand can use: a
// container client and Git are challenged with Basic, everything else with
// Bearer as before.
func TestAuthChallengeSuitsTheClient(t *testing.T) {
	g := &Gateway{opts: Options{RegistryRoot: &RegistryRoot{Upstreams: []string{"dockerhub", "charts"}}}}
	for _, tc := range []struct{ backend, ecosystem, want string }{
		{"npm", "npm", challengeBearer},
		{"pypi", "pip", challengeBearer},
		{"dockerhub", "docker", challengeBasic},
		{"charts", "helm", challengeBasic}, // a Helm upstream in OCI mode speaks the registry API
		{"git", "git", challengeBasic},
	} {
		if got := g.authChallenge(tc.backend, tc.ecosystem); got != tc.want {
			t.Errorf("challenge for %s (%s) = %q, want %q", tc.backend, tc.ecosystem, got, tc.want)
		}
	}
	// Without the host-root registry alias the ecosystem decides.
	if got := (&Gateway{}).authChallenge("ghcr", "docker"); got != challengeBasic {
		t.Errorf("challenge for a registry upstream without the alias = %q, want Basic", got)
	}
	if got := (&Gateway{}).authChallenge("charts", "helm"); got != challengeBearer {
		t.Errorf("challenge for an index-mode Helm upstream = %q, want Bearer", got)
	}
}

// The Docker Engine's first request is the version check at "/v2/". The answer
// to it decides whether `docker login` can work at all: a Bearer challenge whose
// realm is no URL makes the daemon give up ("unsupported protocol scheme").
func TestRegistryVersionCheckIsChallengedWithBasic(t *testing.T) {
	srv := upstreamArtifact(t)
	defer srv.Close()
	g, _ := newSecuredGateway(t, srv.URL, Options{RegistryRoot: &RegistryRoot{Upstreams: []string{"npm"}}})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != `Basic realm="pullthrough"` {
		t.Fatalf("WWW-Authenticate = %q, want a Basic challenge", got)
	}

	// Everything else keeps the challenge it had.
	rr = httptest.NewRecorder()
	g2, _ := newSecuredGateway(t, srv.URL, Options{})
	g2.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg.tgz", nil))
	if got := rr.Header().Get("WWW-Authenticate"); got != `Bearer realm="pullthrough"` {
		t.Fatalf("WWW-Authenticate for a package request = %q, want the Bearer challenge", got)
	}
}
