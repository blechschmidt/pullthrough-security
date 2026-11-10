package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

func TestRegistryRootRoute(t *testing.T) {
	withDefault := &RegistryRoot{
		Upstreams:       []string{"dockerhub", "ghcr"},
		DefaultUpstream: "dockerhub",
		Namespaces:      map[string]string{"docker.io": "dockerhub", "registry-1.docker.io": "dockerhub", "ghcr.io": "ghcr"},
	}
	noDefault := &RegistryRoot{
		Upstreams:  []string{"ghcr", "dockerhub"},
		Namespaces: map[string]string{"docker.io": "dockerhub", "ghcr.io": "ghcr"},
	}

	cases := []struct {
		name     string
		rr       *RegistryRoot
		path     string
		query    string
		wantOK   bool
		upstream string
		wantPath string
		stripNS  bool
	}{
		// API version check.
		{name: "ping uses default upstream", rr: withDefault, path: "/v2/", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/"},
		{name: "ping without trailing slash", rr: withDefault, path: "/v2", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/"},
		{name: "ping without default picks first upstream by name", rr: noDefault, path: "/v2/", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/"},

		// Registry-mirror mode: un-prefixed repository -> default upstream.
		{name: "mirror manifest by tag", rr: withDefault, path: "/v2/library/alpine/manifests/3.19", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/manifests/3.19"},
		{name: "mirror blob", rr: withDefault, path: "/v2/library/alpine/blobs/sha256:abc", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/blobs/sha256:abc"},
		{name: "mirror single-component repository", rr: withDefault, path: "/v2/alpine/manifests/latest", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/alpine/manifests/latest"},
		{name: "mirror tags list", rr: withDefault, path: "/v2/library/alpine/tags/list", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/tags/list"},
		{name: "mirror without default is refused", rr: noDefault, path: "/v2/library/alpine/manifests/3.19", wantOK: false},

		// Upstream-prefixed repository.
		{name: "prefixed manifest", rr: withDefault, path: "/v2/ghcr/acme/app/manifests/v1", wantOK: true, upstream: "ghcr", wantPath: "/v1/ghcr/v2/acme/app/manifests/v1"},
		{name: "prefixed blob without default", rr: noDefault, path: "/v2/dockerhub/library/alpine/blobs/sha256:abc", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/blobs/sha256:abc"},
		{name: "prefixed referrers", rr: noDefault, path: "/v2/ghcr/acme/app/referrers/sha256:abc", wantOK: true, upstream: "ghcr", wantPath: "/v1/ghcr/v2/acme/app/referrers/sha256:abc"},
		{name: "prefixed tags list", rr: noDefault, path: "/v2/ghcr/acme/app/tags/list", wantOK: true, upstream: "ghcr", wantPath: "/v1/ghcr/v2/acme/app/tags/list"},
		{name: "prefixed catalog", rr: noDefault, path: "/v2/ghcr/_catalog", wantOK: true, upstream: "ghcr", wantPath: "/v1/ghcr/v2/_catalog"},
		// A repository on the default upstream whose only component merely shares
		// an upstream's name is NOT a prefix: nothing would be left to address.
		{name: "upstream-named repository stays on default", rr: withDefault, path: "/v2/ghcr/manifests/latest", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/ghcr/manifests/latest"},
		{name: "upstream name alone is not a request", rr: noDefault, path: "/v2/ghcr/", wantOK: false},
		{name: "unknown prefix without default is refused", rr: noDefault, path: "/v2/quay/acme/app/manifests/v1", wantOK: false},

		// containerd "ns" mirror hint.
		{name: "ns hint selects the upstream", rr: noDefault, path: "/v2/acme/app/manifests/v1", query: "ns=ghcr.io", wantOK: true, upstream: "ghcr", wantPath: "/v1/ghcr/v2/acme/app/manifests/v1", stripNS: true},
		{name: "ns hint is case-insensitive", rr: noDefault, path: "/v2/library/alpine/manifests/3.19", query: "ns=Docker.IO", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/manifests/3.19", stripNS: true},
		{name: "ns hint beats the prefix heuristic", rr: withDefault, path: "/v2/ghcr/app/manifests/v1", query: "ns=docker.io", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/ghcr/app/manifests/v1", stripNS: true},
		{name: "unknown ns falls back to default and is stripped", rr: withDefault, path: "/v2/library/alpine/manifests/3.19", query: "ns=quay.io", wantOK: true, upstream: "dockerhub", wantPath: "/v1/dockerhub/v2/library/alpine/manifests/3.19", stripNS: true},
		{name: "unknown ns without default is refused", rr: noDefault, path: "/v2/library/alpine/manifests/3.19", query: "ns=quay.io", wantOK: false},

		// Not registry paths at all.
		{name: "foreign path", rr: withDefault, path: "/v3/x", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			if err != nil {
				t.Fatalf("bad query: %v", err)
			}
			got, ok := tc.rr.route(tc.path, q)
			if ok != tc.wantOK {
				t.Fatalf("route(%q, %q) ok = %v, want %v (got %+v)", tc.path, tc.query, ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.upstream != tc.upstream || got.path != tc.wantPath || got.stripNS != tc.stripNS {
				t.Errorf("route(%q, %q) = %+v, want upstream=%q path=%q stripNS=%v",
					tc.path, tc.query, got, tc.upstream, tc.wantPath, tc.stripNS)
			}
		})
	}
}

func TestIsRegistryRequest(t *testing.T) {
	valid := []string{
		"library/alpine/manifests/3.19",
		"alpine/blobs/sha256:abc",
		"a/b/c/tags/list",
		"acme/app/referrers/sha256:abc",
		"_catalog",
		// A repository may itself contain a component named like a verb.
		"acme/blobs/app/manifests/v1",
	}
	invalid := []string{
		"",
		"manifests/latest",    // no repository component
		"alpine",              // repository only
		"alpine/manifests",    // verb without reference
		"alpine/manifests/",   // empty reference
		"alpine/tags",         // tags without "list"
		"alpine/tags/other",   // not the tags listing
		"alpine/uploads/uuid", // push endpoints are not served
	}
	for _, p := range valid {
		if !isRegistryRequest(p) {
			t.Errorf("isRegistryRequest(%q) = false, want true", p)
		}
	}
	for _, p := range invalid {
		if isRegistryRequest(p) {
			t.Errorf("isRegistryRequest(%q) = true, want false", p)
		}
	}
}

// registryUpstream is a fake registry that records the path and query of every
// request it receives, so a test can assert exactly what the alias forwarded.
type registryUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newRegistryUpstream(t *testing.T) *registryUpstream {
	t.Helper()
	u := &registryUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.seen = append(u.seen, r.URL.RequestURI())
		u.mu.Unlock()
		_, _ = io.WriteString(w, "served:"+r.URL.Path)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *registryUpstream) requests() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.seen...)
}

// newRegistryGateway builds a gateway with one pass-through backend per given
// upstream name and the supplied host-root registry alias configuration.
func newRegistryGateway(t *testing.T, upstreams map[string]string, root *RegistryRoot, deps Dependencies) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	for name, base := range upstreams {
		b, err := httpbackend.New(httpbackend.Options{
			Name:    name,
			BaseURL: base,
			Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
		})
		if err != nil {
			t.Fatalf("backend %s: %v", name, err)
		}
		if err := registry.Register(b); err != nil {
			t.Fatalf("register %s: %v", name, err)
		}
	}
	deps.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	deps.Cache = cache.NewMemoryCache()
	deps.Backends = registry
	g, err := New(deps, Options{HTTPAddr: ":0", RegistryRoot: root})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return g
}

func TestRegistryRootAliasServesThroughBackends(t *testing.T) {
	hub := newRegistryUpstream(t)
	ghcr := newRegistryUpstream(t)
	g := newRegistryGateway(t,
		map[string]string{"dockerhub": hub.URL, "ghcr": ghcr.URL},
		&RegistryRoot{
			Upstreams:       []string{"dockerhub", "ghcr"},
			DefaultUpstream: "dockerhub",
			Namespaces:      map[string]string{"docker.io": "dockerhub", "ghcr.io": "ghcr"},
		}, Dependencies{})
	h := g.routes()

	do := func(target string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr
	}

	// Registry-mirror mode: the daemon asks for the upstream's own repository path.
	if rr := do("/v2/library/alpine/manifests/3.19"); rr.Code != http.StatusOK || rr.Body.String() != "served:/v2/library/alpine/manifests/3.19" {
		t.Fatalf("mirror request: status=%d body=%q", rr.Code, rr.Body.String())
	}
	// Upstream-prefixed repository: the prefix selects the upstream and is removed.
	if rr := do("/v2/ghcr/acme/app/manifests/v1"); rr.Code != http.StatusOK || rr.Body.String() != "served:/v2/acme/app/manifests/v1" {
		t.Fatalf("prefixed request: status=%d body=%q", rr.Code, rr.Body.String())
	}
	// containerd mirror hint: selects the upstream and is not leaked upstream,
	// while unrelated query parameters are preserved.
	if rr := do("/v2/acme/app/tags/list?ns=ghcr.io&n=5"); rr.Code != http.StatusOK {
		t.Fatalf("ns request: status=%d body=%q", rr.Code, rr.Body.String())
	}

	if got, want := hub.requests(), []string{"/v2/library/alpine/manifests/3.19"}; !equalStrings(got, want) {
		t.Errorf("dockerhub upstream saw %v, want %v", got, want)
	}
	if got, want := ghcr.requests(), []string{"/v2/acme/app/manifests/v1", "/v2/acme/app/tags/list?n=5"}; !equalStrings(got, want) {
		t.Errorf("ghcr upstream saw %v, want %v", got, want)
	}
}

func TestRegistryRootAliasUnroutableIsRegistryError(t *testing.T) {
	ghcr := newRegistryUpstream(t)
	g := newRegistryGateway(t, map[string]string{"ghcr": ghcr.URL},
		&RegistryRoot{Upstreams: []string{"ghcr"}}, Dependencies{})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/3.19", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q, want JSON", ct)
	}
	var body struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not a registry error envelope: %v (%q)", err, rr.Body.String())
	}
	if len(body.Errors) != 1 || body.Errors[0].Code != "NAME_UNKNOWN" {
		t.Fatalf("errors = %+v, want one NAME_UNKNOWN", body.Errors)
	}
	// The message must tell the operator both ways out.
	for _, want := range []string{"ghcr", "server.registry.defaultUpstream"} {
		if !strings.Contains(body.Errors[0].Message, want) {
			t.Errorf("error message %q does not mention %q", body.Errors[0].Message, want)
		}
	}
	if len(ghcr.requests()) != 0 {
		t.Errorf("unroutable request reached an upstream: %v", ghcr.requests())
	}
}

func TestRegistryRootAliasNotMountedWhenUnconfigured(t *testing.T) {
	hub := newRegistryUpstream(t)
	for name, root := range map[string]*RegistryRoot{
		"nil":          nil,
		"no upstreams": {DefaultUpstream: "dockerhub"},
	} {
		t.Run(name, func(t *testing.T) {
			g := newRegistryGateway(t, map[string]string{"dockerhub": hub.URL}, root, Dependencies{})
			rr := httptest.NewRecorder()
			g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v2/library/alpine/manifests/3.19", nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 (alias must not be mounted)", rr.Code)
			}
		})
	}
	if len(hub.requests()) != 0 {
		t.Errorf("request reached the upstream through an unmounted alias: %v", hub.requests())
	}
}

// TestRegistryRootAliasEnforcesAccessControl proves the alias is not a side door
// around authentication/RBAC: it must be authorized against the upstream the
// request is routed to, exactly like the path-prefixed mount.
func TestRegistryRootAliasEnforcesAccessControl(t *testing.T) {
	hub := newRegistryUpstream(t)
	ghcr := newRegistryUpstream(t)

	az, err := auth.NewAuthorizer([]auth.Role{
		{Name: "hub-reader", Ecosystems: []string{"docker"}, Upstreams: []string{"dockerhub"}},
	})
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{
		{Name: "ci", Team: "team-a", Roles: []string{"hub-reader"}, Secret: testToken},
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

	g := newRegistryGateway(t,
		map[string]string{"dockerhub": hub.URL, "ghcr": ghcr.URL},
		&RegistryRoot{Upstreams: []string{"dockerhub", "ghcr"}, DefaultUpstream: "dockerhub"},
		Dependencies{
			Enforcer:   enforcer,
			Audit:      auditLog,
			Ecosystems: map[string]string{"dockerhub": "docker", "ghcr": "docker"},
		})
	h := g.routes()

	do := func(target, token string) int {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := do("/v2/library/alpine/manifests/3.19", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous alias request: status = %d, want 401", code)
	}
	if code := do("/v2/library/alpine/manifests/3.19", testToken); code != http.StatusOK {
		t.Errorf("authorized alias request: status = %d, want 200", code)
	}
	// The token may read dockerhub only; the alias must authorize against the
	// upstream it routes to (ghcr), not against the alias itself.
	if code := do("/v2/ghcr/acme/app/manifests/v1", testToken); code != http.StatusForbidden {
		t.Errorf("alias request to an unauthorized upstream: status = %d, want 403", code)
	}
	if len(ghcr.requests()) != 0 {
		t.Errorf("unauthorized request reached the ghcr upstream: %v", ghcr.requests())
	}
	if got, want := hub.requests(), []string{"/v2/library/alpine/manifests/3.19"}; !equalStrings(got, want) {
		t.Errorf("dockerhub upstream saw %v, want %v", got, want)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
