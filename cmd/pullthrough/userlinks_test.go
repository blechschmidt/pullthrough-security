package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends/generic"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/scancoverage"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

func userLinksConfig(t *testing.T, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Server.PublicURL = "https://proxy.example.com"
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(t.TempDir(), "cache")
	cfg.UserLinks.Enabled = true
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"npm":  {Type: "npm", URL: "https://registry.npmjs.org"},
		"pypi": {Type: "pip", URL: "https://pypi.org"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the test configuration is not valid: %v", err)
	}
	return &cfg
}

func mustResolver(t *testing.T) *clientip.Resolver {
	t.Helper()
	r, err := clientip.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Off by default: no service, and every use of the nil service is a no-op.
func TestBuildUserLinksDisabled(t *testing.T) {
	cfg := config.Default()
	svc, err := buildUserLinks(&cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil || svc != nil {
		t.Fatalf("buildUserLinks with the feature off = %v, %v; want nil, nil", svc, err)
	}
	if svc.Enabled() {
		t.Fatal("a nil service reports itself enabled")
	}
	bindUserLinksMetrics(metrics.NewCollector(), svc) // must not panic
}

// Left unconfigured, the registry lives in a directory next to the cache, and
// what is put there survives a restart.
func TestBuildUserLinksDirectoryStore(t *testing.T) {
	cfg := userLinksConfig(t, nil)
	svc, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if svc.PathPrefix() != "/u" || svc.UIPath() != "/links" || svc.PageURL() != "https://proxy.example.com/links/" || svc.SignInEnabled() {
		t.Fatalf("service = %q %q %q signIn=%v", svc.PathPrefix(), svc.UIPath(), svc.PageURL(), svc.SignInEnabled())
	}
	if ttl := svc.Registry().LinkTTL(); ttl != 90*24*time.Hour {
		t.Fatalf("link lifetime = %v, want the default of ninety days", ttl)
	}
	token, base, info, err := svc.Issue(context.Background(), userlinks.Identity{Subject: "ci-bot"}, userlinks.IssueOptions{Label: "pipeline"})
	if err != nil {
		t.Fatal(err)
	}
	if base != "https://proxy.example.com/u/"+token {
		t.Fatalf("personal base = %q", base)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(cfg.Cache.Dir, "userlinks")
	entries, err := os.ReadDir(filepath.Join(dir, "link"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("the registry is not in %s: %v, %v", dir, entries, err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "link", entries[0].Name()))
	if strings.Contains(string(data), token) {
		t.Fatal("the stored record contains the token")
	}

	// A restart: the link is still there and still works.
	again, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	p, err := again.Authenticate(userlinks.WithPathToken(context.Background(), token), httptest.NewRequest("GET", "/v1/npm/x", nil))
	if err != nil || p.Subject != "ci-bot" || p.Attributes[userlinks.AttrLink] != info.ID {
		t.Fatalf("after a restart the link resolves to %+v, %v", p, err)
	}
}

func TestBuildUserLinksStoreSelection(t *testing.T) {
	// "0s" in the configuration means links that do not expire.
	cfg := userLinksConfig(t, func(c *config.Config) {
		c.UserLinks.LinkTTL = 0
		c.UserLinks.Store.Backend = "memory"
		c.UserLinks.MaxLinksPerUser = -1
	})
	svc, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	if ttl, max := svc.Registry().LinkTTL(), svc.Registry().MaxLinksPerUser(); ttl != 0 || max != 0 {
		t.Fatalf("link lifetime %v and limit %d, want none and none", ttl, max)
	}
	_ = svc.Close()

	// A directory of its own.
	own := filepath.Join(t.TempDir(), "links")
	cfg = userLinksConfig(t, func(c *config.Config) { c.UserLinks.Store.Dir = own })
	store, where, err := buildUserLinksStore(cfg)
	if err != nil || where != own {
		t.Fatalf("store = %v at %q, %v; want the configured directory", store, where, err)
	}
	_ = store.Close()

	// The s3 store inherits the cache's bucket and credentials, and keeps its
	// objects under a prefix of its own, next to the cache's.
	cfg = userLinksConfig(t, func(c *config.Config) {
		c.Cache.Backend = "s3"
		c.Cache.S3 = config.S3CacheConfig{Endpoint: "http://127.0.0.1:1", Bucket: "cache-bucket", Prefix: "proxy", AccessKeyID: "k", SecretAccessKey: "s", UsePathStyle: true}
	})
	store, where, err = buildUserLinksStore(cfg)
	if err != nil || where != "s3://cache-bucket/proxy/userlinks/" {
		t.Fatalf("inherited s3 store at %q, %v", where, err)
	}
	_ = store.Close()
	cfg.UserLinks.Store.S3 = config.UserLinksS3Config{Bucket: "links-bucket", Prefix: "/registry"}
	store, where, err = buildUserLinksStore(cfg)
	if err != nil || where != "s3://links-bucket/registry" {
		t.Fatalf("configured s3 store at %q, %v", where, err)
	}
	_ = store.Close()

	// A directory that cannot be used is a start-up error, not a silent
	// fall-back to memory.
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = userLinksConfig(t, func(c *config.Config) { c.UserLinks.Store.Dir = file })
	if _, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger()); err == nil {
		t.Fatal("a store directory that is a file was accepted")
	}
}

// An s3 store that cannot be reached does not keep the proxy from starting:
// links are refused as unverifiable until it can be.
func TestBuildUserLinksStartsWithoutItsStore(t *testing.T) {
	cfg := userLinksConfig(t, func(c *config.Config) {
		c.UserLinks.Store.Backend = "s3"
		c.UserLinks.Store.S3 = config.UserLinksS3Config{Endpoint: "http://127.0.0.1:1", Bucket: "b", AccessKeyID: "k", SecretAccessKey: "s", UsePathStyle: true}
	})
	svc, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil {
		t.Fatalf("the service does not start while its store is unreachable: %v", err)
	}
	defer svc.Close()
	token, _ := userlinks.NewToken()
	_, err = svc.Authenticate(userlinks.WithPathToken(context.Background(), token), httptest.NewRequest("GET", "/v1/npm/x", nil))
	var ae *userlinks.AuthError
	if !errors.As(err, &ae) || ae.Reason != userlinks.ReasonUnavailable {
		t.Fatalf("with the store unreachable: %v, want \"unavailable\"", err)
	}
}

// With the identity provider configured, sign-in is on, and what the page
// offers follows the configuration.
func TestBuildUserLinksWithSignIn(t *testing.T) {
	cfg := userLinksConfig(t, func(c *config.Config) {
		c.UserLinks.SessionKey = "0123456789abcdef0123456789abcdef"
		c.UserLinks.OIDC = config.UserLinksOIDCConfig{Enabled: true, Issuer: "https://idp.example.com", ClientID: "pullthrough"}
		c.UserLinks.Store.Backend = "memory"
	})
	svc, err := buildUserLinks(cfg, nil, mustResolver(t), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if !svc.SignInEnabled() {
		t.Fatal("sign-in is off although an identity provider is configured")
	}
	c := metrics.NewCollector()
	bindUserLinksMetrics(c, svc)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, name := range []string{
		`pullthrough_userlinks_links{state="active"} 0`,
		"pullthrough_userlinks_users 0",
		`pullthrough_userlinks_requests_total{via="path",outcome="ok"} 0`,
		`pullthrough_userlinks_signins_total{result="completed"} 0`,
		"pullthrough_userlinks_registry_synced 1",
		"pullthrough_userlinks_store_errors_total 0",
	} {
		if !strings.Contains(rec.Body.String(), name) {
			t.Errorf("the metrics lack %q", name)
		}
	}
}

// personalLinkRewrites says, for every upstream type the configuration accepts,
// whether its protocol adapter writes links to its own mount into the documents
// it serves — and therefore whether the gateway's personal-link edge rewrites
// that backend's index documents.
//
// It is spelled out, type by type, because both mistakes are costly: a type
// wrongly listed as writing links has its byte-exact, client-verified documents
// (a go.mod, an APT Release file) put at risk of being altered; a type wrongly
// listed as not writing them sends clients away from their personal address at
// the first download. A type that is added to the configuration without being
// added here fails the test below.
var personalLinkRewrites = map[string]bool{
	// Index documents name the artifacts by URL, and the adapter points those
	// URLs at the proxy.
	"npm": true, "pip": true, "cargo": true, "nuget": true, "composer": true, "helm": true,
	"dart": true, "pub": true, "terraform": true, "bazel": true, "nix": true, "openvsx": true,
	"jsr": true, "homebrew": true, "ansible": true, "puppet": true,
	// The routes an operator marked `rewrite` (the catalog's example has one).
	"generic": true,
	// The client builds every URL itself, relative to the address it was
	// configured with; what the proxy serves reaches it byte for byte.
	"go": false, "maven": false, "rubygems": false, "apt": false, "deb": false, "yum": false, "rpm": false,
	"docker": false, "conan": false, "swift": false, "huggingface": false, "conda": false, "cran": false,
	"hex": false, "julia": false, "cpan": false, "hackage": false,
}

// A backend that is told the public address of its mount writes links to it;
// that is what the gateway's personal-link edge goes by (publicMount). This
// holds the wiring of every upstream type to the table above.
func TestEveryUpstreamTypeIsClassifiedForPersonalLinks(t *testing.T) {
	for _, typ := range config.UpstreamTypes() {
		if _, ok := personalLinkRewrites[typ]; !ok && typ != "git" {
			t.Errorf("upstream type %q is not classified for personal links: say in personalLinkRewrites whether its adapter writes links to its own mount", typ)
		}
	}

	cfg := config.Default()
	cfg.Server.PublicURL = "https://proxy.example.com"
	client := upstream.NewWithHTTPClient(http.DefaultClient, "userlinks-test/1")
	built := map[string]bool{}
	for _, e := range scancoverage.Catalog() {
		if e.Gate != scancoverage.GatePackageScan {
			continue // git: built by its own function, below
		}
		for _, typ := range append([]string{e.Type}, e.Aliases...) {
			name := "links-" + typ
			up := config.UpstreamConfig{Type: typ, URL: coverageUpstream(t), Settings: e.Settings}
			if len(e.Routes) > 0 {
				gc := &generic.BackendConfig{}
				for _, r := range e.Routes {
					gc.Routes = append(gc.Routes, generic.RouteConfig{Name: r.Name, Match: r.Match, Cacheable: r.Cacheable, Rewrite: r.Rewrite, Gates: r.Gates})
				}
				up.Generic = gc
			}
			if _, err := buildBackend(&cfg, name, up, client, upstream.Credentials{}); err != nil {
				t.Fatalf("building a %s backend: %v", typ, err)
			}
			built[typ] = true
			want, classified := personalLinkRewrites[typ]
			if got := mountLinks.snapshot()[name]; classified && got != want {
				if want {
					t.Errorf("the %s backend writes links to its mount, but is not wired as doing so: its links would lose a user's personal prefix", typ)
				} else {
					t.Errorf("the %s backend is wired as writing links to its mount, but serves its documents byte for byte: they would be rewritten for personal links", typ)
				}
			}
		}
	}
	for typ := range personalLinkRewrites {
		if !built[typ] {
			t.Errorf("no %s backend was built: the coverage catalog has no entry for the type", typ)
		}
	}

	// A generic backend without a `rewrite` route serves everything as it came.
	plain := &generic.BackendConfig{Routes: []generic.RouteConfig{{Name: "files", Match: `^/files/.+$`, Cacheable: true}}}
	if _, err := buildBackend(&cfg, "links-generic-plain", config.UpstreamConfig{Type: "generic", URL: coverageUpstream(t), Generic: plain}, client, upstream.Credentials{}); err != nil {
		t.Fatal(err)
	}
	if mountLinks.snapshot()["links-generic-plain"] {
		t.Error("a generic backend without a rewrite route is wired as writing links")
	}

	// Git: the LFS batch API answers with the proxy's own address — when LFS is on.
	for name, lfs := range map[string]bool{"links-git-lfs": true, "links-git-plain": false} {
		gitCfg := cfg
		gitCfg.Git.LFS.Enabled = lfs
		rt := &gitRuntime{upstreams: map[string]*git.Upstream{}}
		if _, err := buildGitBackend(&gitCfg, name, config.UpstreamConfig{Type: "git", URL: "https://github.com"},
			newClientPool(gitCfg.Outbound, nil, nil, nil), upstream.Credentials{}, nil, cache.NewMemoryCache(), downloadLogTestLogger(), rt); err != nil {
			t.Fatalf("building a git backend: %v", err)
		}
		if got := mountLinks.snapshot()[name]; got != lfs {
			t.Errorf("git backend with LFS=%v: wired as writing links = %v", lfs, got)
		}
	}

	// The snapshot handed to the gateway is a copy.
	snap := mountLinks.snapshot()
	snap["links-go"] = true
	if mountLinks.snapshot()["links-go"] {
		t.Fatal("changing a snapshot changed the set")
	}
}

// A deployment whose only clients are users with personal links: access control
// is on, nothing else authenticates, and the enforcer is still built — to turn
// away whoever comes without a link.
func TestEnforcerWithPersonalLinksOnly(t *testing.T) {
	cfg := userLinksConfig(t, func(c *config.Config) {
		c.Auth.Enabled = true
		c.Auth.Roles = []config.RoleConfig{{Name: "reader", Ecosystems: []string{"*"}, Upstreams: []string{"*"}}}
		c.UserLinks.DefaultRoles = []string{"reader"}
		c.UserLinks.Store.Backend = "memory"
	})
	enforcer, err := buildEnforcer(cfg, nil, downloadLogTestLogger())
	if err != nil || enforcer == nil {
		t.Fatalf("buildEnforcer = %v, %v", enforcer, err)
	}
	res := enforcer.Check(context.Background(), httptest.NewRequest("GET", "/v1/npm/x", nil), "npm", "npm")
	if res.Allowed || res.Status != 401 {
		t.Fatalf("a request without a link: %+v, want 401", res)
	}
	admitted := enforcer.Admit(&auth.Principal{Subject: "alice", Roles: []string{"reader"}, Method: userlinks.MethodPersonalLink}, "npm", "npm")
	if !admitted.Allowed {
		t.Fatalf("a link's user with the default role: %+v", admitted)
	}
	refused := enforcer.Admit(&auth.Principal{Subject: "bob", Method: userlinks.MethodPersonalLink}, "npm", "npm")
	if refused.Allowed || refused.Status != 403 {
		t.Fatalf("a link's user without a role: %+v, want 403", refused)
	}
	// With access control off there is no enforcer, and a link's user is
	// admitted as they are.
	var none *auth.Enforcer
	if res := none.Admit(&auth.Principal{Subject: "carol"}, "npm", "npm"); !res.Allowed || res.Principal.Subject != "carol" {
		t.Fatalf("Admit without an enforcer: %+v", res)
	}
}

// A registry store at another S3 endpoint than the cache's inherits none of
// the cache's settings: not its credentials, not its InsecureSkipVerify. And a
// store block without a backend says which store it is.
func TestBuildUserLinksStoreAtAnotherEndpoint(t *testing.T) {
	var auths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auths = append(auths, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`))
	}))
	defer srv.Close()
	cfg := userLinksConfig(t, func(c *config.Config) {
		c.Cache.Backend = "filesystem"
		c.Cache.S3 = config.S3CacheConfig{Endpoint: "https://cache.s3.example", Bucket: "cache-bucket", AccessKeyID: "CACHEKEY", SecretAccessKey: "cache-secret", InsecureSkipVerify: true}
		c.UserLinks.Store.Backend = ""
		c.UserLinks.Store.S3 = config.UserLinksS3Config{Endpoint: srv.URL, Bucket: "links", AccessKeyID: "LINKSKEY", SecretAccessKey: "links-secret", UsePathStyle: true}
	})
	store, where, err := buildUserLinksStore(cfg)
	if err != nil || where != "s3://links/userlinks/" {
		t.Fatalf("store at %q, %v; want the configured bucket (the store block says s3)", where, err)
	}
	defer store.Close()
	if _, err := store.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(auths) == 0 || strings.Contains(auths[0], "CACHEKEY") || !strings.Contains(auths[0], "LINKSKEY") {
		t.Fatalf("the store at another endpoint signed with %q", auths)
	}
}
