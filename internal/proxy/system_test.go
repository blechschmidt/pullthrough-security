package proxy

import (
	"bytes"
	"context"
	"net/http"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
)

// A system fetch (Task 180) goes through the whole serve pipeline: it fills
// the cache, is in the download log as the system principal of its tenant,
// reports the cache object every gate admitted, and holds it before a byte is
// served.
func TestSystemFetchServesThroughThePipeline(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	var held []string
	var body bytes.Buffer
	res, err := g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "cargo", Path: "/api/v1/crates/cfg-if/1.0.0/download", Tenant: "team-a",
		Hold: func(key string) { held = append(held, key) },
	}, &body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK || body.String() != crateBody || res.Cache != "MISS" {
		t.Fatalf("result %+v body %q", res, body.String())
	}
	if res.CacheKey == "" || len(held) != 1 || held[0] != res.CacheKey {
		t.Fatalf("held %v for %q", held, res.CacheKey)
	}
	if res.Digest != sha256Hex(crateBody) || res.Size != int64(len(crateBody)) {
		t.Fatalf("digest/size %q %d", res.Digest, res.Size)
	}
	if _, err := g.Gateway.deps.Cache.Stat(context.Background(), res.CacheKey); err != nil {
		t.Fatalf("the object is not in the cache: %v", err)
	}
	e := g.only(t)
	if e.Subject != "system:release-pinner" || e.AuthMethod != "system" || e.Tenant != "team-a" ||
		e.Via != downloadlog.ViaSystem || e.ClientIP != "system" || e.Outcome != downloadlog.OutcomeServed || e.Package != "cfg-if" {
		t.Fatalf("download-log entry %+v", e)
	}

	// A second fetch is a cache hit of the same object.
	res2, err := g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "cargo", Path: "/api/v1/crates/cfg-if/1.0.0/download", Tenant: "team-a"}, nil)
	if err != nil || res2.Cache != "HIT" || res2.CacheKey != res.CacheKey {
		t.Fatalf("second fetch %+v %v", res2, err)
	}
	if n := g.stub.count("/api/v1/crates/cfg-if/1.0.0/download"); n != 1 {
		t.Fatalf("upstream fetched %d times", n)
	}
}

func sha256Hex(s string) string {
	return sha256Digest([]byte(s))
}

// A refused system fetch names the gate and its reason, is in the download
// log as blocked, and holds nothing.
func TestSystemFetchRefusalIsReported(t *testing.T) {
	feed := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-1", Ecosystem: "cargo", Name: "itoa", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Malfeed = feed }})
	held := false
	res, err := g.SystemFetch(context.Background(), SystemFetchRequest{
		Backend: "cargo", Path: "/api/v1/crates/itoa/1.0.11/download", Tenant: "team-a",
		Hold: func(string) { held = true },
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusForbidden || res.Gate != "malfeed" || res.Code == "" || res.Reason == "" || held || res.CacheKey != "" {
		t.Fatalf("refusal %+v held=%v", res, held)
	}
	refused := false
	for _, v := range res.Verdicts {
		if v.Gate == "malfeed" && v.Outcome == "refuse" {
			refused = true
		}
	}
	if !refused {
		t.Fatalf("verdicts %+v", res.Verdicts)
	}
	if e := g.only(t); e.Outcome != downloadlog.OutcomeBlocked || e.Gate != "malfeed" || e.Via != downloadlog.ViaSystem {
		t.Fatalf("entry %+v", e)
	}
}

// The burst of a release's dependencies is not fed to the anomaly detectors,
// nor gated by them.
func TestSystemFetchIsNotAnomalyTraffic(t *testing.T) {
	eng, err := anomaly.New(anomaly.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Anomaly = eng }})
	for i := 0; i < 3; i++ {
		if _, err := g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "cargo", Path: "/api/v1/crates/cfg-if/1.0.0/download", Tenant: "team-a"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := eng.Snapshot().Observed; n != 0 {
		t.Fatalf("system fetches were observed by the anomaly detectors: %d", n)
	}
}

// With access control on, a system fetch is authorized like a client's pull,
// against the roles the request carries: the lock files name the registries,
// and must not reach an upstream no role grants. The refusal is in the audit
// trail and names the access-control gate.
func TestSystemFetchIsAuthorizedByItsRoles(t *testing.T) {
	az, err := auth.NewAuthorizer([]auth.Role{
		{Name: "cargo-reader", Ecosystems: []string{"cargo"}, Upstreams: []string{"cargo"}},
		{Name: "go-reader", Ecosystems: []string{"go"}, Upstreams: []string{"*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{{Name: "ci", Team: "team-a", Roles: []string{"cargo-reader"}, Secret: testToken}})
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("k"), Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) { d.Enforcer, d.Audit = enforcer, auditLog }})
	const crate = "/api/v1/crates/cfg-if/1.0.0/download"

	for _, roles := range [][]string{nil, {"go-reader"}, {"undefined"}} {
		held := false
		res, err := g.SystemFetch(context.Background(), SystemFetchRequest{
			Backend: "cargo", Path: crate, Tenant: "team-a", Roles: roles,
			Hold: func(string) { held = true },
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Status != http.StatusForbidden || res.Gate != "access-control" || res.Reason == "" || held || res.CacheKey != "" {
			t.Fatalf("roles %v: %+v", roles, res)
		}
	}
	if n := g.stub.count(crate); n != 0 {
		t.Fatalf("a refused system fetch reached the upstream %d times", n)
	}
	denied := 0
	for _, r := range sink.Records() {
		if r.Event.Decision == audit.DecisionDeny && r.Event.Subject == "system:release-pinner" && r.Event.Team == "team-a" {
			denied++
		}
	}
	if denied != 3 {
		t.Fatalf("audited denials: %d", denied)
	}

	res, err := g.SystemFetch(context.Background(), SystemFetchRequest{Backend: "cargo", Path: crate, Tenant: "team-a", Roles: []string{"cargo-reader"}}, nil)
	if err != nil || res.Status != http.StatusOK || res.CacheKey == "" {
		t.Fatalf("granted: %+v %v", res, err)
	}
}

func TestSystemFetchRejectsMalformedRequests(t *testing.T) {
	g := newLogGateway(t, logGatewayOptions{})
	for _, req := range []SystemFetchRequest{
		{Backend: "", Path: "/x"},
		{Backend: "cargo", Path: "relative"},
		{Backend: "cargo", Path: "/x?token=1"},
	} {
		if _, err := g.SystemFetch(context.Background(), req, nil); err == nil {
			t.Errorf("accepted %+v", req)
		}
	}
}

// A pinned key is never answered from the negative cache: a "not found"
// remembered from before the object was restored must not hide it.
func TestPinnedKeyBypassesTheNegativeCache(t *testing.T) {
	coal := coalesce.New[*cache.Entry](coalesce.Config{Enabled: true}, classifyUpstreamError)
	pinned := map[string]bool{}
	g := newLogGateway(t, logGatewayOptions{deps: func(d *Dependencies) {
		d.Coalescer = coal
		d.Pins = cache.PinCheckerFunc(func(key string) bool { return pinned[key] })
	}})
	const missing = "/v1/cargo/api/v1/crates/gone/1.0.0/download"
	if rr := g.do(t, http.MethodGet, missing, "10.0.0.1:1"); rr.Code != http.StatusNotFound {
		t.Fatalf("first: %d", rr.Code)
	}
	if rr := g.do(t, http.MethodGet, missing, "10.0.0.1:1"); rr.Code != http.StatusNotFound || g.stub.count("/api/v1/crates/gone/1.0.0/download") != 1 {
		t.Fatalf("the second miss should come from the negative cache: %d %d", rr.Code, g.stub.count("/api/v1/crates/gone/1.0.0/download"))
	}
	// The object is restored (an air-gap import, a backup) under its key and
	// pinned: the negative entry must not hide it.
	key := "cargo/api/v1/crates/gone/1.0.0/download"
	if _, err := g.Gateway.deps.Cache.Stat(context.Background(), key); err == nil {
		t.Fatal("unexpected")
	}
	resolvedKey := cacheKeyFor(t, g, missing)
	if _, err := g.Gateway.deps.Cache.Put(context.Background(), resolvedKey, bytes.NewReader([]byte("restored")), nil); err != nil {
		t.Fatal(err)
	}
	pinned[resolvedKey] = true
	rr := g.do(t, http.MethodGet, missing, "10.0.0.1:1")
	if rr.Code != http.StatusOK || rr.Body.String() != "restored" {
		t.Fatalf("a pinned object was hidden by the negative cache: %d %q", rr.Code, rr.Body.String())
	}
	_ = key
}

// cacheKeyFor resolves the cache key the gateway uses for a request path.
func cacheKeyFor(t *testing.T, g *logGateway, path string) string {
	t.Helper()
	name, rest, ok := splitBackendPath(path)
	if !ok {
		t.Fatal(path)
	}
	b, _ := g.Gateway.deps.Backends.Get(name)
	resolved, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: rest})
	if err != nil {
		t.Fatal(err)
	}
	return resolved.CacheKey
}
