package admin

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

const (
	llmGlobalToken = "global-viewer-token-abcdef0123456789"
	llmTeamBToken  = "team-b-viewer-token-abcdef0123456789"
)

// newLLMPkgScanAdmin builds an admin server over a real gate (mock provider)
// that has scanned a private package for team-a and a shared one for both
// teams, behind RBAC with one global and one tenant-bound viewer.
func newLLMPkgScanAdmin(t *testing.T) *Server {
	t.Helper()
	svc, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled:  true,
		Provider: &pkgscantest.Provider{Usage: commit.Usage{InputTokens: 2000, OutputTokens: 100}},
		Model:    "mock-model",
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Budget:   llmpkgscan.BudgetConfig{Enabled: true, GlobalCeilingUSD: 100, TenantCeilingUSD: 10},
	})
	if err != nil {
		t.Fatalf("llmpkgscan.NewService: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	scan := func(tenant, name, version string, files map[string]string) {
		t.Helper()
		tarball := pkgscantest.NpmTarball(name, version, nil, files)
		rep, err := svc.Assess(context.Background(), llmpkgscan.Request{
			Artifact: llmpkgscan.Artifact{Ecosystem: "npm", Name: name, Version: version, Filename: name + "-" + version + ".tgz",
				Digest: pkgscantest.Digest(tarball), Size: int64(len(tarball))},
			Tenant: tenant,
			Open:   pkgscantest.Opener(tarball, nil),
		})
		if err != nil || rep == nil || !rep.Scanned() {
			t.Fatalf("Assess(%s): %+v, %v", name, rep, err)
		}
	}
	scan("team-a", "acme-secret", "1.0.0", map[string]string{"index.js": "const k = 'internal'; // " + pkgscantest.MaliciousMarker + "\n"})
	scan("team-a", "left-pad", "1.3.0", map[string]string{"index.js": "module.exports = 1;\n"})
	scan("team-b", "left-pad", "1.3.0", map[string]string{"index.js": "module.exports = 1;\n"})
	scan("team-b", "team-b-tool", "0.1.0", map[string]string{"index.js": "module.exports = 2;\n"})

	auth, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "global", Roles: []string{"viewer"}, Secret: llmGlobalToken},
			{Name: "team-b-viewer", Roles: []string{"viewer"}, Secret: llmTeamBToken, Tenant: "team-b"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	return newTestServer(t, Options{LLMPkgScan: svc, AdminAuth: auth})
}

func TestLLMPkgScanEndpointsDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	for _, path := range []string{"/admin/api/llmpkgscan", "/admin/api/llmpkgscan/verdicts"} {
		if code := getJSON(t, srv, path, "", nil); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 when the gate is off", path, code)
		}
	}
}

func TestLLMPkgScanEndpointsRequireAuthentication(t *testing.T) {
	srv := newLLMPkgScanAdmin(t)
	for _, path := range []string{"/admin/api/llmpkgscan", "/admin/api/llmpkgscan/verdicts"} {
		if code := getJSON(t, srv, path, "", nil); code != http.StatusUnauthorized {
			t.Errorf("anonymous %s = %d, want 401", path, code)
		}
	}
	if got := requiredCapability(http.MethodGet, "/api/llmpkgscan/verdicts"); got != adminauth.CapRead {
		t.Errorf("verdicts capability = %v, want read", got)
	}
}

func TestLLMPkgScanStatus(t *testing.T) {
	srv := newLLMPkgScanAdmin(t)

	var st llmpkgscan.Status
	if code := getJSON(t, srv, "/admin/api/llmpkgscan", llmGlobalToken, &st); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !st.Enabled || st.Model != "mock-model" || st.Action != llmpkgscan.ActionBlock || st.FailMode != llmpkgscan.FailOpen {
		t.Errorf("status = %+v", st)
	}
	if st.Scans != 3 || st.CacheHits != 1 || st.VerdictMalicious != 1 || st.VerdictBenign != 2 {
		t.Errorf("tallies = scans %d hits %d malicious %d benign %d", st.Scans, st.CacheHits, st.VerdictMalicious, st.VerdictBenign)
	}
	if !st.Budget.Enabled || len(st.Budget.Tenants) != 2 || st.Budget.GlobalSpentUSD <= 0 || st.CostUSD <= 0 {
		t.Errorf("global budget view = %+v cost %v", st.Budget, st.CostUSD)
	}

	// A tenant-bound caller sees its own budget row and no one else's spend.
	var scoped llmpkgscan.Status
	if code := getJSON(t, srv, "/admin/api/llmpkgscan?tenant=team-a", llmTeamBToken, &scoped); code != http.StatusOK {
		t.Fatalf("scoped status = %d", code)
	}
	if len(scoped.Budget.Tenants) != 1 || scoped.Budget.Tenants[0].Tenant != "team-b" {
		t.Errorf("tenant-bound budget rows = %+v, want team-b only", scoped.Budget.Tenants)
	}
	if scoped.Budget.GlobalSpentUSD != 0 || scoped.CostUSD != 0 {
		t.Errorf("tenant-bound caller sees organization spend: %+v / %v", scoped.Budget, scoped.CostUSD)
	}
	if scoped.Budget.GlobalCeilingUSD != 100 || scoped.Model != "mock-model" {
		t.Errorf("tenant-bound caller lost the shared ceiling or configuration: %+v", scoped)
	}
}

func TestLLMPkgScanVerdictsListing(t *testing.T) {
	srv := newLLMPkgScanAdmin(t)

	names := func(out llmPkgScanVerdicts) string {
		var ns []string
		for _, v := range out.Verdicts {
			ns = append(ns, v.Name)
		}
		return strings.Join(ns, ",")
	}

	var all llmPkgScanVerdicts
	if code := getJSON(t, srv, "/admin/api/llmpkgscan/verdicts", llmGlobalToken, &all); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if all.Count != 3 || len(all.Verdicts) != 3 || all.Tenant != "" {
		t.Fatalf("global listing = %d verdicts (%s)", all.Count, names(all))
	}
	for _, v := range all.Verdicts {
		if v.Name == "acme-secret" {
			if v.Standing.Disposition != llmpkgscan.DispositionMalicious || !v.Standing.Refused || v.Tenant != "team-a" || len(v.Evidence) == 0 {
				t.Errorf("malicious row = %+v standing %+v", v.Verdict, v.Standing)
			}
		}
	}

	// A global identity may narrow to a tenant.
	var asA llmPkgScanVerdicts
	getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?tenant=team-a", llmGlobalToken, &asA)
	if asA.Count != 2 || asA.Tenant != "team-a" || strings.Contains(names(asA), "team-b-tool") {
		t.Errorf("tenant=team-a listing = %s", names(asA))
	}

	// A tenant-bound identity cannot widen its scope through the query string,
	// and is not shown another tenant's private package — by listing or by name.
	var asB llmPkgScanVerdicts
	if code := getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?tenant=team-a", llmTeamBToken, &asB); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if asB.Tenant != "team-b" || asB.Count != 2 || strings.Contains(names(asB), "acme-secret") {
		t.Errorf("team-b listing = tenant %q: %s", asB.Tenant, names(asB))
	}
	for _, v := range asB.Verdicts {
		if v.Tenant != "" || v.CostUSD != 0 {
			t.Errorf("tenant-bound row leaks the scanning tenant or its spend: %+v", v.Verdict)
		}
	}
	var byName llmPkgScanVerdicts
	getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?name=acme-secret&ecosystem=npm&tenant=", llmTeamBToken, &byName)
	if byName.Count != 0 {
		t.Errorf("team-b was shown team-a's private package by name: %s", names(byName))
	}
	getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?name=acme-secret&ecosystem=npm&version=1.0.0", llmGlobalToken, &byName)
	if byName.Count != 1 || byName.Verdicts[0].Verdict.Verdict != "malicious" {
		t.Errorf("by-name lookup = %+v", byName)
	}

	// Limit handling.
	var one llmPkgScanVerdicts
	getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?limit=1", llmGlobalToken, &one)
	if one.Count != 1 {
		t.Errorf("limit=1 returned %d", one.Count)
	}
	for _, bad := range []string{"0", "-3", "many"} {
		if code := getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?limit="+bad, llmGlobalToken, nil); code != http.StatusBadRequest {
			t.Errorf("limit=%s = %d, want 400", bad, code)
		}
	}
	if code := getJSON(t, srv, "/admin/api/llmpkgscan/verdicts?limit=999999", llmGlobalToken, &one); code != http.StatusOK {
		t.Errorf("an oversized limit should be clamped, got %d", code)
	}
}
