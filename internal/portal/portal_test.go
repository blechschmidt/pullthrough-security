package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// Two tenants used throughout: "acme" (alice) and "globex" (bob). The isolation
// tests assert that alice can never observe any globex artifact, and vice versa.
const (
	tokAlice = "alice-token-0123456789abcdef"  // tenant-viewer, tenant acme
	tokBob   = "bob-token-0123456789abcdefxy"  // tenant-viewer, tenant globex
	tokCarol = "carol-token-0123456789abcdef"  // tenant-viewer, NO tenant
	tokDave  = "dave-token-0123456789abcdefxx" // admin "viewer" role, NOT tenant-viewer
)

func testAuth(t *testing.T) *adminauth.Service {
	t.Helper()
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "alice", Tenant: "acme", Roles: []string{"tenant-viewer"}, Secret: tokAlice},
			{Name: "bob", Tenant: "globex", Roles: []string{"tenant-viewer"}, Secret: tokBob},
			{Name: "carol", Roles: []string{"tenant-viewer"}, Secret: tokCarol},
			{Name: "dave", Tenant: "acme", Roles: []string{"viewer"}, Secret: tokDave},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	return svc
}

// --- fakes ------------------------------------------------------------------

type fakeVerdicts struct{ all []riskscore.Assessment }

// Recent returns ALL tenants' assessments — the portal must filter them.
func (f *fakeVerdicts) Recent(limit int) []riskscore.Assessment { return f.all }

type fakeApprovals struct{ all []approvals.Request }

func (f *fakeApprovals) Enabled() bool { return true }

// List returns ALL tenants' requests — the portal must filter them.
func (f *fakeApprovals) List(status string, limit int) []approvals.Request {
	if status == "" {
		return f.all
	}
	var out []approvals.Request
	for _, r := range f.all {
		if string(r.Status) == status {
			out = append(out, r)
		}
	}
	return out
}

// fakeFindings mimics the real store's tenant-scoped Get/Documents (case-insensitive).
type fakeFindings struct{ docs []findings.Document }

func (f *fakeFindings) Documents(tenant, q string) []findings.Document {
	var out []findings.Document
	for _, d := range f.docs {
		if tenant != "" && !strings.EqualFold(d.Tenant, tenant) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(d.Artifact.Coordinate), strings.ToLower(q)) {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (f *fakeFindings) Get(tenant, pkg string) (findings.Document, bool) {
	for _, d := range f.docs {
		if tenant != "" && !strings.EqualFold(d.Tenant, tenant) {
			continue
		}
		if strings.EqualFold(d.Artifact.Coordinate, pkg) || strings.EqualFold(d.Artifact.Name, pkg) {
			return d, true
		}
	}
	return findings.Document{}, false
}

type fakeAttest struct{ bundles []*attestbundle.Bundle }

func (f *fakeAttest) Get(tenant, pkg string) (*attestbundle.Bundle, bool) {
	for _, b := range f.bundles {
		if tenant != "" && !strings.EqualFold(b.Tenant, tenant) {
			continue
		}
		if strings.EqualFold(b.Coordinate, pkg) {
			return b, true
		}
	}
	return nil, false
}

// seededServer wires a portal with data for BOTH tenants.
func seededServer(t *testing.T) *Server {
	t.Helper()
	verdicts := &fakeVerdicts{all: []riskscore.Assessment{
		{
			Tenant: "acme", Score: 88, Band: riskscore.BandCritical, Block: true,
			Artifact: riskscore.Artifact{Coordinate: "npm:evil-acme@1.0.0", Name: "evil-acme", Version: "1.0.0", Ecosystem: "npm"},
			Summary:  "malware match", ScoredAt: time.Unix(1_700_000_000, 0),
			Contributions: []riskscore.Contribution{{Signal: "malfeed", Points: 60, Raw: "known-malware"}},
		},
		{
			Tenant: "globex", Score: 40, Band: riskscore.BandHigh, Warn: true,
			Artifact: riskscore.Artifact{Coordinate: "npm:secret-globex@2.0.0", Name: "secret-globex", Version: "2.0.0", Ecosystem: "npm"},
			Summary:  "license drift", ScoredAt: time.Unix(1_700_000_500, 0),
			Contributions: []riskscore.Contribution{{Signal: "license", Points: 20, Raw: "GPL"}},
		},
	}}
	fdocs := &fakeFindings{docs: []findings.Document{
		{
			Tenant:   "acme",
			Artifact: findings.Artifact{Coordinate: "npm:evil-acme@1.0.0", Name: "evil-acme", Ecosystem: "npm"},
			Findings: []findings.Finding{{
				RuleID: findings.RuleVulnerableDependency, Gate: findings.GateVulnscan,
				Severity: findings.SeverityCritical, Level: findings.LevelError,
				Title: "CVE-2024-9999", Message: "remote code execution",
				Location: findings.Location{Coordinate: "npm:evil-acme@1.0.0"},
			}},
		},
		{
			Tenant:   "globex",
			Artifact: findings.Artifact{Coordinate: "npm:secret-globex@2.0.0", Name: "secret-globex", Ecosystem: "npm"},
			Findings: []findings.Finding{{
				RuleID: findings.RuleVulnerableDependency, Gate: findings.GateVulnscan,
				Severity: findings.SeverityHigh, Level: findings.LevelError,
				Title: "CVE-2024-1111", Message: "globex-only secret",
				Location: findings.Location{Coordinate: "npm:secret-globex@2.0.0"},
			}},
		},
	}}
	apps := &fakeApprovals{all: []approvals.Request{
		{ID: "req-acme", Tenant: "acme", Coordinate: "npm:evil-acme@1.0.0", Ecosystem: "npm", Gate: "malfeed", Reason: "known-malware", Status: approvals.StatusPending, CreatedAt: time.Unix(1_700_000_000, 0)},
		{ID: "req-globex", Tenant: "globex", Coordinate: "npm:secret-globex@2.0.0", Ecosystem: "npm", Gate: "license", Reason: "gpl", Status: approvals.StatusApproved, CreatedAt: time.Unix(1_700_000_100, 0)},
	}}
	att := &fakeAttest{bundles: []*attestbundle.Bundle{
		{Tenant: "acme", Coordinate: "npm:evil-acme@1.0.0", Digest: "sha256:aaa", PredicateType: "x", Envelope: attestbundle.Envelope{PayloadType: "application/vnd.in-toto+json", Payload: "ACME"}},
		{Tenant: "globex", Coordinate: "npm:secret-globex@2.0.0", Digest: "sha256:bbb", PredicateType: "x", Envelope: attestbundle.Envelope{PayloadType: "application/vnd.in-toto+json", Payload: "GLOBEX"}},
	}}

	srv, err := New(Options{
		Auth:         testAuth(t),
		PathPrefix:   "/portal",
		ProxyBaseURL: "https://proxy.example.com",
		Version:      "test",
		Backends:     []onboard.Backend{{Name: "npm", Type: "npm"}, {Name: "pypi", Type: "pip"}},
		Verdicts:     verdicts,
		Findings:     fdocs,
		Approvals:    apps,
		Attest:       att,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// do issues a GET to the portal with the given bearer token (empty = anonymous).
func do(t *testing.T, srv *Server, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode: %v\nbody: %s", err, rec.Body.String())
	}
}

// --- authorization gating ---------------------------------------------------

func TestUnauthenticatedIsRejected(t *testing.T) {
	srv := seededServer(t)
	for _, p := range []string{"/api/portal/summary", "/api/portal/verdicts", "/api/portal/quarantine", "/api/portal/onboarding"} {
		rec := do(t, srv, p, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous = %d, want 401", p, rec.Code)
		}
	}
}

func TestNonTenantViewerForbidden(t *testing.T) {
	srv := seededServer(t)
	// dave holds the admin "viewer" role but NOT tenant-viewer.
	rec := do(t, srv, "/api/portal/summary", tokDave)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("dave (viewer, no tenant-viewer) = %d, want 403", rec.Code)
	}
}

func TestTenantViewerWithoutTenantForbidden(t *testing.T) {
	srv := seededServer(t)
	// carol holds tenant-viewer but is bound to no tenant: cannot be scoped.
	rec := do(t, srv, "/api/portal/verdicts", tokCarol)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("carol (no tenant) = %d, want 403", rec.Code)
	}
}

func TestUserinfoReflectsEligibility(t *testing.T) {
	srv := seededServer(t)
	cases := []struct {
		token   string
		canView bool
		tenant  string
	}{
		{tokAlice, true, "acme"},
		{tokBob, true, "globex"},
		{tokCarol, false, ""},
		{tokDave, false, "acme"},
		{"", false, ""},
	}
	for _, c := range cases {
		rec := do(t, srv, "/api/portal/userinfo", c.token)
		if rec.Code != http.StatusOK {
			t.Fatalf("userinfo status = %d", rec.Code)
		}
		var resp userinfoResponse
		decode(t, rec, &resp)
		if resp.CanView != c.canView {
			t.Errorf("token %q canView = %v, want %v", c.token, resp.CanView, c.canView)
		}
		if c.token != "" && resp.Tenant != c.tenant {
			t.Errorf("token %q tenant = %q, want %q", c.token, resp.Tenant, c.tenant)
		}
	}
}

// --- tenant isolation: the core security property ---------------------------

func TestVerdictsAreTenantScoped(t *testing.T) {
	srv := seededServer(t)

	// Alice (acme) sees only acme verdicts.
	rec := do(t, srv, "/api/portal/verdicts", tokAlice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice verdicts = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "evil-acme") {
		t.Error("alice should see her own acme verdict")
	}
	if strings.Contains(body, "globex") {
		t.Fatalf("LEAK: alice saw globex data:\n%s", body)
	}

	// Bob (globex) sees only globex verdicts.
	rec = do(t, srv, "/api/portal/verdicts", tokBob)
	body = rec.Body.String()
	if !strings.Contains(body, "secret-globex") {
		t.Error("bob should see his own globex verdict")
	}
	if strings.Contains(body, "evil-acme") || strings.Contains(body, "acme") {
		t.Fatalf("LEAK: bob saw acme data:\n%s", body)
	}
}

func TestSummaryCountsOnlyOwnTenant(t *testing.T) {
	srv := seededServer(t)
	rec := do(t, srv, "/api/portal/summary", tokAlice)
	var resp summaryResponse
	decode(t, rec, &resp)
	if resp.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme", resp.Tenant)
	}
	if resp.Verdicts.Total != 1 || resp.Verdicts.Block != 1 {
		t.Errorf("verdict tallies = %+v, want 1 total / 1 block", resp.Verdicts)
	}
	if resp.Quarantine.Open != 1 {
		t.Errorf("quarantine open = %d, want 1 (acme only)", resp.Quarantine.Open)
	}
	if resp.Findings.Coordinates != 1 {
		t.Errorf("findings coordinates = %d, want 1 (acme only)", resp.Findings.Coordinates)
	}
}

func TestQuarantineIsTenantScoped(t *testing.T) {
	srv := seededServer(t)
	rec := do(t, srv, "/api/portal/quarantine", tokAlice)
	var resp quarantineResponse
	decode(t, rec, &resp)
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("alice quarantine total = %d, want 1", resp.Total)
	}
	if resp.Items[0].ID != "req-acme" {
		t.Errorf("alice saw %q, want req-acme", resp.Items[0].ID)
	}
	if strings.Contains(rec.Body.String(), "globex") {
		t.Fatalf("LEAK: alice saw globex quarantine:\n%s", rec.Body.String())
	}
}

func TestCoordinateCannotCrossTenant(t *testing.T) {
	srv := seededServer(t)

	// Alice asking about HER OWN coordinate: found, with remediation.
	rec := do(t, srv, "/api/portal/coordinate?coordinate=npm:evil-acme@1.0.0", tokAlice)
	var own coordinateResponse
	decode(t, rec, &own)
	if !own.Found {
		t.Fatal("alice should find her own coordinate")
	}
	if !own.Blocked {
		t.Error("evil-acme should be reported as blocked")
	}
	if len(own.Findings) == 0 || own.Findings[0].Remediation == "" {
		t.Error("expected findings with remediation guidance")
	}

	// Alice asking about GLOBEX's coordinate: must not be found, no leak.
	rec = do(t, srv, "/api/portal/coordinate?coordinate=npm:secret-globex@2.0.0", tokAlice)
	var cross coordinateResponse
	decode(t, rec, &cross)
	if cross.Found {
		t.Fatalf("LEAK: alice resolved globex coordinate: %+v", cross)
	}
	if cross.Verdict != nil || len(cross.Findings) != 0 || cross.Attestation.Available {
		t.Fatalf("LEAK: alice got globex detail: %+v", cross)
	}
	if strings.Contains(rec.Body.String(), "globex-only secret") {
		t.Fatalf("LEAK: alice saw globex finding message:\n%s", rec.Body.String())
	}
}

func TestTenantQueryParamIsIgnored(t *testing.T) {
	srv := seededServer(t)
	// A malicious caller appends ?tenant=globex hoping to widen scope. The portal
	// reads the tenant ONLY from the identity, so this must return acme data.
	rec := do(t, srv, "/api/portal/summary?tenant=globex", tokAlice)
	var resp summaryResponse
	decode(t, rec, &resp)
	if resp.Tenant != "acme" {
		t.Fatalf("tenant override leaked: got %q, want acme", resp.Tenant)
	}
	if resp.Findings.Coordinates != 1 {
		t.Errorf("findings coordinates = %d, want 1 (acme only, query param ignored)", resp.Findings.Coordinates)
	}
}

func TestSARIFDownloadIsTenantScoped(t *testing.T) {
	srv := seededServer(t)

	// Batch SARIF for alice contains only acme artifacts.
	rec := do(t, srv, "/api/portal/findings/sarif", tokAlice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice sarif = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "sarif") {
		t.Errorf("content-type = %q, want sarif", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "evil-acme") {
		t.Error("alice batch SARIF should include her artifact")
	}
	if strings.Contains(body, "globex") {
		t.Fatalf("LEAK: alice SARIF contained globex:\n%s", body)
	}

	// Single-artifact SARIF for a globex package must 404 for alice.
	rec = do(t, srv, "/api/portal/findings/sarif?package=npm:secret-globex@2.0.0", tokAlice)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("alice cross-tenant SARIF = %d, want 404\n%s", rec.Code, rec.Body.String())
	}
}

func TestAttestationDownloadIsTenantScoped(t *testing.T) {
	srv := seededServer(t)

	// Alice can download her own attestation.
	rec := do(t, srv, "/api/portal/attestation?package=npm:evil-acme@1.0.0", tokAlice)
	if rec.Code != http.StatusOK {
		t.Fatalf("alice attestation = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ACME") {
		t.Error("expected acme attestation payload")
	}

	// Alice cannot download globex's attestation.
	rec = do(t, srv, "/api/portal/attestation?package=npm:secret-globex@2.0.0", tokAlice)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("alice cross-tenant attestation = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "GLOBEX") {
		t.Fatalf("LEAK: alice got globex attestation payload:\n%s", rec.Body.String())
	}
}

// --- onboarding & static page -----------------------------------------------

func TestOnboardingSnippetsRendered(t *testing.T) {
	srv := seededServer(t)
	rec := do(t, srv, "/api/portal/onboarding", tokAlice)
	var resp onboardingResponse
	decode(t, rec, &resp)
	if resp.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme", resp.Tenant)
	}
	if len(resp.Snippets) < 2 {
		t.Fatalf("expected snippets for npm + pip, got %d", len(resp.Snippets))
	}
	joined := rec.Body.String()
	if !strings.Contains(joined, "registry=https://proxy.example.com/v1/npm/") {
		t.Errorf("npm snippet not rendered:\n%s", joined)
	}
	// No real token is ever minted by the portal.
	if strings.Contains(joined, tokAlice) {
		t.Error("portal must not embed the caller's bearer token in snippets")
	}
}

func TestStaticPageServed(t *testing.T) {
	srv := seededServer(t)
	rec := do(t, srv, "/portal/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("portal page = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("content-type = %q, want text/html", ct)
	}
	if !strings.Contains(rec.Body.String(), "Self-Service") {
		t.Error("portal page body missing expected title")
	}
}

func TestNewRequiresAuth(t *testing.T) {
	if _, err := New(Options{PathPrefix: "/portal"}); err == nil {
		t.Fatal("New without an adminauth Service should error")
	}
}
