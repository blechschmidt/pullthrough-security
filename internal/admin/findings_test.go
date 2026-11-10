package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
)

// fakeFindings is a minimal FindingsInspector backed by a real store.
type fakeFindings struct {
	store *findings.Store
}

func (f fakeFindings) Get(tenant, pkg string) (findings.Document, bool) {
	return f.store.Get(tenant, pkg)
}
func (f fakeFindings) Documents(tenant, q string) []findings.Document {
	return f.store.Documents(tenant, q)
}
func (f fakeFindings) ToolVersion() string { return "test" }

func newFindingsServer(t *testing.T, inspector FindingsInspector) *Server {
	t.Helper()
	return newTestServer(t, Options{Cache: &fakeCache{}, Findings: inspector})
}

func seedDoc(tenant, name, version string) findings.Document {
	return findings.Document{
		Tenant: tenant,
		Artifact: findings.Artifact{
			Ecosystem: "npm", Name: name, Version: version, Coordinate: name + "@" + version,
		},
		Findings: []findings.Finding{{
			RuleID: findings.RuleVulnerableDependency, Gate: findings.GateVulnscan,
			Severity: findings.SeverityCritical, Level: findings.LevelError,
			Identifier: "CVE-9", Title: "bad", Message: "bad", Location: findings.Location{Coordinate: name + "@" + version},
		}},
	}
}

func TestHandleFindingsSARIFSingle(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	store.Record(seedDoc("acme", "lodash", "4.17.21"))
	srv := newFindingsServer(t, fakeFindings{store: store})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/findings/sarif?tenant=acme&package=lodash", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/sarif+json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	var log findings.Log
	if err := json.Unmarshal(rec.Body.Bytes(), &log); err != nil {
		t.Fatalf("decoding SARIF: %v", err)
	}
	if log.Version != "2.1.0" || log.Schema != findings.SARIFSchema {
		t.Errorf("bad SARIF header: %s %s", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
		t.Fatalf("want 1 run / 1 result, got %d runs", len(log.Runs))
	}
	if log.Runs[0].Results[0].RuleID != findings.RuleVulnerableDependency {
		t.Errorf("unexpected ruleId %q", log.Runs[0].Results[0].RuleID)
	}
}

func TestHandleFindingsSARIFMissing(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	srv := newFindingsServer(t, fakeFindings{store: store})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/findings/sarif?tenant=acme&package=ghost", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown package, got %d", rec.Code)
	}
}

func TestHandleFindingsSARIFBatch(t *testing.T) {
	store := findings.NewStore(findings.StoreOptions{})
	store.Record(seedDoc("acme", "lodash", "4.17.21"))
	store.Record(seedDoc("acme", "left-pad", "1.3.0"))
	store.Record(seedDoc("other", "express", "4.0.0"))
	srv := newFindingsServer(t, fakeFindings{store: store})

	// No package => batch for the tenant.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/findings/sarif?tenant=acme", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var log findings.Log
	if err := json.Unmarshal(rec.Body.Bytes(), &log); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("batch for tenant acme should have 2 results, got %d", len(log.Runs[0].Results))
	}
}

func TestHandleFindingsDisabled(t *testing.T) {
	srv := newFindingsServer(t, nil) // Findings inspector nil
	req := httptest.NewRequest(http.MethodGet, "/admin/api/findings/sarif?package=x", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when findings disabled, got %d", rec.Code)
	}

	// The JSON list endpoint reports the surface absent rather than 404.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/findings", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list endpoint status = %d", rec.Code)
	}
	var resp findingsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Error("expected enabled:false when findings disabled")
	}
}
