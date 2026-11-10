package admin

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/queryapi"
)

// stubFindings is a minimal FindingsProvider seeding one block-adjacent,
// unverified-signature coordinate so the query endpoint has content to join.
type stubFindings struct{ docs []findings.Document }

func (s *stubFindings) Documents(tenant, q string) []findings.Document {
	return append([]findings.Document(nil), s.docs...)
}

func newTestQueryEngine() *queryapi.Engine {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	fp := &stubFindings{docs: []findings.Document{{
		Tenant: "acme",
		Artifact: findings.Artifact{
			Ecosystem: "npm", Name: "evil", Version: "1.0.0",
			Coordinate: "npm/evil@1.0.0",
		},
		Findings: []findings.Finding{
			{RuleID: "PT-SIGVERIFY", Gate: findings.GateSigverify, Severity: findings.SeverityHigh, Level: findings.LevelError, Title: "unverified"},
		},
		GeneratedAt: now.Add(-time.Hour),
	}}}
	return queryapi.New(queryapi.Config{Now: func() time.Time { return now }}, queryapi.Providers{Findings: fp})
}

func TestQueryEndpointDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	rec := postJSON(t, srv, "/admin/api/query", `{"select":["coordinate"]}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when engine absent, got %d", rec.Code)
	}
}

func TestQueryEndpointRun(t *testing.T) {
	srv := newTestServer(t, Options{QueryAPI: newTestQueryEngine()})
	body := `{"tenant":"acme","select":["coordinate","signatureVerified"],"where":{"field":"signatureVerified","op":"eq","value":false}}`
	rec := postJSON(t, srv, "/admin/api/query", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var res queryapi.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Total != 1 || res.Returned != 1 {
		t.Fatalf("expected 1 match, got total=%d returned=%d", res.Total, res.Returned)
	}
	if res.Rows[0]["coordinate"] != "evil@1.0.0" {
		t.Errorf("unexpected row: %v", res.Rows[0])
	}
	if res.Cost <= 0 {
		t.Error("expected positive cost in response")
	}
}

func TestQueryEndpointValidationError(t *testing.T) {
	srv := newTestServer(t, Options{QueryAPI: newTestQueryEngine()})
	rec := postJSON(t, srv, "/admin/api/query", `{"select":["bogusField"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	var body struct{ Code, Error string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != "invalid_field" {
		t.Errorf("expected code invalid_field, got %q (%s)", body.Code, body.Error)
	}
}

func TestQuerySchemaEndpoint(t *testing.T) {
	srv := newTestServer(t, Options{QueryAPI: newTestQueryEngine()})
	var schema queryapi.Schema
	if code := getJSON(t, srv, "/admin/api/query/schema", "", &schema); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if len(schema.Fields) == 0 {
		t.Fatal("schema should advertise fields")
	}
	if schema.MaxLimit == 0 {
		t.Error("schema should advertise result bounds")
	}
}

func TestQueryEndpointMalformedBody(t *testing.T) {
	srv := newTestServer(t, Options{QueryAPI: newTestQueryEngine()})
	rec := postJSON(t, srv, "/admin/api/query", `{"select":["coordinate"], "unknownKey": 1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown key, got %d", rec.Code)
	}
}
