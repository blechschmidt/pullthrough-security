package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/vexexport"
)

// fakeVEXExporter is a minimal VEXExporter for the endpoint test.
type fakeVEXExporter struct {
	enabled bool
	canSign bool
	last    vexexport.Request
}

func (f *fakeVEXExporter) Enabled() bool { return f.enabled }
func (f *fakeVEXExporter) CanSign() bool { return f.canSign }
func (f *fakeVEXExporter) Export(_ context.Context, req vexexport.Request) (*vexexport.Result, error) {
	f.last = req
	res := &vexexport.Result{
		Format:     req.Format,
		MediaType:  req.Format.MediaType(),
		Filename:   "vex.json",
		Document:   []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[]}`),
		Statements: 2,
		Scope:      "artifact",
	}
	if req.Sign {
		res.Signature = &vexexport.Signature{Algorithm: "ed25519", KeyID: "abc123", Digest: "deadbeef", Value: "c2ln"}
	}
	return res, nil
}

func TestHandleVEXExportDisabled(t *testing.T) {
	srv := newTestServer(t, Options{}) // no exporter wired
	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?name=lodash", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404 when export disabled, got %d", rec.Code)
	}
}

func TestHandleVEXExportOpenVEX(t *testing.T) {
	exp := &fakeVEXExporter{enabled: true}
	srv := newTestServer(t, Options{VEXExport: exp})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?ecosystem=npm&name=lodash&version=4.17.21", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.openvex+json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd == "" {
		t.Error("expected a Content-Disposition header")
	}
	if n := rec.Header().Get("X-Vex-Statements"); n != "2" {
		t.Errorf("X-Vex-Statements = %q, want 2", n)
	}
	// The handler forwarded the query into the request.
	if exp.last.Ecosystem != "npm" || exp.last.Name != "lodash" || exp.last.Version != "4.17.21" {
		t.Errorf("forwarded request = %+v", exp.last)
	}
	if exp.last.Format != vexexport.FormatOpenVEX {
		t.Errorf("format = %q, want openvex", exp.last.Format)
	}
}

func TestHandleVEXExportCycloneDX(t *testing.T) {
	exp := &fakeVEXExporter{enabled: true}
	srv := newTestServer(t, Options{VEXExport: exp})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?format=cyclonedx&snapshot=snap-1", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if exp.last.Format != vexexport.FormatCycloneDX {
		t.Errorf("format = %q, want cyclonedx", exp.last.Format)
	}
	if exp.last.SnapshotID != "snap-1" {
		t.Errorf("snapshot = %q", exp.last.SnapshotID)
	}
}

func TestHandleVEXExportSignNoKey(t *testing.T) {
	exp := &fakeVEXExporter{enabled: true, canSign: false}
	srv := newTestServer(t, Options{VEXExport: exp})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?name=x&sign=true", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 signing without a key, got %d", rec.Code)
	}
}

func TestHandleVEXExportSigned(t *testing.T) {
	exp := &fakeVEXExporter{enabled: true, canSign: true}
	srv := newTestServer(t, Options{VEXExport: exp})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?name=x&sign=1", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !exp.last.Sign {
		t.Error("expected Sign=true forwarded")
	}
	if sig := rec.Header().Get("X-Vex-Signature"); sig != "c2ln" {
		t.Errorf("X-Vex-Signature = %q", sig)
	}
	if alg := rec.Header().Get("X-Vex-Signature-Algorithm"); alg != "ed25519" {
		t.Errorf("X-Vex-Signature-Algorithm = %q", alg)
	}
}

func TestHandleVEXExportBadFormat(t *testing.T) {
	exp := &fakeVEXExporter{enabled: true}
	srv := newTestServer(t, Options{VEXExport: exp})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/vex/export?name=x&format=bogus", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad format, got %d", rec.Code)
	}
}
