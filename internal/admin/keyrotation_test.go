package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/keyrotation"
)

// fakeKeyRotation is a stub KeyRotationInspector for the admin handler tests.
type fakeKeyRotation struct {
	enabled  bool
	status   keyrotation.ScanResult
	out      keyrotation.RotationOutcome
	err      error
	gotID    string
	gotForce bool
}

func (f *fakeKeyRotation) Enabled() bool                                 { return f.enabled }
func (f *fakeKeyRotation) Status(context.Context) keyrotation.ScanResult { return f.status }
func (f *fakeKeyRotation) Rotate(_ context.Context, id string, force bool) (keyrotation.RotationOutcome, error) {
	f.gotID = id
	f.gotForce = force
	return f.out, f.err
}

func TestKeysStatusDisabled(t *testing.T) {
	srv := newTestServer(t, Options{})
	var resp keyrotation.ScanResult
	if code := getJSON(t, srv, "/admin/api/keys/status", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if resp.Enabled {
		t.Error("expected enabled=false when key-rotation absent")
	}
}

func TestKeysStatusEnabled(t *testing.T) {
	fk := &fakeKeyRotation{
		enabled: true,
		status: keyrotation.ScanResult{
			Enabled: true,
			Counts:  keyrotation.StatusCounts{Total: 2, Warning: 1, OK: 1},
			Materials: []keyrotation.MaterialStatus{
				{Material: keyrotation.Material{ID: "cache.kek", Kind: keyrotation.KindCacheKEK}, Status: keyrotation.StatusWarning, HasExpiry: true},
			},
		},
	}
	srv := newTestServer(t, Options{KeyRotation: fk})
	var resp keyrotation.ScanResult
	if code := getJSON(t, srv, "/admin/api/keys/status", "", &resp); code != http.StatusOK {
		t.Fatalf("status code = %d", code)
	}
	if !resp.Enabled || resp.Counts.Total != 2 || resp.Counts.Warning != 1 {
		t.Fatalf("unexpected status: %+v", resp)
	}
}

func post(t *testing.T, srv *Server, path, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	if body != "" {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestKeysRotateUnsupported(t *testing.T) {
	fk := &fakeKeyRotation{
		enabled: true,
		out:     keyrotation.RotationOutcome{MaterialID: "audit.hmac", Supported: false, Detail: "rotate out-of-band"},
		err:     keyrotation.ErrRotationUnsupported,
	}
	srv := newTestServer(t, Options{KeyRotation: fk})
	code, bodyBytes := post(t, srv, "/admin/api/keys/rotate", `{"material":"audit.hmac"}`)
	// Unsupported is informative, not a failure: 200 with the outcome.
	if code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	var out keyrotation.RotationOutcome
	if err := json.Unmarshal(bodyBytes, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Supported {
		t.Fatal("expected Supported=false outcome")
	}
	if fk.gotID != "audit.hmac" {
		t.Fatalf("rotate called with id %q", fk.gotID)
	}
}

func TestKeysRotateInFlightConflict(t *testing.T) {
	fk := &fakeKeyRotation{enabled: true, err: keyrotation.ErrRotationInFlight}
	srv := newTestServer(t, Options{KeyRotation: fk})
	code, _ := post(t, srv, "/admin/api/keys/rotate", `{"material":"cache.kek"}`)
	if code != http.StatusConflict {
		t.Fatalf("status code = %d, want 409", code)
	}
}

func TestKeysRotateMissingMaterial(t *testing.T) {
	fk := &fakeKeyRotation{enabled: true}
	srv := newTestServer(t, Options{KeyRotation: fk})
	code, _ := post(t, srv, "/admin/api/keys/rotate", `{}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", code)
	}
}

func TestKeysRotateSuccess(t *testing.T) {
	fk := &fakeKeyRotation{
		enabled: true,
		out:     keyrotation.RotationOutcome{MaterialID: "cache.kek", Supported: true, Performed: true, NewPrimaryKeyID: "kek-2", Rewrapped: 3},
	}
	srv := newTestServer(t, Options{KeyRotation: fk})
	code, bodyBytes := post(t, srv, "/admin/api/keys/rotate", `{"material":"cache.kek","force":true}`)
	if code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", code)
	}
	if !fk.gotForce {
		t.Fatal("force flag not propagated")
	}
	var out keyrotation.RotationOutcome
	if err := json.Unmarshal(bodyBytes, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Performed || out.NewPrimaryKeyID != "kek-2" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}
