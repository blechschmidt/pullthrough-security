package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

// stubFullMirror records the controls it receives.
type stubFullMirror struct {
	calls []string
}

func (s *stubFullMirror) Status() fullmirror.Status {
	return fullmirror.Status{Enabled: true, Leader: true, Upstreams: []fullmirror.UpstreamStatus{
		{Upstream: "npm", Type: "npm", State: fullmirror.StateFollowing, Counters: fullmirror.Counters{Fetched: 3, Refused: 1}},
	}, Totals: fullmirror.Totals{Upstreams: 1, Fetched: 3, Refused: 1}}
}

func (s *stubFullMirror) UpstreamStatus(name string) (fullmirror.UpstreamStatus, error) {
	if name != "npm" {
		return fullmirror.UpstreamStatus{}, fmt.Errorf("%w: %q", fullmirror.ErrUnknownUpstream, name)
	}
	return s.Status().Upstreams[0], nil
}

func (s *stubFullMirror) Pause(_ context.Context, upstream, by, reason string) error {
	if upstream != "" && upstream != "npm" {
		return fmt.Errorf("%w: %q", fullmirror.ErrUnknownUpstream, upstream)
	}
	s.calls = append(s.calls, "pause:"+upstream+":"+by+":"+reason)
	return nil
}

func (s *stubFullMirror) Resume(_ context.Context, upstream, by string) error {
	s.calls = append(s.calls, "resume:"+upstream+":"+by)
	return nil
}

func (s *stubFullMirror) Resync(_ context.Context, upstream, by string) error {
	s.calls = append(s.calls, "resync:"+upstream+":"+by)
	return nil
}

func newFullMirrorServer(t *testing.T, fm FullMirrorController, wa WebAuthnController, rec *recordingAudit) http.Handler {
	t.Helper()
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "v", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
			{Name: "o", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"},
			{Name: "a", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"},
			{Name: "t", Roles: []string{"admin"}, Tenant: "team-a", Secret: "tenant-admin-token-abcdef0123456789"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	opts := Options{Cache: &fakeCache{}, AdminAuth: svc, AuditLog: rec, WebAuthn: wa}
	if fm != nil {
		opts.FullMirror = fm
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return srv.Handler()
}

func fmDo(h http.Handler, method, path, token, body string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	for i := 0; i+1 < len(header); i += 2 {
		r.Header.Set(header[i], header[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const (
	fmViewer   = "viewer-token-abcdef0123456789"
	fmOperator = "operator-token-abcdef0123456789"
	fmAdmin    = "admin-token-abcdef0123456789xyz"
	fmTenant   = "tenant-admin-token-abcdef0123456789"
)

func TestFullMirrorStatusEndpoint(t *testing.T) {
	// Nothing mirrored: a disabled status, not an error.
	h := newFullMirrorServer(t, nil, nil, &recordingAudit{})
	w := fmDo(h, http.MethodGet, "/admin/api/fullmirror/status", fmViewer, "")
	var st fullmirror.Status
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Enabled || st.Upstreams == nil {
		t.Fatalf("disabled status: %d %s", w.Code, w.Body.String())
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmAdmin, ""); w.Code != http.StatusNotFound {
		t.Errorf("pause with nothing mirrored: %d", w.Code)
	}

	fm := &stubFullMirror{}
	h = newFullMirrorServer(t, fm, nil, &recordingAudit{})
	w = fmDo(h, http.MethodGet, "/admin/api/fullmirror/status", fmViewer, "")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil || !st.Enabled || st.Totals.Refused != 1 || len(st.Upstreams) != 1 {
		t.Fatalf("status: %d %s", w.Code, w.Body.String())
	}
	var us fullmirror.UpstreamStatus
	w = fmDo(h, http.MethodGet, "/admin/api/fullmirror/status?upstream=npm", fmTenant, "")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &us) != nil || us.Upstream != "npm" || us.Counters.Fetched != 3 {
		t.Fatalf("one upstream: %d %s", w.Code, w.Body.String())
	}
	if w := fmDo(h, http.MethodGet, "/admin/api/fullmirror/status?upstream=pypi", fmViewer, ""); w.Code != http.StatusNotFound {
		t.Errorf("unknown upstream: %d", w.Code)
	}
	if w := fmDo(h, http.MethodGet, "/admin/api/fullmirror/status", "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status: %d", w.Code)
	}
}

func TestFullMirrorControlsAndTheirCapabilities(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         adminauth.Capability
	}{
		{http.MethodGet, "/api/fullmirror/status", adminauth.CapRead},
		{http.MethodPost, "/api/fullmirror/pause", adminauth.CapOperate},
		{http.MethodPost, "/api/fullmirror/resume", adminauth.CapOperate},
		{http.MethodPost, "/api/fullmirror/resync", adminauth.CapAdminister},
	} {
		if got := requiredCapability(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s needs %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}

	fm := &stubFullMirror{}
	rec := &recordingAudit{}
	h := newFullMirrorServer(t, fm, nil, rec)
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmViewer, `{"upstream":"npm"}`); w.Code != http.StatusForbidden {
		t.Errorf("a viewer paused the mirror: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmOperator, `{"upstream":"npm","reason":"upstream incident"}`); w.Code != http.StatusOK {
		t.Fatalf("operator pause: %d %s", w.Code, w.Body.String())
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/resume", fmOperator, ""); w.Code != http.StatusOK {
		t.Fatalf("operator resume of everything: %d %s", w.Code, w.Body.String())
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/resync", fmOperator, `{"upstream":"npm"}`); w.Code != http.StatusForbidden {
		t.Errorf("an operator resynced: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/resync", fmAdmin, `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("a resync naming no upstream: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/resync?upstream=npm", fmAdmin, ""); w.Code != http.StatusOK {
		t.Errorf("admin resync: %d %s", w.Code, w.Body.String())
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmAdmin, `{"upstream":"pypi"}`); w.Code != http.StatusNotFound {
		t.Errorf("pause of an unknown upstream: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmAdmin, `{"upstream":"npm","extra":1}`); w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", w.Code)
	}
	// A tenant-bound identity may read but not steer an instance-wide job.
	if w := fmDo(h, http.MethodPost, "/admin/api/fullmirror/pause", fmTenant, `{"upstream":"npm"}`); w.Code != http.StatusForbidden {
		t.Errorf("a tenant-bound admin paused the mirror: %d", w.Code)
	}
	want := []string{"pause:npm:o:upstream incident", "resume::o", "resync:npm:a"}
	if strings.Join(fm.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls %v, want %v", fm.calls, want)
	}
	// Every allowed mutation is attributed in the audit log.
	allowed := 0
	for _, ev := range rec.events {
		if ev.Type == audit.EventAdmin && ev.Decision == audit.DecisionAllow && strings.Contains(ev.Resource, "/fullmirror/") {
			allowed++
		}
	}
	if allowed < 3 {
		t.Errorf("%d audited full-mirror mutations", allowed)
	}
}

func TestFullMirrorControlsNeedAStepUp(t *testing.T) {
	wa := &stubWebAuthn{
		enabled: true, enforcing: true, acceptToken: "fresh",
		protected: map[string]bool{"/api/fullmirror/pause": true, "/api/fullmirror/resume": true, "/api/fullmirror/resync": true},
	}
	fm := &stubFullMirror{}
	h := newFullMirrorServer(t, fm, wa, &recordingAudit{})
	for _, path := range []string{"/admin/api/fullmirror/pause", "/admin/api/fullmirror/resume", "/admin/api/fullmirror/resync"} {
		w := fmDo(h, http.MethodPost, path, fmAdmin, `{"upstream":"npm"}`)
		if w.Code != http.StatusUnauthorized || w.Header().Get(StepUpRequiredHeader) != "webauthn" {
			t.Errorf("%s without a step-up: %d %q", path, w.Code, w.Header().Get(StepUpRequiredHeader))
		}
		if w := fmDo(h, http.MethodPost, path, fmAdmin, `{"upstream":"npm"}`, StepUpTokenHeader, "fresh"); w.Code != http.StatusOK {
			t.Errorf("%s with a step-up: %d %s", path, w.Code, w.Body.String())
		}
	}
	if len(fm.calls) != 3 {
		t.Errorf("calls %v", fm.calls)
	}
	// Reading the status needs none.
	if w := fmDo(h, http.MethodGet, "/admin/api/fullmirror/status", fmViewer, ""); w.Code != http.StatusOK {
		t.Errorf("status under step-up enforcement: %d", w.Code)
	}
}
