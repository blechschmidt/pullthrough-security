package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// stubFullScan records the controls it receives.
type stubFullScan struct {
	mu       sync.Mutex
	calls    []string
	rescanOf fullscan.RescanRequest
}

func (s *stubFullScan) Status() fullscan.Status {
	return fullscan.Status{Enabled: true, Leader: true, Subject: fullscan.Subject, StateDir: "/var/lib/pt/fullscan", Upstreams: []fullscan.UpstreamStatus{{
		Upstream: "npm", Figures: fullscan.Figures{Cached: 3, Scanned: 2, Pending: 1, Malicious: 1},
		OldestUnscanned: &fullscan.Oldest{Path: "/@acme/secret/-/secret-1.0.0.tgz", Key: "team-b/npm:@acme/secret", Cached: time.Unix(0, 0), State: fullscan.StatePending},
	}}}
}

func (s *stubFullScan) UpstreamStatus(name string) (fullscan.UpstreamStatus, error) {
	if name != "npm" {
		return fullscan.UpstreamStatus{}, fmt.Errorf("%w: %q", fullscan.ErrUnknownUpstream, name)
	}
	return s.Status().Upstreams[0], nil
}

func (s *stubFullScan) record(call string) {
	s.mu.Lock()
	s.calls = append(s.calls, call)
	s.mu.Unlock()
}

func (s *stubFullScan) Pause(_ context.Context, upstream, by, reason string) error {
	if upstream != "" && upstream != "npm" {
		return fmt.Errorf("%w: %q", fullscan.ErrUnknownUpstream, upstream)
	}
	s.record("pause " + upstream + " " + by + " " + reason)
	return nil
}

func (s *stubFullScan) Resume(_ context.Context, upstream, by string) error {
	s.record("resume " + upstream + " " + by)
	return nil
}

func (s *stubFullScan) Rescan(_ context.Context, req fullscan.RescanRequest) (fullscan.RescanRequest, error) {
	if req.Filter == "bogus" {
		return fullscan.RescanRequest{}, fmt.Errorf("fullscan: unknown re-scan filter %q", req.Filter)
	}
	s.record("rescan " + req.Upstream + " " + req.Filter + " " + req.By)
	req.Seq = 7
	s.mu.Lock()
	s.rescanOf = req
	s.mu.Unlock()
	return req, nil
}

func newFullScanServer(t *testing.T, fs FullScanController) http.Handler {
	t.Helper()
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "v", Roles: []string{"viewer"}, Secret: fmViewer},
			{Name: "o", Roles: []string{"operator"}, Secret: fmOperator},
			{Name: "a", Roles: []string{"admin"}, Secret: fmAdmin},
			{Name: "t", Roles: []string{"admin"}, Tenant: "team-a", Secret: fmTenant},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{Cache: &fakeCache{}, AdminAuth: svc, AuditLog: &recordingAudit{}}
	if fs != nil {
		opts.FullScan = fs
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

// compactJSON renders a JSON body without indentation.
func compactJSON(b []byte) string {
	var buf bytes.Buffer
	if json.Compact(&buf, b) != nil {
		return string(b)
	}
	return buf.String()
}

func TestFullScanEndpoints(t *testing.T) {
	// Without a full scan: an empty status, and controls answer 404.
	h := newFullScanServer(t, nil)
	if w := fmDo(h, http.MethodGet, "/admin/api/fullscan/status", fmViewer, ""); w.Code != http.StatusOK || !strings.Contains(compactJSON(w.Body.Bytes()), `"enabled":false`) {
		t.Fatalf("status without a full scan: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmAdmin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("pause without a full scan: %d", w.Code)
	}

	fs := &stubFullScan{}
	h = newFullScanServer(t, fs)
	w := fmDo(h, http.MethodGet, "/admin/api/fullscan/status", fmViewer, "")
	var st fullscan.Status
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &st) != nil || st.Upstreams[0].OldestUnscanned.Path == "" {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodGet, "/admin/api/fullscan/status?upstream=npm", fmViewer, ""); w.Code != http.StatusOK || !strings.Contains(compactJSON(w.Body.Bytes()), `"malicious":1`) {
		t.Fatalf("status of one upstream: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodGet, "/admin/api/fullscan/status?upstream=pypi", fmViewer, ""); w.Code != http.StatusNotFound {
		t.Fatalf("status of an upstream outside the scope: %d", w.Code)
	}
	// A tenant-bound identity sees the figures, not what other tenants'
	// caches hold, and cannot steer the full scan.
	w = fmDo(h, http.MethodGet, "/admin/api/fullscan/status", fmTenant, "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "/var/lib") || !strings.Contains(compactJSON(w.Body.Bytes()), `"pending":1`) {
		t.Fatalf("a tenant-bound identity's status: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmTenant, `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("a tenant-bound pause: %d", w.Code)
	}

	// Pausing and resuming are operational; a re-scan is the administrator's.
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmViewer, `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("a viewer's pause: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmOperator, `{"upstream":"npm","reason":"bill review"}`); w.Code != http.StatusOK {
		t.Fatalf("an operator's pause: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmOperator, `{"upstream":"pypi"}`); w.Code != http.StatusNotFound {
		t.Fatalf("pausing an upstream outside the scope: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/pause", fmOperator, `{"bogus":1}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown field: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/resume?upstream=npm", fmOperator, ``); w.Code != http.StatusOK {
		t.Fatalf("an operator's resume: %d %s", w.Code, w.Body)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/rescan", fmOperator, `{"upstream":"npm"}`); w.Code != http.StatusForbidden {
		t.Fatalf("an operator's re-scan: %d", w.Code)
	}
	if w := fmDo(h, http.MethodPost, "/admin/api/fullscan/rescan", fmAdmin, `{"filter":"bogus"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("an unknown filter: %d %s", w.Code, w.Body)
	}
	w = fmDo(h, http.MethodPost, "/admin/api/fullscan/rescan", fmAdmin, `{"upstream":"npm","filter":"flagged"}`)
	if w.Code != http.StatusOK || !strings.Contains(compactJSON(w.Body.Bytes()), `"seq":7`) {
		t.Fatalf("an administrator's re-scan: %d %s", w.Code, w.Body)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	want := []string{"pause npm o bill review", "resume npm o", "rescan npm flagged a"}
	if strings.Join(fs.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %q, want %q", fs.calls, want)
	}
}
