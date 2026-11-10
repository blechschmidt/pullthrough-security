package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

func TestRequiredCapability(t *testing.T) {
	cases := []struct {
		method, path string
		want         adminauth.Capability
	}{
		{http.MethodGet, "/api/overview", adminauth.CapRead},
		{http.MethodGet, "/api/cache", adminauth.CapRead},
		{http.MethodDelete, "/api/cache/entry", adminauth.CapOperate},
		{http.MethodDelete, "/api/quarantine/entry", adminauth.CapOperate},
		{http.MethodPost, "/api/backup/run", adminauth.CapOperate},
		{http.MethodPost, "/api/approvals/approve", adminauth.CapApprove},
		{http.MethodPost, "/api/approvals/deny", adminauth.CapApprove},
		{http.MethodPost, "/api/policyengine/reload", adminauth.CapAdminister},
		{http.MethodPut, "/api/ratelimit/policy", adminauth.CapAdminister},
		{http.MethodPost, "/api/policyengine/test", adminauth.CapRead},
		{http.MethodPost, "/api/simreplay/simulate", adminauth.CapRead},
		// The gRPC/Connect security API (Task 159) is a read-only POST subtree.
		{http.MethodPost, "/api/grpc/pullthrough.security.v1.SecurityQueryService/GetRiskVerdict", adminauth.CapRead},
		{http.MethodPost, "/api/grpc/pullthrough.security.v1.SecurityQueryService/StreamQueryCorpus", adminauth.CapRead},
	}
	for _, tc := range cases {
		if got := requiredCapability(tc.method, tc.path); got != tc.want {
			t.Errorf("requiredCapability(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// recordingAudit captures admin events for attribution assertions.
type recordingAudit struct{ events []audit.Event }

func (r *recordingAudit) Log(_ context.Context, ev audit.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func newRBACServer(t *testing.T, rec *recordingAudit) *Server {
	t.Helper()
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "v", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
			{Name: "o", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"},
			{Name: "a", Roles: []string{"admin"}, Secret: "admin-token-abcdef0123456789xyz"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	srv, err := New(Options{
		Cache:     &fakeCache{},
		AdminAuth: svc,
		AuditLog:  rec,
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return srv
}

func TestRBACMiddleware(t *testing.T) {
	rec := &recordingAudit{}
	srv := newRBACServer(t, rec)
	h := srv.Handler()

	do := func(method, path, token string) int {
		r := httptest.NewRequest(method, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Unauthenticated API request → 401 with a login hint header absent (no OIDC).
	if code := do(http.MethodGet, "/admin/api/overview", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous overview = %d, want 401", code)
	}

	// Viewer can read.
	if code := do(http.MethodGet, "/admin/api/overview", "viewer-token-abcdef0123456789"); code != http.StatusOK {
		t.Errorf("viewer overview = %d, want 200", code)
	}
	// Viewer cannot delete a cache entry (needs operate) → 403.
	if code := do(http.MethodDelete, "/admin/api/cache/entry?key=missing", "viewer-token-abcdef0123456789"); code != http.StatusForbidden {
		t.Errorf("viewer delete = %d, want 403", code)
	}

	// Operator can attempt the delete (404 because the key is absent, but it
	// passed authorization).
	if code := do(http.MethodDelete, "/admin/api/cache/entry?key=missing", "operator-token-abcdef0123456789"); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Errorf("operator delete = %d, should have passed authz", code)
	}

	// Static dashboard assets are reachable without auth.
	if code := do(http.MethodGet, "/admin/", ""); code != http.StatusOK {
		t.Errorf("dashboard root = %d, want 200", code)
	}

	// The operator's authorized mutation (and the viewer's denied one) were
	// recorded in the audit log with the subject.
	var sawOperatorAllow, sawViewerDeny bool
	for _, ev := range rec.events {
		if ev.Type != audit.EventAdmin {
			continue
		}
		if ev.Subject == "o" && ev.Decision == audit.DecisionAllow {
			sawOperatorAllow = true
		}
		if ev.Subject == "v" && ev.Decision == audit.DecisionDeny {
			sawViewerDeny = true
		}
	}
	if !sawOperatorAllow {
		t.Error("expected an allow audit event attributed to operator 'o'")
	}
	if !sawViewerDeny {
		t.Error("expected a deny audit event attributed to viewer 'v'")
	}
}

// fakeGRPC is a minimal GRPCHandler mounting a stub Connect-style subtree so the
// test can assert the admin RBAC middleware governs the /api/grpc subtree.
type fakeGRPC struct{ hits int }

func (f *fakeGRPC) Enabled() bool { return true }

func (f *fakeGRPC) Handler() (string, http.Handler) {
	return "/pullthrough.security.v1.SecurityQueryService/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits++
		w.WriteHeader(http.StatusOK)
	})
}

func TestGRPCSubtreeRBAC(t *testing.T) {
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "v", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	grpc := &fakeGRPC{}
	srv, err := New(Options{Cache: &fakeCache{}, AdminAuth: svc, GRPC: grpc})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	h := srv.Handler()

	rpcPath := "/admin/api/grpc/pullthrough.security.v1.SecurityQueryService/GetRiskVerdict"

	do := func(token string) int {
		r := httptest.NewRequest(http.MethodPost, rpcPath, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// Unauthenticated → 401, and the handler was never reached.
	if code := do(""); code != http.StatusUnauthorized {
		t.Errorf("anonymous gRPC = %d, want 401", code)
	}
	if grpc.hits != 0 {
		t.Fatalf("handler reached %d times before auth; want 0", grpc.hits)
	}

	// A read-capable viewer reaches the mounted Connect handler.
	if code := do("viewer-token-abcdef0123456789"); code != http.StatusOK {
		t.Errorf("viewer gRPC = %d, want 200", code)
	}
	if grpc.hits != 1 {
		t.Fatalf("handler reached %d times; want 1", grpc.hits)
	}
}
