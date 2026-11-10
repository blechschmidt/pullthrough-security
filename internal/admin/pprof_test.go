package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
)

func TestProfilingDisabledByDefault(t *testing.T) {
	srv, err := New(Options{Cache: &fakeCache{}})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	h := srv.Handler()
	r := httptest.NewRequest(http.MethodGet, "/admin/api/debug/pprof/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	// With profiling off, the path is not registered; the API catch-all does not
	// exist either, so it must not return a pprof index (200 with the pprof body).
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Types of profiles") {
		t.Fatalf("pprof index served while profiling disabled")
	}
}

func TestProfilingTokenGuarded(t *testing.T) {
	srv, err := New(Options{
		Cache:     &fakeCache{},
		Token:     "s3cret-token",
		Profiling: ProfilingOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	h := srv.Handler()

	// No token → 401 (the profiling path is under /api/ so the token guard applies).
	r := httptest.NewRequest(http.MethodGet, "/admin/api/debug/pprof/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated pprof index = %d, want 401", w.Code)
	}

	// With the token → the pprof index renders.
	r = httptest.NewRequest(http.MethodGet, "/admin/api/debug/pprof/", nil)
	r.Header.Set("Authorization", "Bearer s3cret-token")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated pprof index = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "pprof") {
		t.Fatalf("pprof index body did not contain expected content: %q", w.Body.String())
	}
}

func TestProfilingNamedProfileServed(t *testing.T) {
	srv, err := New(Options{
		Cache:     &fakeCache{},
		Token:     "s3cret-token",
		Profiling: ProfilingOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	h := srv.Handler()

	// The heap profile is a named runtime profile served by the index handler via
	// the stripped prefix; debug=1 yields a text rendering.
	r := httptest.NewRequest(http.MethodGet, "/admin/api/debug/pprof/heap?debug=1", nil)
	r.Header.Set("Authorization", "Bearer s3cret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("heap profile = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "heap profile") {
		t.Fatalf("heap profile body unexpected: %q", w.Body.String()[:min(200, len(w.Body.String()))])
	}
}

func TestProfilingRBAC(t *testing.T) {
	svc, err := adminauth.New(adminauth.Options{
		Prefix: "/admin",
		StaticTokens: []adminauth.StaticToken{
			{Name: "v", Roles: []string{"viewer"}, Secret: "viewer-token-abcdef0123456789"},
			{Name: "o", Roles: []string{"operator"}, Secret: "operator-token-abcdef0123456789"},
		},
	})
	if err != nil {
		t.Fatalf("adminauth.New: %v", err)
	}
	srv, err := New(Options{
		Cache:     &fakeCache{},
		AdminAuth: svc,
		Profiling: ProfilingOptions{Enabled: true},
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	h := srv.Handler()

	do := func(token string) int {
		r := httptest.NewRequest(http.MethodGet, "/admin/api/debug/pprof/", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// A viewer has only CapRead; profiling requires CapOperate → 403.
	if code := do("viewer-token-abcdef0123456789"); code != http.StatusForbidden {
		t.Errorf("viewer pprof = %d, want 403", code)
	}
	// An operator holds CapOperate → 200.
	if code := do("operator-token-abcdef0123456789"); code != http.StatusOK {
		t.Errorf("operator pprof = %d, want 200", code)
	}
	// Anonymous → 401.
	if code := do(""); code != http.StatusUnauthorized {
		t.Errorf("anonymous pprof = %d, want 401", code)
	}
}

func TestRequiredCapabilityProfiling(t *testing.T) {
	if got := requiredCapability(http.MethodGet, "/api/debug/pprof/"); got != adminauth.CapOperate {
		t.Errorf("pprof index capability = %v, want operate", got)
	}
	if got := requiredCapability(http.MethodGet, "/api/debug/pprof/profile"); got != adminauth.CapOperate {
		t.Errorf("pprof profile capability = %v, want operate", got)
	}
	if got := requiredCapability(http.MethodGet, "/api/debug/pprof/trace"); got != adminauth.CapOperate {
		t.Errorf("pprof trace capability = %v, want operate", got)
	}
}
