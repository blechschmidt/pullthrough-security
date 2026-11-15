package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// A sign-in callback registered at the identity provider under a path of its
// own is served at the gateway's root, for GET only, next to the admin surface.
func TestSignInCallbackMounted(t *testing.T) {
	cb := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "callback:"+r.URL.RawQuery)
	})
	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "admin:"+r.URL.Path)
	})
	g := newGatewayWithDeps(t, "https://registry.npmjs.org",
		Dependencies{AdminHandler: admin, SignInCallbacks: map[string]http.Handler{"/auth/oidc": cb}},
		Options{AdminPrefix: "/admin"})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/oidc?code=c&state=s", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "callback:code=c&state=s" {
		t.Fatalf("GET /auth/oidc = %d %q", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/oidc", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /auth/oidc = %d", rr.Code)
	}
	for _, path := range []string{"/auth/oidc/x", "/auth"} {
		rr = httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/auth/callback", nil))
	if rr.Body.String() != "admin:/admin/auth/callback" {
		t.Fatalf("the admin surface's own callback = %q", rr.Body.String())
	}
}

// A callback path Go's router would panic on is refused by New with an error:
// the proxy does not get as far as building its routes.
func TestSignInCallbackPathRefused(t *testing.T) {
	h := http.NotFoundHandler()
	for _, path := range []string{"//auth/oidc", "/auth/./oidc", "/x/../oidc", "/auth/%6Fidc", "/auth/{x}"} {
		_, err := New(Dependencies{
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Cache: cache.NewMemoryCache(), Backends: backends.NewRegistry(),
			SignInCallbacks: map[string]http.Handler{path: h},
		}, Options{HTTPAddr: ":0"})
		if err == nil || !strings.Contains(err.Error(), "sign-in callback") {
			t.Errorf("New with callback path %q: err = %v", path, err)
		}
	}
}
