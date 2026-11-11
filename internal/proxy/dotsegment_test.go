package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// A "." or ".." path segment must never reach a backend, whatever spelling it
// arrives in. The mux canonicalizes the plain spelling with a redirect; it
// matches on the escaped path, so "%2e%2e" comes through to the handler, where
// r.URL.Path already reads "..". A backend that forwarded it would have the
// upstream answer for a different path than the one that was parsed, classified
// and gated — with the proxy's credentials on the request.
func TestHandleBackendRefusesDotSegments(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.EscapedPath())
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "files",
		BaseURL: srv.URL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	g, err := New(Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: registry,
	}, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	serve := func(target string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
		return rr
	}
	upstreamRequests := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}

	for _, target := range []string{
		"/v1/files/a/%2e%2e/secret",
		"/v1/files/a/%2E%2E/secret",
		"/v1/files/a/.%2e/secret",
		"/v1/files/%2e%2e/admin",
		"/v1/files/a/%2e/b",
		"/v1/files/a/b/%2e%2e",
		// Behind a path parameter (stripped by servlet containers) ...
		"/v1/files/a/%2e%2e;x=1/secret",
		"/v1/files/a/%2e%2e%3bx/secret",
		// ... a backslash (a separator to IIS) ...
		"/v1/files/a/%2e%2e%5csecret",
		// ... an encoded slash ...
		"/v1/files/a/%2e%2e%2fsecret",
		// ... or a second layer of encoding, for the hop that decodes once more.
		"/v1/files/a/%252e%252e/secret",
		"/v1/files/a/%252e%252e%252fsecret",
	} {
		rr := serve(target)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400", target, rr.Code)
		}
	}
	if got := upstreamRequests(); len(got) != 0 {
		t.Fatalf("requests with dot segments reached the upstream: %q", got)
	}

	// The plain spelling never reaches the handler: the mux redirects it to the
	// canonical path, which is then an ordinary request.
	// (The status is 301 or 307 depending on the Go release.)
	if rr := serve("/v1/files/a/../b"); rr.Code/100 != 3 || rr.Header().Get("Location") != "/v1/files/b" {
		t.Errorf("GET /v1/files/a/../b = %d Location %q, want a redirect to /v1/files/b", rr.Code, rr.Header().Get("Location"))
	}

	// Names that merely contain dots are untouched.
	for _, target := range []string{
		"/v1/files/a/b.tar.gz",
		"/v1/files/.well-known/terraform.json",
		"/v1/files/a/.../b",
		"/v1/files/a/..b/c",
		"/v1/files/pool/gcc_12.2.0-14%2Bdeb12u1_amd64.deb",
	} {
		if rr := serve(target); rr.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", target, rr.Code)
		}
	}
	if got := upstreamRequests(); len(got) != 5 {
		t.Errorf("upstream saw %d requests %q, want the 5 well-formed ones", len(got), got)
	}
}
