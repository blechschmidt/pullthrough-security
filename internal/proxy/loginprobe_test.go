package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/swift"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// newSwiftGateway builds a gateway with one Swift registry upstream, "swiftpm",
// in front of upstreamURL. With secured set, access control is on and
// testToken grants the swift ecosystem.
func newSwiftGateway(t *testing.T, upstreamURL string, secured bool) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := swift.New(swift.Options{
		Name:        "swiftpm",
		UpstreamURL: upstreamURL,
		Client:      upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	_ = registry.Register(b)

	deps := Dependencies{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Ecosystems: map[string]string{"swiftpm": "swift"},
	}
	if secured {
		az, err := auth.NewAuthorizer([]auth.Role{{Name: "swift-reader", Ecosystems: []string{"swift"}, Upstreams: []string{"*"}}})
		if err != nil {
			t.Fatalf("authorizer: %v", err)
		}
		ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{{Name: "dev", Team: "team-a", Roles: []string{"swift-reader"}, Secret: testToken}})
		if err != nil {
			t.Fatalf("token auth: %v", err)
		}
		deps.Enforcer, err = auth.NewEnforcer(auth.EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{})})
		if err != nil {
			t.Fatalf("enforcer: %v", err)
		}
	}
	g, err := New(deps, Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return g
}

// `swift package-registry login <registry> --token <token>` POSTs the token to
// the registry URL itself when that URL has a path — a proxy mount always does
// — and stores it only when the answer is 200. The proxy answers that check
// itself, once access control admitted the caller, and never forwards it: the
// upstream would judge the proxy's own credentials. Before, the gateway's
// GET/HEAD-only rule answered 405, and SwiftPM could not be given a token.
func TestSwiftRegistryLoginIsAnsweredByTheProxy(t *testing.T) {
	var upstreamHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		http.Error(w, "the upstream must not see a login", http.StatusTeapot)
	}))
	defer srv.Close()

	post := func(g *Gateway, path, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, req)
		return rr
	}

	secured := newSwiftGateway(t, srv.URL, true)
	for _, tc := range []struct {
		name, path, token string
		want              int
	}{
		{"no credentials", "/v1/swiftpm", "", http.StatusUnauthorized},
		{"a token the proxy does not know", "/v1/swiftpm", "not-a-proxy-token", http.StatusUnauthorized},
		{"the mount, as SwiftPM posts it", "/v1/swiftpm", testToken, http.StatusOK},
		{"the mount with a trailing slash", "/v1/swiftpm/", testToken, http.StatusOK},
		{"SE-0378's /login below the registry", "/v1/swiftpm/login", testToken, http.StatusOK},
		{"any other POST is still refused", "/v1/swiftpm/mona/LinkedList/1.0.0", testToken, http.StatusMethodNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := post(secured, tc.path, tc.token)
			if rr.Code != tc.want {
				t.Fatalf("POST %s: status %d (body %q), want %d", tc.path, rr.Code, rr.Body.String(), tc.want)
			}
			if tc.want == http.StatusOK && rr.Header().Get("Content-Version") != "1" {
				t.Errorf("POST %s: Content-Version %q, want 1", tc.path, rr.Header().Get("Content-Version"))
			}
		})
	}

	// Without access control every caller is admitted, so every login is good.
	open := newSwiftGateway(t, srv.URL, false)
	if rr := post(open, "/v1/swiftpm", "anything"); rr.Code != http.StatusOK {
		t.Fatalf("open proxy: POST /v1/swiftpm: status %d, want 200", rr.Code)
	}
	// A GET of the mount is not a login: it goes to the backend, which has no
	// such resource.
	rr := httptest.NewRecorder()
	open.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/swiftpm/login", nil))
	if rr.Code == http.StatusOK {
		t.Fatalf("GET /v1/swiftpm/login: status 200, want a refusal")
	}

	if n := upstreamHits.Load(); n != 0 {
		t.Fatalf("the upstream received %d request(s); a login check must never be forwarded", n)
	}
}
