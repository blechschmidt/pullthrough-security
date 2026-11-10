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

// recordingMetrics is a test MetricsRecorder capturing the calls the gateway
// makes, so we can assert request/upstream/bytes telemetry is emitted.
type recordingMetrics struct {
	mu        sync.Mutex
	requests  []string // "backend method code"
	upstreams int
	upOK      int
	bytes     int64
	policies  []string // "ecosystem action"
}

func (m *recordingMetrics) IncRequest(backend, method, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, backend+" "+method+" "+code)
}
func (m *recordingMetrics) ObserveUpstreamLatency(_ string, _ float64, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreams++
	if ok {
		m.upOK++
	}
}
func (m *recordingMetrics) AddBytesServed(_ string, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes += n
}
func (m *recordingMetrics) IncPolicyDecision(ecosystem, action string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = append(m.policies, ecosystem+" "+action)
}

// newGatewayWithDeps builds a gateway around a single "npm" backend with extra
// dependencies/options merged in, so observability wiring can be exercised.
func newGatewayWithDeps(t *testing.T, baseURL string, deps Dependencies, opts Options) *Gateway {
	t.Helper()
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: baseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "test/1"),
	})
	if err != nil {
		t.Fatalf("httpbackend.New: %v", err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatalf("Register: %v", err)
	}
	deps.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	deps.Cache = cache.NewMemoryCache()
	deps.Backends = registry
	opts.HTTPAddr = ":0"
	g, err := New(deps, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestMetricsEndpointMounted(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "# HELP up\n")
	})
	g := newGatewayWithDeps(t, "https://registry.npmjs.org",
		Dependencies{MetricsHandler: handler}, Options{MetricsPath: "/metrics"})

	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusOK || rr.Body.String() != "# HELP up\n" {
		t.Errorf("metrics endpoint = %d %q", rr.Code, rr.Body.String())
	}
}

func TestMetricsEndpointAbsentWhenDisabled(t *testing.T) {
	g := newGateway(t, "https://registry.npmjs.org", upstream.Credentials{})
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("metrics status with no handler = %d, want 404", rr.Code)
	}
}

func TestAdminSurfaceMounted(t *testing.T) {
	admin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "admin:"+r.URL.Path)
	})
	g := newGatewayWithDeps(t, "https://registry.npmjs.org",
		Dependencies{AdminHandler: admin}, Options{AdminPrefix: "/admin"})

	for _, path := range []string{"/admin", "/admin/", "/admin/api/overview"} {
		rr := httptest.NewRecorder()
		g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusOK || rr.Body.String() != "admin:"+path {
			t.Errorf("admin path %q = %d %q", path, rr.Code, rr.Body.String())
		}
	}
}

func TestRequestAndUpstreamMetricsRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ARTIFACT")
	}))
	defer srv.Close()

	rec := &recordingMetrics{}
	g := newGatewayWithDeps(t, srv.URL, Dependencies{Metrics: rec}, Options{})

	// Cache miss: triggers one upstream fetch and serves 8 bytes.
	rr := httptest.NewRecorder()
	g.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	// Cache hit: no upstream fetch, serves the bytes from cache.
	g.routes().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/npm/pkg-1.0.0.tgz", nil))

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.requests) != 2 {
		t.Errorf("requests recorded = %v, want 2", rec.requests)
	}
	if rec.requests[0] != "npm GET 200" {
		t.Errorf("first request label = %q", rec.requests[0])
	}
	if rec.upstreams != 1 || rec.upOK != 1 {
		t.Errorf("upstream observations = %d (ok %d), want 1 successful (cache absorbs the 2nd read)", rec.upstreams, rec.upOK)
	}
	if rec.bytes != int64(len("ARTIFACT")*2) {
		t.Errorf("bytes served = %d, want %d", rec.bytes, len("ARTIFACT")*2)
	}
}
