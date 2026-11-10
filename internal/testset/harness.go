package testset

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// discardLogger is a no-op logger for the harness gateways; the harness asserts
// on HTTP verdicts, not log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Run validates the corpus and then drives every fixture's representative pulls
// end-to-end through a real in-process gateway fronted by a deterministic stub
// upstream, returning a coverage report. It never touches the network.
//
// If the corpus fails validation the report records the failure and no fixture
// is run (a malformed corpus is itself the regression to surface).
func Run(ctx context.Context) *Report {
	rep := newReport()
	if err := Validate(); err != nil {
		rep.ValidationError = err.Error()
		rep.finalize()
		return rep
	}
	rep.Complete = true
	for _, f := range Corpus() {
		rep.Fixtures = append(rep.Fixtures, runFixture(ctx, f))
	}
	rep.finalize()
	return rep
}

// stubUpstream is a deterministic upstream that serves fixed bytes for any
// request and counts how many times each path was fetched, so the harness can
// prove a cached artifact is served without a repeat upstream fetch.
type stubUpstream struct {
	mu   sync.Mutex
	hits map[string]int
	body []byte
}

func newStubUpstream() *stubUpstream {
	return &stubUpstream{hits: map[string]int{}, body: []byte("pullthrough-testset-artifact-body\n")}
}

func (s *stubUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits[r.URL.Path]++
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(s.body)
}

func (s *stubUpstream) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

// runFixture builds a one-backend gateway for the fixture and exercises each of
// its representative pulls.
func runFixture(ctx context.Context, f Fixture) FixtureResult {
	res := FixtureResult{
		ID:         f.ID,
		Ecosystem:  f.Ecosystem,
		Backend:    f.Backend,
		BuildCmd:   f.BuildCmd,
		Dependency: f.Dep.Coordinate(),
		Files:      append([]string(nil), f.Files...),
		Pass:       true,
	}

	stub := newStubUpstream()
	srv := httptest.NewServer(stub)
	defer srv.Close()

	// Artifact paths are cacheable GETs; everything else is served directly. The
	// upstream path the backend requests is the gateway path minus the mount
	// prefix (the default pass-through router), so key cacheability on that.
	artifactRest := map[string]bool{}
	for _, p := range f.Pulls {
		if p.Kind == KindArtifact {
			artifactRest[strings.TrimPrefix(p.Path, f.mount())] = true
		}
	}
	cacheable := func(r *backends.Request) bool {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return false
		}
		return artifactRest[strings.TrimPrefix(r.Path, "/")]
	}

	gw, cleanup, err := buildGateway(f.Backend, f.Ecosystem, srv.URL, cacheable)
	if err != nil {
		res.Pass = false
		res.Pulls = append(res.Pulls, PullResult{Detail: "gateway setup failed: " + err.Error()})
		return res
	}
	defer cleanup()
	handler := gw.Handler()

	for _, p := range f.Pulls {
		pr := runPull(ctx, handler, stub, f, p)
		if !pr.ok() {
			res.Pass = false
		}
		res.Pulls = append(res.Pulls, pr)
	}
	return res
}

// buildGateway wires an in-process gateway fronting a single generic HTTP
// backend mounted at the fixture's backend name, pointed at the stub upstream.
func buildGateway(backendName, ecosystem, upstreamURL string, cacheable httpbackend.Cacheability) (*proxy.Gateway, func(), error) {
	registry := backends.NewRegistry()
	b, err := httpbackend.New(httpbackend.Options{
		Name:      backendName,
		BaseURL:   upstreamURL,
		Client:    upstream.NewWithHTTPClient(http.DefaultClient, "testset/1"),
		Cacheable: cacheable,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := registry.Register(b); err != nil {
		return nil, nil, err
	}
	deps := proxy.Dependencies{
		Logger:     discardLogger(),
		Cache:      cache.NewMemoryCache(),
		Backends:   registry,
		Ecosystems: map[string]string{backendName: ecosystem},
	}
	gw, err := proxy.New(deps, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		return nil, nil, err
	}
	return gw, func() {}, nil
}

// runPull issues one representative pull and, for cacheable artifact GETs,
// proves the repeat fetch is served from cache (no second upstream hit).
func runPull(ctx context.Context, handler http.Handler, stub *stubUpstream, f Fixture, p Pull) PullResult {
	pr := PullResult{Kind: string(p.Kind), Method: p.method(), Path: p.Path, Desc: p.Desc}

	// Non-GET pulls (git's upload-pack POST negotiation) can't be expressed
	// through the generic Resolve/Fetch backend and aren't cacheable; record them
	// as documented-only rather than driving a misleading request.
	if p.method() != http.MethodGet {
		pr.Detail = "documented (POST negotiation; not driven by the hermetic harness)"
		pr.Documented = true
		return pr
	}

	rest := strings.TrimPrefix(p.Path, f.mount())
	upstreamPath := "/" + strings.SplitN(rest, "?", 2)[0]

	req := httptest.NewRequest(http.MethodGet, p.Path, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	pr.Status = rec.Code
	pr.Served = rec.Code >= 200 && rec.Code < 300
	if !pr.Served {
		pr.Detail = fmt.Sprintf("gateway returned %d", rec.Code)
		return pr
	}

	if p.Kind != KindArtifact {
		pr.Detail = "routed and served"
		return pr
	}

	before := stub.count(upstreamPath)
	req2 := httptest.NewRequest(http.MethodGet, p.Path, nil).WithContext(ctx)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	after := stub.count(upstreamPath)
	if rec2.Code < 200 || rec2.Code >= 300 {
		pr.Served = false
		pr.Detail = fmt.Sprintf("repeat fetch returned %d", rec2.Code)
		return pr
	}
	cached := after == before // no new upstream hit on the repeat fetch
	pr.Cached = &cached
	if cached {
		pr.Detail = "served and cached (repeat fetch did not re-hit upstream)"
	} else {
		pr.Detail = fmt.Sprintf("repeat fetch re-hit upstream (%d→%d)", before, after)
	}
	return pr
}
