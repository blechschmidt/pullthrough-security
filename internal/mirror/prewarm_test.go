package mirror

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// stubBackend is a minimal Backend: it maps the request path to a cache key and
// serves a fixed body, counting fetches so tests can assert upstream calls.
type stubBackend struct {
	name      string
	body      string
	cacheable bool
	fetches   int64
	failFetch bool
}

func (b *stubBackend) Name() string { return b.name }

func (b *stubBackend) Resolve(_ context.Context, req *backends.Request) (*backends.Resolved, error) {
	return &backends.Resolved{
		UpstreamURL: "https://upstream.example" + req.Path,
		CacheKey:    b.name + ":" + strings.TrimLeft(req.Path, "/"),
		Cacheable:   b.cacheable,
		MediaType:   "application/octet-stream",
		Metadata:    map[string]string{"backend": b.name},
	}, nil
}

func (b *stubBackend) Fetch(_ context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	atomic.AddInt64(&b.fetches, 1)
	if b.failFetch {
		return nil, errors.New("upstream unreachable")
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(b.body)),
		Size:      int64(len(b.body)),
		MediaType: "application/octet-stream",
	}, nil
}

// stubProvider is a BackendProvider over a fixed map.
type stubProvider map[string]backends.Backend

func (p stubProvider) Get(name string) (backends.Backend, bool) {
	b, ok := p[name]
	return b, ok
}

func TestWarmFetchesAndCaches(t *testing.T) {
	npm := &stubBackend{name: "npm", body: "lodash-bytes", cacheable: true}
	provider := stubProvider{"npm": npm}
	c := cache.NewMemoryCache()
	defer c.Close()

	w, err := NewWarmer(provider, c, nil)
	if err != nil {
		t.Fatalf("NewWarmer: %v", err)
	}

	manifest := &PrewarmManifest{Packages: []PrewarmEntry{
		{Upstream: "npm", Path: "/lodash/-/lodash-4.17.21.tgz"},
	}}

	report, err := w.Warm(context.Background(), manifest, WarmOptions{})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if report.Fetched != 1 || report.Cached != 0 || report.Failed != 0 {
		t.Fatalf("first warm report = %+v", report)
	}
	if got := atomic.LoadInt64(&npm.fetches); got != 1 {
		t.Errorf("fetches = %d, want 1", got)
	}

	// The artifact landed under the resolved cache key.
	if _, err := c.Stat(context.Background(), "npm:lodash/-/lodash-4.17.21.tgz"); err != nil {
		t.Errorf("artifact not cached under expected key: %v", err)
	}

	// A second warm finds it already cached and does not refetch.
	report2, err := w.Warm(context.Background(), manifest, WarmOptions{})
	if err != nil {
		t.Fatalf("second Warm: %v", err)
	}
	if report2.Cached != 1 || report2.Fetched != 0 {
		t.Errorf("second warm report = %+v", report2)
	}
	if got := atomic.LoadInt64(&npm.fetches); got != 1 {
		t.Errorf("fetches after second warm = %d, want still 1", got)
	}
}

func TestWarmUnknownUpstream(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close()
	w, _ := NewWarmer(stubProvider{}, c, nil)

	manifest := &PrewarmManifest{Packages: []PrewarmEntry{{Upstream: "ghost", Path: "/x"}}}
	report, err := w.Warm(context.Background(), manifest, WarmOptions{ContinueOnError: true})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if report.Failed != 1 {
		t.Errorf("failed = %d, want 1", report.Failed)
	}
}

func TestWarmNonCacheableReported(t *testing.T) {
	idx := &stubBackend{name: "npm", body: "index", cacheable: false}
	c := cache.NewMemoryCache()
	defer c.Close()
	w, _ := NewWarmer(stubProvider{"npm": idx}, c, nil)

	manifest := &PrewarmManifest{Packages: []PrewarmEntry{{Upstream: "npm", Path: "/lodash"}}}
	report, err := w.Warm(context.Background(), manifest, WarmOptions{ContinueOnError: true})
	if err != nil {
		t.Fatalf("Warm: %v", err)
	}
	if report.Failed != 1 {
		t.Errorf("non-cacheable should be reported as error, report = %+v", report)
	}
	if got := atomic.LoadInt64(&idx.fetches); got != 0 {
		t.Errorf("non-cacheable entry should not be fetched, got %d", got)
	}
}

func TestWarmAbortsOnError(t *testing.T) {
	bad := &stubBackend{name: "npm", cacheable: true, failFetch: true}
	c := cache.NewMemoryCache()
	defer c.Close()
	w, _ := NewWarmer(stubProvider{"npm": bad}, c, nil)

	manifest := &PrewarmManifest{Packages: []PrewarmEntry{{Upstream: "npm", Path: "/x"}}}
	_, err := w.Warm(context.Background(), manifest, WarmOptions{})
	if err == nil {
		t.Fatal("expected error when fetch fails and ContinueOnError is false")
	}
}
