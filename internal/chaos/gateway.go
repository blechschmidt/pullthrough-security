package chaos

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// discardLogger is a no-op logger; the harness asserts on HTTP verdicts, not
// log output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// GatewayOptions configures an in-process gateway fronting a single "npm"
// backend, for the end-to-end upstream/storage fault scenarios.
type GatewayOptions struct {
	// BaseURL is the upstream base URL the backend proxies (e.g. a
	// FaultyUpstream.URL()). Required.
	BaseURL string
	// Cache is the cache the gateway fills through. Defaults to a fresh in-memory
	// cache; pass a *FaultyCache to inject storage faults.
	Cache cache.Cache
	// Coalescer, when set, wires the pull-path request coalescer + negative cache.
	Coalescer *coalesce.Coalescer[*cache.Entry]
	// Digest, when non-empty, is injected into every resolved artifact so the
	// gateway's fill-time content-digest verifier runs (integrity scenarios).
	Digest string
}

// BuildGateway constructs an in-process proxy.Gateway per opts and returns its
// HTTP handler. All reads under "/v1/npm/..." resolve to the configured
// upstream and cache.
func BuildGateway(opts GatewayOptions) (http.Handler, error) {
	registry := backends.NewRegistry()
	base, err := httpbackend.New(httpbackend.Options{
		Name:    "npm",
		BaseURL: opts.BaseURL,
		Client:  upstream.NewWithHTTPClient(http.DefaultClient, "chaos/1"),
	})
	if err != nil {
		return nil, err
	}
	var backend backends.Backend = base
	if opts.Digest != "" {
		backend = digestInjector{Backend: base, digest: opts.Digest}
	}
	if err := registry.Register(backend); err != nil {
		return nil, err
	}

	c := opts.Cache
	if c == nil {
		c = cache.NewMemoryCache()
	}
	g, err := proxy.New(proxy.Dependencies{
		Logger:    discardLogger(),
		Cache:     c,
		Backends:  registry,
		Coalescer: opts.Coalescer,
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		return nil, err
	}
	return g.Handler(), nil
}

// digestInjector decorates a backend so every resolved artifact carries a fixed
// expected content digest, exercising the gateway's fill-time digest verifier
// without depending on an ecosystem that resolves digests natively.
type digestInjector struct {
	backends.Backend
	digest string
}

func (d digestInjector) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	resolved, err := d.Backend.Resolve(ctx, req)
	if err != nil {
		return nil, err
	}
	resolved.Digest = d.digest
	return resolved, nil
}

// NPMPullPath is the canonical gateway path for an npm tarball pull.
func NPMPullPath(artifact string) string { return "/v1/npm/" + artifact }
