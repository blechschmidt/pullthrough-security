// Package httpbackend implements a generic HTTP pull-through Backend. It is the
// shared substrate that every HTTP-based package ecosystem reuses: it maps an
// inbound request path onto an upstream base URL, performs the conditional
// upstream fetch (injecting configured credentials), and reports the result in
// the protocol-agnostic terms of the backends package.
//
// Ecosystem-specific backends (pip, npm, cargo, Go modules, NuGet, Docker/OCI;
// Tasks 4–6) build on this by supplying a path-rewriting Router and a
// Cacheability policy, or by embedding a *Backend and overriding Resolve.
package httpbackend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics, so a hostile or chatty upstream cannot make us buffer megabytes.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// maxIndexDocBytes bounds how much of an index document (npm packument, PyPI
// Simple page, cargo config, NuGet service index/registration) the backend will
// buffer to perform URL rewriting. Documents larger than this are streamed
// through unmodified rather than buffered into memory; their dependent artifact
// links then point directly at the upstream instead of back through the proxy.
const maxIndexDocBytes = 32 << 20 // 32 MiB

// Internal metadata keys used to carry per-request decisions from Resolve into
// Fetch (which only receives the *Resolved). They are prefixed with an
// underscore to distinguish them from caller-meaningful metadata; index
// documents are non-cacheable, so these are never persisted to the cache.
const (
	metaIndex  = "_index"
	metaAccept = "_accept"
)

// Router maps an inbound request to the upstream path (and optional query) that
// should be fetched, relative to the backend's base URL. Returning a leading
// slash is optional; it is normalized. The default router forwards the request
// path and query unchanged.
type Router func(req *backends.Request) (upstreamPath string, upstreamQuery url.Values)

// AbsoluteRouter, when set, may map a request directly to an absolute upstream
// URL, bypassing BaseURL joining. Returning ok=false falls back to the Router +
// BaseURL path. It lets one ecosystem route span multiple upstream hosts — e.g.
// PyPI's separate file CDN (files.pythonhosted.org) or cargo's download host
// (crates.io) — that cannot be expressed as a single base URL.
//
// SECURITY: the returned URL is fetched verbatim. The ecosystem MUST validate
// the host against an allowlist before returning ok=true, or the proxy becomes
// an open relay (SSRF). httpbackend only enforces that the scheme is http(s).
type AbsoluteRouter func(req *backends.Request) (absoluteURL string, ok bool)

// Cacheability decides whether a resolved request may be cached. The default
// policy caches idempotent reads (GET/HEAD) and treats everything else as
// non-cacheable. Ecosystem backends override this to, e.g., cache immutable
// artifacts forever while revalidating mutable index documents.
type Cacheability func(req *backends.Request) bool

// IndexPredicate reports whether a request targets a rewritable index document
// (a package listing/metadata document whose embedded artifact URLs must be
// rewritten to point back through the proxy) as opposed to an immutable
// artifact. Only documents for which it returns true are buffered and passed
// through the Rewriter, so artifacts of arbitrary size are never buffered.
type IndexPredicate func(req *backends.Request) bool

// Coordinator extracts the logical package coordinate (name and version) of a
// resolved artifact request from its path. It is consulted during Resolve so the
// admission-policy layer (Task 9) can identify the artifact being served
// (allowlists/denylists, provenance lookup). It returns ok=false for requests
// that do not address a concrete, versioned artifact (e.g. index documents), in
// which case no coordinate is attached.
type Coordinator func(req *backends.Request) (coord backends.Coordinate, ok bool)

// Rewriter transforms an index document body before it is served. It receives
// the raw upstream bytes and the upstream media type and returns the
// (possibly) transformed bytes. It is invoked only for resources an
// IndexPredicate classified as index documents. Rewriting must be deterministic
// for a given input so that conditional revalidation (If-None-Match) against
// the upstream's validator remains correct.
type Rewriter func(body []byte, mediaType string) ([]byte, error)

// Options configures a Backend.
type Options struct {
	// Name is the route identifier (e.g. "npm"). Required.
	Name string
	// BaseURL is the upstream base URL (e.g. "https://registry.npmjs.org").
	// Required.
	BaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional.
	Credentials upstream.Credentials
	// Router rewrites inbound paths to upstream paths. Optional; defaults to a
	// pass-through router.
	Router Router
	// AbsoluteRouter optionally maps a request to an absolute upstream URL,
	// bypassing BaseURL. Consulted before Router. Optional.
	AbsoluteRouter AbsoluteRouter
	// Cacheable decides cacheability. Optional; defaults to caching GET/HEAD.
	Cacheable Cacheability
	// Coordinator extracts the package coordinate of an artifact request, for the
	// admission-policy layer. Optional; when nil resolved artifacts carry no
	// coordinate.
	Coordinator Coordinator
	// Index classifies a request as a rewritable index document. Optional; when
	// nil no request is treated as an index document and Rewrite is never called.
	Index IndexPredicate
	// Rewrite transforms index-document bodies. Optional; required for Index to
	// have any effect.
	Rewrite Rewriter
	// ForwardAccept forwards the client's Accept header to the upstream for index
	// requests. Ecosystems with content-negotiated index formats (PyPI Simple's
	// HTML/JSON, NuGet) set this so the upstream returns the representation the
	// client asked for. Artifact requests never forward it.
	ForwardAccept bool
}

// Backend is a generic HTTP pull-through backend implementing backends.Backend.
type Backend struct {
	name          string
	base          *url.URL
	client        upstream.Doer
	creds         upstream.Credentials
	router        Router
	absRouter     AbsoluteRouter
	cacheable     Cacheability
	coordinator   Coordinator
	index         IndexPredicate
	rewrite       Rewriter
	forwardAccept bool
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("httpbackend: name is required")
	}
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, fmt.Errorf("httpbackend %q: base URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("httpbackend %q: invalid base URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("httpbackend %q: base URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("httpbackend %q: upstream client is required", opts.Name)
	}

	router := opts.Router
	if router == nil {
		router = passthroughRouter
	}
	cacheable := opts.Cacheable
	if cacheable == nil {
		cacheable = cacheReads
	}

	return &Backend{
		name:          opts.Name,
		base:          base,
		client:        opts.Client,
		creds:         opts.Credentials,
		router:        router,
		absRouter:     opts.AbsoluteRouter,
		cacheable:     cacheable,
		coordinator:   opts.Coordinator,
		index:         opts.Index,
		rewrite:       opts.Rewrite,
		forwardAccept: opts.ForwardAccept,
	}, nil
}

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It maps the inbound request onto an
// absolute upstream URL and derives a stable cache key.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("httpbackend: nil request")
	}

	var (
		abs     *url.URL
		query   url.Values
		keyPath string // path used for the cache key (host-qualified for abs routes)
	)

	if b.absRouter != nil {
		if absoluteURL, ok := b.absRouter(req); ok {
			u, err := url.Parse(absoluteURL)
			if err != nil {
				return nil, fmt.Errorf("httpbackend %q: invalid absolute upstream URL: %w", b.name, err)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return nil, fmt.Errorf("httpbackend %q: absolute upstream URL must be http(s), got %q", b.name, u.Scheme)
			}
			abs = u
			query = u.Query()
			// Qualify the key with the host so artifacts from distinct upstream
			// hosts (e.g. multiple PyPI file CDNs) never collide.
			keyPath = u.Host + u.EscapedPath()
		}
	}

	if abs == nil {
		upstreamPath, upstreamQuery := b.router(req)
		rel := "/" + strings.TrimLeft(upstreamPath, "/")

		// Join onto the base URL, preserving any base path prefix (e.g. a registry
		// served under "/repository/maven").
		abs = b.joinBase(rel)
		if upstreamQuery == nil {
			upstreamQuery = req.Query
		}
		if enc := upstreamQuery.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		query = upstreamQuery
		keyPath = rel
	}

	cacheable := b.cacheable(req)
	cacheKey := b.cacheKey(keyPath, query, cacheable)

	metadata := map[string]string{
		"backend": b.name,
	}
	if b.index != nil && b.index(req) {
		metadata[metaIndex] = "1"
		if b.forwardAccept && req.Header != nil {
			// Fold every Accept header line into one list: a client may split its
			// content negotiation across several lines (RFC 9110 §5.3), and
			// Header.Get would forward only the first of them.
			if accept := strings.Join(req.Header.Values("Accept"), ", "); accept != "" {
				metadata[metaAccept] = accept
			}
		}
	}

	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		CacheKey:    cacheKey,
		Cacheable:   cacheable,
		Metadata:    metadata,
	}
	if b.coordinator != nil {
		if coord, ok := b.coordinator(req); ok {
			resolved.Coordinate = coord
		}
	}
	return resolved, nil
}

// Fetch implements backends.Backend. It performs the upstream HTTP request,
// honoring a conditional revalidation request and translating the response into
// a FetchResult (or a *backends.StatusError for non-success statuses).
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("httpbackend: nil resolved")
	}

	var reqHeader http.Header
	if accept := resolved.Metadata[metaAccept]; accept != "" {
		reqHeader = http.Header{"Accept": {accept}}
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Header:      reqHeader,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
	})
	if err != nil {
		return nil, err
	}

	if resp.NotModified {
		return &backends.FetchResult{
			Resolved:    resolved,
			Status:      http.StatusNotModified,
			NotModified: true,
		}, nil
	}

	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		_ = resp.Body.Close()
		return nil, &backends.StatusError{
			Status: resp.Status,
			URL:    resolved.UpstreamURL,
			Body:   snippet,
		}
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	// PropagateResponseHeaders deliberately drops the validator headers (they are
	// "proxy-owned"), but the proxy core promotes the upstream validator into the
	// cache entry's metadata and serves it back for conditional requests. Re-attach
	// them explicitly so that flow has the upstream's strong validators to work
	// with rather than only a synthesized one.
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	if resolved.Metadata[metaIndex] == "1" && b.rewrite != nil {
		return b.fetchIndexDocument(resolved, resp, header)
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Digest:    resolved.Digest,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchIndexDocument buffers a (bounded) index document, rewrites its embedded
// URLs to route dependent artifacts back through the proxy, and returns the
// transformed bytes. Documents exceeding maxIndexDocBytes are streamed through
// unmodified rather than buffered. The caller has already verified
// b.rewrite != nil.
func (b *Backend) fetchIndexDocument(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexDocBytes+1))
	if err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("httpbackend %q: reading index document: %w", b.name, err)
	}
	if int64(len(buf)) > maxIndexDocBytes {
		// Too large to rewrite safely; stream the already-read prefix plus the
		// remainder through unmodified. Content-Length is unknown at this point.
		combined := io.MultiReader(bytes.NewReader(buf), resp.Body)
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   bodyReadCloser{Reader: combined, Closer: resp.Body},
			Size:      -1,
			MediaType: resp.ContentType,
			Digest:    resolved.Digest,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}
	_ = resp.Body.Close()

	out, err := b.rewrite(buf, resp.ContentType)
	if err != nil {
		return nil, fmt.Errorf("httpbackend %q: rewriting index document: %w", b.name, err)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(out)),
		Size:      int64(len(out)),
		MediaType: resp.ContentType,
		Digest:    resolved.Digest,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// bodyReadCloser pairs a Reader with an independent Closer so a buffered prefix
// can be concatenated with the unread remainder of an upstream body while still
// closing the underlying connection.
type bodyReadCloser struct {
	io.Reader
	io.Closer
}

// joinBase appends rel (an absolute path) to the base URL's path, preserving any
// base path prefix (e.g. a registry served under "/repository/maven").
func (b *Backend) joinBase(rel string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	// rel is already escaped by the caller only when it came from req.Path; treat
	// it as an opaque path segment string and let url.URL handle encoding on
	// String() via the Path/RawPath fields.
	combined := basePath + rel
	out.Path = combined
	out.RawPath = "" // let net/url re-derive the encoded form from Path
	return &out
}

// cacheKey derives a stable cache key. Cacheable (typically immutable) resources
// key on path alone so the same artifact shares one entry regardless of
// incidental query parameters; non-cacheable resources include the query so the
// (rare, short-lived) entries do not collide.
func (b *Backend) cacheKey(path string, query url.Values, cacheable bool) string {
	key := b.name + ":" + strings.TrimLeft(path, "/")
	if !cacheable {
		if enc := query.Encode(); enc != "" {
			key += "?" + enc
		}
	}
	return key
}

// passthroughRouter forwards the inbound path and query unchanged.
func passthroughRouter(req *backends.Request) (string, url.Values) {
	return req.Path, req.Query
}

// cacheReads caches idempotent reads and nothing else.
func cacheReads(req *backends.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == ""
}

func readSnippet(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxErrorBodySnippet))
	return strings.TrimSpace(string(buf))
}
