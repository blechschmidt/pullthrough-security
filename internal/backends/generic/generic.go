// Package generic implements a config-driven, declarative pull-through backend
// for ecosystems that have no dedicated adapter (Task 147). Instead of writing a
// Go backend, an operator onboards a new upstream entirely in YAML: a base URL,
// an ordered set of path-classification routes, and per-route decisions about
// cacheability, verify-on-fetch content-address verification, metadata URL
// rewriting, and which content gates apply. New sources can therefore be added
// without code changes.
//
// It is a thin, security-conscious layer over the same primitives the dedicated
// backends use. In particular:
//
//   - The route set is an explicit allowlist. A request whose path matches no
//     route is rejected (backends.ErrNotSupported → 501), so a generic upstream
//     can never become an open relay for arbitrary paths, and the upstream URL is
//     always this backend's own configured base (no client-controlled host).
//   - Cacheable routes flow through the gateway's gated serveCacheable pipeline
//     exactly like every other backend (the backend only sets Cacheable and a
//     stable content-addressable cache key; the gateway owns the gates).
//   - A verified route streams the fetched artifact through a hasher and compares
//     the result to a digest recovered from a sibling checksum file or embedded in
//     the request path, aborting the cache write and the client stream on a
//     mismatch — the verify-on-fetch content-addressable pattern used by the
//     openvsx, nix, and julia backends.
//   - A metadata route can have the absolute upstream-base URLs embedded in its
//     body rewritten to the proxy's public base so dependent downloads route back
//     through the proxy (and its gates), the dart/openvsx pattern.
//
// Unsafe or incoherent declarations (a bad regexp, a verify rule without a
// digest source, rewrite combined with caching, an unknown gate name) are
// rejected at configuration-load time by BackendConfig.Validate, which is shared
// with the configuration preflight so a candidate config is rejected before
// rollout.
package generic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They are underscore-prefixed to mark them
// as internal and are not persisted to the cache as meaningful data.
const (
	metaRoute     = "_route"     // matched route name/ordinal, for diagnostics
	metaVerify    = "_verify"    // "1" when the artifact must be checksum-verified
	metaAlgorithm = "_algorithm" // digest algorithm for a verified route
	metaDigest    = "_digest"    // expected digest when embedded in the path
	metaRewrite   = "_rewrite"   // "1" when the body's upstream URLs must be rewritten
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates, the
// dossier, and the admission pipeline.
const (
	// MetaChecksumVerified records the algorithm (e.g. "sha256") when an artifact
	// was content-verified, "none" when a verified route served an artifact with no
	// recoverable digest (fail-open), or is absent for non-verified routes.
	MetaChecksumVerified = "generic.checksumVerified"
	// MetaRoute records the matched route's name/ordinal.
	MetaRoute = "generic.route"
	// MetaContentGates records the operator-declared content-gate allowlist for the
	// matched route (comma-separated), as audit/telemetry of intended coverage.
	MetaContentGates = "generic.contentGates"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// defaultMaxRewriteBytes bounds a metadata document buffered for URL rewriting
// when the config does not set a positive MaxRewriteBytes.
const defaultMaxRewriteBytes = 32 << 20 // 32 MiB

// maxSidecarBytes bounds a checksum sidecar fetch. A sidecar is a short line; the
// cap is generous slack that still stops a hostile upstream returning megabytes.
const maxSidecarBytes = 8 << 10 // 8 KiB

// Options configures a generic Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "mysource").
	// Required.
	Name string
	// UpstreamURL is the upstream base URL. The backend joins each inbound path
	// onto it. Required.
	UpstreamURL string
	// PublicBaseURL overrides BackendConfig.PublicBaseURL (the cmd wiring passes
	// the proxy's derived public mount here). When both are empty the backend falls
	// back to the root-relative "/v1/<name>" mount for body rewriting.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional.
	Credentials upstream.Credentials
	// Config is the declarative route definition. Required and must validate.
	Config BackendConfig
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// compiledRoute is a route with its Match regexp compiled.
type compiledRoute struct {
	label     string
	match     *regexp.Regexp
	cacheable bool
	rewrite   bool
	verify    *VerifyConfig
	gates     string // pre-joined for metadata
	mediaType string
}

// Backend is a declarative, config-driven pull-through backend implementing
// backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	baseStr    string
	publicBase string
	client     upstream.Doer
	creds      upstream.Credentials
	routes     []compiledRoute
	maxRewrite int64
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend. It returns an error for an
// invalid upstream URL or an unsafe/incoherent declarative config.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("generic: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("generic %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("generic %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("generic %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("generic %q: upstream client is required", opts.Name)
	}
	// Authoritative, load-time validation of the declarative config.
	if err := opts.Config.Validate(opts.Name); err != nil {
		return nil, err
	}

	routes := make([]compiledRoute, 0, len(opts.Config.Routes))
	for i := range opts.Config.Routes {
		rc := &opts.Config.Routes[i]
		// Validate already compiled this successfully; MustCompile is safe but we
		// re-compile with error handling to avoid any panic on an edge case.
		re, cerr := regexp.Compile(rc.Match)
		if cerr != nil {
			return nil, fmt.Errorf("generic %q: compiling route %q: %w", opts.Name, rc.Match, cerr)
		}
		label := rc.Name
		if label == "" {
			label = fmt.Sprintf("route-%d", i)
		}
		routes = append(routes, compiledRoute{
			label:     label,
			match:     re,
			cacheable: rc.Cacheable,
			rewrite:   rc.Rewrite,
			verify:    normalizeVerify(rc.Verify),
			gates:     strings.Join(rc.Gates, ","),
			mediaType: rc.MediaType,
		})
	}

	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		publicBase = strings.TrimRight(strings.TrimSpace(opts.Config.PublicBaseURL), "/")
	}
	if publicBase == "" {
		publicBase = "/v1/" + opts.Name
	}

	maxRewrite := opts.Config.MaxRewriteBytes
	if maxRewrite <= 0 {
		maxRewrite = defaultMaxRewriteBytes
	}

	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}

	return &Backend{
		name:       opts.Name,
		base:       base,
		baseStr:    base.String(),
		publicBase: publicBase,
		client:     opts.Client,
		creds:      opts.Credentials,
		routes:     routes,
		maxRewrite: maxRewrite,
		metrics:    m,
	}, nil
}

// normalizeVerify lowercases the algorithm/source and defaults the source to
// "sidecar", so Resolve/Fetch can switch on canonical values.
func normalizeVerify(v *VerifyConfig) *VerifyConfig {
	if v == nil {
		return nil
	}
	out := *v
	out.Algorithm = strings.ToLower(strings.TrimSpace(v.Algorithm))
	out.Source = strings.ToLower(strings.TrimSpace(v.Source))
	if out.Source == "" {
		out.Source = sourceSidecar
	}
	return &out
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It matches the inbound path against the
// ordered route allowlist, derives the upstream URL and cache key, and records
// the per-route serving decisions. A path matching no route is not served.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("generic: nil request")
	}

	route, submatches, ok := b.match(req.Path)
	if !ok {
		b.metrics.incUnmatched()
		return nil, fmt.Errorf("%w: %q matches no generic route for backend %q", backends.ErrNotSupported, req.Path, b.name)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	cacheable := route.cacheable && isRead(req)
	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   cacheable,
		CacheKey:    b.cacheKey(req.Path, req.Query, cacheable),
		MediaType:   route.mediaType,
		Metadata: map[string]string{
			"backend": b.name,
			metaRoute: route.label,
			MetaRoute: route.label,
		},
	}
	if route.gates != "" {
		resolved.Metadata[MetaContentGates] = route.gates
	}

	if route.rewrite {
		resolved.Metadata[metaRewrite] = "1"
	}

	if route.verify != nil && cacheable {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaAlgorithm] = route.verify.Algorithm
		if route.verify.Source == sourcePath {
			raw := ""
			if route.verify.DigestGroup < len(submatches) {
				raw = submatches[route.verify.DigestGroup]
			}
			digest, dok := normalizeEmbeddedDigest(raw, route.verify.Algorithm)
			if dok {
				resolved.Metadata[metaDigest] = digest
			}
			// A path digest we could not parse is handled in Fetch per fail-open/
			// closed policy (same as a missing sidecar), so no error here.
		}
	}

	return resolved, nil
}

// match returns the first route whose regexp matches path, with its submatches.
func (b *Backend) match(path string) (compiledRoute, []string, bool) {
	for _, r := range b.routes {
		if sm := r.match.FindStringSubmatch(path); sm != nil {
			return r, sm, true
		}
	}
	return compiledRoute{}, nil, false
}

// Fetch implements backends.Backend. A verified route streams the artifact
// through a hasher that aborts on a digest mismatch; a rewrite route buffers a
// (bounded) metadata document and rewrites embedded upstream URLs through the
// proxy; everything else is proxied byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("generic: nil resolved")
	}

	// A verified artifact may need the sibling checksum sidecar fetched first.
	var (
		expected    string
		haveDigest  bool
		verifyRoute = resolved.Metadata[metaVerify] == "1"
		algorithm   = resolved.Metadata[metaAlgorithm]
	)
	if verifyRoute {
		if d, ok := resolved.Metadata[metaDigest]; ok {
			expected, haveDigest = d, true
		} else if route, ok := b.routeByLabel(resolved.Metadata[metaRoute]); ok && route.verify != nil && route.verify.Source == sourceSidecar {
			expected, haveDigest = b.fetchSidecarDigest(ctx, resolved.UpstreamURL, route.verify)
		}
		if !haveDigest && (b.verifyFailsClosed(resolved.Metadata[metaRoute])) {
			b.metrics.incChecksumMissing()
			return nil, fmt.Errorf("generic %q: no %s digest available for verified route %q (%s); refusing to serve unverified artifact (set verify.failOpen to allow)",
				b.name, algorithm, resolved.Metadata[metaRoute], resolved.UpstreamURL)
		}
	}

	resp, err := b.get(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	// Metadata/listing documents: rewrite embedded upstream URLs through the proxy.
	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchRewritten(resolved, resp, header)
	}

	mediaType := b.mediaType(resolved, resp.ContentType)

	if !verifyRoute {
		b.metrics.incMetadataServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incArtifactsServed()

	content := resp.Body
	if haveDigest {
		resolved.Metadata[MetaChecksumVerified] = algorithm
		content = newVerifyingReader(resp.Body, algorithm, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incArtifactsVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", algorithm)
	} else {
		// fail-open: no digest recoverable, and the route tolerates it.
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// routeByLabel finds a compiled route by its label.
func (b *Backend) routeByLabel(label string) (compiledRoute, bool) {
	for _, r := range b.routes {
		if r.label == label {
			return r, true
		}
	}
	return compiledRoute{}, false
}

// verifyFailsClosed reports whether a verified route refuses to serve when no
// digest is recoverable (the default; FailOpen flips it).
func (b *Backend) verifyFailsClosed(label string) bool {
	r, ok := b.routeByLabel(label)
	if !ok || r.verify == nil {
		return false
	}
	return !r.verify.FailOpen
}

// fetchSidecarDigest fetches the checksum sidecar for a verified artifact and
// returns the digest it declares. A missing, unreadable, or malformed sidecar
// yields ok=false (handled by the route's fail-open/closed policy).
func (b *Backend) fetchSidecarDigest(ctx context.Context, artifactURL string, v *VerifyConfig) (string, bool) {
	scURL, ok := sidecarURL(artifactURL, v)
	if !ok {
		return "", false
	}
	resp, err := b.get(ctx, scURL, "")
	if err != nil {
		return "", false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return "", false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxSidecarBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxSidecarBytes {
		return "", false
	}
	digest, parsed := parseChecksumSidecar(body, v.Algorithm)
	if !parsed {
		return "", false
	}
	b.metrics.incSidecarsFetched()
	return digest, true
}

// fetchRewritten buffers a (bounded) metadata document and rewrites every
// absolute upstream-origin URL it embeds to the proxy's public base, so a
// client's dependent download routes back through the proxy. Only the configured
// upstream base is rewritten, so external links are left intact. A document
// exceeding the configured cap is streamed through unmodified.
func (b *Backend) fetchRewritten(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, b.maxRewrite+1))
	if err != nil {
		drainClose(resp.Body)
		return nil, fmt.Errorf("generic %q: reading metadata document: %w", b.name, err)
	}
	if int64(len(data)) > b.maxRewrite {
		// Too large to rewrite safely; stream the prefix plus the remainder through
		// unmodified. Dependent links then point at the upstream directly.
		b.metrics.incMetadataServed()
		combined := io.MultiReader(strings.NewReader(string(data)), resp.Body)
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   bodyReadCloser{Reader: combined, Closer: resp.Body},
			Size:      -1,
			MediaType: b.mediaType(resolved, resp.ContentType),
			Header:    header,
			Status:    resp.Status,
		}, nil
	}
	drainClose(resp.Body)

	body := string(data)
	if b.baseStr != "" && strings.Contains(body, b.baseStr) {
		body = strings.ReplaceAll(body, b.baseStr, b.publicBase)
		b.metrics.incMetadataRewrite()
	}
	b.metrics.incMetadataServed()

	// Content-Length changed by the rewrite; drop any upstream value.
	header.Del("Content-Length")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(body)),
		Size:      int64(len(body)),
		MediaType: b.mediaType(resolved, resp.ContentType),
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// mediaType selects the response content type: a route override wins, else the
// upstream content type, else a generic octet-stream.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	if resolved.MediaType != "" {
		return resolved.MediaType
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
}

// get performs a GET against the upstream with the backend's credentials.
func (b *Backend) get(ctx context.Context, rawURL, ifNoneMatch string) (*upstream.Response, error) {
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: ifNoneMatch,
	})
}

// statusError drains the body and returns a StatusError carrying a snippet.
func (b *Backend) statusError(resp *upstream.Response, rawURL string) error {
	snippet := readSnippet(resp.Body)
	drainClose(resp.Body)
	return &backends.StatusError{Status: resp.Status, URL: rawURL, Body: snippet}
}

// joinPath appends the inbound path to the upstream base, preserving any
// base-path prefix (e.g. an upstream served under a sub-path).
func (b *Backend) joinPath(p string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(p, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key. Cacheable (typically immutable) resources
// key on path alone; non-cacheable resources include the query so short-lived
// entries do not collide.
func (b *Backend) cacheKey(p string, query url.Values, cacheable bool) string {
	key := b.name + ":" + strings.TrimLeft(p, "/")
	if !cacheable {
		if enc := query.Encode(); enc != "" {
			key += "?" + enc
		}
	}
	return key
}

// bodyReadCloser pairs a Reader with an independent Closer so a buffered prefix
// can be concatenated with the unread remainder of an upstream body while still
// closing the underlying connection.
type bodyReadCloser struct {
	io.Reader
	io.Closer
}

func isRead(req *backends.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == ""
}

func readSnippet(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxErrorBodySnippet))
	return strings.TrimSpace(string(buf))
}

// drainClose drains a small amount of the body (to allow connection reuse) and
// closes it. Safe to call with a nil body.
func drainClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096))
	_ = body.Close()
}
