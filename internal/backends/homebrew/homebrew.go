// Package homebrew implements a pull-through proxy backend for Homebrew, the
// macOS/Linux package manager, bringing it to parity with the
// pip/npm/cargo/dart/nix backends. Homebrew splits across two upstreams, both of
// which this backend fronts:
//
//   - Formula metadata, from the formulae.brew.sh JSON API. The full index
//     (/api/formula.json) and the per-formula documents (/api/formula/<name>.json)
//     enumerate each formula's "bottle" — a precompiled binary tarball — with its
//     download URL and SHA-256. These documents are mutable and revalidated live.
//
//   - Bottle tarballs, which Homebrew now distributes as OCI blobs in GitHub
//     Packages (ghcr.io). A bottle's download URL is a content-addressed OCI blob
//     reference, https://ghcr.io/v2/<repo>/blobs/sha256:<digest>, fetched via the
//     Docker Registry v2 bearer-token handshake (see auth.go).
//
// Security model: every bottle URL in a served formula document is rewritten to
// the proxy's own synthetic "/bottle/<name>/<version>/v2/.../blobs/sha256:<hex>"
// endpoint (under PublicBaseURL) so the client's download flows back through the
// proxy rather than directly to ghcr. On a request for that endpoint the backend
// reconstructs the exact upstream blob URL from the configured bottle-registry
// base and the verbatim OCI blob path, fetches the blob (following the token
// handshake and any blob-storage redirect), and streams it through a verifying
// reader that recomputes its SHA-256 and refuses to cache or serve any bottle
// whose content does not match the hash named in its URL — verify-on-fetch,
// content-addressable caching, with a *DigestMismatchError on failure. The
// rewrite carries the formula name and version ahead of the blob path so the
// admission gates (nameguard, policy, provenance, risk, and the install-hook /
// content-analysis content gates) see a concrete coordinate.
//
// A Homebrew bottle is addressed by an opaque OCI digest, and OSV.dev defines no
// ecosystem keyed by a Homebrew formula coordinate, so coordinate-based OSV
// scanning is not applicable (see internal/vulnscan/purl.go) — like the conda,
// Bazel, Julia, and Nix backends. A formula's underlying source is covered via
// the provenance/commit-scanning paths instead.
//
// Client configuration points Homebrew at the proxy with
// HOMEBREW_API_DOMAIN="<publicBase>/api" and
// HOMEBREW_ARTIFACT_DOMAIN="<publicBase>" (see docs/clients.md); because bottle
// URLs are rewritten in the served metadata, the latter is not strictly
// required.
package homebrew

import (
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

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They are not persisted to the cache as
// meaningful data.
const (
	metaKind    = "_kind"    // resource-class label, for diagnostics/gates
	metaRewrite = "_rewrite" // "1" when the body is a formula doc to rewrite
	metaBlob    = "_blob"    // verbatim OCI blob path for a bottle
	metaRepo    = "_repo"    // OCI repository (bearer-token scope) for a bottle
	metaDigest  = "_digest"  // expected lowercase-hex SHA-256 for a bottle
	metaName    = "_name"    // formula name for a bottle
	metaVersion = "_version" // formula version for a bottle
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaDigestVerified records "sha256" when a bottle's content was verified
	// against the content address named in its URL.
	MetaDigestVerified = "homebrew.digestVerified"
	// MetaVersion records the formula version a bottle is pinned to.
	MetaVersion = "homebrew.version"
)

// defaultBottleRegistry is the OCI registry Homebrew's core bottles live in.
const defaultBottleRegistry = "https://ghcr.io"

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxFormulaBytes bounds a formula document fetch. The full index
	// (/api/formula.json) is large (tens of MiB) but bounded; the cap stops a
	// hostile upstream returning an unbounded body.
	maxFormulaBytes = 128 << 20 // 128 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Homebrew Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "homebrew").
	// Required.
	Name string
	// UpstreamURL is the formulae API base URL, e.g. "https://formulae.brew.sh".
	// The backend appends "/api/..." protocol paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/homebrew". It is used to
	// rewrite bottle download URLs in served formula metadata so bottle downloads
	// route back through the proxy. When empty, rewritten links fall back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// BottleRegistryURL is the OCI registry base Homebrew bottles are fetched
	// from, e.g. "https://ghcr.io". Only bottle URLs on this registry's host are
	// rewritten through the proxy; others are left pointing at their origin
	// (fail-open). Defaults to https://ghcr.io.
	BottleRegistryURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstreams. Optional; public
	// Homebrew bottles pull anonymously (the bottle registry still issues an
	// anonymous bearer token). A private tap may require a token.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Homebrew pull-through backend implementing backends.Backend.
type Backend struct {
	name         string
	base         *url.URL
	publicBase   string
	bottleBase   *url.URL
	registryHost string
	client       upstream.Doer
	auth         *authenticator
	creds        upstream.Credentials
	metrics      *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("homebrew: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("homebrew %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("homebrew %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("homebrew %q: upstream client is required", opts.Name)
	}

	registryURL := strings.TrimSpace(opts.BottleRegistryURL)
	if registryURL == "" {
		registryURL = defaultBottleRegistry
	}
	bottleBase, err := url.Parse(strings.TrimRight(registryURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: invalid bottle registry URL: %w", opts.Name, err)
	}
	if bottleBase.Scheme != "http" && bottleBase.Scheme != "https" {
		return nil, fmt.Errorf("homebrew %q: bottle registry URL must be http(s), got %q", opts.Name, bottleBase.Scheme)
	}

	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		// Fall back to the root-relative mount; the client resolves a relative
		// bottle URL against the request URL.
		publicBase = "/v1/" + opts.Name
	}

	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}

	return &Backend{
		name:         opts.Name,
		base:         base,
		publicBase:   publicBase,
		bottleBase:   bottleBase,
		registryHost: bottleBase.Host,
		client:       opts.Client,
		auth:         newAuthenticator(opts.Client, opts.Credentials, m.incTokensFetched),
		creds:        opts.Credentials,
		metrics:      m,
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against
// the Homebrew layout, derives the upstream URL and cache key, attaches the
// formula coordinate for the admission gates, and decides cacheability (only a
// bottle blob is cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("homebrew: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Homebrew path", backends.ErrNotSupported, req.Path)
	}

	resolved := &backends.Resolved{
		Cacheable: res.cacheable() && isRead(req),
		CacheKey:  b.cacheKey(res, req.Path),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
	}

	if res.isBottle() {
		// The bottle's upstream URL is reconstructed from the configured registry
		// base and the verbatim OCI blob path carried in the request — never a host
		// taken from untrusted input.
		resolved.UpstreamURL = b.bottleURL(res.blobPath)
		resolved.MediaType = "application/gzip"
		resolved.Coordinate = backends.Coordinate{Name: res.name, Version: res.version}
		resolved.Metadata[metaBlob] = res.blobPath
		resolved.Metadata[metaRepo] = res.repo
		resolved.Metadata[metaDigest] = res.digest
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		resolved.Metadata[MetaVersion] = res.version
		return resolved, nil
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}
	resolved.UpstreamURL = abs.String()
	if res.rewrites() {
		resolved.Metadata[metaRewrite] = "1"
	}
	if res.kind == kindFormula {
		resolved.Coordinate = backends.Coordinate{Name: res.name}
	}
	return resolved, nil
}

// Fetch implements backends.Backend. A bottle is fetched via the ghcr token
// handshake and streamed through a verifying reader so a SHA-256 mismatch aborts
// the cache write and client stream. A formula document is buffered and its
// bottle URLs rewritten through the proxy. Other metadata is proxied byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("homebrew: nil resolved")
	}
	switch resolved.Metadata[metaKind] {
	case "bottle":
		return b.fetchBottle(ctx, resolved)
	default:
		return b.fetchMetadata(ctx, resolved)
	}
}

// fetchBottle fetches a bottle OCI blob through the registry bearer-token
// handshake and streams it through a verifying reader keyed on the SHA-256
// content address named in its URL.
func (b *Backend) fetchBottle(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	scope := "repository:" + resolved.Metadata[metaRepo] + ":pull"
	req := upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
		Header:      http.Header{"Accept": {"application/octet-stream"}},
	}
	resp, err := b.auth.do(ctx, req, scope)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	b.metrics.incBottlesServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}

	expected := resolved.Metadata[metaDigest]
	resolved.Metadata[MetaDigestVerified] = "sha256"
	content := newBottleVerifier(resp.Body, expected,
		resolved.Metadata[metaName], resolved.Metadata[metaVersion], resolved.UpstreamURL,
		func(ok bool) {
			if ok {
				b.metrics.incBottlesVerified()
			} else {
				b.metrics.incBottleHashMismatch()
			}
		})
	header.Set("X-Content-Hash-Verified", "sha256")

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/gzip"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		Digest:    "sha256:" + expected,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchMetadata fetches a formulae.brew.sh document. A formula document (the
// full index or a per-formula document) is buffered so its bottle URLs can be
// rewritten through the proxy; other metadata is proxied byte-exact.
func (b *Backend) fetchMetadata(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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

	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchFormula(resolved, resp, header)
	}

	b.metrics.incMetadataServed()
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchFormula buffers a formula document and rewrites its bottle URLs to the
// proxy's bottle endpoint. A document that does not parse as JSON is served
// unchanged (fail-open), so a non-standard metadata document still reaches the
// client.
func (b *Backend) fetchFormula(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFormulaBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: reading formula document: %w", b.name, err)
	}
	if int64(len(data)) > maxFormulaBytes {
		return nil, fmt.Errorf("homebrew %q: formula document exceeds %d bytes", b.name, maxFormulaBytes)
	}

	rewritten, n := rewriteBottleURLs(data, b.publicBase, b.registryHost)
	if n > 0 {
		b.metrics.incFormulaRewritten()
		data = rewritten
	}
	// A rewrite changes the body length; let the serving layer recompute it.
	header.Del("Content-Length")
	header.Del("ETag")

	b.metrics.incFormulaServed()
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(string(data))),
		Size:      int64(len(data)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// bottleURL reconstructs the upstream OCI blob URL from the configured bottle
// registry base and the verbatim blob path.
func (b *Backend) bottleURL(blobPath string) string {
	out := *b.bottleBase
	basePath := strings.TrimRight(b.bottleBase.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(blobPath, "/")
	out.RawPath = ""
	return out.String()
}

// get performs a GET against the formulae API with the backend's credentials.
func (b *Backend) get(ctx context.Context, rawURL, ifNoneMatch string) (*upstream.Response, error) {
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: ifNoneMatch,
		Header:      http.Header{"Accept": {"application/json"}},
	})
}

// statusError drains the body and returns a StatusError carrying a diagnostic
// snippet.
func (b *Backend) statusError(resp *upstream.Response, url string) error {
	snippet := readSnippet(resp.Body)
	drainClose(resp.Body)
	return &backends.StatusError{Status: resp.Status, URL: url, Body: snippet}
}

// joinPath appends the inbound formulae-API path to the upstream base,
// preserving any base-path prefix.
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key. A bottle embeds its SHA-256 content
// address, so a digest-scoped key is content-addressable across formulae;
// metadata keys on its layout path.
func (b *Backend) cacheKey(res resource, path string) string {
	if res.isBottle() {
		return b.name + ":bottle:sha256:" + res.digest
	}
	return b.name + ":" + strings.TrimLeft(path, "/")
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
