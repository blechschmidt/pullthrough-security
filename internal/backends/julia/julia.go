// Package julia implements a pull-through proxy backend for the Julia package
// ecosystem's Pkg Server Protocol (the public default is pkg.julialang.org,
// fronting the General registry), bringing Julia to parity with the
// pip/npm/cargo/go/maven/conan/hex/bazel backends.
//
// The Pkg Server Protocol (https://pkgdocs.julialang.org/dev/protocol/) is a
// small, fully content-addressed HTTP tree. Every resource other than the
// mutable /registries listing is addressed by its git-tree-sha1 — the SHA-1 Git
// tree object hash of the (decompressed) tarball's contents — which means the
// request path is itself the integrity record. On a cache miss the backend
// recomputes that tree hash over the fetched, gzip-compressed tarball and
// refuses to cache or serve bytes that do not match the hash named in the URL,
// so a tampered or corrupt upstream can neither poison the cache nor reach a
// client. Verification is streaming (the archive is tee'd through a Git
// tree-hasher while it is written to the cache; only per-file tree metadata is
// held in memory, never the archive body), so a mismatch aborts the cache write
// and the client stream at end-of-stream.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /registries                  map of registry uuids -> current tree hash (mutable, live)
//	GET /registry/<uuid>/<hash>       a registry's tarball at <hash>             (immutable, verified)
//	GET /package/<uuid>/<hash>        a package's source tarball at <hash>       (immutable, verified)
//	GET /artifact/<hash>              an artifact tarball at <hash>              (immutable, verified)
//
// The Pkg Server Protocol addresses packages by UUID and git-tree-sha1, never
// by human name or semantic version, so no name/semver coordinate is available
// at the pull layer. The UUID and tree hash are attached as the coordinate for
// nameguard, provenance, policy, and risk; coordinate-based OSV scanning is not
// applicable (see internal/vulnscan/purl.go) because OSV.dev's Julia ecosystem
// is keyed by package name, which the protocol does not expose — the underlying
// source commit is covered via the provenance/commit-scanning paths instead.
//
// Client configuration points the Julia client at the proxied server by setting
// JULIA_PKG_SERVER to "<publicBase>/v1/<name>" (see docs/clients.md).
package julia

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
// (which only receives the *Resolved). They mirror the convention used by the
// Hex, Conan, Conda, and CRAN backends and are not persisted to the cache as
// meaningful data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the tarball must be tree-hash-verified
	metaFilename = "_filename" // final path component (resource or hash)
	metaUUID     = "_uuid"     // registry/package UUID (empty for artifacts)
	metaHash     = "_hash"     // expected git-tree-sha1 recorded in the URL
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaTreeHashVerified records "git-sha1" when a tarball's content was
	// verified against the git-tree-sha1 named in its URL, "unsupported" when the
	// URL carries a hash whose algorithm the backend cannot yet verify (a future
	// SHA3-256 tree hash), or "none" for the non-content-addressed resources.
	MetaTreeHashVerified = "julia.treeHashVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Julia Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "julia"). Required.
	Name string
	// UpstreamURL is the Pkg Server base URL, e.g. "https://pkg.julialang.org".
	// The backend appends the "/registries", "/registry/...", "/package/..." and
	// "/artifact/..." protocol paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream server. Optional; the
	// public pkg.julialang.org server is unauthenticated, while a private Pkg
	// Server deployment may require a token.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Julia Pkg Server pull-through backend implementing
// backends.Backend.
type Backend struct {
	name    string
	base    *url.URL
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("julia: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("julia %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("julia %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("julia %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("julia %q: upstream client is required", opts.Name)
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:    opts.Name,
		base:    base,
		client:  opts.Client,
		creds:   opts.Credentials,
		metrics: m,
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against
// the Pkg Server Protocol layout, derives the upstream URL and cache key,
// attaches the UUID/tree-hash coordinate for the admission gates, and decides
// cacheability (only the immutable, content-addressed tarballs are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("julia: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Julia Pkg Server path", backends.ErrNotSupported, req.Path)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   res.cacheable() && isRead(req),
		CacheKey:    b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend":    b.name,
			metaKind:     res.kindLabel(),
			metaFilename: res.filename,
		},
		Artifact: res.artifact(),
	}

	// Attach the best available coordinate so nameguard, policy, provenance, and
	// risk can identify the artifact. The protocol exposes only a UUID and a
	// git-tree-sha1 (never a name/semver), so those are what we carry.
	if res.uuid != "" || res.hash != "" {
		resolved.Coordinate = backends.Coordinate{Name: res.uuid, Version: res.hash}
	}

	if res.verifiable() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaUUID] = res.uuid
		resolved.Metadata[metaHash] = res.hash
	}

	return resolved, nil
}

// Fetch implements backends.Backend. Content-addressed tarballs are verified
// against the git-tree-sha1 named in their URL — streaming, so a mismatch aborts
// the cache write and client stream without buffering the archive. The mutable
// /registries listing is proxied directly, byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("julia: nil resolved")
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

	mediaType := b.mediaType(resolved, resp.ContentType)

	// The mutable /registries listing is proxied without content verification —
	// it is not content-addressed (its body is a map of per-registry tree hashes,
	// which the client then uses to fetch individually verified tarballs).
	if resolved.Metadata[metaVerify] != "1" {
		b.metrics.incListingServed()
		resolved.Metadata[MetaTreeHashVerified] = "none"
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incTarballsServed()

	// The expected hash is the git-tree-sha1 named in the URL itself; no sibling
	// resource fetch is required. Verify the fetched tarball's content against it.
	expected := resolved.Metadata[metaHash]
	resolved.Metadata[MetaTreeHashVerified] = "git-sha1"
	content := newTreeHashVerifier(resp.Body, expected, resolved.Metadata[metaFilename], resolved.UpstreamURL, func(ok bool) {
		if ok {
			b.metrics.incTarballsVerified()
		} else {
			b.metrics.incTreeHashMismatch()
		}
	})
	header.Set("X-Tree-Hash-Verified", "git-sha1")

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// mediaType selects the response content type. The content-addressed resources
// are gzip-compressed tarballs; the /registries listing is a small text map. A
// present upstream content type is otherwise preserved.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "registry", "package", "artifact":
		return "application/gzip"
	case "registries":
		if upstreamCT != "" {
			return upstreamCT
		}
		return "text/plain; charset=utf-8"
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

// statusError drains the body and returns a StatusError carrying a diagnostic
// snippet.
func (b *Backend) statusError(resp *upstream.Response, url string) error {
	snippet := readSnippet(resp.Body)
	drainClose(resp.Body)
	return &backends.StatusError{Status: resp.Status, URL: url, Body: snippet}
}

// joinPath appends the inbound Julia path to the upstream base, preserving any
// base-path prefix (e.g. a Pkg Server served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A content-addressed path embeds the tree hash, so the path alone is a
// content-addressable key; query parameters are incidental and excluded.
func (b *Backend) cacheKey(path string) string {
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
