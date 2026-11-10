// Package hackage implements a pull-through proxy backend for Hackage
// (hackage.haskell.org), the central package repository for the Haskell
// ecosystem, and Hackage-compatible mirrors. It proxies the Hackage HTTP tree —
// the incremental 01-index package index, the TUF security metadata, per-package
// .cabal files, and the source-distribution (sdist) tarballs — bringing the
// Haskell ecosystem to parity with the pip/npm/cargo/hex/cpan backends: sdist
// tarballs are cached content-addressably beneath their immutable
// {name}-{version} coordinate, fetched bytes are verified against the SHA-256
// the sibling TUF target metadata (package.json) declares — where available —
// before they are cached or served, and the package coordinate (name/version)
// is attached for nameguard, vulnscan (OSV "Hackage" ecosystem), provenance,
// policy, and license enforcement.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /01-index.tar.gz                              incremental package index (mutable, live)
//	GET /root.json|/snapshot.json|/timestamp.json|…   TUF security metadata      (mutable, live)
//	GET /package/<name>-<ver>/<name>.cabal            package description        (mutable, live)
//	GET /package/<name>-<ver>/package.json            TUF target metadata        (mutable, live)
//	GET /package/<name>-<ver>/<name>-<ver>.tar.gz     sdist tarball              (immutable, verified, cacheable)
//
// Security model: an sdist filename pins its name-version coordinate, so the
// cache key (which embeds the full repository path) is itself content-
// addressable. On a cache miss the backend additionally fetches the sibling
// package.json TUF target metadata, reads the SHA-256 Hackage records for the
// tarball target, and verifies the fetched bytes against it — streaming, so a
// mismatch aborts the cache write and the client stream without buffering the
// archive. This mirrors cabal's own security model (cabal reads the same hash
// from the signed index). The declared hash is not always available on a public
// Hackage mirror (the canonical copy lives inside the signed 01-index, which is
// too large to fetch per-pull); when it is absent the tarball is served
// byte-exact and the absence is recorded in metrics, so a cabal client that
// verifies against its own copy of the index still performs end-to-end checking.
//
// Client configuration points cabal at "<publicBase>/v1/<name>" as a
// remote-repo (secure or legacy) in ~/.cabal/config (see docs/clients.md).
package hackage

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
// Hex, CPAN, and CRAN backends and are not persisted to the cache as meaningful
// data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the file must be checksum-verified
	metaFilename = "_filename" // requested filename (the sdist tarball)
	metaName     = "_name"     // package name, for the package.json lookup
	metaVersion  = "_version"  // release version, for the package.json lookup
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records "sha256" when an sdist was verified against its
	// TUF target metadata, or "none" when no declared digest was available.
	MetaChecksumVerified = "hackage.checksumVerified"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxTargetBytes bounds a package.json TUF target metadata fetch. These
	// documents are small (one package version's target hashes); the cap stops a
	// hostile upstream returning an unbounded body.
	maxTargetBytes = 4 << 20 // 4 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Hackage Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "hackage").
	// Required.
	Name string
	// UpstreamURL is the Hackage repository base URL, e.g.
	// "https://hackage.haskell.org". The backend appends the "/01-index.tar.gz",
	// "/package/..." and TUF-metadata repository paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream repository. Optional;
	// the public hackage.haskell.org repository pulls anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Hackage repository pull-through backend implementing
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
		return nil, errors.New("hackage: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("hackage %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("hackage %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("hackage %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("hackage %q: upstream client is required", opts.Name)
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
// the Hackage layout, derives the upstream URL and cache key, attaches the
// package coordinate for the admission gates, and decides cacheability (only
// immutable sdist tarballs are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("hackage: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Hackage repository path", backends.ErrNotSupported, req.Path)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   res.cacheable() && isRead(req),
		CacheKey:    b.name + ":" + strings.TrimLeft(req.Path, "/"),
		Metadata: map[string]string{
			"backend":    b.name,
			metaKind:     res.kindLabel(),
			metaFilename: res.filename,
		},
	}

	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableFile() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
	}

	return resolved, nil
}

// Fetch implements backends.Backend. An sdist tarball is verified against the
// SHA-256 its sibling package.json TUF target metadata declares — where
// available — streaming so a mismatch aborts the cache write and client stream
// without buffering. The index, TUF metadata, and .cabal files are proxied
// directly, byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("hackage: nil resolved")
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

	// Index, TUF metadata, and .cabal documents are proxied without content
	// verification; a cabal client performs its own signature/hash check.
	if resolved.Metadata[metaVerify] != "1" {
		b.metrics.incIndexServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incSdistsServed()

	// Resolve the declared SHA-256 from the sibling package.json TUF target
	// metadata. A missing resource (or a target absent from it) is recorded and
	// the tarball is served unverified; fail-open is the only option when the
	// upstream publishes no per-package digest, and the absence is observable via
	// metrics.
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incSdistsVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", "sha256")
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

// fetchExpectedChecksum fetches the sibling package.json TUF target metadata for
// the requested sdist and returns the SHA-256 it declares for the tarball
// target. A missing or unparseable resource, or a target absent from it, yields
// ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	name := resolved.Metadata[metaName]
	version := resolved.Metadata[metaVersion]
	filename := resolved.Metadata[metaFilename]
	if name == "" || version == "" || filename == "" {
		return expectedChecksum{}, false
	}
	targetURL := b.targetMetadataURL(name, version)
	resp, err := b.get(ctx, targetURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTargetBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxTargetBytes {
		return expectedChecksum{}, false
	}
	sha, found := parseTargetSHA256(body, filename)
	if !found {
		return expectedChecksum{}, false
	}
	b.metrics.incTargetsFetched()
	return expectedChecksum{filename: filename, hex: sha}, true
}

// mediaType selects the response content type.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "sdist":
		return "application/gzip"
	case "index":
		return "application/gzip"
	case "cabal":
		return "text/plain; charset=utf-8"
	case "tuf-metadata", "target-metadata":
		return "application/json"
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
}

// targetMetadataURL builds the /package/<name>-<version>/package.json URL for a
// release relative to the upstream base, preserving any base-path prefix.
func (b *Backend) targetMetadataURL(name, version string) string {
	return b.joinPath("/package/" + name + "-" + version + "/package.json").String()
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

// joinPath appends the inbound Hackage path to the upstream base, preserving any
// base-path prefix (e.g. a repository served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
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
