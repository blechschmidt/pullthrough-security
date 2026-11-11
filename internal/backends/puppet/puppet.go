// Package puppet implements a pull-through proxy backend for Puppet Forge
// (forgeapi.puppet.com), the registry for Puppet modules. It proxies the Forge
// v3 REST API — module metadata, release metadata, and listing/search
// endpoints — and the content-addressable release tarballs that make up a
// published module version, bringing the Puppet ecosystem to parity with the
// npm/pip/cargo/maven backends: a release tarball is cached content-addressably
// beneath its immutable {owner}-{name}-{version} coordinate, fetched bytes are
// verified against the file_sha256 (or legacy file_md5) the release-metadata
// document publishes before they are cached or served, and the module
// coordinate ("owner-name") is attached for nameguard, vulnscan, provenance,
// policy, and license enforcement.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /v3/modules/<owner>-<name>                 module metadata  (mutable, rewritten)
//	GET /v3/releases/<owner>-<name>-<version>      release metadata (mutable, rewritten)
//	GET /v3/files/<owner>-<name>-<version>.tar.gz  release tarball  (immutable, cacheable, verified)
//
// Security model: a release-file path pins its {owner}-{name}-{version}
// coordinate in its filename, so the cache key (which embeds the full repository
// path) is itself content-addressable. On a cache miss the backend fetches the
// sibling release-metadata document, reads the release's published file_sha256
// (preferring it over the legacy file_md5), and verifies the fetched bytes
// against it — streaming, so a mismatch aborts the cache write and the client
// stream without buffering the tarball. A tampered mirror can neither poison the
// cache nor reach a client.
//
// Metadata documents are served with any absolute upstream URL they embed
// rewritten to the proxy's PublicBaseURL. Forge release documents reference the
// tarball with a relative "file_uri" (e.g. "/v3/files/..."), so a client that
// resolves it against the proxy mount flows the download back through the proxy
// (and its content gates and checksum verification) without any rewrite; the
// rewrite additionally covers any absolute self-reference the API emits.
//
// OSV coverage: OSV.dev defines no Puppet-Forge ecosystem. A module is addressed
// by an "owner-name" slug that is not an OSV key, so no coordinate OSV lookup is
// performed at the pull layer (see internal/vulnscan/purl.go). The module is
// still defended by the content, name, provenance, and policy gates, and its
// underlying source repository is covered by the provenance / commit-scanning
// paths.
//
// Client configuration points the Puppet module tool / r10k at
// "<publicBase>/v1/<name>" as the Forge base URL (see docs/clients.md).
package puppet

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
// JSR, Dart, Hex, and CRAN backends and are not persisted to the cache as
// meaningful data.
const (
	metaKind       = "_kind"       // resource-class label, for diagnostics/gates
	metaVerify     = "_verify"     // "1" when the artifact must be checksum-verified
	metaRewrite    = "_rewrite"    // "1" when the body is a metadata doc to rewrite
	metaBasePrefix = "_baseprefix" // path prefix before "/v3", for the release-meta lookup
	metaSlug       = "_slug"       // "owner-name-version", for the release-meta lookup
	metaCoord      = "_coord"      // "owner-name", for diagnostics
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaVersion records the module version a release tarball is pinned to.
	MetaVersion = "puppet.version"
	// MetaChecksumVerified records the algorithm a release tarball was verified
	// with ("sha256" or "md5"), or "none" when no digest was available.
	MetaChecksumVerified = "puppet.checksumVerified"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxMetaBytes bounds a metadata document fetch (both the served document and
	// the release-metadata lookup performed to resolve a tarball's checksum). These
	// JSON documents are small for a single module/release but are capped so a
	// hostile upstream cannot return an unbounded body.
	maxMetaBytes = 32 << 20 // 32 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Puppet Forge Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "puppet").
	// Required.
	Name string
	// UpstreamURL is the Forge API base URL, e.g. "https://forgeapi.puppet.com".
	// The backend appends the "/v3/..." repository paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/puppet". It is used to rewrite
	// any absolute upstream URL embedded in a served metadata document so links
	// route back through the proxy. When empty, rewriting falls back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional; the
	// public forgeapi.puppet.com registry pulls anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Puppet Forge pull-through backend implementing backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	origin     string // scheme://host of the upstream, used for rewriting
	publicBase string
	client     upstream.Doer
	creds      upstream.Credentials
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("puppet: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("puppet %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("puppet %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("puppet %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("puppet %q: client is required", opts.Name)
	}
	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		publicBase = "/v1/" + opts.Name
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:       opts.Name,
		base:       base,
		origin:     base.Scheme + "://" + base.Host,
		publicBase: publicBase,
		client:     opts.Client,
		creds:      opts.Credentials,
		metrics:    m,
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against
// the Forge layout, derives the upstream URL and cache key, attaches the module
// coordinate for the admission gates, and decides cacheability (only an
// immutable release tarball is cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("puppet: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a valid Forge path", backends.ErrNotSupported, req.Path)
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
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
		Artifact: res.artifact(),
	}

	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	switch res.kind {
	case kindArtifact:
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaBasePrefix] = res.basePrefix
		resolved.Metadata[metaSlug] = res.releaseSlug()
		resolved.Metadata[metaCoord] = res.coordinateName()
		resolved.Metadata[MetaVersion] = res.version
	case kindMetadata:
		resolved.Metadata[metaRewrite] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A release tarball is verified against the
// digest its sibling release-metadata document declares — streaming so a
// mismatch aborts the cache write and client stream without buffering. Metadata
// documents are buffered and any absolute upstream URL they embed is rewritten
// to the proxy's PublicBaseURL before they are served.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("puppet: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchRelease(ctx, resolved)
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

	return b.fetchMetadata(resolved, resp, header)
}

// fetchMetadata buffers a metadata document and rewrites any absolute upstream
// URL it embeds to the proxy's PublicBaseURL. A body that does not parse as JSON
// is served unchanged (fail-open), so a non-standard document still reaches the
// client.
func (b *Backend) fetchMetadata(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("puppet %q: reading metadata: %w", b.name, err)
	}
	if int64(len(data)) > maxMetaBytes {
		return nil, fmt.Errorf("puppet %q: metadata document exceeds %d bytes", b.name, maxMetaBytes)
	}

	if rewritten, changed := rewriteMetadata(data, b.origin, b.publicBase); changed {
		b.metrics.incMetadataRewritten()
		data = rewritten
	}
	b.metrics.incMetadataServed()

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

// fetchRelease resolves a release-tarball request: it reads the sibling
// release-metadata document to recover the published digest, then fetches and
// verifies the tarball.
func (b *Backend) fetchRelease(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = string(expected.algo)
		if expected.algo == algoMD5 {
			b.metrics.incMD5Fallback()
		}
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
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

	b.metrics.incReleasesServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/gzip"
	}

	content := resp.Body
	if haveChecksum {
		coord := resolved.Metadata[metaCoord]
		content = newVerifyingReader(resp.Body, expected, coord, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incReleasesVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", string(expected.algo))
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

// fetchExpectedChecksum fetches the sibling release-metadata document for a
// release tarball and returns the strongest digest it declares (SHA-256 over
// the legacy MD5). A missing or unparseable document, or an absent/malformed
// digest, yields ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	slug := resolved.Metadata[metaSlug]
	if slug == "" {
		return expectedChecksum{}, false
	}
	metaURL := b.releaseMetaURL(resolved.Metadata[metaBasePrefix], slug)
	resp, err := b.get(ctx, metaURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxMetaBytes {
		return expectedChecksum{}, false
	}
	rm, perr := parseReleaseMeta(body)
	if perr != nil {
		return expectedChecksum{}, false
	}
	b.metrics.incReleaseMetaFetch()
	return rm.checksum()
}

// releaseMetaURL builds the upstream release-metadata URL for a release slug,
// preserving the request's path prefix before "/v3".
func (b *Backend) releaseMetaURL(basePrefix, slug string) string {
	path := strings.TrimRight(basePrefix, "/") + "/v3/releases/" + slug
	return b.joinPath(path).String()
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

// joinPath appends the inbound Forge path to the upstream base, preserving any
// base-path prefix (e.g. an API served under a sub-path).
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
