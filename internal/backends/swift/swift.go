// Package swift implements a pull-through proxy backend for the Swift Package
// Manager's package-registry protocol (SE-0292 / the "Swift Package Registry
// Service" specification that the swiftlang reference server and Swift
// Package Index implement). It brings the Swift ecosystem to parity with the
// pip/npm/cargo/maven backends: release metadata, package manifests, and source
// archives are proxied and cached content-addressably beneath their immutable
// {scope}/{name}/{version} coordinate, fetched archives are verified against the
// SHA-256 checksum the release metadata records before they are cached or
// served, and the package coordinate ("scope.name") plus its source-repository
// URLs are attached for nameguard, vulnscan, provenance, policy, and license
// enforcement.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /{scope}/{name}                     list releases (revalidated)
//	GET /{scope}/{name}/{version}           release metadata (immutable, cached)
//	GET /{scope}/{name}/{version}/Package.swift   manifest (immutable, cached)
//	GET /{scope}/{name}/{version}.zip       source archive (immutable, verified)
//	GET /identifiers?url=...                SCM-URL lookup (revalidated)
//
// Security model: a published release is immutable, so anything addressed
// beneath a concrete version is content-addressable — the proxy caches it
// indefinitely. On a cache miss the backend fetches the release metadata,
// reads the "source-archive" SHA-256 checksum, and streams the archive through
// a verifying reader so a hash mismatch aborts the cache write and the client
// stream. The mutable discovery endpoints (release list, identifier lookup) are
// revalidated rather than cached.
//
// Client configuration points the Swift registry at "<publicBase>/v1/<name>"
// (see docs/clients.md): `swift package-registry set <publicBase>/v1/<name>`.
package swift

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
// Conan, Maven, and Terraform backends and are not persisted to the cache as
// meaningful data.
const (
	metaKind   = "_kind"   // resource-class label, for diagnostics/gates
	metaVerify = "_verify" // "1" when the archive must be checksum-verified
	metaAccept = "_accept" // the client Accept header to forward upstream
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaScope records the package scope.
	MetaScope = "swift.scope"
	// MetaName records the package name (within its scope).
	MetaName = "swift.name"
	// MetaVersion records the release version a resource is pinned to.
	MetaVersion = "swift.version"
	// MetaChecksumVerified records "sha256" when an archive was verified against
	// the release metadata, or "none" when no checksum was available.
	MetaChecksumVerified = "swift.checksumVerified"
	// MetaRepositoryURL records the artifact's source repository (for provenance).
	MetaRepositoryURL = "swift.repositoryURL"
)

// Content negotiation. The Swift registry selects the API version and wire
// format via the Accept header; the proxy forwards the client's Accept when
// present and otherwise supplies a sensible per-resource default so a strict
// registry does not answer 406.
const (
	acceptJSON     = "application/vnd.swift.registry.v1+json"
	acceptSwift    = "application/vnd.swift.registry.v1+swift"
	acceptZip      = "application/vnd.swift.registry.v1+zip"
	contentVersion = "Content-Version"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxMetadataBytes bounds a release metadata fetch performed to resolve the
	// source-archive checksum. These documents are small JSON; the cap stops a
	// hostile upstream returning a huge body in place of metadata.
	maxMetadataBytes = 4 << 20 // 4 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Swift Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "swiftpm").
	// Required.
	Name string
	// UpstreamURL is the Swift registry base URL, e.g.
	// "https://swiftpackageregistry.example.com". The backend appends the
	// "/{scope}/{name}/..." API paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional;
	// public registries pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Swift Package Registry pull-through backend implementing
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
		return nil, errors.New("swift: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("swift %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("swift %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("swift %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("swift %q: upstream client is required", opts.Name)
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
// the Swift registry layout, derives the upstream URL and cache key, attaches
// the package coordinate for the admission gates, and decides cacheability (only
// resources pinned beneath an immutable release version are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("swift: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Swift registry path", backends.ErrNotSupported, req.Path)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   res.cacheable() && isRead(req),
		CacheKey:    b.cacheKey(req.Path, req.Query),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
	}

	// Forward the client's Accept header so the registry returns the requested
	// API version/representation; fall back to a per-resource default.
	resolved.Metadata[metaAccept] = acceptFor(res, headerGet(req.Header, "Accept"))

	// Attach the coordinate and qualifiers so nameguard, policy, provenance,
	// vulnscan, license, and policyengine can identify the artifact.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		resolved.Metadata[MetaScope] = res.scope
		resolved.Metadata[MetaName] = res.name
		if res.version != "" {
			resolved.Metadata[MetaVersion] = res.version
		}
	}

	if res.isArchive() {
		resolved.Metadata[metaVerify] = "1"
		resolved.MediaType = "application/zip"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For a source archive it first fetches the
// release metadata, reads the source-archive SHA-256 checksum, and streams the
// archive through a verifying reader so a hash mismatch aborts the cache write
// and the client stream. Metadata, manifests, release lists, and the identifier
// lookup are proxied directly with the Content-Version header preserved.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("swift: nil resolved")
	}

	resp, err := b.get(ctx, resolved.UpstreamURL, resolved.Metadata[metaAccept], resolved.IfNoneMatch)
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
	// Preserve the registry's API-version header and the archive's Digest header
	// so the client can run its own negotiation and integrity check.
	if cv := resp.Header.Get(contentVersion); cv != "" {
		header.Set(contentVersion, cv)
	}
	if dg := resp.Header.Get("Digest"); dg != "" {
		header.Set("Digest", dg)
	}

	// Non-archive resources (release list, metadata, manifest, identifiers) are
	// proxied without content verification.
	if resolved.Metadata[metaVerify] != "1" {
		b.recordKindMetric(resolved)
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: b.mediaType(resolved, resp.ContentType),
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incArchivesServed()

	// Resolve the expected SHA-256 from the release metadata. A missing metadata
	// document (or an absent checksum) is recorded and the archive is served
	// unverified — fail-open is the only option when the registry publishes no
	// checksum, and the absence is observable via metrics.
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
				b.metrics.incArchivesVerified()
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
		MediaType: "application/zip",
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchExpectedChecksum fetches the release metadata for the archive's version
// (the archive URL with its ".zip" suffix removed) and returns the SHA-256 the
// metadata records for the "source-archive" resource. A missing or unparseable
// metadata document, or an absent checksum, yields ok=false (served unverified).
// The source-repository URL, when present, is surfaced for provenance.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	metaURL, ok := strings.CutSuffix(resolved.UpstreamURL, archiveExt)
	if !ok {
		return expectedChecksum{}, false
	}
	// Drop any query string on the metadata request.
	if i := strings.IndexByte(metaURL, '?'); i >= 0 {
		metaURL = metaURL[:i]
	}
	resp, err := b.get(ctx, metaURL, acceptJSON, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxMetadataBytes {
		return expectedChecksum{}, false
	}
	b.metrics.incMetadataFetched()
	rm, perr := parseReleaseMetadata(body)
	if perr != nil {
		return expectedChecksum{}, false
	}
	if repo := rm.repositoryURL(); repo != "" {
		resolved.Metadata[MetaRepositoryURL] = repo
	}
	hex, found := rm.sourceArchiveChecksum()
	if !found {
		return expectedChecksum{}, false
	}
	return expectedChecksum{hex: hex}, true
}

// recordKindMetric counts served non-archive resources by their class.
func (b *Backend) recordKindMetric(resolved *backends.Resolved) {
	switch resolved.Metadata[metaKind] {
	case "manifest":
		b.metrics.incManifestsServed()
	case "releases", "release", "identifiers":
		b.metrics.incMetadataServed()
	}
}

// mediaType selects the response content type for non-archive resources.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "manifest":
		return "text/x-swift; charset=utf-8"
	case "releases", "release", "identifiers":
		if upstreamCT != "" {
			return upstreamCT
		}
		return "application/json"
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
}

// acceptFor returns the Accept header to send upstream: the client's own value
// when present, otherwise a sensible per-resource default.
func acceptFor(res resource, clientAccept string) string {
	if a := strings.TrimSpace(clientAccept); a != "" {
		return a
	}
	switch res.kind {
	case kindManifest:
		return acceptSwift
	case kindArchive:
		return acceptZip
	default:
		return acceptJSON
	}
}

// get performs a GET against the upstream with the backend's credentials and the
// supplied Accept header.
func (b *Backend) get(ctx context.Context, rawURL, accept, ifNoneMatch string) (*upstream.Response, error) {
	h := make(http.Header)
	if accept != "" {
		h.Set("Accept", accept)
	}
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Header:      h,
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

// joinPath appends the inbound Swift path to the upstream base, preserving any
// base-path prefix (e.g. a registry served under "/registry").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// Query parameters (the swift-version selector on a manifest, the url= on an
// identifier lookup) change the representation, so they are folded into the key.
func (b *Backend) cacheKey(path string, q url.Values) string {
	key := b.name + ":" + strings.TrimLeft(path, "/")
	if enc := q.Encode(); enc != "" {
		key += "?" + enc
	}
	return key
}

func headerGet(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
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
