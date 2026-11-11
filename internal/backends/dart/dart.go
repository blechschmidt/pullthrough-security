// Package dart implements a pull-through proxy backend for the Dart/Flutter
// "pub" package manager, speaking the Hosted Pub Repository API (repository-spec
// v2) that pub.dev and self-hosted pub servers expose. It brings the Dart
// ecosystem to parity with the pip/npm/cargo/maven backends: the list-versions
// document and package archives are proxied, archives are cached
// content-addressably beneath their immutable {package}/{version} coordinate and
// verified against the SHA-256 "archive_sha256" content hash before they are
// cached or served, and the package coordinate plus its pubspec repository URL
// are attached for nameguard, vulnscan, provenance, policy, and license
// enforcement.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /api/packages/{package}             list versions (revalidated; archive_url rewritten)
//	GET /api/packages/{package}/advisories  security advisories (revalidated)
//	GET /api/archives/{package}-{version}.tar.gz   package archive (immutable, verified)
//
// Security model: the list-versions document the proxy serves has every
// "archive_url" rewritten to the proxy's own "/api/archives/..." endpoint, so a
// client's archive download flows back through the proxy rather than directly to
// the upstream or its blob storage. On a request for that endpoint the backend
// re-reads the upstream list-versions document to recover the real archive URL
// and the "archive_sha256", fetches the archive (following redirects to any blob
// store), and streams it through a verifying reader so a hash mismatch aborts the
// cache write and the client stream.
//
// Client configuration points pub at "<publicBase>/v1/<name>" via the
// PUB_HOSTED_URL environment variable (see docs/clients.md).
package dart

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
	metaVerify  = "_verify"  // "1" when the resource is an archive to verify
	metaRewrite = "_rewrite" // "1" when the body is a list-versions doc to rewrite
	metaVersion = "_version" // archive version, for the metadata lookup
	metaName    = "_name"    // package name, for the metadata lookup
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaVersion records the release version an archive is pinned to.
	MetaVersion = "dart.version"
	// MetaChecksumVerified records "sha256" when an archive was verified against
	// the list-versions document, or "none" when no content hash was available.
	MetaChecksumVerified = "dart.checksumVerified"
	// MetaRepository records the package's source repository (for provenance).
	MetaRepository = "dart.repository"
)

// API version header the pub client negotiates.
const acceptJSON = "application/vnd.pub.v2+json"

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxVersionsBytes bounds a list-versions fetch (both the served document and
	// the lookup performed to resolve an archive's URL/checksum). These JSON docs
	// can be large for popular packages with many releases, but are bounded; the
	// cap stops a hostile upstream returning an unbounded body.
	maxVersionsBytes = 32 << 20 // 32 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// archivePathPrefix is the proxy's synthetic archive endpoint, relative to a
// backend mount. It mirrors pub.dev's own "/api/archives/<name>-<version>.tar.gz"
// convention so rewritten archive_url values look familiar to clients.
const archivePathPrefix = "/api/archives/"

// Options configures a Dart Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "pub"). Required.
	Name string
	// UpstreamURL is the pub repository base URL, e.g. "https://pub.dev".
	// Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/pub". It is used to rewrite
	// the list-versions document's archive_url fields so archive downloads route
	// back through the proxy. When empty, rewritten links fall back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream repository. Optional;
	// public repositories (pub.dev) pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Dart/pub pull-through backend implementing backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	publicBase string
	client     upstream.Doer
	creds      upstream.Credentials
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("dart: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("dart %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("dart %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("dart %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("dart %q: upstream client is required", opts.Name)
	}
	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		// Fall back to the root-relative mount; pub resolves a relative archive_url
		// against the request URL.
		publicBase = "/v1/" + opts.Name
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:       opts.Name,
		base:       base,
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
// the pub layout, derives the upstream URL and cache key, attaches the package
// coordinate for the admission gates, decides cacheability (only a concrete
// version archive is cached), and states whether the resource is a payload or a
// document (see resource.artifact).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("dart: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a pub repository path", backends.ErrNotSupported, req.Path)
	}

	// For an archive the upstream URL is not the synthetic "/api/archives/..."
	// path (which exists only on the proxy); Fetch discovers the real archive URL
	// from the list-versions document, so Resolve points the upstream URL at that
	// document. All other resources map directly to their upstream path.
	var upstreamURL string
	if res.isArchive() {
		upstreamURL = b.versionsURL(res.name)
	} else {
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		upstreamURL = abs.String()
	}

	resolved := &backends.Resolved{
		UpstreamURL: upstreamURL,
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

	switch {
	case res.isArchive():
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		resolved.Metadata[MetaVersion] = res.version
		resolved.MediaType = "application/gzip"
	case res.isVersions():
		resolved.Metadata[metaRewrite] = "1"
		resolved.Metadata[metaName] = res.name
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For an archive it re-reads the upstream
// list-versions document to recover the real archive URL and the content hash,
// then streams the archive through a verifying reader so a hash mismatch aborts
// the cache write and the client stream. The list-versions document is buffered
// and its archive_url fields rewritten through the proxy; advisories are proxied
// as-is.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("dart: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchArchive(ctx, resolved)
	}

	resp, err := b.get(ctx, resolved.UpstreamURL, acceptJSON, resolved.IfNoneMatch)
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

	// The list-versions document must have its archive_url fields rewritten so
	// archive downloads route through the proxy; it is buffered for that.
	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchVersions(resolved, resp, header)
	}

	b.metrics.incAdvisoriesServed()
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

// fetchVersions buffers the list-versions document, rewrites its archive_url
// fields to the proxy's archive endpoint, and returns the rewritten bytes. If
// the body does not parse as JSON it is served unchanged (fail-open), so a
// non-standard discovery document still reaches the client.
func (b *Backend) fetchVersions(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionsBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("dart %q: reading list-versions: %w", b.name, err)
	}
	if int64(len(data)) > maxVersionsBytes {
		return nil, fmt.Errorf("dart %q: list-versions document exceeds %d bytes", b.name, maxVersionsBytes)
	}

	pkg := resolved.Metadata[metaName]
	rewritten, rerr := rewriteArchiveURLs(data, func(version string) string {
		return b.archiveURL(pkg, version)
	})
	if rerr == nil {
		b.metrics.incVersionsRewritten()
		data = rewritten
	}
	// Even if rewriting failed to parse, the (unmodified) bytes are still served.

	b.metrics.incVersionsServed()
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(string(data))),
		Size:      int64(len(data)),
		MediaType: "application/json",
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchArchive resolves an archive request: it reads the upstream list-versions
// document, finds the requested version's real archive URL and content hash,
// then fetches and verifies the archive.
func (b *Backend) fetchArchive(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	version := resolved.Metadata[metaVersion]

	// Step 1: read the list-versions document to recover the archive URL, the
	// content hash, and the source repository.
	metaResp, err := b.get(ctx, resolved.UpstreamURL, acceptJSON, "")
	if err != nil {
		return nil, err
	}
	if !metaResp.IsSuccess() {
		return nil, b.statusError(metaResp, resolved.UpstreamURL)
	}
	body, rerr := io.ReadAll(io.LimitReader(metaResp.Body, maxVersionsBytes+1))
	drainClose(metaResp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("dart %q: reading list-versions: %w", b.name, rerr)
	}
	if int64(len(body)) > maxVersionsBytes {
		return nil, fmt.Errorf("dart %q: list-versions document exceeds %d bytes", b.name, maxVersionsBytes)
	}
	vl, perr := parseVersionList(body)
	if perr != nil {
		return nil, fmt.Errorf("dart %q: parsing list-versions: %w", b.name, perr)
	}
	entry, found := vl.archiveFor(version)
	if !found || strings.TrimSpace(entry.ArchiveURL) == "" {
		return nil, &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    resolved.UpstreamURL,
			Body:   fmt.Sprintf("version %q not found in list-versions document", version),
		}
	}

	// Resolve a possibly-relative archive_url against the list-versions URL.
	archiveURL, aerr := resolveArchiveURL(resolved.UpstreamURL, entry.ArchiveURL)
	if aerr != nil {
		return nil, fmt.Errorf("dart %q: invalid archive_url %q: %w", b.name, entry.ArchiveURL, aerr)
	}
	if repo := entry.repository(); repo != "" {
		resolved.Metadata[MetaRepository] = repo
	}
	hex, haveChecksum := normalizeDigest(entry.ArchiveSha256)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	// Step 2: fetch the archive. Credentials are sent only when the archive stays
	// on the upstream host (pub's own rule); blob-store redirect targets carry
	// their own signed query auth and must not receive the proxy's token.
	creds := b.creds
	if !sameHost(b.base, archiveURL) {
		creds = upstream.Credentials{}
	}
	archResp, err := b.getWithCreds(ctx, archiveURL, "", resolved.IfNoneMatch, creds)
	if err != nil {
		return nil, err
	}
	if archResp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !archResp.IsSuccess() {
		return nil, b.statusError(archResp, archiveURL)
	}

	b.metrics.incArchivesServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, archResp.Header)
	if archResp.ETag != "" {
		header.Set("ETag", archResp.ETag)
	}

	content := archResp.Body
	if haveChecksum {
		content = newVerifyingReader(archResp.Body, expectedChecksum{hex: hex}, archiveURL, func(ok bool) {
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
		Size:      archResp.ContentLength,
		MediaType: "application/gzip",
		Header:    header,
		Status:    archResp.Status,
	}, nil
}

// archiveURL builds the proxy's archive endpoint for a package version.
func (b *Backend) archiveURL(pkg, version string) string {
	return b.publicBase + archivePathPrefix + pkg + "-" + version + archiveExt
}

// versionsURL builds the upstream list-versions URL for a package.
func (b *Backend) versionsURL(pkg string) string {
	return b.joinPath("/api/packages/" + pkg).String()
}

// get performs a GET against the upstream with the backend's own credentials.
func (b *Backend) get(ctx context.Context, rawURL, accept, ifNoneMatch string) (*upstream.Response, error) {
	return b.getWithCreds(ctx, rawURL, accept, ifNoneMatch, b.creds)
}

// getWithCreds performs a GET with the supplied credentials and Accept header.
func (b *Backend) getWithCreds(ctx context.Context, rawURL, accept, ifNoneMatch string, creds upstream.Credentials) (*upstream.Response, error) {
	h := make(http.Header)
	if accept != "" {
		h.Set("Accept", accept)
	}
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Header:      h,
		Creds:       creds,
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

// joinPath appends the inbound pub path to the upstream base, preserving any
// base-path prefix.
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// resolveArchiveURL resolves a possibly-relative archive_url against the
// list-versions URL it was read from, and requires an http(s) result so a
// hostile document cannot smuggle a "file://" or other scheme into the fetch.
func resolveArchiveURL(base, archive string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	au, err := url.Parse(strings.TrimSpace(archive))
	if err != nil {
		return "", err
	}
	resolved := bu.ResolveReference(au)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("archive URL scheme must be http(s), got %q", resolved.Scheme)
	}
	return resolved.String(), nil
}

// sameHost reports whether rawURL targets the same host as base (used to decide
// whether to send the proxy's credentials to an archive URL).
func sameHost(base *url.URL, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, base.Host)
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
