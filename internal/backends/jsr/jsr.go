// Package jsr implements a pull-through proxy backend for the JSR registry
// (jsr.io), the modern JavaScript/TypeScript registry used by Deno, Node, Bun,
// and other runtimes. It proxies the JSR static HTTP tree — the package
// metadata document, per-version metadata (which carries the publish manifest),
// and the content-addressable module files that make up a published version —
// bringing the JSR ecosystem to parity with the npm/pip/cargo/maven backends:
// module files are cached content-addressably beneath their immutable
// {scope}/{name}/{version}/{path} coordinate, fetched bytes are verified against
// the SHA-256 the version manifest declares before they are cached or served,
// and the package coordinate ("@scope/name") is attached for nameguard,
// vulnscan, provenance, policy, and license enforcement.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /@<scope>/<name>/meta.json             package metadata   (mutable, revalidated, rewritten)
//	GET /@<scope>/<name>/<version>_meta.json   version metadata   (immutable, revalidated, rewritten)
//	GET /@<scope>/<name>/<version>/<path...>   a module file      (immutable, cacheable, verified)
//
// Security model: a module-file path pins its {scope}/{name}/{version}/{path}
// coordinate, so the cache key (which embeds the full repository path) is itself
// content-addressable. On a cache miss the backend additionally fetches the
// sibling <version>_meta.json resource, reads the file's SHA-256 from the
// "manifest" map, and verifies the fetched bytes against it — streaming, so a
// mismatch aborts the cache write and the client stream without buffering the
// file. A tampered mirror can neither poison the cache nor reach a client.
//
// Metadata documents are served with any absolute upstream URL they embed
// rewritten to the proxy's PublicBaseURL, so a client that follows an embedded
// link still flows back through the proxy. JSR's documents are predominantly
// relative, so this is usually a no-op, but it holds defensively for any
// absolute self-reference the registry emits.
//
// OSV coverage: OSV.dev defines no "JSR" ecosystem. JSR is npm-adjacent — its
// packages are mirrored to npm under the synthetic "@jsr/<scope>__<name>" name
// (served from npm.jsr.io) — but a JSR-native coordinate ("@scope/name") is not
// an npm name and OSV publishes no JSR-keyed advisories, so no coordinate OSV
// lookup is performed at the pull layer (see internal/vulnscan/purl.go). The
// package is still defended by the content, name, provenance, and policy gates.
//
// Client configuration points the runtime at "<publicBase>/v1/<name>" (see
// docs/clients.md): e.g. Deno's JSR_URL, or npm via the npm.jsr.io compatibility
// endpoint fronted separately.
package jsr

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
// Dart, Hex, and CRAN backends and are not persisted to the cache as meaningful
// data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the file must be checksum-verified
	metaRewrite  = "_rewrite"  // "1" when the body is a metadata doc to rewrite
	metaName     = "_name"     // "@scope/name", for the version-meta lookup
	metaVersion  = "_version"  // release version, for the version-meta lookup
	metaFilePath = "_filepath" // module-file path within the version (manifest key)
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaVersion records the release version a module file is pinned to.
	MetaVersion = "jsr.version"
	// MetaChecksumVerified records "sha256" when a module file was verified
	// against its version manifest, or "none" when no digest was available.
	MetaChecksumVerified = "jsr.checksumVerified"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxMetaBytes bounds a metadata document fetch (both the served document and
	// the version-meta lookup performed to resolve a module file's checksum).
	// These JSON documents are small for a single package/version but are capped
	// so a hostile upstream cannot return an unbounded body.
	maxMetaBytes = 32 << 20 // 32 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a JSR Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "jsr"). Required.
	Name string
	// UpstreamURL is the JSR registry base URL, e.g. "https://jsr.io". The backend
	// appends the "/@<scope>/<name>/..." repository paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/jsr". It is used to rewrite
	// any absolute upstream URL embedded in a served metadata document so links
	// route back through the proxy. When empty, rewriting falls back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional; the
	// public jsr.io registry pulls anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a JSR registry pull-through backend implementing backends.Backend.
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
		return nil, errors.New("jsr: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("jsr %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("jsr %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("jsr %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
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
// the JSR registry layout, derives the upstream URL and cache key, attaches the
// package coordinate for the admission gates, and decides cacheability (only an
// immutable module file is cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("jsr: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a JSR registry path", backends.ErrNotSupported, req.Path)
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
	case kindModuleFile:
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaName] = res.coordinateName()
		resolved.Metadata[metaVersion] = res.version
		resolved.Metadata[metaFilePath] = res.filePath
		resolved.Metadata[MetaVersion] = res.version
	case kindPackageMeta, kindVersionMeta:
		resolved.Metadata[metaRewrite] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A module file is verified against the
// SHA-256 its sibling <version>_meta.json manifest declares — streaming so a
// mismatch aborts the cache write and client stream without buffering. Metadata
// documents are buffered and any absolute upstream URL they embed is rewritten
// to the proxy's PublicBaseURL before they are served.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("jsr: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchModule(ctx, resolved)
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
		return nil, fmt.Errorf("jsr %q: reading metadata: %w", b.name, err)
	}
	if int64(len(data)) > maxMetaBytes {
		return nil, fmt.Errorf("jsr %q: metadata document exceeds %d bytes", b.name, maxMetaBytes)
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

// fetchModule resolves a module-file request: it reads the sibling
// <version>_meta.json to recover the file's declared SHA-256, then fetches and
// verifies the file.
func (b *Backend) fetchModule(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
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

	b.metrics.incModulesServed()

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
		mediaType = "application/octet-stream"
	}

	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incModulesVerified()
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

// fetchExpectedChecksum fetches the sibling <version>_meta.json for a module
// file and returns the SHA-256 its "manifest" map declares for the file's path.
// A missing or unparseable document, or a file absent from the manifest, yields
// ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	coord := resolved.Metadata[metaName]
	version := resolved.Metadata[metaVersion]
	filePath := resolved.Metadata[metaFilePath]
	if coord == "" || version == "" || filePath == "" {
		return expectedChecksum{}, false
	}
	metaURL := b.versionMetaURL(coord, version)
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
	vm, perr := parseVersionMeta(body)
	if perr != nil {
		return expectedChecksum{}, false
	}
	b.metrics.incVersionMetaFetched()
	hex, found := vm.checksumFor(filePath)
	if !found {
		return expectedChecksum{}, false
	}
	return expectedChecksum{filePath: filePath, hex: hex}, true
}

// versionMetaURL builds the upstream <version>_meta.json URL for a package
// coordinate ("@scope/name") and version.
func (b *Backend) versionMetaURL(coord, version string) string {
	return b.joinPath("/" + coord + "/" + version + "_meta.json").String()
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

// joinPath appends the inbound JSR path to the upstream base, preserving any
// base-path prefix (e.g. a registry served under a sub-path).
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
