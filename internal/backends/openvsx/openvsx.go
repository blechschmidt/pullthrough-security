// Package openvsx implements a pull-through proxy backend for the Eclipse Open
// VSX registry (open-vsx.org) and API-compatible self-hosted deployments — the
// vendor-neutral marketplace VS Code / VSCodium / Theia clients install editor
// extensions from. It brings IDE extensions to parity with the other ecosystem
// backends: extension query/metadata documents are proxied, the immutable .vsix
// extension archives are cached content-addressably beneath their
// {namespace}.{extension}@{version} coordinate and verified against the SHA-256
// the registry publishes in a sibling ".sha256" sidecar before they are cached
// or served, and the extension coordinate is attached for nameguard, provenance,
// policy, and the install/activation content gate.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /api/-/query?extensionId=…            query documents           (mutable, live, URL-rewritten)
//	GET /api/{namespace}/{extension}[/{version}]      metadata          (mutable, live, URL-rewritten)
//	GET /api/{ns}/{ext}/…/file/{file}.vsix    extension archive         (immutable, SHA-256 verified)
//	GET /api/{ns}/{ext}/…/file/{file}.sha256  archive checksum sidecar  (immutable, byte-exact)
//	GET /vscode/…                             VS Code gallery protocol  (mutable, live, URL-rewritten)
//
// Security model: the metadata/query documents the proxy serves have every
// absolute upstream URL (files.download, files.sha256, gallery asset URLs, …)
// rewritten to the proxy's own public base, so a client's .vsix download flows
// back through the proxy — and therefore through the install/activation content
// gate — rather than directly to the upstream or its CDN. On a .vsix request the
// backend fetches the sibling .sha256 sidecar to recover the published digest,
// then streams the archive through a verifying reader so a hash mismatch aborts
// the cache write and the client stream without buffering the archive. A
// tampered mirror/CDN can neither poison the cache nor reach a client.
//
// OSV coverage: VS Code / OpenVSX extensions are NOT covered by any OSV.dev
// ecosystem — OSV defines no ecosystem keyed by the {namespace}.{extension}
// coordinate — so the vulnerability-scanning gate performs no coordinate lookup
// for this backend (see internal/vulnscan/purl.go). The supply-chain defense for
// extensions is instead the install/activation content gate (install-script /
// lifecycle-hook risk analysis over the .vsix manifest; see internal/installhooks)
// plus the name/provenance/policy gates.
//
// Client configuration points an editor's gallery service at
// "<publicBase>/v1/<name>" (see docs/clients.md): set the VS Code product.json
// extensionsGallery.serviceUrl / itemUrl, or the ovsx CLI's --registryUrl, to the
// proxy mount. The POST-based VS Code gallery extensionquery is not proxied — the
// pull-through core serves idempotent GET/HEAD only — so clients use the OpenVSX
// REST API (GET /api/…) which this backend fully fronts.
package openvsx

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
// dart/hex backends and are not persisted to the cache as meaningful data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the .vsix must be checksum-verified
	metaRewrite  = "_rewrite"  // "1" when the body's upstream URLs must be rewritten
	metaFilename = "_filename" // requested .vsix filename
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records "sha256" when a .vsix was verified against its
	// sibling .sha256 sidecar, or "none" when no digest was available.
	MetaChecksumVerified = "openvsx.checksumVerified"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxMetadataBytes bounds a metadata/query/gallery document buffered for URL
	// rewriting. Query responses listing many extensions can be sizeable but are
	// bounded; the cap stops a hostile upstream returning an unbounded body.
	maxMetadataBytes = 32 << 20 // 32 MiB
	// maxSidecarBytes bounds a .sha256 sidecar fetch. The sidecar is a single
	// 64-character hex line; the cap is generous slack.
	maxSidecarBytes = 4 << 10 // 4 KiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// vsixMediaType is the content type served for a .vsix archive (a zip).
const vsixMediaType = "application/octet-stream"

// Options configures an OpenVSX Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "openvsx").
	// Required.
	Name string
	// UpstreamURL is the OpenVSX registry base URL, e.g. "https://open-vsx.org".
	// The backend appends the "/api/..." and "/vscode/..." repository paths.
	// Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/openvsx". It is used to
	// rewrite the absolute upstream URLs embedded in metadata/query documents
	// (files.download, files.sha256, gallery asset URLs, …) so extension downloads
	// route back through the proxy. When empty, rewritten links fall back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional; the
	// public open-vsx.org registry pulls anonymously, while a private deployment
	// is read with a token.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is an OpenVSX registry pull-through backend implementing
// backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	baseStr    string
	publicBase string
	client     upstream.Doer
	creds      upstream.Credentials
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("openvsx: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("openvsx %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("openvsx %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("openvsx %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("openvsx %q: upstream client is required", opts.Name)
	}
	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		// Fall back to the root-relative mount; a client resolves a rewritten
		// absolute-origin link against the proxy host it is already talking to.
		publicBase = "/v1/" + opts.Name
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
		metrics:    m,
	}, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against the
// OpenVSX layout, derives the upstream URL and cache key, attaches the extension
// coordinate for the admission gates, decides cacheability (only immutable
// .vsix archives are cached), and states whether the resource is a payload (see
// resource.artifact).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("openvsx: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not an OpenVSX registry path", backends.ErrNotSupported, req.Path)
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
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
		Artifact: res.artifact(),
	}

	// Attach the coordinate so nameguard, policy, provenance, the installhooks
	// content gate, and policyengine can identify the extension.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	switch {
	case res.verifiableFile():
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaFilename] = res.filename
		resolved.MediaType = vsixMediaType
	case res.rewritable():
		resolved.Metadata[metaRewrite] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A .vsix archive is verified against its
// sibling .sha256 sidecar — streaming, so a mismatch aborts the cache write and
// client stream without buffering. Metadata/query/gallery documents are buffered
// (bounded) and their embedded absolute upstream URLs rewritten through the
// proxy; the byte-exact /file/ sidecars are proxied as-is.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("openvsx: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchVsix(ctx, resolved)
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

	// Metadata/gallery documents must have their embedded upstream URLs rewritten
	// so downloads route through the proxy; they are buffered for that.
	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchRewritten(resolved, resp, header)
	}

	// A byte-exact /file/ sidecar (the .sha256, signature, manifest, …): passthrough.
	b.metrics.incFileServed()
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/octet-stream"
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

// fetchRewritten buffers a metadata/gallery document and rewrites every absolute
// upstream-origin URL it embeds to the proxy's public base, so a client's
// extension download (and its checksum/manifest fetches) route back through the
// proxy. Only the configured upstream base URL is rewritten, so external links
// (an extension's source repository, homepage, …) are left intact. If the body
// does not reference the upstream base it is served unchanged.
func (b *Backend) fetchRewritten(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("openvsx %q: reading metadata document: %w", b.name, err)
	}
	if int64(len(data)) > maxMetadataBytes {
		return nil, fmt.Errorf("openvsx %q: metadata document exceeds %d bytes", b.name, maxMetadataBytes)
	}

	body := string(data)
	if strings.Contains(body, b.baseStr) {
		body = strings.ReplaceAll(body, b.baseStr, b.publicBase)
		b.metrics.incMetadataRewrite()
	}

	if resolved.Metadata[metaKind] == "gallery" {
		b.metrics.incGalleryServed()
	} else {
		b.metrics.incMetadataServed()
	}

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	// Content-Length changed by the rewrite; drop any upstream value and let the
	// new byte length drive it.
	header.Del("Content-Length")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(body)),
		Size:      int64(len(body)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchVsix fetches a .vsix archive, recovers the published SHA-256 from the
// sibling .sha256 sidecar, and streams the archive through a verifying reader so
// a hash mismatch aborts the cache write and the client stream.
func (b *Backend) fetchVsix(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	// Resolve the expected digest from the sibling .sha256 sidecar. A missing or
	// malformed sidecar is recorded and the archive is served unverified; fail-open
	// is the only option when the upstream publishes no digest, and the absence is
	// observable via metrics.
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)

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

	b.metrics.incVsixServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	content := resp.Body
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incVsixVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", "sha256")
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: vsixMediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchExpectedChecksum fetches the .sha256 sidecar for the requested .vsix and
// returns the SHA-256 it declares. The sidecar URL is the archive URL with its
// ".vsix" suffix replaced by ".sha256" (OpenVSX's files.sha256 convention). A
// missing, unreadable, or malformed sidecar yields ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	sidecarURL, ok := sha256SidecarURL(resolved.UpstreamURL)
	if !ok {
		return expectedChecksum{}, false
	}
	resp, err := b.get(ctx, sidecarURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxSidecarBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxSidecarBytes {
		return expectedChecksum{}, false
	}
	sha, parsed := parseSHA256Sidecar(body)
	if !parsed {
		return expectedChecksum{}, false
	}
	b.metrics.incSHA256Fetched()
	return expectedChecksum{filename: resolved.Metadata[metaFilename], sha256: sha}, true
}

// sha256SidecarURL derives the .sha256 sidecar URL from a .vsix archive URL by
// replacing the ".vsix" path suffix with ".sha256", preserving the scheme, host,
// and (query-less) path. It returns ok=false for a URL that is not a .vsix path.
func sha256SidecarURL(vsixURL string) (string, bool) {
	u, err := url.Parse(vsixURL)
	if err != nil {
		return "", false
	}
	if !strings.HasSuffix(u.Path, vsixExt) {
		return "", false
	}
	u.Path = strings.TrimSuffix(u.Path, vsixExt) + ".sha256"
	u.RawPath = ""
	u.RawQuery = ""
	return u.String(), true
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

// joinPath appends the inbound OpenVSX path to the upstream base, preserving any
// base-path prefix (e.g. a registry served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A .vsix path pins its version, so the path alone is a content-addressable key;
// query parameters are incidental and excluded.
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
