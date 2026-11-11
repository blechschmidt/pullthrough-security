// Package ansible implements a pull-through proxy backend for Ansible Galaxy
// (galaxy.ansible.com), the registry for Ansible collections and roles. It
// proxies the Galaxy v3 REST API — collection index, versions list, and
// version-detail metadata, plus the legacy v1 role endpoints — and the
// content-addressable collection artifact tarballs that make up a published
// collection version, bringing the Ansible ecosystem to parity with the
// npm/pip/cargo/maven backends: a collection artifact is cached content-
// addressably beneath its immutable {namespace}-{name}-{version} coordinate,
// fetched bytes are verified against the SHA-256 the version-detail document
// publishes before they are cached or served, and the collection coordinate
// ("namespace.name") is attached for nameguard, vulnscan, provenance, policy,
// and license enforcement.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET .../collections/index/<ns>/<name>/                     collection metadata (mutable, rewritten)
//	GET .../collections/index/<ns>/<name>/versions/            versions list      (mutable, rewritten)
//	GET .../collections/index/<ns>/<name>/versions/<version>/  version detail     (mutable, rewritten)
//	GET .../collections/artifacts/<ns>-<name>-<version>.tar.gz collection tarball (immutable, cacheable, verified)
//
// Security model: an artifact path pins its {namespace}-{name}-{version}
// coordinate in its filename, so the cache key (which embeds the full repository
// path) is itself content-addressable. On a cache miss the backend fetches the
// sibling version-detail document, reads the artifact's published SHA-256 from
// "artifact.sha256", and verifies the fetched bytes against it — streaming, so a
// mismatch aborts the cache write and the client stream without buffering the
// tarball. A tampered mirror can neither poison the cache nor reach a client.
//
// Metadata documents are served with every link into the registry rewritten
// onto the proxy's mount (see rewrite.go): the root-relative links Galaxy uses
// for pagination and cross-references ("links.next", "href", "versions_url",
// ...) gain the mount's path, and absolute upstream URLs — in particular a
// version detail's "download_url" — move to the proxy's PublicBaseURL. A client
// that follows any of them therefore still flows back through the proxy (and
// its content gates and checksum verification) rather than missing the mount or
// reaching the upstream directly.
//
// Galaxy answers its short "/api/v3/collections/..." aliases with a redirect to
// the canonical ".../content/<repo>/collections/index/..." path. The shared
// upstream client normally follows it, and the final document is rewritten as
// above. When the egress policy forbids following, the redirect is relayed to
// the client instead, with its Location mapped onto the mount. A redirect that
// leaves the registry, or one answering an artifact request, is never relayed:
// that request fails, so a client is never steered past the proxy.
//
// OSV coverage: OSV.dev defines no Ansible-Galaxy ecosystem. A collection is
// addressed by a "namespace.name" FQCN that is not an OSV key, so no coordinate
// OSV lookup is performed at the pull layer (see internal/vulnscan/purl.go). The
// collection is still defended by the content, name, provenance, and policy
// gates, and its underlying source repository is covered by the provenance /
// commit-scanning paths.
//
// Client configuration points ansible-galaxy at "<publicBase>/v1/<name>" as a
// Galaxy server (see docs/clients.md).
package ansible

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
	metaKind      = "_kind"      // resource-class label, for diagnostics/gates
	metaVerify    = "_verify"    // "1" when the artifact must be checksum-verified
	metaRewrite   = "_rewrite"   // "1" when the body is a metadata doc to rewrite
	metaIndexBase = "_indexbase" // ".../collections" base for the version-detail lookup
	metaCoord     = "_coord"     // "namespace.name", for diagnostics
	metaNamespace = "_namespace" // collection namespace, for the version-detail lookup
	metaName      = "_name"      // collection name, for the version-detail lookup
	metaVersion   = "_version"   // collection version, for the version-detail lookup
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaVersion records the collection version an artifact is pinned to.
	MetaVersion = "ansible.version"
	// MetaChecksumVerified records "sha256" when a collection artifact was
	// verified against its version-detail digest, or "none" when no digest was
	// available.
	MetaChecksumVerified = "ansible.checksumVerified"
)

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxMetaBytes bounds a metadata document fetch (both the served document and
	// the version-detail lookup performed to resolve an artifact's checksum). These
	// JSON documents are small for a single collection/version but are capped so a
	// hostile upstream cannot return an unbounded body.
	maxMetaBytes = 32 << 20 // 32 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures an Ansible Galaxy Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "ansible").
	// Required.
	Name string
	// UpstreamURL is the Galaxy base URL, e.g. "https://galaxy.ansible.com". The
	// backend appends the "/api/..." repository paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/ansible". Links in served
	// metadata documents and relayed redirects are rewritten onto it so they
	// route back through the proxy: an absolute upstream URL (notably a version
	// detail's "download_url") becomes absolute at this base, and a root-relative
	// link gains this base's path. When empty — or itself root-relative — every
	// rewritten link takes the root-relative "/v1/<name>" form, which only
	// clients that resolve a relative "download_url" (ansible-core 2.19+) can
	// install from.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional; the
	// public galaxy.ansible.com registry pulls anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is an Ansible Galaxy pull-through backend implementing
// backends.Backend.
type Backend struct {
	name    string
	base    *url.URL
	links   *linkRewriter // maps upstream links and redirects onto the mount
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("ansible: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("ansible %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("ansible %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("ansible %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("ansible %q: client is required", opts.Name)
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
		name:    opts.Name,
		base:    base,
		links:   newLinkRewriter(base, publicBase),
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
// the Galaxy layout, derives the upstream URL and cache key, attaches the
// collection coordinate for the admission gates, and decides cacheability (only
// an immutable collection artifact is cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("ansible: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a valid Galaxy path", backends.ErrNotSupported, req.Path)
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
		resolved.Metadata[metaIndexBase] = res.indexBase
		resolved.Metadata[metaNamespace] = res.namespace
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		resolved.Metadata[metaCoord] = res.coordinateName()
		resolved.Metadata[MetaVersion] = res.version
	case kindMetadata:
		resolved.Metadata[metaRewrite] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A collection artifact is verified against
// the SHA-256 its sibling version-detail document declares — streaming so a
// mismatch aborts the cache write and client stream without buffering. Metadata
// documents are buffered and every link they carry into the registry is
// rewritten onto the proxy's mount before they are served; a redirect the
// shared client did not follow is surfaced with its target mapped onto the
// mount so the proxy core can relay it, or refused when it may not be relayed
// (see statusError).
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("ansible: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchArtifact(ctx, resolved)
	}

	resp, err := b.get(ctx, resolved.UpstreamURL, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL, true)
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	// The proxy relays a Location only on a redirect, and only once it is mapped
	// onto the mount (statusError). On a served document these headers would
	// reach the client naming the upstream's own tree, so they are dropped.
	header.Del("Location")
	header.Del("Content-Location")
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	return b.fetchMetadata(resolved, resp, header)
}

// fetchMetadata buffers a metadata document and rewrites every link it carries
// into the registry onto the proxy's mount. A body that does not parse as JSON
// is served unchanged (fail-open), so a non-standard document still reaches the
// client.
func (b *Backend) fetchMetadata(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ansible %q: reading metadata: %w", b.name, err)
	}
	if int64(len(data)) > maxMetaBytes {
		return nil, fmt.Errorf("ansible %q: metadata document exceeds %d bytes", b.name, maxMetaBytes)
	}

	if rewritten, changed := b.links.rewriteDocument(data); changed {
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

// fetchArtifact resolves a collection-artifact request: it reads the sibling
// version-detail document to recover the published SHA-256, then fetches and
// verifies the tarball.
func (b *Backend) fetchArtifact(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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
		// A redirect is never relayed for an artifact: the client would fetch the
		// tarball from wherever it points, past the checksum verification, the
		// cache, and the content gates that are bound to this artifact path.
		return nil, b.statusError(resp, resolved.UpstreamURL, false)
	}

	b.metrics.incArtifactsServed()

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
				b.metrics.incArtifactsVerified()
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

// fetchExpectedChecksum fetches the sibling version-detail document for a
// collection artifact and returns the lowercase hex SHA-256 its "artifact"
// object declares. A missing or unparseable document, or an absent/malformed
// digest, yields ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (string, bool) {
	indexBase := resolved.Metadata[metaIndexBase]
	ns := resolved.Metadata[metaNamespace]
	name := resolved.Metadata[metaName]
	version := resolved.Metadata[metaVersion]
	if indexBase == "" || ns == "" || name == "" || version == "" {
		return "", false
	}
	metaURL := b.versionDetailURL(indexBase, ns, name, version)
	resp, err := b.get(ctx, metaURL, "")
	if err != nil {
		return "", false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return "", false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetaBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxMetaBytes {
		return "", false
	}
	vd, perr := parseVersionDetail(body)
	if perr != nil {
		return "", false
	}
	b.metrics.incVersionMetaFetched()
	return vd.sha256()
}

// versionDetailURL builds the upstream version-detail URL for a collection
// coordinate from the artifact path's ".../collections" index base.
func (b *Backend) versionDetailURL(indexBase, ns, name, version string) string {
	path := strings.TrimRight(indexBase, "/") + "/index/" + ns + "/" + name + "/versions/" + version + "/"
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

// errRedirectNotRelayed marks an upstream redirect that the shared client did
// not follow and that the proxy must not hand on to the client. It is
// deliberately not a StatusError: relaying the bare 3xx would give the client a
// redirect with no target, which a tool that follows redirects takes for a
// successful answer, so the fetch fails as a gateway error instead.
var errRedirectNotRelayed = errors.New("upstream redirect was not followed and cannot be relayed")

// statusError drains the body of a non-success upstream response and returns
// the error to surface for it.
//
// An ordinary failure becomes a StatusError carrying a diagnostic snippet. A
// redirect only reaches the backend when the shared client did not follow it
// (the egress policy can forbid following). With relayRedirect set, such a
// redirect becomes a StatusError carrying its target mapped onto the mount, so
// the proxy core relays a redirect the client can follow back through this
// backend. Otherwise — relaying is off, or the target lies outside the proxied
// tree — it becomes errRedirectNotRelayed: the client is never steered past the
// proxy.
func (b *Backend) statusError(resp *upstream.Response, rawURL string, relayRedirect bool) error {
	if !isRedirect(resp.Status) {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return &backends.StatusError{Status: resp.Status, URL: rawURL, Body: snippet}
	}
	drainClose(resp.Body)
	if !relayRedirect {
		return fmt.Errorf("ansible %q: %w (status %d): an artifact is served only from its own verified path",
			b.name, errRedirectNotRelayed, resp.Status)
	}
	location, ok := b.links.location(rawURL, resp.Header.Get("Location"))
	if !ok {
		return fmt.Errorf("ansible %q: %w (status %d): its target is outside the registry",
			b.name, errRedirectNotRelayed, resp.Status)
	}
	return &backends.StatusError{Status: resp.Status, URL: rawURL, Location: location}
}

// isRedirect reports whether status is a redirect whose Location a client
// follows automatically.
func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// joinPath appends the inbound Galaxy path to the upstream base, preserving any
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
