// Package helm implements a pull-through proxy backend for the Helm ecosystem.
// It covers both transports a Helm client uses to obtain charts, bringing Helm
// to parity with the pip/npm/cargo/go/nuget/maven/rubygems/composer backends:
//
//   - The classic chart-repository protocol (`helm repo add`): a repository
//     publishes an index.yaml enumerating every chart version, the URL its .tgz
//     is served at, and the .tgz's SHA-256 digest. The proxy serves index.yaml
//     live (it is mutable) with every chart URL rewritten to lead back through
//     this mount, so the archive download cannot bypass the proxy even when the
//     repository hosts its archives elsewhere. On a chart cache miss it consults
//     index.yaml for the archive's upstream location and published digest, and
//     verifies the fetched archive against the digest before the bytes are
//     cached or served.
//
//   - OCI-registry-hosted charts (`helm pull oci://`): charts are pushed/pulled
//     as OCI artifacts over the Docker Registry v2 API. The proxy reuses the
//     Docker/OCI backend plumbing (the token handshake, digest-addressed caching,
//     and content-digest verification) and layers Helm-aware coordinate and
//     telemetry on top.
//
// Protocol mapping, classic mode (route prefix "/v1/<name>" stripped):
//
//	GET /index.yaml                       repository index (mutable, chart URLs rewritten).
//	GET /-/<chart>/<version>/<file>       chart archive as the index lists it, on whatever
//	                                      host (immutable, cached, SHA-256-verified).
//	GET /-/<chart>/<version>/<file>.prov  its provenance signature (immutable, cached).
//	GET /<name>-<version>.tgz             chart archive by repository-relative path
//	                                      (immutable, cached, SHA-256-verified).
//	GET /<name>-<version>.tgz.prov        provenance signature (immutable, cached, served as-is).
//
// The "/-/" URLs are the ones a rewritten index hands out. They name an index
// entry, not a location: the backend looks the entry up in the upstream index
// and fetches the location recorded there, so it only ever fetches what the
// upstream itself lists for that chart version (see path.go and rewrite.go).
// That location is an http(s) URL — on the upstream's host or any other — or an
// "oci://" reference, which a classic index may use to point at a chart stored
// in a registry (see oci.go).
//
// Protocol mapping, OCI mode (Registry v2, delegated to the docker backend):
//
//	GET /v2/                              API version / auth probe.
//	GET /v2/<chart>/manifests/<ref>       chart manifest (OCI artifact).
//	GET /v2/<chart>/blobs/<digest>        config and chart-content blobs.
//
// Security model: in classic mode the index.yaml `digest` is the repository's own
// declared SHA-256 of each .tgz; the backend verifies the artifact content
// against it as the bytes stream through, so a tampered or corrupt mirror can
// neither poison the cache nor reach a client. The index is never served with a
// chart URL the backend did not rewrite: a document it cannot fully account for
// is refused rather than passed through. In OCI mode the Registry v2
// content-addressing the docker backend already verifies provides the same
// guarantee. Either way the resolved chart coordinate (name + version) feeds the
// admission pipeline (sigverify, vulnscan via embedded image refs, riskscore,
// policyengine).
//
// Client configuration points Helm at "<publicBase>/v1/<name>" (classic) or
// "oci://<publicHost>/v1/<name>" (OCI); see docs/clients.md.
package helm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/docker"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They mirror the convention used by the
// Maven, RubyGems, and Docker backends and are not persisted as meaningful cache
// data.
const (
	metaKind     = "_kind"     // resource class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the chart .tgz must be checksum-verified
	metaName     = "_name"     // chart name
	metaVersion  = "_version"  // chart version
	metaFilename = "_filename" // archive basename, for the index lookup
	metaIndexed  = "_indexed"  // "1" when the upstream URL is looked up in the index
	metaRewrite  = "_rewrite"  // "1" on the repository index, which is served rewritten
	metaOCI      = "_oci"      // "1" when the request is an OCI manifest (for metrics)
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha256" when a chart was verified against the
	// index digest, or "none" when no digest could be recovered for it.
	MetaChecksumVerified = "helm.checksumVerified"
	// MetaArchiveURL records the upstream URL an index-resolved request was
	// fetched from (without query or credentials), for provenance/diagnostics.
	MetaArchiveURL = "helm.archiveURL"
	// MetaProvenance records "1" on a served chart provenance (.prov) sidecar so
	// the admission pipeline can observe that signed provenance is available.
	MetaProvenance = "helm.provenance"
	// MetaAppVersion records the application version the resolved chart packages.
	MetaAppVersion = "helm.appVersion"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Helm Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "bitnami").
	// Required.
	Name string
	// UpstreamURL is the base URL of the chart repository (classic mode, e.g.
	// "https://charts.bitnami.com/bitnami") or the OCI registry (OCI mode, e.g.
	// "https://registry-1.docker.io"). Required.
	UpstreamURL string
	// PublicBaseURL is this backend's externally reachable base URL
	// ("<publicUrl>/v1/<name>"). In classic mode the chart URLs of the served
	// index.yaml are rewritten to absolute URLs under it. When it is empty or not
	// an absolute http(s) URL (no public URL is configured), they are rewritten
	// to references relative to the repository URL instead, which a Helm client
	// resolves against the URL it added the repository under — so chart downloads
	// flow back through the proxy either way. Unused in OCI mode.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add repository/registry-mirror failover
	// transparently. Every outbound fetch goes through it, including archives
	// the index places on another host or in a registry, so the egress guard it
	// carries applies to those as well.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional; public
	// repositories and registries pull anonymously.
	Credentials upstream.Credentials
	// OCI selects the OCI-registry transport (helm pull oci://) instead of the
	// classic chart-repository protocol. When set, requests are delegated to a
	// Docker Registry v2 pull-through backend.
	OCI bool
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Helm pull-through backend implementing backends.Backend. It
// operates in one of two modes selected at construction: the classic
// chart-repository protocol, or OCI-registry delegation to an embedded docker
// backend.
type Backend struct {
	name    string
	base    *url.URL
	client  upstream.Doer
	creds   upstream.Credentials
	metrics *Metrics
	// oci, when non-nil, is the Registry v2 pull-through backend used to serve
	// OCI-hosted charts; the backend is in OCI mode iff it is set.
	oci *docker.Backend

	// links mints the chart URLs of the rewritten index (classic mode).
	links linker
	// indexSnap is the working copy of the repository index and indexRefresh the
	// one-slot lock serializing its refreshes (see indexcache.go).
	indexSnap    atomic.Pointer[indexSnapshot]
	indexRefresh chan struct{}
	// now is the clock, replaceable in tests.
	now func() time.Time
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend in either classic or OCI mode.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("helm: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("helm %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("helm %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("helm %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("helm %q: upstream client is required", opts.Name)
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	b := &Backend{
		name:         opts.Name,
		base:         base,
		client:       opts.Client,
		creds:        opts.Credentials,
		metrics:      m,
		links:        linker{base: linkBase(opts.PublicBaseURL)},
		indexRefresh: make(chan struct{}, 1),
		now:          time.Now,
	}
	if opts.OCI {
		// Reuse the Docker Registry v2 pull-through plumbing (token handshake,
		// digest-addressed caching, content-digest verification) for OCI charts.
		db, err := docker.New(docker.Options{
			Name:        opts.Name,
			UpstreamURL: opts.UpstreamURL,
			Client:      opts.Client,
			Credentials: opts.Credentials,
		})
		if err != nil {
			return nil, fmt.Errorf("helm %q: building OCI backend: %w", opts.Name, err)
		}
		b.oci = db
	}
	return b, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. In OCI mode it delegates to the embedded
// docker backend (annotating the result for Helm-aware telemetry). In classic
// mode it classifies the inbound path against the Helm chart-repository layout,
// derives the upstream URL and cache key, attaches the chart coordinate for the
// admission gates, and decides cacheability.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("helm: nil request")
	}

	if b.oci != nil {
		resolved, err := b.oci.Resolve(ctx, req)
		if err != nil {
			return nil, err
		}
		// Tag/manifest fetches are the unit of an OCI chart pull; flag them so Fetch
		// can count them as charts served.
		if strings.Contains(req.Path, "/manifests/") {
			if resolved.Metadata == nil {
				resolved.Metadata = map[string]string{}
			}
			resolved.Metadata[metaOCI] = "1"
		}
		return resolved, nil
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Helm chart-repository path", backends.ErrNotSupported, req.Path)
	}

	resolved := &backends.Resolved{
		Cacheable: res.cacheable() && isRead(req),
		Metadata: map[string]string{
			"backend":   b.name,
			metaKind:    res.kindLabel(),
			metaName:    res.name,
			metaVersion: res.version,
		},
	}

	switch {
	case res.indexed:
		// The archive's upstream URL is whatever the repository index lists for
		// this chart version, which is only known once the index is consulted at
		// fetch time (Resolve does no I/O). Until then the resource is identified
		// by the index entry it names. The locator ends in the archive filename
		// because that is what the content gates read off it, and it is the same
		// on a cache hit and a miss; the URL actually fetched is recorded in
		// MetaArchiveURL when the cache is filled.
		entry := res.name + "/" + res.version + "/" + res.filename
		if res.kind == kindProvenance {
			entry += provExt
		}
		resolved.UpstreamURL = b.indexURL() + "#" + entry
		resolved.CacheKey = b.cacheKey(indexedPrefix + "/" + entry)
		resolved.Metadata[metaIndexed] = "1"
	case res.kind == kindIndex && res.root:
		resolved.UpstreamURL = b.indexURL()
		resolved.CacheKey = b.cacheKey(req.Path)
		resolved.Metadata[metaRewrite] = "1"
	default:
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		resolved.UpstreamURL = abs.String()
		resolved.CacheKey = b.cacheKey(req.Path)
	}

	// Attach the chart coordinate so nameguard, policy, provenance, sigverify,
	// vulnscan, license, riskscore, and policyengine can identify the artifact.
	// The repository index addresses no single chart and carries no coordinate.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	switch res.kind {
	case kindChart:
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaFilename] = res.filename
	case kindProvenance:
		resolved.Metadata[MetaProvenance] = "1"
		resolved.Metadata[metaFilename] = res.filename
	}

	return resolved, nil
}

// Fetch implements backends.Backend. In OCI mode it delegates to the docker
// backend's verifying fetch. In classic mode the repository index is served
// rewritten (fetchIndex); an index-resolved archive or provenance request is
// looked up in the index and fetched from the location recorded there
// (fetchIndexed); and a repository-relative path is fetched from under the
// upstream base. A chart archive is verified, as it streams, against the SHA-256
// digest the index publishes for it.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("helm: nil resolved")
	}

	if b.oci != nil {
		res, err := b.oci.Fetch(ctx, resolved)
		if err == nil && res != nil && !res.NotModified && resolved.Metadata[metaOCI] == "1" {
			b.metrics.incOCIChartsServed()
		}
		return res, err
	}

	switch {
	case resolved.Metadata[metaRewrite] == "1":
		return b.fetchIndex(ctx, resolved)
	case resolved.Metadata[metaIndexed] == "1":
		return b.fetchIndexed(ctx, resolved)
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
	})
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: resolved.UpstreamURL, Body: snippet}
	}

	b.recordKindMetric(resolved)
	header := responseHeader(resp)

	// Non-chart resources (provenance sidecars, an index.yaml below the
	// repository root) are proxied without content verification.
	if resolved.Metadata[metaVerify] != "1" {
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: resp.ContentType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	// Recover the expected SHA-256 from the repository index. A missing or
	// unrecoverable digest is recorded and the chart is served unverified
	// (fail-open is the only option when the upstream publishes no digest for the
	// version; the absence is observable via metrics).
	expected, haveChecksum := b.expectedChecksum(ctx, resolved.Metadata[metaName], resolved.Metadata[metaVersion], resolved.Metadata[metaFilename])
	return b.chartResult(resolved, resp, header, expected, haveChecksum, resolved.UpstreamURL), nil
}

// fetchIndexed serves an index-resolved archive (or its provenance sidecar):
// it looks the request up in the repository index and fetches the location the
// index records for that chart version — on whatever host that is — through the
// backend's own upstream client. The request path never contributes to the URL
// fetched, so a client cannot steer the proxy anywhere the upstream index does
// not point; a request for something the index does not list is a 404 answered
// without any archive fetch.
//
// An entry may list several locations for the same archive (mirrors); they are
// tried in the index's order until one answers.
func (b *Backend) fetchIndexed(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	chart, version, file := resolved.Metadata[metaName], resolved.Metadata[metaVersion], resolved.Metadata[metaFilename]

	var locations []chartLocation
	if err := b.lookupIndex(ctx, func(idx *Index) bool {
		locations = idx.locate(chart, version, file)
		return len(locations) > 0
	}); err != nil {
		return nil, err
	}
	if len(locations) == 0 {
		return nil, &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    resolved.UpstreamURL,
			Body:   fmt.Sprintf("the repository index lists no archive %q for chart %q version %q", file, chart, version),
		}
	}

	var lastErr error
	for _, loc := range locations {
		res, err := b.fetchLocation(ctx, resolved, loc)
		if err == nil {
			return res, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// fetchLocation fetches one location the index lists for the requested chart
// version: the archive itself, verified against the digest the same index entry
// declares, or — for a provenance request — the sidecar next to it.
func (b *Backend) fetchLocation(ctx context.Context, resolved *backends.Resolved, loc chartLocation) (*backends.FetchResult, error) {
	// inContext names the chart an error is about; an upstream status inside it
	// is still recognized as one by the gateway.
	inContext := func(err error) error {
		return fmt.Errorf("helm %q: chart %q version %q: %w",
			b.name, resolved.Metadata[metaName], resolved.Metadata[metaVersion], err)
	}
	target, err := b.resolveLocation(loc.URL)
	if err != nil {
		return nil, inContext(err)
	}
	if target.Scheme == ociScheme {
		res, err := b.fetchOCILocation(ctx, resolved, loc, target)
		if err != nil {
			return nil, inContext(err)
		}
		return res, nil
	}
	provenance := resolved.Metadata[MetaProvenance] == "1"
	fetchURL := target.String()
	if provenance {
		// Helm looks for provenance at the chart URL with ".prov" appended.
		fetchURL += provExt
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    fetchURL,
		Method: http.MethodGet,
		Creds:  b.credentialsFor(target),
	})
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return nil, fmt.Errorf("helm %q: upstream answered an unconditional request for %s with 304", b.name, fetchURL)
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: fetchURL, Body: snippet}
	}

	resolved.Metadata[MetaArchiveURL] = displayURL(target)
	header := responseHeader(resp)
	if provenance {
		b.metrics.incProvenanceServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: resp.ContentType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}
	expected, haveChecksum := loc.checksum()
	return b.chartResult(resolved, resp, header, expected, haveChecksum, fetchURL), nil
}

// chartResult wraps a fetched chart archive for the cache: when the index
// publishes a digest for it the body is verified against that digest as it
// streams, so a mismatch fails the cache write and nothing unverified is stored
// or served. A chart the index publishes no digest for is served unverified,
// and counted.
func (b *Backend) chartResult(resolved *backends.Resolved, resp *upstream.Response, header http.Header, expected expectedChecksum, haveChecksum bool, source string) *backends.FetchResult {
	content := resp.Body
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		content = newVerifyingReader(resp.Body, expected, source, func(ok bool) {
			if ok {
				b.metrics.incChartsVerified()
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
		MediaType: resp.ContentType,
		Header:    header,
		Status:    resp.Status,
	}
}

// expectedChecksum recovers the SHA-256 digest the repository index publishes
// for a chart requested by its repository-relative path. It matches the
// requested .tgz basename against the index's per-URL locators (authoritative),
// falling back to an exact (name, version) match. When the index cannot be
// obtained or lists no digest, it reports false.
func (b *Backend) expectedChecksum(ctx context.Context, name, version, filename string) (expectedChecksum, bool) {
	var (
		cv    ChartVersion
		found bool
	)
	if err := b.lookupIndex(ctx, func(idx *Index) bool {
		if cv, found = idx.FindByFilename(filename); !found {
			cv, found = idx.FindVersion(name, version)
		}
		return found
	}); err != nil || !found {
		return expectedChecksum{}, false
	}
	return cv.Checksum()
}

// resolveLocation turns a location listed in the index into the absolute URL to
// fetch. A relative location is resolved against the repository URL the way a
// Helm client resolves it (the repository URL is treated as a directory, and
// its query string carries over). The result is an http(s) URL or an OCI
// reference (see oci.go) — the transports a Helm client would use for it;
// nothing else is fetched.
func (b *Backend) resolveLocation(location string) (*url.URL, error) {
	target, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("the index lists an unusable location: %w", err)
	}
	if !target.IsAbs() {
		base := *b.base
		base.Path = strings.TrimSuffix(base.Path, "/") + "/"
		if base.RawPath != "" {
			base.RawPath = strings.TrimSuffix(base.RawPath, "/") + "/"
		}
		target = base.ResolveReference(target)
		target.RawQuery = base.RawQuery
	}
	switch target.Scheme {
	case "http", "https", ociScheme:
	default:
		return nil, fmt.Errorf("the index lists it at %q; only http(s) and oci locations can be fetched", location)
	}
	if target.Host == "" {
		return nil, fmt.Errorf("the index lists it at %q, which names no host", location)
	}
	target.Fragment = ""
	return target, nil
}

// credentialsFor returns the credentials to present to target: the upstream's
// own, but only when target is the upstream itself (same scheme and host). An
// archive the index places elsewhere — a release asset on another host is the
// common case — must not be sent the repository's credentials. Helm applies the
// same rule to its repository credentials.
func (b *Backend) credentialsFor(target *url.URL) upstream.Credentials {
	if strings.EqualFold(target.Scheme, b.base.Scheme) && strings.EqualFold(target.Host, b.base.Host) {
		return b.creds
	}
	return upstream.Credentials{}
}

// displayURL renders a fetched URL for metadata and diagnostics, without the
// parts that may carry secrets (userinfo, a signed query string).
func displayURL(u *url.URL) string {
	out := *u
	out.User = nil
	out.RawQuery = ""
	out.Fragment = ""
	return out.String()
}

// responseHeader collects the upstream response headers worth relaying with a
// proxied artifact, re-attaching the validators PropagateResponseHeaders
// leaves to the caller.
func responseHeader(resp *upstream.Response) http.Header {
	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}
	return header
}

// linkBase validates a public base URL for use as the prefix of rewritten chart
// URLs and returns it with a trailing slash, or "" when it is not an absolute
// http(s) URL — in which case the rewritten index uses relative references.
func linkBase(publicBaseURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(publicBaseURL), "/")
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	base := u.String() + "/"
	if !quotable(base) {
		return ""
	}
	return base
}

// indexURL is the upstream URL of the repository index.
func (b *Backend) indexURL() string {
	return b.joinPath("/" + indexFile).String()
}

// recordKindMetric counts served index/provenance documents.
func (b *Backend) recordKindMetric(resolved *backends.Resolved) {
	switch resolved.Metadata[metaKind] {
	case "index":
		b.metrics.incIndexServed()
	case "provenance":
		b.metrics.incProvenanceServed()
	}
}

// joinPath appends the inbound Helm path to the upstream base, preserving any
// base-path prefix (e.g. a repository served under "/bitnami").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
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
