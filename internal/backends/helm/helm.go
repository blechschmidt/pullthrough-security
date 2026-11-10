// Package helm implements a pull-through proxy backend for the Helm ecosystem.
// It covers both transports a Helm client uses to obtain charts, bringing Helm
// to parity with the pip/npm/cargo/go/nuget/maven/rubygems/composer backends:
//
//   - The classic chart-repository protocol (`helm repo add`): a repository
//     publishes an index.yaml enumerating every chart version, the URL its .tgz
//     is served at, and the .tgz's SHA-256 digest. The proxy serves index.yaml
//     live (it is mutable), and on a chart .tgz cache miss it fetches and parses
//     index.yaml to recover the published digest and verifies the fetched archive
//     against it before the bytes are cached or served.
//
//   - OCI-registry-hosted charts (`helm pull oci://`): charts are pushed/pulled
//     as OCI artifacts over the Docker Registry v2 API. The proxy reuses the
//     Docker/OCI backend plumbing (the token handshake, digest-addressed caching,
//     and content-digest verification) and layers Helm-aware coordinate and
//     telemetry on top.
//
// Protocol mapping, classic mode (route prefix "/v1/<name>" stripped):
//
//	GET /index.yaml                       repository index (mutable, parsed).
//	GET /<name>-<version>.tgz             chart archive (immutable, cached, SHA-256-verified).
//	GET /<name>-<version>.tgz.prov        provenance signature (immutable, cached, served as-is).
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
// neither poison the cache nor reach a client. In OCI mode the Registry v2
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
	metaName     = "_name"     // parsed chart name
	metaVersion  = "_version"  // parsed chart version
	metaFilename = "_filename" // .tgz basename, for authoritative index lookup
	metaOCI      = "_oci"      // "1" when the request is an OCI manifest (for metrics)
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha256" when a chart was verified against the
	// index digest, or "none" when no digest could be recovered for it.
	MetaChecksumVerified = "helm.checksumVerified"
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
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add repository/registry-mirror failover
	// transparently.
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
		name:    opts.Name,
		base:    base,
		client:  opts.Client,
		creds:   opts.Credentials,
		metrics: m,
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

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	cacheable := res.cacheable() && isRead(req)
	resolved := &backends.Resolved{
		UpstreamURL: abs.String(),
		Cacheable:   cacheable,
		CacheKey:    b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend":   b.name,
			metaKind:    res.kindLabel(),
			metaName:    res.name,
			metaVersion: res.version,
		},
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
	}

	return resolved, nil
}

// Fetch implements backends.Backend. In OCI mode it delegates to the docker
// backend's verifying fetch. In classic mode, for a chart .tgz it fetches and
// parses the repository index, recovers the published SHA-256 digest, and
// verifies the streamed archive against it; the index and provenance sidecars
// are proxied directly.
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

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	// Non-chart resources (index, provenance sidecars) are proxied without
	// content verification.
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
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved.Metadata[metaName], resolved.Metadata[metaVersion], resolved.Metadata[metaFilename])
	content := resp.Body
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
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
	}, nil
}

// fetchExpectedChecksum fetches the repository index.yaml and recovers the
// SHA-256 digest published for the requested chart. It matches the requested
// .tgz basename against the index's per-URL locators (authoritative), falling
// back to an exact (name, version) match.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, name, version, filename string) (expectedChecksum, bool) {
	indexURL := b.joinPath("/" + indexFile).String()
	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    indexURL,
		Method: http.MethodGet,
		Creds:  b.creds,
	})
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxIndexBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxIndexBytes {
		return expectedChecksum{}, false
	}
	idx, perr := ParseIndex(body)
	if perr != nil {
		b.metrics.incIndexErrors()
		return expectedChecksum{}, false
	}
	b.metrics.incIndexParsed()

	cv, ok := idx.FindByFilename(filename)
	if !ok {
		cv, ok = idx.FindVersion(name, version)
	}
	if !ok {
		return expectedChecksum{}, false
	}
	return cv.Checksum()
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
