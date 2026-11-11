// Package terraform implements a pull-through proxy backend for the
// Terraform/OpenTofu registry protocols, bringing Infrastructure-as-Code
// providers and modules to parity with the other ecosystem backends. IaC
// providers run with broad privilege at plan/apply time, so they are a
// high-value supply-chain target; this backend caches them and independently
// verifies their integrity and authenticity before they reach a client.
//
// It covers both registry protocols a Terraform/OpenTofu client speaks, behind a
// synthesized service-discovery document:
//
//   - The module registry protocol (`module "x" { source = "<host>/ns/name/sys" }`):
//     the client lists versions, then asks the download endpoint for the module
//     source, which answers with an X-Terraform-Get go-getter URL. The proxy
//     resolves that URL and rewrites it so the source archive is fetched and
//     cached through the proxy (for plain HTTP(S) sources; other getters are
//     passed through).
//
//   - The provider registry protocol (`required_providers`): the client lists
//     versions, then asks the download endpoint for a concrete os/arch package,
//     which answers with the release ZIP URL, the signed SHA256SUMS manifest and
//     its detached GPG signature, the expected ZIP SHA-256, and the provider's
//     trusted signing keys. The proxy rewrites those URLs to flow through (and be
//     cached by) the proxy, and — the cornerstone guarantee — on a cache miss it
//     independently verifies that the ZIP hashes to the SHASUMS-declared digest
//     and that the SHASUMS manifest carries a valid signature from a
//     registry-asserted key. A digest mismatch or an invalid signature aborts the
//     cache write and the response; the signature status is surfaced to the
//     admission pipeline.
//
// Client configuration points Terraform/OpenTofu at the proxy host with this
// backend mounted at "/v1/<name>" (see docs/clients.md); setting server.publicUrl
// is recommended so the rewritten artifact URLs are absolute.
package terraform

import (
	"bytes"
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
// Maven and Helm backends and are not persisted as meaningful cache data.
const (
	metaKind = "_kind" // resource-class label, for diagnostics/gates
	metaPath = "_path" // original (prefix-stripped) request path, for re-classification in Fetch
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records "sha256" when a provider ZIP was verified
	// against its signed SHASUMS manifest, or "none" when no digest was available.
	MetaChecksumVerified = "terraform.checksumVerified"
	// MetaSignatureVerified records the SHASUMS-signature outcome: "verified",
	// "unsigned", or "invalid" (the last is a hard failure and never served).
	MetaSignatureVerified = "terraform.signatureVerified"
	// MetaSigningKeyID records the GPG key id the registry asserts for the provider.
	MetaSigningKeyID = "terraform.signingKeyId"
	// MetaFilename records the provider release ZIP basename.
	MetaFilename = "terraform.filename"
)

// routePrefix mirrors the gateway's backend mount ("/v1/<name>/..."). It is used
// to synthesize the service-discovery document's endpoint paths.
const routePrefix = "/v1/"

// Size bounds for the small documents the backend buffers and parses on the pull
// path. They cap a hostile upstream that returns a huge body in place of a
// descriptor, manifest, or signature.
const (
	maxDescriptorBytes  = 1 << 20 // 1 MiB: provider/module JSON descriptors
	maxShasumsBytes     = 4 << 20 // 4 MiB: SHA256SUMS manifest
	maxSignatureBytes   = 64 << 10
	maxErrorBodySnippet = 2 << 10
)

// Options configures a Terraform Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "terraform-registry").
	// Required.
	Name string
	// UpstreamURL is the registry base URL, e.g. "https://registry.terraform.io"
	// (or "https://registry.opentofu.org"). Required.
	UpstreamURL string
	// PublicBaseURL is this backend's externally reachable base URL
	// ("<publicUrl>/v1/<name>"), used to rewrite artifact URLs so they flow through
	// the proxy. When it carries no scheme (the proxy's publicUrl is unset) the
	// backend cannot emit absolute rewritten URLs and falls back to passing the
	// upstream artifact URLs through unmodified (no caching/verification of those
	// artifacts); this is recorded via metrics. Optional but recommended.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// registry-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional;
	// public registries pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Terraform/OpenTofu registry pull-through backend implementing
// backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	publicBase string
	canRewrite bool
	client     upstream.Doer
	creds      upstream.Credentials
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("terraform: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("terraform %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("terraform %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("terraform %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("terraform %q: upstream client is required", opts.Name)
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	canRewrite := strings.HasPrefix(publicBase, "http://") || strings.HasPrefix(publicBase, "https://")
	return &Backend{
		name:       opts.Name,
		base:       base,
		publicBase: publicBase,
		canRewrite: canRewrite,
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
// the Terraform registry layout, derives the upstream URL and cache key, attaches
// the module/provider coordinate for the admission gates, and decides
// cacheability (only the immutable proxy-synthetic artifacts are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("terraform: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Terraform registry path", backends.ErrNotSupported, req.Path)
	}

	resolved := &backends.Resolved{
		Cacheable: res.cacheable() && isRead(req),
		CacheKey:  b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
			metaPath:  req.Path,
		},
		Artifact: res.artifact(),
	}
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	// The upstream URL the proxy fetches depends on the resource. Synthetic
	// artifact endpoints re-derive their bytes from the upstream descriptor/download
	// endpoint (recorded here); discovery is synthesized with no upstream fetch.
	switch res.kind {
	case kindDiscovery:
		resolved.UpstreamURL = ""
	case kindModuleArchive:
		resolved.UpstreamURL = b.moduleDownloadURL(res)
	case kindProviderZip, kindProviderShasums, kindProviderShasumsSig:
		resolved.UpstreamURL = b.providerDescriptorURL(res)
	default:
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		resolved.UpstreamURL = abs.String()
	}

	return resolved, nil
}

// Fetch implements backends.Backend. It dispatches on the resolved resource
// kind: discovery is synthesized; version lists, descriptors, and registry
// metadata are proxied (the module download and provider descriptor are rewritten
// so artifacts flow through the proxy); and the synthetic artifact endpoints
// fetch, verify, and cache the actual bytes.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("terraform: nil resolved")
	}
	res, ok := classify(resolved.Metadata[metaPath])
	if !ok {
		return nil, fmt.Errorf("terraform %q: cannot re-classify %q", b.name, resolved.Metadata[metaPath])
	}

	switch res.kind {
	case kindDiscovery:
		return b.fetchDiscovery(resolved), nil
	case kindModuleDownload:
		return b.fetchModuleDownload(ctx, resolved, res)
	case kindModuleArchive:
		return b.fetchModuleArchive(ctx, resolved, res)
	case kindProviderDownload:
		return b.fetchProviderDownload(ctx, resolved, res)
	case kindProviderZip:
		return b.fetchProviderZip(ctx, resolved, res)
	case kindProviderShasums:
		return b.fetchProviderShasums(ctx, resolved, res, false)
	case kindProviderShasumsSig:
		return b.fetchProviderShasums(ctx, resolved, res, true)
	default:
		return b.proxyDirect(ctx, resolved, res)
	}
}

// fetchDiscovery synthesizes the service-discovery document advertising this
// backend's module and provider endpoints (host-absolute paths under the
// backend's mount, so they resolve regardless of the proxy's external host).
func (b *Backend) fetchDiscovery(resolved *backends.Resolved) *backends.FetchResult {
	mount := routePrefix + b.name
	doc := fmt.Sprintf(`{"modules.v1":%q,"providers.v1":%q}`,
		mount+"/v1/modules/", mount+"/v1/providers/")
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(doc)),
		Size:      int64(len(doc)),
		MediaType: "application/json",
		Header:    header,
		Status:    http.StatusOK,
	}
}

// proxyDirect proxies a live registry document (version lists, metadata) without
// modification, recording the per-kind metric.
func (b *Backend) proxyDirect(ctx context.Context, resolved *backends.Resolved, res resource) (*backends.FetchResult, error) {
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
	switch res.kind {
	case kindModuleVersions:
		b.metrics.incModuleVersions()
	case kindProviderVersions:
		b.metrics.incProviderVersions()
	}
	return b.streamResult(resolved, resp, resp.Body, resp.ContentType), nil
}

// fetchModuleDownload proxies the module download endpoint and rewrites its
// X-Terraform-Get header so the source archive is fetched through the proxy. When
// the source is not a plain HTTP(S) getter (or no absolute public base is
// configured, or the request is for the latest version with no version in the
// path) the original header is passed through unchanged.
func (b *Backend) fetchModuleDownload(ctx context.Context, resolved *backends.Resolved, res resource) (*backends.FetchResult, error) {
	resp, err := b.get(ctx, resolved.UpstreamURL, "")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}
	b.metrics.incModuleDownloads()

	getURL := resp.Header.Get("X-Terraform-Get")
	drainClose(resp.Body)

	header := make(http.Header)
	if g, ok := parseTerraformGet(getURL); ok && g.cacheable() && b.canRewrite && res.version != "" {
		header.Set("X-Terraform-Get", g.rewrite(b.publicArchiveURL(res)))
	} else if getURL != "" {
		header.Set("X-Terraform-Get", getURL)
		b.metrics.incModuleArchivePassed()
	}
	// The download endpoint is a metadata response (typically 204 No Content); the
	// archive bytes arrive on the separate archive request.
	status := resp.Status
	if status == http.StatusOK {
		// Normalize a 200-with-empty-body to 204 so the client treats it as a
		// header-only response.
		status = http.StatusNoContent
	}
	return &backends.FetchResult{
		Resolved: resolved,
		Content:  io.NopCloser(bytes.NewReader(nil)),
		Size:     0,
		Header:   header,
		Status:   status,
	}, nil
}

// fetchModuleArchive resolves the module download endpoint's X-Terraform-Get to
// the source archive URL, then fetches and caches the archive bytes.
func (b *Backend) fetchModuleArchive(ctx context.Context, resolved *backends.Resolved, res resource) (*backends.FetchResult, error) {
	// resolved.UpstreamURL is the upstream module download endpoint.
	resp, err := b.get(ctx, resolved.UpstreamURL, "")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}
	getURL := resp.Header.Get("X-Terraform-Get")
	drainClose(resp.Body)

	g, ok := parseTerraformGet(getURL)
	if !ok || !g.cacheable() {
		return nil, fmt.Errorf("terraform %q: module %s has no cacheable HTTP(S) source archive (X-Terraform-Get=%q)",
			b.name, res.coordinateName(), getURL)
	}

	arc, err := b.get(ctx, g.url, "")
	if err != nil {
		return nil, err
	}
	if !arc.IsSuccess() {
		return nil, b.statusError(arc, g.url)
	}
	b.metrics.incModuleArchives()
	mediaType := arc.ContentType
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	return b.streamResult(resolved, arc, arc.Body, mediaType), nil
}

// fetchProviderDownload proxies the provider package descriptor and rewrites its
// download_url / shasums_url / shasums_signature_url to proxy-synthetic endpoints
// so the ZIP and signature material flow through (and are cached/verified by) the
// proxy. Every other field — protocols, shasum, signing_keys — is preserved so
// the client's own verification still succeeds. When no absolute public base is
// configured the descriptor is passed through unmodified.
func (b *Backend) fetchProviderDownload(ctx context.Context, resolved *backends.Resolved, res resource) (*backends.FetchResult, error) {
	resp, err := b.get(ctx, resolved.UpstreamURL, "")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}
	data, err := readAllLimited(resp.Body, maxDescriptorBytes)
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("terraform %q: reading provider descriptor: %w", b.name, err)
	}
	b.metrics.incProviderDownloads()

	out := data
	if b.canRewrite {
		if _, perr := parseProviderPackage(data); perr != nil {
			b.metrics.incJSONParseErrors()
		} else if rewritten, rerr := rewriteProviderPackage(data,
			b.publicProviderURL(res, "zip"),
			b.publicProviderURL(res, "shasums"),
			b.publicProviderURL(res, "shasums.sig")); rerr == nil {
			out = rewritten
		}
	} else {
		b.metrics.incModuleArchivePassed()
	}

	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(out)),
		Size:      int64(len(out)),
		MediaType: "application/json",
		Header:    header,
		Status:    http.StatusOK,
	}, nil
}

// fetchProviderZip re-derives the provider package descriptor, verifies the
// SHASUMS manifest's GPG signature against the registry-asserted keys and the
// ZIP's SHA-256 against the signed manifest, then streams and caches the ZIP. A
// present-but-invalid signature or a digest mismatch aborts the response so
// unverified bytes are never cached or served.
func (b *Backend) fetchProviderZip(ctx context.Context, resolved *backends.Resolved, res resource) (*backends.FetchResult, error) {
	pkg, err := b.fetchDescriptor(ctx, resolved.UpstreamURL)
	if err != nil {
		return nil, err
	}

	// Recover and verify the signed SHASUMS manifest first, so a forged signature
	// is rejected before any ZIP bytes are fetched.
	expected, haveChecksum, sigStatus, err := b.verifyManifest(ctx, pkg)
	if err != nil {
		return nil, err
	}

	resolved.Metadata[MetaFilename] = pkg.Filename
	switch sigStatus {
	case sigVerified:
		b.metrics.incSignatureVerified()
		resolved.Metadata[MetaSignatureVerified] = string(sigVerified)
		if kid := pkg.primaryKeyID(); kid != "" {
			resolved.Metadata[MetaSigningKeyID] = kid
		}
	default:
		b.metrics.incSignatureMissing()
		resolved.Metadata[MetaSignatureVerified] = string(sigUnsigned)
	}

	zip, err := b.get(ctx, pkg.DownloadURL, "")
	if err != nil {
		return nil, err
	}
	if !zip.IsSuccess() {
		return nil, b.statusError(zip, pkg.DownloadURL)
	}

	header := make(http.Header)
	header.Set("Content-Disposition", "attachment; filename="+headerSafe(pkg.Filename))
	if sigStatus == sigVerified {
		header.Set("X-Terraform-Signature", "verified")
	} else {
		header.Set("X-Terraform-Signature", "unsigned")
	}

	content := zip.Body
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		header.Set("X-Checksum-Verified", "sha256")
		content = newVerifyingReader(zip.Body, expected, pkg.DownloadURL, func(okv bool) {
			if okv {
				b.metrics.incProvidersVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	mediaType := zip.ContentType
	if mediaType == "" {
		mediaType = "application/zip"
	}
	return b.streamResult(resolved, zip, content, mediaType), nil
}

// verifyManifest fetches the SHASUMS manifest and its detached signature for a
// provider package, verifies the signature against the registry-asserted keys,
// and recovers the manifest-declared SHA-256 for the package filename. A
// present-but-invalid signature is a hard error. A missing manifest (or a
// filename absent from it) yields haveChecksum=false (fail-open: served
// unverified, recorded via metrics) rather than an error.
func (b *Backend) verifyManifest(ctx context.Context, pkg *providerPackage) (expectedChecksum, bool, signatureStatus, error) {
	if pkg.ShasumsURL == "" {
		return expectedChecksum{}, false, sigUnsigned, nil
	}
	shaResp, err := b.get(ctx, pkg.ShasumsURL, "")
	if err != nil {
		return expectedChecksum{}, false, sigUnsigned, nil
	}
	if !shaResp.IsSuccess() {
		drainClose(shaResp.Body)
		return expectedChecksum{}, false, sigUnsigned, nil
	}
	shasums, rerr := readAllLimited(shaResp.Body, maxShasumsBytes)
	drainClose(shaResp.Body)
	if rerr != nil {
		return expectedChecksum{}, false, sigUnsigned, nil
	}

	// Verify the manifest's detached signature against the registry-asserted keys.
	var sig []byte
	if pkg.ShasumsSignatureURL != "" {
		if sResp, serr := b.get(ctx, pkg.ShasumsSignatureURL, ""); serr == nil {
			if sResp.IsSuccess() {
				sig, _ = readAllLimited(sResp.Body, maxSignatureBytes)
			}
			drainClose(sResp.Body)
		}
	}
	status, sigErr := verifySHASUMSSignature(shasums, sig, pkg.armoredKeys(), pkg.ShasumsSignatureURL)
	if sigErr != nil {
		b.metrics.incSignatureFailed()
		return expectedChecksum{}, false, status, sigErr
	}

	// Recover the SHA-256 declared for this package and cross-check it against the
	// descriptor's own shasum field (when present); a disagreement is tampering.
	sums := parseSHASUMS(shasums)
	hexsum, ok := sums[pkg.Filename]
	if !ok {
		return expectedChecksum{}, false, status, nil
	}
	if declared, dok := normalizeHex(pkg.Shasum); dok && declared != hexsum {
		return expectedChecksum{}, false, status, &ChecksumMismatchError{
			Expected: "sha256:" + hexsum,
			Actual:   "sha256:" + declared,
			URL:      pkg.ShasumsURL,
		}
	}
	return expectedChecksum{hex: hexsum}, true, status, nil
}

// fetchProviderShasums proxies the SHASUMS manifest (sig=false) or its detached
// signature (sig=true) for a provider package, re-derived from the descriptor.
// These cached, served-as-is endpoints let the client's own verification run
// entirely through the proxy.
func (b *Backend) fetchProviderShasums(ctx context.Context, resolved *backends.Resolved, res resource, sig bool) (*backends.FetchResult, error) {
	pkg, err := b.fetchDescriptor(ctx, resolved.UpstreamURL)
	if err != nil {
		return nil, err
	}
	target := pkg.ShasumsURL
	mediaType := "text/plain; charset=utf-8"
	if sig {
		target = pkg.ShasumsSignatureURL
		mediaType = "application/octet-stream"
	}
	if target == "" {
		return nil, fmt.Errorf("terraform %q: provider descriptor has no %s URL", b.name, map[bool]string{false: "shasums", true: "signature"}[sig])
	}
	resp, err := b.get(ctx, target, "")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, target)
	}
	ct := resp.ContentType
	if ct == "" {
		ct = mediaType
	}
	return b.streamResult(resolved, resp, resp.Body, ct), nil
}

// fetchDescriptor fetches and parses a provider package descriptor from the
// upstream registry.
func (b *Backend) fetchDescriptor(ctx context.Context, descriptorURL string) (*providerPackage, error) {
	resp, err := b.get(ctx, descriptorURL, "")
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, descriptorURL)
	}
	data, rerr := readAllLimited(resp.Body, maxDescriptorBytes)
	drainClose(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("terraform %q: reading provider descriptor: %w", b.name, rerr)
	}
	pkg, perr := parseProviderPackage(data)
	if perr != nil {
		b.metrics.incJSONParseErrors()
		return nil, perr
	}
	return pkg, nil
}

// streamResult builds a FetchResult that propagates upstream caching headers and
// streams content (which may be a verifying wrapper around resp.Body).
func (b *Backend) streamResult(resolved *backends.Resolved, resp *upstream.Response, content io.ReadCloser, mediaType string) *backends.FetchResult {
	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}
	if mediaType != "" {
		header.Set("Content-Type", mediaType)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}
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

// moduleDownloadURL builds the upstream module download endpoint for a module
// archive request (the proxy re-fetches it to recover X-Terraform-Get).
func (b *Backend) moduleDownloadURL(res resource) string {
	return b.joinPath("/v1/modules/" + res.namespace + "/" + res.name + "/" + res.system + "/" + res.version + "/download").String()
}

// providerDescriptorURL builds the upstream provider package descriptor endpoint
// for a synthetic provider artifact request.
func (b *Backend) providerDescriptorURL(res resource) string {
	return b.joinPath("/v1/providers/" + res.namespace + "/" + res.name + "/" + res.version + "/download/" + res.os + "/" + res.arch).String()
}

// publicArchiveURL is the proxy-side module archive endpoint for X-Terraform-Get
// rewriting.
func (b *Backend) publicArchiveURL(res resource) string {
	return b.publicBase + "/v1/modules/" + res.namespace + "/" + res.name + "/" + res.system + "/" + res.version + "/archive"
}

// publicProviderURL is the proxy-side provider artifact endpoint (suffix "zip",
// "shasums", or "shasums.sig") for descriptor rewriting.
func (b *Backend) publicProviderURL(res resource, suffix string) string {
	return b.publicBase + "/v1/providers/" + res.namespace + "/" + res.name + "/" + res.version + "/download/" + res.os + "/" + res.arch + "/" + suffix
}

// joinPath appends the given registry path to the upstream base, preserving any
// base-path prefix.
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

// readAllLimited reads up to max bytes, returning an error if the source exceeds
// the bound (so a hostile oversized body is rejected rather than truncated).
func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > max {
		return nil, fmt.Errorf("terraform: body exceeds %d bytes", max)
	}
	return buf, nil
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

// headerSafe strips characters that are unsafe in an HTTP header value.
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
