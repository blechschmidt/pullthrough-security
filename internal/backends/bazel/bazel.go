// Package bazel implements a pull-through proxy backend for the Bazel Central
// Registry (bcr.bazel.build) and Bzlmod-format module registries. It proxies the
// registry's static HTTP tree — the per-module metadata.json, the per-version
// MODULE.bazel and source.json descriptors, module patches, and the external
// source archives source.json references — bringing Bazel's module ecosystem to
// parity with the pip/npm/cargo/maven/conan/conda/cran/hex backends: source
// archives are cached content-addressably beneath their immutable
// name/version coordinate, fetched bytes are verified against the
// Subresource-Integrity ("integrity") digest source.json declares before they
// are cached or served, and the module coordinate (name/version) is attached for
// nameguard, vulnscan, provenance, policy, and license enforcement.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /bazel_registry.json                        registry config    (mutable, live)
//	GET /modules/<name>/metadata.json               module metadata    (mutable, live)
//	GET /modules/<name>/<version>/MODULE.bazel      module file        (immutable, cacheable)
//	GET /modules/<name>/<version>/source.json       source descriptor  (rewritten, live)
//	GET /modules/<name>/<version>/patches/<file>    module patch       (immutable, cacheable)
//	GET /modules/<name>/<version>/overlay/<path>    module overlay file (immutable, cacheable)
//	GET /modules/<name>/<version>/archive[/<file>]  source archive     (proxy-synthetic, verified, cacheable)
//
// Security model: a module version pins its source archive, and source.json
// records that archive's SRI integrity digest — the ecosystem's own integrity
// record, which Bazel itself verifies. The archive lives at an arbitrary
// external URL, so the backend rewrites source.json's "url" to a
// proxy-synthetic "/modules/<name>/<version>/archive/<file>" endpoint (and drops
// "mirror_urls", so no declared location lets a client fetch around the proxy);
// a request to that endpoint re-reads source.json, resolves the external URL and
// the expected integrity, fetches the archive, and verifies the fetched bytes
// against the SRI — streaming, so a mismatch aborts the cache write and the
// client stream without buffering the archive. A tampered mirror can neither
// poison the cache nor reach a client. source.json's integrity is left
// byte-exact in the rewritten descriptor, so a Bazel client still performs its
// own end-to-end verification.
//
// The <file> segment is the upstream archive's own file name. Bazel infers the
// archive format from the suffix of the URL's last path segment, so the endpoint
// has to end in one ("platforms-0.0.10.tar.gz"); the bare ".../archive" form
// remains valid and addresses the same cache entry (see path.go).
//
// OSV coverage: Bazel modules are intentionally not OSV-scanned by coordinate —
// OSV.dev defines no Bazel-module ecosystem (see internal/vulnscan/purl.go). A
// module's security posture is instead carried by its underlying source
// repository (commonly GitHub), which the provenance/commit-scanning paths
// cover. This mirrors the conda decision.
//
// Client configuration points Bazel at "<publicBase>/v1/<name>" (see
// docs/clients.md): add `--registry=<publicBase>/v1/<name>` to .bazelrc, or pass
// it on the command line.
package bazel

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
// Conda, CRAN, Hex, and Dart backends and are not persisted to the cache as
// meaningful data.
const (
	metaKind    = "_kind"    // resource-class label, for diagnostics/gates
	metaName    = "_name"    // module name, for source.json lookup
	metaVersion = "_version" // module version, for source.json lookup
	metaRewrite = "_rewrite" // "1" when a source.json body must be URL-rewritten
	metaVerify  = "_verify"  // "1" when the resource is the verifiable archive
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records the SRI algorithm ("sha256"/"sha384"/"sha512")
	// when an archive was verified against source.json's integrity, or "none" when
	// no integrity was available.
	MetaChecksumVerified = "bazel.checksumVerified"
	// MetaArchiveURL records the external source-archive URL an archive request
	// resolved to, for provenance/diagnostics.
	MetaArchiveURL = "bazel.archiveURL"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Bazel registry Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "bazel"). Required.
	Name string
	// UpstreamURL is the registry base URL, e.g. "https://bcr.bazel.build". The
	// backend appends the "/modules/..." and "/bazel_registry.json" registry
	// paths. Required.
	UpstreamURL string
	// PublicBaseURL is this backend's externally reachable base URL
	// ("<publicUrl>/v1/<name>"), used to rewrite source.json archive URLs so they
	// flow through (and are verified by) the proxy. When empty (or not absolute)
	// source.json is passed through unchanged and archive fetches are not proxied.
	PublicBaseURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool (and the egress allowlist)
	// can be injected transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry. Optional; the
	// public BCR pulls anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Bazel registry pull-through backend implementing
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
		return nil, errors.New("bazel: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("bazel %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("bazel %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("bazel %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("bazel %q: upstream client is required", opts.Name)
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
// the Bazel registry layout, derives the upstream URL and cache key, attaches
// the module coordinate for the admission gates, and decides cacheability (only
// the immutable per-version files and the proxy-synthetic archive are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("bazel: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Bazel registry path", backends.ErrNotSupported, req.Path)
	}

	resolved := &backends.Resolved{
		Cacheable: res.cacheable() && isRead(req),
		CacheKey:  b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
		Artifact: res.artifact(),
	}

	// The upstream URL depends on the resource. The synthetic archive endpoint
	// records the module's source.json URL (re-read at fetch time to resolve the
	// external archive); every other resource maps straight to its registry path.
	if res.kind == kindArchive {
		resolved.UpstreamURL = b.sourceURL(res.name, res.version)
		// The file name that may trail the endpoint is cosmetic (it tells Bazel the
		// archive format), so every spelling of the endpoint shares one cache entry
		// — the one the bare ".../archive" form has always used. A client therefore
		// cannot multiply cache entries for an archive by varying the name.
		resolved.CacheKey = b.cacheKey(archivePath(res.name, res.version))
	} else {
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		resolved.UpstreamURL = abs.String()
	}

	// Attach the coordinate and qualifiers so nameguard, policy, provenance,
	// vulnscan, license, and policyengine can identify the artifact.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		resolved.Metadata[metaName] = res.name
		if res.version != "" {
			resolved.Metadata[metaVersion] = res.version
		}
	}

	if res.verifiableArchive() {
		resolved.Metadata[metaVerify] = "1"
	}
	if res.kind == kindSource && b.canRewrite {
		resolved.Metadata[metaRewrite] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. It dispatches on the resolved resource: the
// synthetic archive endpoint re-reads source.json and fetches+verifies the
// external archive; source.json is rewritten so archive URLs flow through the
// proxy; everything else is proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("bazel: nil resolved")
	}

	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchArchive(ctx, resolved)
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

	// source.json is rewritten so its archive URL points at the proxy's synthetic
	// archive endpoint (see rewriteSourceJSON). A body that does not parse is
	// served unchanged (fail-open).
	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchSource(resolved, resp, header)
	}

	b.metrics.incIndexServed()
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: b.mediaType(resolved, resp.ContentType),
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchSource buffers the source.json body, rewrites its archive URL to the
// proxy's synthetic archive endpoint (dropping any mirror URLs), and returns the
// rewritten bytes. A body that does not decode to a JSON object, declares no
// archive URL, or describes a non-archive source (git_repository, local_path) is
// served unchanged, so such a descriptor still reaches the client intact.
func (b *Backend) fetchSource(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("bazel %q: reading source.json: %w", b.name, err)
	}
	if int64(len(data)) > maxSourceBytes {
		return nil, fmt.Errorf("bazel %q: source.json exceeds %d bytes", b.name, maxSourceBytes)
	}

	archiveURL := b.publicArchiveURL(resolved.Metadata[metaName], resolved.Metadata[metaVersion])
	if rewritten, rerr := rewriteSourceJSON(data, archiveURL); rerr == nil {
		data = rewritten
		b.metrics.incSourceRewritten()
	}
	// Even if rewriting failed to parse, the (unmodified) bytes are still served.

	b.metrics.incIndexServed()
	header.Del("Content-Length")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(string(data))),
		Size:      int64(len(data)),
		MediaType: "application/json",
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchArchive resolves a synthetic archive request: it reads the module's
// source.json to recover the external archive URL(s) and the SRI integrity, then
// fetches the archive and verifies the fetched bytes against the integrity —
// streaming, so a mismatch aborts the cache write and client stream. The file
// name a request may carry after ".../archive/" plays no part: what is fetched
// and verified is decided by source.json alone.
func (b *Backend) fetchArchive(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	name := resolved.Metadata[metaName]
	version := resolved.Metadata[metaVersion]

	// Step 1: read source.json (recorded as the resolved upstream URL) to recover
	// the archive URL and the expected integrity.
	srcResp, err := b.get(ctx, resolved.UpstreamURL, "")
	if err != nil {
		return nil, err
	}
	if !srcResp.IsSuccess() {
		return nil, b.statusError(srcResp, resolved.UpstreamURL)
	}
	body, rerr := io.ReadAll(io.LimitReader(srcResp.Body, maxSourceBytes+1))
	drainClose(srcResp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("bazel %q: reading source.json: %w", b.name, rerr)
	}
	if int64(len(body)) > maxSourceBytes {
		return nil, fmt.Errorf("bazel %q: source.json exceeds %d bytes", b.name, maxSourceBytes)
	}
	info, perr := parseSource(body)
	if perr != nil {
		return nil, fmt.Errorf("bazel %q: parsing source.json for %s@%s: %w", b.name, name, version, perr)
	}
	b.metrics.incSourceFetched()

	candidates := info.archiveURLs()
	if len(candidates) == 0 {
		return nil, &backends.StatusError{
			Status: http.StatusBadGateway,
			URL:    resolved.UpstreamURL,
			Body:   fmt.Sprintf("source.json for %s@%s declares no http(s) archive url", name, version),
		}
	}

	expected, haveIntegrity := parseIntegrity(info.Integrity)
	if haveIntegrity {
		resolved.Metadata[MetaChecksumVerified] = expected.algo
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	// Step 2: fetch the archive from the primary URL, falling back to the
	// descriptor's mirror URLs (which the rewritten source.json no longer exposes
	// to the client) when it is unavailable.
	archResp, archiveURL, err := b.openArchive(ctx, candidates, resolved.IfNoneMatch)
	if err != nil {
		return nil, err
	}
	resolved.Metadata[MetaArchiveURL] = archiveURL
	if archResp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}

	b.metrics.incArchivesServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, archResp.Header)
	if archResp.ETag != "" {
		header.Set("ETag", archResp.ETag)
	}

	content := archResp.Body
	if haveIntegrity {
		content = newVerifyingReader(archResp.Body, expected, name, version, archiveURL, func(ok bool) {
			if ok {
				b.metrics.incArchivesVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", expected.algo)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      archResp.ContentLength,
		MediaType: "application/octet-stream",
		Header:    header,
		Status:    archResp.Status,
	}, nil
}

// openArchive requests the archive from each candidate URL in turn and returns
// the first usable response (2xx, or 304 for a conditional request) together
// with the URL that produced it. Candidates after the first are the descriptor's
// mirror URLs: they are only consulted when the one before failed, exactly as a
// Bazel client would use them. When every candidate fails, the error of the
// first — the canonical location — is returned.
//
// Credentials are sent only to a candidate on the registry's own host; an
// external archive (the common case — a GitHub release) must not receive the
// proxy's registry token.
func (b *Backend) openArchive(ctx context.Context, candidates []string, ifNoneMatch string) (*upstream.Response, string, error) {
	var firstErr error
	for _, candidate := range candidates {
		creds := b.creds
		if !sameHost(b.base, candidate) {
			creds = upstream.Credentials{}
		}
		resp, err := b.getWithCreds(ctx, candidate, ifNoneMatch, creds)
		if err == nil {
			if resp.NotModified || resp.IsSuccess() {
				return resp, candidate, nil
			}
			err = b.statusError(resp, candidate)
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			// The client went away (or the deadline passed): do not walk the mirrors.
			break
		}
	}
	return nil, "", firstErr
}

// mediaType selects the response content type for a directly-proxied resource.
// The JSON descriptors are served as application/json; MODULE.bazel and patches
// as text; otherwise (overlay files) the upstream content type is preserved.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "registry", "metadata", "source":
		return "application/json"
	case "module-bazel", "patch":
		return "text/plain; charset=utf-8"
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
}

// get performs a GET against the upstream with the backend's credentials.
func (b *Backend) get(ctx context.Context, rawURL, ifNoneMatch string) (*upstream.Response, error) {
	return b.getWithCreds(ctx, rawURL, ifNoneMatch, b.creds)
}

// getWithCreds performs a GET with the supplied credentials.
func (b *Backend) getWithCreds(ctx context.Context, rawURL, ifNoneMatch string, creds upstream.Credentials) (*upstream.Response, error) {
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
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

// joinPath appends the inbound registry path to the upstream base, preserving
// any base-path prefix (e.g. a registry served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// sourceURL builds the upstream source.json URL for a module version, preserving
// any base-path prefix.
func (b *Backend) sourceURL(name, version string) string {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/modules/" + name + "/" + version + "/" + sourceFile
	out.RawPath = ""
	out.RawQuery = ""
	return out.String()
}

// archivePath is the canonical (bare) path of a module version's synthetic
// archive endpoint, relative to the registry root.
func archivePath(name, version string) string {
	return "/modules/" + name + "/" + version + "/" + archiveEndpoint
}

// publicArchiveURL composes the proxy-synthetic archive endpoint a rewritten
// source.json points beneath (rewriteSourceJSON appends the archive's file
// name). When no absolute public base is configured it falls back to the
// root-relative form; that form is not usable in a source.json (Bazel requires
// an absolute URL there), which is why rewriting is disabled without one.
func (b *Backend) publicArchiveURL(name, version string) string {
	base := b.publicBase
	if base == "" {
		base = "/v1/" + b.name
	}
	return base + archivePath(name, version)
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A per-version file (or the synthetic archive) pins its content, so the path
// alone is a content-addressable key; query parameters are incidental and
// excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
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
