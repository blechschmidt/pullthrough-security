// Package composer implements a pull-through proxy backend for the Composer/
// Packagist ecosystem (packagist.org and any Satis/Toran/Artifactory/Nexus mirror
// serving the same protocol). It brings PHP to parity with the other package
// backends: the repository root (packages.json), the Composer v2 metadata layout
// (/p2/<vendor>/<package>.json), the legacy v1 provider documents, and dist
// archive downloads are all proxied and cached, and a fetched dist archive is
// verified against the SHA-1 shasum the package's v2 metadata declares before the
// bytes are cached or served.
//
// Protocol mapping (route prefix "/v1/<name>" stripped):
//
//	GET /packages.json                          repository root (mutable).
//	GET /p2/<vendor>/<package>.json             v2 release metadata (mutable, parsed).
//	GET /p2/<vendor>/<package>~dev.json         v2 dev metadata (mutable, parsed).
//	GET /p/<vendor>/<package>.json              legacy v1 provider (mutable).
//	GET /dist/<vendor>/<package>/<ref>.<ext>    dist archive (immutable, cached, SHA-1-verified).
//
// Security model: the v2 metadata is the upstream's own declared digest of each
// version's dist archive (the "dist.shasum" SHA-1). A dist request names a
// package and a source reference; on a cache miss the backend fetches the
// package's v2 metadata, locates the version with that reference, fetches the
// real upstream download URL it advertises, and verifies the streamed archive
// against the declared shasum. A mismatch aborts the cache write and the
// response, so a tampered or corrupt mirror can neither poison the cache nor
// reach a client. This mirrors the checksum verification the Maven and RubyGems
// backends perform.
//
// Client configuration adds "<publicBase>/v1/<name>" as a composer repository
// (see docs/clients.md).
package composer

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

// Internal metadata keys carry per-request decisions from Resolve into Fetch.
const (
	metaKind      = "_kind"      // resource class label, for diagnostics/gates
	metaVerify    = "_verify"    // "1" when the dist archive must be verified
	metaVendor    = "_vendor"    // parsed vendor
	metaPkg       = "_pkg"       // parsed package
	metaReference = "_reference" // dist source reference (for dist requests)
	metaDistExt   = "_ext"       // dist archive extension
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha1" when a dist archive was verified, or
	// "none" when no shasum could be recovered for it.
	MetaChecksumVerified = "composer.checksumVerified"
	// MetaLicenses records a comma-separated list of license identifiers declared
	// for the served version, for the license-compliance gate.
	MetaLicenses = "composer.licenses"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Composer Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "packagist").
	// Required.
	Name string
	// UpstreamURL is the repository base URL, e.g. "https://repo.packagist.org".
	// Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional; public
	// repositories pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Composer pull-through backend implementing backends.Backend.
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
		return nil, errors.New("composer: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("composer %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("composer %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("composer %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("composer %q: upstream client is required", opts.Name)
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

// Resolve implements backends.Backend. It classifies the inbound path against the
// Composer layout, derives the upstream URL and cache key, attaches the package
// coordinate for the admission gates, and decides cacheability (immutable dist
// archives cached; mutable metadata revalidated). For a dist request the upstream
// URL is the package's v2 metadata document, from which Fetch derives the real
// download URL and verification shasum.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("composer: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Composer layout path", backends.ErrNotSupported, req.Path)
	}

	var upstreamURL string
	if res.kind == kindDist {
		// The dist path is the proxy's own locator; the real upstream URL is
		// discovered from the package metadata at Fetch time.
		upstreamURL = b.metadataURL(res.vendor, res.pkg)
	} else {
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		upstreamURL = abs.String()
	}

	cacheable := res.cacheable() && isRead(req)
	resolved := &backends.Resolved{
		UpstreamURL: upstreamURL,
		Cacheable:   cacheable,
		CacheKey:    b.cacheKey(req.Path),
		Metadata: map[string]string{
			"backend":     b.name,
			metaKind:      res.kindLabel(),
			metaVendor:    res.vendor,
			metaPkg:       res.pkg,
			metaReference: res.reference,
			metaDistExt:   res.ext,
		},
	}

	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn}
	}

	if res.verifiableArtifact() {
		resolved.Metadata[metaVerify] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A dist request first fetches and parses the
// package's v2 metadata to recover the real download URL and the SHA-1 shasum,
// then fetches and verifies the archive. Metadata/root/provider documents are
// proxied directly (and v2 metadata is parsed to count it and validate it).
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("composer: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchDist(ctx, resolved)
	}
	return b.fetchDocument(ctx, resolved)
}

// fetchDocument proxies a metadata/root/provider document, parsing v2 metadata to
// validate it and surface counts.
func (b *Backend) fetchDocument(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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

	b.metrics.incMetadataServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	// v2 metadata is small enough to buffer-validate; doing so lets a malformed
	// document be counted, and keeps the parser on the hot path (and thus fuzzed
	// against real traffic). Other documents stream straight through.
	if resolved.Metadata[metaKind] == "metadata" {
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
		drainClose(resp.Body)
		if rerr != nil {
			return nil, fmt.Errorf("composer %q: reading metadata: %w", b.name, rerr)
		}
		if int64(len(data)) > maxMetadataBytes {
			return nil, fmt.Errorf("composer %q: metadata exceeds %d bytes", b.name, maxMetadataBytes)
		}
		if _, perr := ParseMetadata(data); perr != nil {
			b.metrics.incMetadataErrors()
		} else {
			b.metrics.incMetadataParsed()
		}
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   io.NopCloser(bytes.NewReader(data)),
			Size:      int64(len(data)),
			MediaType: resp.ContentType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchDist resolves a dist request: it fetches the package's v2 metadata, finds
// the version matching the requested reference, fetches the upstream download URL
// it advertises, and streams the archive through a SHA-1-verifying reader.
func (b *Backend) fetchDist(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	reference := resolved.Metadata[metaReference]
	version, found := b.lookupDist(ctx, resolved.UpstreamURL, reference)
	if !found || version.Dist.URL == "" {
		return nil, &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    resolved.UpstreamURL,
			Body:   fmt.Sprintf("composer: no dist with reference %q in package metadata", reference),
		}
	}

	if version.Version != "" {
		resolved.Coordinate.Version = version.Version
	}
	if names := strings.Join(version.License, ","); names != "" {
		resolved.Metadata[MetaLicenses] = names
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    version.Dist.URL,
		Method: http.MethodGet,
		Creds:  b.creds,
	})
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: version.Dist.URL, Body: snippet}
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}

	content := resp.Body
	if expected, ok := version.Checksum(); ok {
		resolved.Metadata[MetaChecksumVerified] = "sha1"
		content = newVerifyingReader(resp.Body, expected, version.Dist.URL, func(ok bool) {
			if ok {
				b.metrics.incDistVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", "sha1")
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

// lookupDist fetches and parses the v2 metadata at metadataURL and returns the
// version whose dist reference matches.
func (b *Backend) lookupDist(ctx context.Context, metadataURL, reference string) (Version, bool) {
	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    metadataURL,
		Method: http.MethodGet,
		Creds:  b.creds,
	})
	if err != nil {
		return Version{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return Version{}, false
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(data)) > maxMetadataBytes {
		return Version{}, false
	}
	md, perr := ParseMetadata(data)
	if perr != nil {
		b.metrics.incMetadataErrors()
		return Version{}, false
	}
	b.metrics.incMetadataParsed()
	return md.FindByReference(reference)
}

// metadataURL builds the v2 metadata document URL for a package.
func (b *Backend) metadataURL(vendor, pkg string) string {
	return b.joinPath("/p2/" + vendor + "/" + pkg + ".json").String()
}

// joinPath appends the inbound Composer path to the upstream base, preserving any
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
