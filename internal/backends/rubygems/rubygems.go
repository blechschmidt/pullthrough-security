// Package rubygems implements a pull-through proxy backend for the RubyGems
// ecosystem (rubygems.org and any Gemstash/Artifactory/Nexus mirror serving the
// same protocol). It brings Ruby to parity with the pip/npm/cargo/go/nuget/maven
// backends: the compact index (/versions, /names, /info/<gem>), .gem fetches, the
// legacy Marshal spec indexes, and the dependency API are all proxied and cached,
// and a fetched .gem is verified against the SHA-256 checksum the gem's compact-
// index /info document declares before the bytes are cached or served.
//
// Protocol mapping (route prefix "/v1/<name>" stripped):
//
//	GET /versions                       compact-index gem→versions list (mutable).
//	GET /names                          compact-index gem-name list (mutable).
//	GET /info/<gem>                     per-gem versions + checksums (mutable, parsed).
//	GET /gems/<name>-<version>.gem      gem package (immutable, cached, SHA-256-verified).
//	GET /quick/Marshal.4.8/<n>-<v>.gemspec.rz  legacy Marshal gemspec (immutable, cached).
//	GET /specs.4.8.gz, /latest_specs.4.8.gz, /prerelease_specs.4.8.gz  Marshal indexes (mutable).
//	GET /api/v1/dependencies            legacy dependency resolver (mutable).
//
// Security model: the compact-index /info/<gem> document is the upstream's own
// declared digest of each released .gem. On a .gem cache miss the backend fetches
// that document, recovers the SHA-256 digest for the exact version (and platform)
// requested, and verifies the artifact content against it as the bytes stream
// through. A mismatch aborts the cache write and the response, so a tampered or
// corrupt mirror can neither poison the cache nor reach a client. This mirrors
// the checksum verification the Maven backend performs against sidecars.
//
// Client configuration points Bundler/RubyGems at "<publicBase>/v1/<name>" (see
// docs/clients.md).
package rubygems

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
// Maven and Docker backends and are not persisted as meaningful cache data.
const (
	metaKind    = "_kind"    // resource class label, for diagnostics/gates
	metaVerify  = "_verify"  // "1" when the .gem must be checksum-verified
	metaName    = "_name"    // parsed gem name
	metaVersion = "_version" // parsed version token (with platform suffix)
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha256" when an artifact was verified, or
	// "none" when no checksum could be recovered for it.
	MetaChecksumVerified = "rubygems.checksumVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a RubyGems Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "rubygems").
	// Required.
	Name string
	// UpstreamURL is the gem-server base URL, e.g. "https://rubygems.org".
	// Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream. Optional; public gem
	// servers pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a RubyGems pull-through backend implementing backends.Backend.
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
		return nil, errors.New("rubygems: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("rubygems %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("rubygems %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("rubygems %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("rubygems %q: upstream client is required", opts.Name)
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
// RubyGems layout, derives the upstream URL and cache key, attaches the gem
// coordinate for the admission gates, decides cacheability (immutable .gem /
// gemspec cached; mutable index documents revalidated), and states for the
// content gates whether the resource is the installable .gem or a metadata
// document (resource.artifact).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("rubygems: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a RubyGems layout path", backends.ErrNotSupported, req.Path)
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
		Artifact: res.artifact(),
	}

	// Attach the gem coordinate so nameguard, policy, provenance, vulnscan,
	// license, and policyengine can identify the artifact. Index documents that
	// address no single gem carry no coordinate.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableArtifact() {
		resolved.Metadata[metaVerify] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For a .gem it first fetches and parses the
// gem's compact-index /info document, recovers the SHA-256 checksum for the
// requested version, and verifies the streamed artifact against it. Index and
// legacy documents are proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("rubygems: nil resolved")
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

	// Non-artifact resources (index/legacy documents) are proxied without
	// verification.
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

	// Recover the expected SHA-256 from the gem's compact-index /info document.
	// A missing or unrecoverable checksum is recorded and the gem is served
	// unverified (fail-open is the only option when the upstream publishes no
	// digest for the version; the absence is observable via metrics).
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved.Metadata[metaName], resolved.Metadata[metaVersion])
	content := resp.Body
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incGemsVerified()
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

// fetchExpectedChecksum fetches the gem's /info/<gem> compact-index document and
// recovers the SHA-256 digest declared for the requested version token.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, gem, version string) (expectedChecksum, bool) {
	if gem == "" || version == "" {
		return expectedChecksum{}, false
	}
	infoURL := b.joinPath("/info/" + gem).String()
	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    infoURL,
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
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxInfoBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxInfoBytes {
		return expectedChecksum{}, false
	}
	info, perr := ParseInfo(body)
	if perr != nil {
		b.metrics.incInfoParseErrors()
		return expectedChecksum{}, false
	}
	b.metrics.incInfoParsed()
	hex, ok := info.ChecksumFor(version)
	if !ok {
		return expectedChecksum{}, false
	}
	return expectedChecksum{hex: hex}, true
}

// recordKindMetric counts served index/legacy documents by family.
func (b *Backend) recordKindMetric(resolved *backends.Resolved) {
	switch resolved.Metadata[metaKind] {
	case "index", "info":
		b.metrics.incIndexServed()
	case "legacy-index", "dependency-api":
		b.metrics.incLegacyServed()
	}
}

// joinPath appends the inbound RubyGems path to the upstream base, preserving any
// base-path prefix (e.g. a Gemstash mounted under "/private").
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
