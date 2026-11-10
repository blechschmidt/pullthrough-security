// Package cpan implements a pull-through proxy backend for CPAN, the
// Comprehensive Perl Archive Network, and CPAN-compatible mirrors (a local
// minicpan, an Artifactory CPAN repository, the MetaCPAN-fronted www.cpan.org
// CDN). It proxies a mirror's static HTTP tree — the modules/ master indices and
// the authors/id distribution tarballs they describe — bringing the Perl
// ecosystem to parity with the pip/npm/cargo/maven/conan backends: distributions
// are cached content-addressably beneath their immutable author-tree path, fetched
// bytes are verified against the SHA-256 the sibling CHECKSUMS file declares before
// they are cached or served, and the distribution coordinate (name/version) is
// attached for nameguard, vulnscan, provenance, policy, and license enforcement.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /modules/02packages.details.txt.gz             master package index (mutable, live)
//	GET /authors/id/<A>/<AB>/<AUTHOR>/CHECKSUMS         per-author integrity record (mutable, live)
//	GET /authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Ver>.tar.gz   distribution (immutable, verified)
//
// Security model: a distribution filename pins its version, so the cache key
// (which embeds the full mirror path) is itself content-addressable. On a cache
// miss the backend additionally fetches the sibling CHECKSUMS file and verifies
// the fetched tarball against the SHA-256 it declares — streaming, so a mismatch
// aborts the cache write and the client stream without buffering the archive. A
// tampered mirror can neither poison the cache nor reach a client.
//
// OSV coverage: CPAN is an OSV.dev ecosystem keyed by distribution name and
// version, and a CPAN distribution filename encodes exactly that coordinate, so
// the backend attaches it and the vulnscan gate performs a real CPAN OSV lookup
// (see internal/vulnscan/purl.go).
//
// Client configuration points cpanm at "<publicBase>/v1/<name>" (see
// docs/clients.md): `cpanm --mirror <publicBase>/v1/<name> --mirror-only <Dist>`.
package cpan

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
// CRAN and Conan backends and are not persisted to the cache as meaningful data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the file must be checksum-verified
	metaFilename = "_filename" // requested filename (index or distribution)
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records "sha256" when a distribution was verified
	// against its CHECKSUMS file, or "none" when no digest was available.
	MetaChecksumVerified = "cpan.checksumVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a CPAN Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "cpan"). Required.
	Name string
	// UpstreamURL is the CPAN mirror base URL, e.g. "https://www.cpan.org". The
	// backend appends the "modules/..." and "authors/..." mirror paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream mirror. Optional; public
	// CPAN mirrors pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a CPAN mirror pull-through backend implementing backends.Backend.
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
		return nil, errors.New("cpan: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("cpan %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("cpan %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("cpan %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("cpan %q: upstream client is required", opts.Name)
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
// CPAN mirror layout, derives the upstream URL and cache key, attaches the
// distribution coordinate for the admission gates, and decides cacheability (only
// immutable distribution tarballs are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("cpan: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a CPAN mirror path", backends.ErrNotSupported, req.Path)
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
			"backend":    b.name,
			metaKind:     res.kindLabel(),
			metaFilename: res.filename,
		},
	}

	// Attach the coordinate so nameguard, policy, provenance, vulnscan, license,
	// and policyengine can identify the artifact. It is empty for index documents
	// and for a distribution whose filename did not parse into a coordinate.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableFile() {
		resolved.Metadata[metaVerify] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. Distribution tarballs are verified against
// the sibling CHECKSUMS file's SHA-256 — streaming so a mismatch aborts the cache
// write and client stream without buffering. Index documents (module indices,
// CHECKSUMS, sidecars) are proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("cpan: nil resolved")
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

	mediaType := b.mediaType(resolved, resp.ContentType)

	// Index documents are proxied without content verification.
	if resolved.Metadata[metaVerify] != "1" {
		b.metrics.incIndexServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incDistributionsServed()

	// Resolve the expected SHA-256 from the sibling CHECKSUMS file. A missing
	// CHECKSUMS (or a distribution absent from it) is recorded and the tarball is
	// served unverified; fail-open is the only option when the upstream publishes
	// no digest, and the absence is observable via metrics.
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "sha256"
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incDistributionsVerified()
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

// fetchExpectedChecksum fetches the sibling CHECKSUMS file (same author directory
// as the requested tarball) and returns the SHA-256 it declares for the
// distribution. A missing or unparseable CHECKSUMS, or a distribution absent from
// it, yields ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	filename := resolved.Metadata[metaFilename]
	if filename == "" {
		return expectedChecksum{}, false
	}
	checksumsURL, ok := siblingURL(resolved.UpstreamURL, checksumsFile)
	if !ok {
		return expectedChecksum{}, false
	}
	resp, err := b.get(ctx, checksumsURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxChecksumsBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxChecksumsBytes {
		return expectedChecksum{}, false
	}
	cs, perr := ParseChecksums(body)
	if perr != nil {
		return expectedChecksum{}, false
	}
	b.metrics.incChecksumsFetched()
	sha, found := cs.sha256For(filename)
	if !found {
		return expectedChecksum{}, false
	}
	return expectedChecksum{filename: filename, sha256: sha}, true
}

// mediaType selects the response content type from the known CPAN file
// extensions, falling back to the upstream's content type.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	name := resolved.Metadata[metaFilename]
	switch {
	case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".gz"):
		return "application/gzip"
	case strings.HasSuffix(name, ".tar.bz2") || strings.HasSuffix(name, ".bz2"):
		return "application/x-bzip2"
	case strings.HasSuffix(name, ".tar.xz") || strings.HasSuffix(name, ".xz"):
		return "application/x-xz"
	case strings.HasSuffix(name, ".zip"):
		return "application/zip"
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
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

// joinPath appends the inbound CPAN path to the upstream base, preserving any
// base-path prefix (e.g. a mirror served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A distribution filename pins its version, so the path alone is a
// content-addressable key; query parameters are incidental and excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
}

// siblingURL rewrites rawURL so its final path segment is replaced with name,
// yielding the URL of a sibling file in the same directory (used to locate the
// CHECKSUMS file from a requested tarball). It returns ok=false if the URL cannot
// be parsed or has no path segment to replace.
func siblingURL(rawURL, name string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	slash := strings.LastIndex(u.Path, "/")
	if slash < 0 {
		return "", false
	}
	u.Path = u.Path[:slash+1] + name
	u.RawPath = ""
	u.RawQuery = ""
	return u.String(), true
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
