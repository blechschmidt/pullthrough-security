// Package conda implements a pull-through proxy backend for the Conda package
// manager used across the scientific-Python and data-engineering ecosystems. It
// proxies a Conda channel's static HTTP tree — per-subdir repodata.json indices
// and the .conda / .tar.bz2 package archives beneath each subdir — bringing the
// ecosystem to parity with the pip/npm/cargo/maven/conan backends: package
// archives are cached content-addressably beneath their immutable
// name-version-build coordinate, fetched bytes are verified against the SHA-256
// the subdir's repodata.json declares before they are cached or served, and the
// package coordinate (name/version, with the subdir and build surfaced as
// metadata) is attached for nameguard, vulnscan, provenance, policy, and license
// enforcement.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /channeldata.json                         channel summary (mutable, live)
//	GET /<subdir>/repodata.json                   per-subdir index (mutable, live)
//	GET /<subdir>/<name>-<ver>-<build>.tar.bz2    package (immutable, verified)
//	GET /<subdir>/<name>-<ver>-<build>.conda      package v2 (immutable, verified)
//
// Security model: a package filename pins its version and build, so the cache
// key (which embeds the subdir and filename) is itself content-addressable. On a
// cache miss the backend additionally fetches the subdir's repodata.json and
// verifies the fetched archive against the SHA-256 it declares (falling back to
// MD5 only for older indices) — streaming, so a mismatch aborts the cache write
// and the client stream without buffering the archive. A tampered mirror can
// neither poison the cache nor reach a client.
//
// Client configuration points the Conda channel at "<publicBase>/v1/<name>"
// (see docs/clients.md): add it under `channels:` in .condarc, or pass
// `-c <publicBase>/v1/<name>`.
package conda

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
// Conan and Maven backends and are not persisted to the cache as meaningful
// data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the file must be checksum-verified
	metaFilename = "_filename" // requested package filename, for repodata lookup
	metaSubdir   = "_subdir"   // subdir the package lives under
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaSubdir records the Conda subdir (platform selector) a package belongs to.
	MetaSubdir = "conda.subdir"
	// MetaBuild records a package's build string.
	MetaBuild = "conda.build"
	// MetaChecksumVerified records "sha256"/"md5" when a package was verified
	// against its repodata.json, or "none" when no digest was available.
	MetaChecksumVerified = "conda.checksumVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Conda Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "conda-forge").
	// Required.
	Name string
	// UpstreamURL is the Conda channel base URL, e.g.
	// "https://conda.anaconda.org/conda-forge". The backend appends the
	// "/<subdir>/..." channel paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream channel. Optional; public
	// channels pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Conda channel pull-through backend implementing backends.Backend.
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
		return nil, errors.New("conda: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("conda %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("conda %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("conda %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("conda %q: upstream client is required", opts.Name)
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

// Resolve implements backends.Backend. It classifies the inbound path against
// the Conda channel layout, derives the upstream URL and cache key, attaches the
// package coordinate for the admission gates, and decides cacheability (only
// immutable package archives are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("conda: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Conda channel path", backends.ErrNotSupported, req.Path)
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

	// Attach the coordinate and qualifiers so nameguard, policy, provenance,
	// vulnscan, license, and policyengine can identify the artifact.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		if res.subdir != "" {
			resolved.Metadata[MetaSubdir] = res.subdir
		}
		if res.build != "" {
			resolved.Metadata[MetaBuild] = res.build
		}
	}

	if res.verifiableFile() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaFilename] = res.filename
		resolved.Metadata[metaSubdir] = res.subdir
	}

	return resolved, nil
}

// Fetch implements backends.Backend. Package archives are verified against the
// subdir's repodata.json — streaming so a mismatch aborts the cache write and
// client stream without buffering. Index documents (repodata.json,
// channeldata.json) are proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("conda: nil resolved")
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

	b.metrics.incPackagesServed()

	// Resolve the expected digest from the subdir's repodata.json. A missing index
	// (or an entry absent from it) is recorded and the package is served unverified
	// — fail-open is the only option when the upstream publishes no digest, and the
	// absence is observable via metrics.
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = expected.algo
	} else {
		b.metrics.incChecksumMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incPackagesVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", expected.algo)
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

// fetchExpectedChecksum fetches the subdir's repodata.json (the sibling of the
// requested package) and returns the digest it declares for the package. A
// missing or unparseable index, or a filename absent from it, yields ok=false
// (served unverified). SHA-256 is preferred; MD5 is a fallback.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	filename := resolved.Metadata[metaFilename]
	if filename == "" {
		return expectedChecksum{}, false
	}
	repodataURL, ok := siblingURL(resolved.UpstreamURL, repodataFile)
	if !ok {
		return expectedChecksum{}, false
	}
	resp, err := b.get(ctx, repodataURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	b.metrics.incRepodataFetched()
	sha, md5hex, found, perr := repodataChecksum(resp.Body, filename)
	drainClose(resp.Body)
	if perr != nil || !found {
		return expectedChecksum{}, false
	}
	return chooseChecksum(filename, sha, md5hex)
}

// mediaType selects the response content type. For known Conda files the
// extension is authoritative; otherwise the upstream's content type is
// preserved, falling back to application/octet-stream.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	name := resolved.Metadata[metaFilename]
	switch resolved.Metadata[metaKind] {
	case "repodata", "channeldata":
		switch {
		case strings.HasSuffix(name, ".json"):
			return "application/json"
		case strings.HasSuffix(name, ".zst"):
			return "application/zstd"
		case strings.HasSuffix(name, ".bz2"):
			return "application/x-bzip2"
		}
		if upstreamCT != "" {
			return upstreamCT
		}
		return "application/json"
	case "package":
		return "application/octet-stream"
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

// joinPath appends the inbound Conda path to the upstream base, preserving any
// base-path prefix (e.g. a channel served under a repository sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A package filename pins its version and build, so the path alone is a
// content-addressable key; query parameters are incidental and excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
}

// siblingURL rewrites rawURL so its final path segment is replaced with name,
// yielding the URL of a sibling file in the same directory (used to locate a
// subdir's repodata.json from a requested package). It returns ok=false if the
// URL cannot be parsed or has no path segment to replace.
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
