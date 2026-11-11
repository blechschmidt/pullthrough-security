// Package hex implements a pull-through proxy backend for the Elixir/Erlang Hex
// package registry (hex.pm, served from repo.hex.pm) and Hex-compatible private
// repositories. It proxies the registry-v2 static HTTP tree — the signed
// /names, /versions, and /packages/<name> protobuf resources and the release
// tarballs under /tarballs/ — bringing the Elixir ecosystem to parity with the
// pip/npm/cargo/maven/conan/cran backends: tarballs are cached content-
// addressably beneath their immutable name-version coordinate, fetched bytes are
// verified against the outer_checksum the sibling /packages/<name> resource
// declares before they are cached or served, and the package coordinate
// (name/version) is attached for nameguard, vulnscan (OSV "Hex" ecosystem),
// provenance, policy, and license enforcement.
//
// Layout mapping (see path.go for the full route table):
//
//	GET /names                            all package names   (signed protobuf, mutable, live)
//	GET /versions                         all versions        (signed protobuf, mutable, live)
//	GET /packages/<name>                  one package's releases (signed protobuf, mutable, live)
//	GET /tarballs/<name>-<version>.tar    release tarball     (immutable, verified, cacheable)
//	GET /installs/...                     Hex/Rebar self-install lists and builds (live)
//
// The /installs/ tree is what `mix local.hex`, `mix local.rebar`, and Hex's own
// update check read when HEX_MIRROR points at the proxy. It is passed through
// live and byte-exact (the lists are signature-checked by Mix) and is neither
// cached nor gated; path.go explains why.
//
// Security model: a tarball filename pins its version, so the cache key (which
// embeds the full repository path) is itself content-addressable. On a cache
// miss the backend additionally fetches the sibling /packages/<name> resource,
// decodes the signed protobuf, and verifies the fetched tarball against the
// release's outer_checksum (a SHA-256 over the whole tarball) — streaming, so a
// mismatch aborts the cache write and the client stream without buffering the
// archive. A tampered mirror can neither poison the cache nor reach a client.
// The registry resources are passed through byte-exact, so a mix/hex client that
// pins the repository public key still performs its own end-to-end signature
// verification.
//
// Client configuration points mix/hex at "<publicBase>/v1/<name>" (see
// docs/clients.md): `mix hex.repo add <name> <publicBase>/v1/<name>` and set
// `HEX_MIRROR`/`:hex_mirror` for the default repo.
package hex

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
// Conan, Conda, and CRAN backends and are not persisted to the cache as
// meaningful data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the file must be checksum-verified
	metaFilename = "_filename" // requested filename (resource or tarball)
	metaName     = "_name"     // package name, for /packages/<name> lookup
	metaVersion  = "_version"  // release version, for outer_checksum lookup
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaChecksumVerified records "sha256" when a tarball was verified against
	// its /packages/<name> resource, or "none" when no digest was available.
	MetaChecksumVerified = "hex.checksumVerified"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Hex Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "hex"). Required.
	Name string
	// UpstreamURL is the Hex repository base URL, e.g. "https://repo.hex.pm". The
	// backend appends the "/names", "/versions", "/packages/..." and
	// "/tarballs/..." repository paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream repository. Optional;
	// the public hex.pm repository pulls anonymously, while a private
	// organization repository is read with a token.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Hex repository pull-through backend implementing
// backends.Backend.
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
		return nil, errors.New("hex: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("hex %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("hex %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("hex %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("hex %q: upstream client is required", opts.Name)
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
// the Hex registry-v2 layout, derives the upstream URL and cache key, attaches
// the package coordinate for the admission gates, and decides cacheability (only
// immutable release tarballs are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("hex: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Hex repository path", backends.ErrNotSupported, req.Path)
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
		Artifact: res.artifact(),
	}

	// Attach the coordinate so nameguard, policy, provenance, vulnscan, license,
	// and policyengine can identify the artifact.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableFile() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
	}

	return resolved, nil
}

// Fetch implements backends.Backend. Release tarballs are verified against the
// outer_checksum the sibling /packages/<name> resource declares — streaming so a
// mismatch aborts the cache write and client stream without buffering. The
// signed registry resources and the /installs/ tree are proxied directly,
// byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("hex: nil resolved")
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

	// Registry resources (names/versions/packages) and the /installs/ tree are
	// proxied byte-exact without content verification; the client performs its
	// own signature and checksum checks against them.
	if resolved.Metadata[metaVerify] != "1" {
		if resolved.Metadata[metaKind] == "install" {
			b.metrics.incInstallsServed()
		} else {
			b.metrics.incRegistryServed()
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

	b.metrics.incTarballsServed()

	// Resolve the expected outer_checksum from the sibling /packages/<name>
	// resource. A missing resource (or a release absent from it) is recorded and
	// the tarball is served unverified; fail-open is the only option when the
	// upstream publishes no digest, and the absence is observable via metrics.
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
				b.metrics.incTarballsVerified()
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

// fetchExpectedChecksum fetches the /packages/<name> registry resource for the
// requested tarball and returns the outer_checksum it declares for the release.
// A missing or unparseable resource, or a release absent from it, yields
// ok=false (served unverified).
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	name := resolved.Metadata[metaName]
	version := resolved.Metadata[metaVersion]
	if name == "" || version == "" {
		return expectedChecksum{}, false
	}
	resourceURL := b.packageResourceURL(name)
	resp, err := b.get(ctx, resourceURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxRegistryBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxRegistryBytes {
		return expectedChecksum{}, false
	}
	idx, perr := ParsePackageResource(body)
	if perr != nil {
		return expectedChecksum{}, false
	}
	b.metrics.incResourceFetched()
	sha, found := idx.outerFor(version)
	if !found {
		return expectedChecksum{}, false
	}
	return expectedChecksum{filename: resolved.Metadata[metaFilename], sha256: sha}, true
}

// mediaType selects the response content type. Tarballs are uncompressed tar;
// the signed registry resources are opaque protobuf octet streams. A present
// upstream content type is otherwise preserved.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "tarball":
		return "application/octet-stream"
	case "names", "versions", "package-index":
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

// joinPath appends the inbound Hex path to the upstream base, preserving any
// base-path prefix (e.g. a repository served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// packageResourceURL builds the /packages/<name> URL for a package relative to
// the upstream base, preserving any base-path prefix.
func (b *Backend) packageResourceURL(name string) string {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/packages/" + name
	out.RawPath = ""
	out.RawQuery = ""
	return out.String()
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A tarball filename pins its version, so the path alone is a content-
// addressable key; query parameters are incidental and excluded.
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
