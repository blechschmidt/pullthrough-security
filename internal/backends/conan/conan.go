// Package conan implements a pull-through proxy backend for the Conan 2.x C/C++
// package manager. It speaks the Conan "revisions" REST API that JFrog
// Artifactory (and thus ConanCenter) and the reference conan_server expose,
// bringing the native-code ecosystem to parity with the pip/npm/cargo/maven
// backends: recipe and package files are proxied and cached content-addressably
// beneath their immutable revisions, fetched bytes are MD5-verified before they
// are cached or served, conaninfo.txt package descriptors are surfaced to the
// admission gates, and the package coordinate (name/version@user/channel) is
// attached for nameguard, vulnscan, provenance, policy, and license enforcement.
//
// Protocol mapping (Conan v2, see path.go for the full route table):
//
//	GET /v1/ping | /v2/ping                                     server capabilities (live)
//	GET /v2/users/authenticate | check_credentials              auth passthrough (live)
//	GET /v2/conans/search | .../search                          search (live)
//	GET .../latest | .../revisions                              revision pointers/lists (revalidated)
//	GET .../revisions/{rrev}/files[/{file}]                     recipe files (immutable, verified)
//	GET .../packages/{pid}/revisions/{prev}/files[/{file}]      package files (immutable, verified)
//
// The capability probe is the one request a Conan 2.x client still sends to the
// v1 route: it reads the X-Conan-Server-Capabilities header of GET /v1/ping
// before any /v2 call, so that header must be relayed (it is — the probe is
// served live, and live responses carry the upstream's headers).
//
// Security model: a recipe revision (rrev) and package revision (prev) are
// content hashes of the files they pin, so the cache key (which embeds them) is
// itself content-addressable. On a cache miss the backend additionally verifies
// the fetched file's MD5 — streaming for large archives, in memory for the small
// conaninfo.txt — so a corrupted or tampered transfer can neither poison the
// cache nor reach a client. The expected digest comes from the revision's
// conanmanifest.txt where the manifest records one (conanfile.py,
// conaninfo.txt). The manifest lists a revision's files in their unpacked form,
// so the conan_export.tgz / conan_sources.tgz / conan_package.tgz archives are
// never in it; those are verified against the X-Checksum-Md5 header that
// Artifactory-based remotes (ConanCenter included) send with every file.
//
// Client configuration points the Conan remote at "<publicBase>/v1/<name>"
// (see docs/clients.md): `conan remote add proxy <publicBase>/v1/<name>`.
package conan

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
// Maven and Terraform backends and are not persisted to the cache as meaningful
// data.
const (
	metaKind     = "_kind"      // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"    // "1" when the file must be checksum-verified
	metaFilename = "_filename"  // requested file path, for manifest lookup
	metaConanInf = "_conaninfo" // "1" when the file is a package conaninfo.txt
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaReference records the canonical Conan reference "name/version@user/channel".
	MetaReference = "conan.reference"
	// MetaUser records the recipe user ("_" for ConanCenter's unqualified recipes).
	MetaUser = "conan.user"
	// MetaChannel records the recipe channel.
	MetaChannel = "conan.channel"
	// MetaRecipeRevision records the recipe revision (rrev) a resource is pinned to.
	MetaRecipeRevision = "conan.recipeRevision"
	// MetaPackageID records the package_id for a package-level resource.
	MetaPackageID = "conan.packageId"
	// MetaPackageRevision records the package revision (prev) for a package file.
	MetaPackageRevision = "conan.packageRevision"
	// MetaConanInfo is "1" when the served file is a package conaninfo.txt.
	MetaConanInfo = "conan.conaninfo"
	// MetaChecksumVerified records "md5" when a file's MD5 was verified before it
	// was cached or served, or "none" when the upstream declared no digest for it.
	MetaChecksumVerified = "conan.checksumVerified"
	// MetaChecksumSource records where the expected MD5 came from when
	// MetaChecksumVerified is "md5": "manifest" (the revision's conanmanifest.txt)
	// or "upstream-header" (the X-Checksum-Md5 header sent with the file).
	MetaChecksumSource = "conan.checksumSource"
)

// Values of MetaChecksumSource.
const (
	checksumSourceManifest = "manifest"
	checksumSourceHeader   = "upstream-header"
)

// Size bounds for the small documents the backend buffers on the pull path.
const (
	// maxManifestBytes bounds a conanmanifest.txt fetch. These list one MD5 per
	// file, so a few MiB is generous; the cap stops a hostile upstream returning a
	// huge body in place of a manifest.
	maxManifestBytes = 4 << 20 // 4 MiB
	// maxConanInfoBytes bounds the in-memory buffering used to verify conaninfo.txt.
	maxConanInfoBytes = 1 << 20 // 1 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Conan Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "conancenter").
	// Required.
	Name string
	// UpstreamURL is the Conan remote base URL, e.g. "https://center2.conan.io".
	// The backend appends the "/v2/..." API paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream remote. Optional; public
	// remotes (ConanCenter) pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Conan 2.x pull-through backend implementing backends.Backend.
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
		return nil, errors.New("conan: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("conan %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("conan %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("conan %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("conan %q: upstream client is required", opts.Name)
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
// the Conan v2 layout, derives the upstream URL and cache key, attaches the
// package coordinate for the admission gates, and decides cacheability (only
// resources pinned beneath an immutable revision are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("conan: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Conan v2 path", backends.ErrNotSupported, req.Path)
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
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
	}

	// Attach the coordinate and reference qualifiers so nameguard, policy,
	// provenance, vulnscan, license, and policyengine can identify the artifact.
	if cn := res.coordinateName(); cn != "" {
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
		resolved.Metadata[MetaReference] = res.reference()
		if res.user != "" {
			resolved.Metadata[MetaUser] = res.user
		}
		if res.channel != "" {
			resolved.Metadata[MetaChannel] = res.channel
		}
		if res.rrev != "" {
			resolved.Metadata[MetaRecipeRevision] = res.rrev
		}
		if res.pkgID != "" {
			resolved.Metadata[MetaPackageID] = res.pkgID
		}
		if res.prev != "" {
			resolved.Metadata[MetaPackageRevision] = res.prev
		}
	}

	if res.verifiableFile() {
		resolved.Metadata[metaVerify] = "1"
		resolved.Metadata[metaFilename] = res.filename
		if res.isConanInfo() {
			resolved.Metadata[metaConanInf] = "1"
		}
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For content files it resolves the expected
// MD5 (from the revision's conanmanifest.txt, else the upstream's X-Checksum-Md5
// header) and verifies the file against it — streaming for large archives, in
// memory for conaninfo.txt (which it also surfaces to the admission gates).
// Discovery documents, search, file listings, and the manifest itself are
// proxied directly, with the upstream's response headers (notably the ping's
// X-Conan-Server-Capabilities) handed to the gateway for relay.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("conan: nil resolved")
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

	b.recordKindMetric(resolved)

	header := make(http.Header)
	// PropagateResponseHeaders hands the upstream's end-to-end headers to the
	// gateway: the ping's X-Conan-Server-Capabilities (which the client requires)
	// and Artifactory's X-Checksum-Sha256 / -Sha1 / -Md5. The gateway relays them
	// on live (non-cacheable) responses; a cacheable file is served from its cache
	// entry, which does not replay them.
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	// Non-file resources (discovery, search, listings, and the manifest itself)
	// are proxied without content verification.
	if resolved.Metadata[metaVerify] != "1" {
		mediaType := b.mediaType(resolved, resp.ContentType)
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	b.metrics.incFilesServed()

	// Resolve the expected MD5. The revision's conanmanifest.txt is the primary
	// source, but it records a revision's files in their unpacked form, so it
	// covers conanfile.py and conaninfo.txt and never the .tgz archives that carry
	// everything else. For those (and for a remote that publishes no manifest) the
	// digest is taken from the X-Checksum-Md5 header Artifactory-based remotes send
	// with the file. When neither exists the file is served unverified — fail-open
	// is the only option when the upstream declares no digest — and the gap is
	// recorded in the cache metadata and observable via metrics.
	expected, haveChecksum := b.fetchExpectedChecksum(ctx, resolved)
	source := checksumSourceManifest
	if !haveChecksum {
		if md5hex, ok := headerMD5(resp.Header); ok {
			expected = expectedChecksum{filename: resolved.Metadata[metaFilename], md5hex: md5hex}
			haveChecksum, source = true, checksumSourceHeader
		}
	}
	if haveChecksum {
		resolved.Metadata[MetaChecksumVerified] = "md5"
		resolved.Metadata[MetaChecksumSource] = source
	} else {
		b.metrics.incManifestMissing()
		resolved.Metadata[MetaChecksumVerified] = "none"
	}

	mediaType := b.mediaType(resolved, resp.ContentType)

	// conaninfo.txt is small and surfaced to the gates: buffer, verify in memory,
	// and return the buffered bytes.
	if resolved.Metadata[metaConanInf] == "1" {
		return b.fetchConanInfo(resolved, resp, header, mediaType, expected, haveChecksum)
	}

	// Larger files (conan_package.tgz, conan_sources.tgz, conanfile.py, ...) stream
	// through a verifying reader so a hash mismatch aborts the cache write and the
	// client stream without buffering. The outcome is known only at end-of-stream,
	// so the reader reports it via the callback for accurate counts.
	content := resp.Body
	if haveChecksum {
		content = newVerifyingReader(resp.Body, expected, resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incFilesVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", "md5")
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

// fetchConanInfo buffers, verifies, and returns a package's conaninfo.txt,
// surfacing it to the admission pipeline via cache metadata.
func (b *Backend) fetchConanInfo(resolved *backends.Resolved, resp *upstream.Response, header http.Header, mediaType string, expected expectedChecksum, haveChecksum bool) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxConanInfoBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("conan %q: reading conaninfo.txt: %w", b.name, err)
	}
	if int64(len(data)) > maxConanInfoBytes {
		return nil, fmt.Errorf("conan %q: conaninfo.txt exceeds %d bytes", b.name, maxConanInfoBytes)
	}

	if haveChecksum {
		if verr := verifyBytes(data, expected, resolved.UpstreamURL); verr != nil {
			b.metrics.incChecksumMismatch()
			return nil, verr
		}
		b.metrics.incFilesVerified()
		header.Set("X-Checksum-Verified", "md5")
	}

	b.metrics.incConanInfoServed()
	resolved.Metadata[MetaConanInfo] = "1"

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(data)),
		Size:      int64(len(data)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchExpectedChecksum fetches the conanmanifest.txt sibling of the requested
// file (same revision, filename replaced) and returns the MD5 it declares for
// the file. A missing or unparseable manifest, or a filename absent from it (as
// the .tgz archives always are), yields ok=false; the caller then falls back to
// the upstream's X-Checksum-Md5 header.
func (b *Backend) fetchExpectedChecksum(ctx context.Context, resolved *backends.Resolved) (expectedChecksum, bool) {
	filename := resolved.Metadata[metaFilename]
	if filename == "" {
		return expectedChecksum{}, false
	}
	manifestURL, ok := siblingURL(resolved.UpstreamURL, manifestFile)
	if !ok {
		return expectedChecksum{}, false
	}
	resp, err := b.get(ctx, manifestURL, "")
	if err != nil {
		return expectedChecksum{}, false
	}
	if !resp.IsSuccess() {
		drainClose(resp.Body)
		return expectedChecksum{}, false
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	drainClose(resp.Body)
	if rerr != nil || int64(len(body)) > maxManifestBytes {
		return expectedChecksum{}, false
	}
	b.metrics.incManifestParsed()
	md5hex, found := ParseManifest(body).digestFor(filename)
	if !found {
		return expectedChecksum{}, false
	}
	return expectedChecksum{filename: filename, md5hex: md5hex}, true
}

// recordKindMetric counts served resources by their class for observability.
func (b *Backend) recordKindMetric(resolved *backends.Resolved) {
	switch resolved.Metadata[metaKind] {
	case "recipe-files", "package-files":
		b.metrics.incFileListingServed()
	case "recipe-latest", "recipe-revisions", "package-latest", "package-revisions",
		"search", "ping", "users":
		b.metrics.incMetadataServed()
	}
}

// mediaType selects the response content type. For known Conan content files the
// extension is authoritative (Conan servers routinely serve them as a generic
// octet-stream), so a correct type is set regardless; otherwise the upstream's
// content type is preserved, falling back to application/octet-stream.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	switch resolved.Metadata[metaKind] {
	case "recipe-latest", "recipe-revisions", "package-latest", "package-revisions",
		"recipe-files", "package-files", "search":
		if upstreamCT != "" {
			return upstreamCT
		}
		return "application/json"
	}
	if name := baseName(resolved.Metadata[metaFilename]); name != "" {
		if ct := fileContentType(name); ct != "" {
			return ct
		}
	}
	if upstreamCT != "" {
		return upstreamCT
	}
	return "application/octet-stream"
}

// fileContentType maps a Conan content filename to its canonical content type.
// Returns "" for an unrecognized extension (the caller falls back to upstream).
func fileContentType(name string) string {
	switch {
	case name == "conanfile.py" || strings.HasSuffix(name, ".py"):
		return "text/x-python; charset=utf-8"
	case strings.HasSuffix(name, ".txt"):
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(name, ".tgz") || strings.HasSuffix(name, ".tar.gz"):
		return "application/gzip"
	default:
		return ""
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

// joinPath appends the inbound Conan path to the upstream base, preserving any
// base-path prefix (e.g. an Artifactory remote served under
// "/artifactory/api/conan/<repo>").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// The Conan v2 layout embeds the recipe/package revision (a content hash), so the
// path alone is a content-addressable key; query parameters are incidental and
// excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
}

// siblingURL rewrites rawURL so its final path segment is replaced with name,
// yielding the URL of a sibling file in the same directory (used to locate a
// revision's conanmanifest.txt from a requested file). It returns ok=false if
// the URL cannot be parsed or has no path segment to replace.
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

// baseName returns the final path component of a slash-separated path.
func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
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
