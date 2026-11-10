// Package composer implements a pull-through proxy backend for the Composer/
// Packagist ecosystem (packagist.org and any Satis/Toran/Artifactory/Nexus mirror
// serving the same protocol). It brings PHP to parity with the other package
// backends: the repository root (packages.json), the Composer v2 metadata layout
// (/p2/<vendor>/<package>.json), the legacy v1 provider documents, and dist
// archive downloads are all proxied; dist archives are cached and, when the
// package's v2 metadata declares a SHA-1 shasum for them, verified against it
// before the bytes are cached or served.
//
// Protocol mapping (route prefix "/v1/<name>" stripped; see path.go):
//
//	GET /packages.json                          repository root (mutable, rewritten).
//	GET /p2/<vendor>/<package>.json             v2 release metadata (mutable, dist URLs rewritten).
//	GET /p2/<vendor>/<package>~dev.json         v2 dev metadata (mutable, dist URLs rewritten).
//	GET /p/<vendor>/<package>.json              legacy v1 provider (mutable, as-is).
//	GET /lists/<...>.json                       filter-list summary (mutable, as-is).
//	GET /dist/<vendor>/<package>/<version>/<reference>.<type>
//	                                            dist archive (immutable, cached, shasum-verified).
//
// Routing model: a Composer client follows the URLs the repository hands it. The
// root document and every v2 metadata document are therefore rewritten on the way
// out (see rewrite.go) so that metadata lookups and dist downloads all come back
// to this backend; a client configured with only the proxy repository never
// contacts the upstream or the hosts it delegates archives to. The dist endpoint
// names the package and the version, so Resolve yields a complete coordinate and
// the admission gates evaluate the archive before it is fetched.
//
// Security model: a dist request names a package, a version and a dist reference.
// On a cache miss the backend re-reads the package's v2 metadata from the
// upstream, requires an entry with exactly that version, reference and type, and
// fetches the download URL that entry lists — nothing else, so the endpoint
// cannot be used to relay arbitrary URLs or to pull a commit the upstream never
// published for that version. The fetch goes through the shared upstream client
// (and its egress guard), following redirects such as GitHub's
// api.github.com -> codeload.github.com. The upstream's credentials are only sent
// when the archive lives on the upstream host itself.
//
// When the entry declares a "dist.shasum" (SHA-1) the streamed archive is
// verified against it, and a mismatch aborts the cache write and the response,
// so a tampered or corrupt mirror can neither poison the cache nor reach a
// client. Packagist does not publish a shasum for archives a VCS host generates
// on the fly (every GitHub zipball has an empty one): such an archive is cached
// exactly as fetched, its integrity resting on TLS to the host the metadata
// names and on the content gates that inspect the cached bytes. Every later
// request for that version and reference is then served those same bytes.
//
// Client configuration adds "<publicBase>/v1/<name>" as a composer repository
// and disables the default packagist.org repository (see docs/clients.md).
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
	metaVersion   = "_version"   // package version (for dist requests)
	metaReference = "_reference" // dist reference token (for dist requests)
	metaDistExt   = "_ext"       // dist type / archive extension
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates.
const (
	// MetaChecksumVerified records "sha1" when a dist archive was verified, or
	// "none" when the metadata declared no shasum for it (it is then cached as
	// fetched).
	MetaChecksumVerified = "composer.checksumVerified"
	// MetaLicenses records a comma-separated list of license identifiers declared
	// for the served version, for the license-compliance gate.
	MetaLicenses = "composer.licenses"
	// MetaDistURL records the upstream URL a dist archive was fetched from: the
	// "dist.url" the upstream metadata lists for the served version, less any
	// credentials or query string.
	MetaDistURL = "composer.distUrl"
	// MetaReference records the dist reference (for a VCS-backed package, the
	// commit id) of the served archive, when the metadata declares one.
	MetaReference = "composer.reference"
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
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/packagist". It is used to
	// rewrite the lookup templates in packages.json and the dist URLs in v2
	// metadata so every request routes back through the proxy. It must be an
	// absolute http(s) URL or a root-relative path. When empty it falls back to
	// the root-relative "/v1/<name>" form; Composer cannot download a dist from a
	// root-relative URL, so in that mode the root document also advertises the
	// dist endpoint as a preferred dist mirror (see rewrite.go).
	PublicBaseURL string
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
	name string
	base *url.URL
	// publicBase is the base every rewritten URL is built from, without a
	// trailing slash: an absolute URL, or the root-relative mount.
	publicBase string
	// absolutePublicBase reports whether publicBase is an absolute URL (and a
	// rewritten dist URL therefore directly downloadable by a Composer client).
	absolutePublicBase bool
	client             upstream.Doer
	creds              upstream.Credentials
	metrics            *Metrics
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
	publicBase, absolute, err := normalizePublicBase(opts.Name, opts.PublicBaseURL)
	if err != nil {
		return nil, err
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:               opts.Name,
		base:               base,
		publicBase:         publicBase,
		absolutePublicBase: absolute,
		client:             opts.Client,
		creds:              opts.Credentials,
		metrics:            m,
	}, nil
}

// normalizePublicBase validates the configured public base and reports whether
// it is absolute. An empty value falls back to the root-relative mount, which a
// client resolves against the proxy host it is already talking to.
func normalizePublicBase(name, raw string) (base string, absolute bool, err error) {
	base = strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return "/v1/" + name, false, nil
	}
	if strings.HasPrefix(base, "/") && !strings.HasPrefix(base, "//") {
		return base, false, nil
	}
	u, perr := url.Parse(base)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false, fmt.Errorf("composer %q: public base URL %q must be an absolute http(s) URL or a root-relative path", name, raw)
	}
	return base, true, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against the
// Composer layout, derives the upstream URL and cache key, attaches the package
// coordinate for the admission gates, and decides cacheability (immutable dist
// archives cached; mutable metadata revalidated). A dist path names the package
// and the version, so its coordinate is complete here — before the gates run and
// before anything is fetched. For a dist request the upstream URL is the
// package's v2 metadata document, from which Fetch derives the real download URL
// and verification shasum.
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

	var upstreamURL, cacheKey string
	if res.kind == kindDist {
		// The dist path is the proxy's own locator; the real upstream URL is
		// discovered from the package metadata at Fetch time. The cache key is
		// built from the parsed locator so every spelling of it shares one entry.
		upstreamURL = b.metadataURL(res.vendor, res.pkg, isDevVersion(res.version))
		cacheKey = b.name + ":" + res.distKey()
	} else {
		abs := b.joinPath(req.Path)
		if enc := req.Query.Encode(); enc != "" {
			abs.RawQuery = enc
		}
		upstreamURL = abs.String()
		cacheKey = b.cacheKey(req.Path)
	}

	cacheable := res.cacheable() && isRead(req)
	resolved := &backends.Resolved{
		UpstreamURL: upstreamURL,
		Cacheable:   cacheable,
		CacheKey:    cacheKey,
		Metadata: map[string]string{
			"backend":     b.name,
			metaKind:      res.kindLabel(),
			metaVendor:    res.vendor,
			metaPkg:       res.pkg,
			metaVersion:   res.version,
			metaReference: res.reference,
			metaDistExt:   res.ext,
		},
	}

	if cn := res.coordinateName(); cn != "" {
		// Only a dist carries a version; a metadata document identifies the
		// package alone and is not a gated artifact.
		resolved.Coordinate = backends.Coordinate{Name: cn, Version: res.version}
	}

	if res.verifiableArtifact() {
		resolved.Metadata[metaVerify] = "1"
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A dist request first fetches and parses the
// package's v2 metadata to recover the real download URL and the SHA-1 shasum,
// then fetches and verifies the archive. The root and v2 metadata documents are
// buffered and rewritten so the URLs they hand a client point back at the proxy;
// other documents are proxied as-is.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("composer: nil resolved")
	}
	if resolved.Metadata[metaVerify] == "1" {
		return b.fetchDist(ctx, resolved)
	}
	return b.fetchDocument(ctx, resolved)
}

// fetchDocument proxies a metadata/root/provider document. The repository root
// and v2 metadata are rewritten (see rewrite.go); the legacy provider and
// filter-list documents stream straight through.
func (b *Backend) fetchDocument(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	kind := resolved.Metadata[metaKind]
	rewritten := kind == "root" || kind == "metadata"

	// A rewritten document is a different representation than the upstream's, so
	// the upstream's validator does not describe it: no conditional request is
	// made on its behalf and no upstream ETag is passed on. (A Composer client
	// does not use entity tags.)
	ifNoneMatch := resolved.IfNoneMatch
	if rewritten {
		ifNoneMatch = ""
	}

	resp, err := b.client.Do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: ifNoneMatch,
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

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	// Unlike the entity tag, the modification time still describes a rewritten
	// document (it changes when the upstream's does), so it is handed on with the
	// result; it is what a Composer client keys its metadata reuse on.
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	if !rewritten {
		b.metrics.incMetadataServed()
		if resp.ETag != "" {
			header.Set("ETag", resp.ETag)
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

	// Both rewritten documents are small enough to buffer (bounded): the root is a
	// few hundred bytes, a package's v2 metadata at most a few MiB.
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	drainClose(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("composer %q: reading %s document: %w", b.name, kind, rerr)
	}
	if int64(len(data)) > maxMetadataBytes {
		return nil, fmt.Errorf("composer %q: %s document exceeds %d bytes", b.name, kind, maxMetadataBytes)
	}

	// A document that cannot be rewritten is refused rather than passed through:
	// served as-is it would send the client around the proxy.
	var out []byte
	if kind == "root" {
		out, err = b.rewriteRoot(data)
	} else {
		out, err = b.rewriteMetadata(data)
		if err != nil {
			b.metrics.incMetadataErrors()
		} else {
			b.metrics.incMetadataParsed()
		}
	}
	if err != nil {
		return nil, fmt.Errorf("composer %q: upstream %s is malformed: %w", b.name, resolved.UpstreamURL, err)
	}
	b.metrics.incMetadataServed()

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(out)),
		Size:      int64(len(out)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchDist resolves a dist request: it re-reads the package's v2 metadata,
// requires an entry with exactly the requested version, reference and type,
// fetches the upstream download URL that entry lists, and — when the entry
// declares a shasum — streams the archive through a SHA-1-verifying reader.
func (b *Backend) fetchDist(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	meta := resolved.Metadata
	entry, err := b.lookupDist(ctx, meta[metaVendor], meta[metaPkg], meta[metaVersion], meta[metaReference], meta[metaDistExt])
	if err != nil {
		return nil, err
	}

	// The entry was only ever advertised to clients when its URL is http(s) (see
	// rewriteMetadata); anything else is not something the proxy fetches.
	distURL, err := url.Parse(entry.Dist.URL)
	if err != nil || (distURL.Scheme != "http" && distURL.Scheme != "https") || distURL.Host == "" {
		return nil, &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    resolved.UpstreamURL,
			Body:   "composer: the listed dist URL is not an http(s) URL",
		}
	}

	if names := strings.Join(entry.License, ","); names != "" {
		meta[MetaLicenses] = names
	}
	// Recorded for the audit trail without credentials or a query string: some
	// registries put access tokens in their dist URLs, and cache metadata is not a
	// place to keep them.
	recorded := *distURL
	recorded.User, recorded.RawQuery, recorded.Fragment = nil, "", ""
	meta[MetaDistURL] = recorded.String()
	if entry.Dist.Reference != "" {
		meta[MetaReference] = entry.Dist.Reference
	}

	// The upstream's credentials belong to the upstream: a dist hosted elsewhere
	// (GitHub, a CDN) must never receive them.
	creds := b.creds
	if !strings.EqualFold(distURL.Host, b.base.Host) {
		creds = upstream.Credentials{}
	}
	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    entry.Dist.URL,
		Method: http.MethodGet,
		Creds:  creds,
	})
	if err != nil {
		return nil, err
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: entry.Dist.URL, Body: snippet}
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}

	content := resp.Body
	if expected, ok := entry.Checksum(); ok {
		meta[MetaChecksumVerified] = "sha1"
		content = newVerifyingReader(resp.Body, expected, entry.Dist.URL, func(ok bool) {
			if ok {
				b.metrics.incDistVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		header.Set("X-Checksum-Verified", "sha1")
	} else {
		// No shasum to hold the archive to (the norm for VCS-generated archives):
		// it is cached exactly as fetched.
		b.metrics.incChecksumMissing()
		meta[MetaChecksumVerified] = "none"
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

// lookupDist finds the upstream metadata entry a dist request refers to. Release
// versions live in the package's main v2 document and dev versions in its "~dev"
// sibling; the likelier document is read first and the other one as a fallback,
// so a mirror that files versions differently is still served. A dist that
// neither document lists is a 404 — the request is never forwarded anywhere.
func (b *Backend) lookupDist(ctx context.Context, vendor, pkg, version, token, distType string) (Version, error) {
	name := vendor + "/" + pkg
	dev := isDevVersion(version)
	var firstErr error
	for _, wantDev := range [2]bool{dev, !dev} {
		md, err := b.fetchMetadata(ctx, b.metadataURL(vendor, pkg, wantDev))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if entry, ok := md.FindDist(name, version, token, distType); ok {
			return entry, nil
		}
	}
	if firstErr != nil {
		// The dist may well be listed in the document that could not be read;
		// report the upstream failure rather than a misleading "not found".
		return Version{}, firstErr
	}
	return Version{}, &backends.StatusError{
		Status: http.StatusNotFound,
		URL:    b.metadataURL(vendor, pkg, dev),
		Body:   fmt.Sprintf("composer: %s %s with dist reference %q (%s) is not listed in the upstream metadata", name, version, token, distType),
	}
}

// fetchMetadata fetches and parses one v2 metadata document. A document the
// upstream does not have (404/410) yields a nil Metadata and no error.
func (b *Backend) fetchMetadata(ctx context.Context, metadataURL string) (*Metadata, error) {
	resp, err := b.client.Do(ctx, upstream.Request{
		URL:    metadataURL,
		Method: http.MethodGet,
		Creds:  b.creds,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status == http.StatusNotFound || resp.Status == http.StatusGone {
		drainClose(resp.Body)
		return nil, nil
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: metadataURL, Body: snippet}
	}
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	drainClose(resp.Body)
	if rerr != nil {
		return nil, fmt.Errorf("composer %q: reading metadata: %w", b.name, rerr)
	}
	if int64(len(data)) > maxMetadataBytes {
		return nil, fmt.Errorf("composer %q: metadata exceeds %d bytes", b.name, maxMetadataBytes)
	}
	md, perr := ParseMetadata(data)
	if perr != nil {
		b.metrics.incMetadataErrors()
		return nil, fmt.Errorf("composer %q: upstream %s is malformed: %w", b.name, metadataURL, perr)
	}
	b.metrics.incMetadataParsed()
	return md, nil
}

// metadataURL builds the upstream v2 metadata document URL for a package: the
// release document, or its "~dev" sibling.
func (b *Backend) metadataURL(vendor, pkg string, dev bool) string {
	suffix := ".json"
	if dev {
		suffix = "~dev.json"
	}
	return b.joinPath("/p2/" + vendor + "/" + pkg + suffix).String()
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
