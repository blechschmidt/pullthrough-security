// Package docker implements a Docker Registry v2 (OCI distribution) pull-through
// proxy backend. It fronts an upstream registry (Docker Hub, GHCR, a private
// registry, ...) and serves the read endpoints of the distribution API:
//
//	GET/HEAD /v2/                         API version / auth probe
//	GET/HEAD /v2/<name>/manifests/<ref>   image manifest or manifest list (multi-arch index)
//	GET/HEAD /v2/<name>/blobs/<digest>    config and layer blobs
//	GET      /v2/<name>/referrers/<digest> OCI referrers (signatures, SBOMs, attestations)
//	GET      /v2/<name>/tags/list         tag listing
//	GET      /v2/_catalog                 repository listing
//
// Nothing else under /v2/ is forwarded. The proxy answers the upstream's
// authentication challenges with its own credentials, so an open-ended /v2/
// pass-through would also reach a registry-hosted token endpoint (Artifactory
// and Nexus /v2/token, Quay /v2/auth) and relay a token minted for the proxy's
// account to the client (see parseReference).
//
// It performs the registry bearer-token handshake against the upstream
// (see auth.go), caches immutable, digest-addressed content in the shared
// content-addressable store, and verifies that fetched bytes hash to their
// expected digest before they are stored or served (see digest.go). Manifest
// lists are handled transparently: the client's Accept header is forwarded so
// the upstream returns either a multi-arch index or a platform-specific
// manifest, and digest-addressed sub-manifests are cached like any other
// immutable object.
//
// Caching policy:
//   - Blobs (always digest-addressed) and manifests referenced by digest are
//     immutable; they are cached and digest-verified, and keyed by digest so the
//     same content shared across repositories is stored once.
//   - Manifests referenced by a tag are mutable (a tag can be re-pushed), so
//     they are never cached; they are served live with conditional revalidation.
//   - Listing and probe endpoints are served live.
package docker

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

// Internal metadata keys carry per-request decisions from Resolve to Fetch
// (which only receives the *Resolved). They mirror the convention used by the
// generic httpbackend and are not persisted to the cache as meaningful data.
const (
	metaAccept = "_accept"
	metaScope  = "_scope"
	// metaKind records the distribution-API resource class ("manifest", "blob", or
	// "referrers") so downstream gates (e.g. signature verification) can target
	// image manifests without re-parsing the path. It is advisory metadata.
	metaKind = "_kind"
	// metaRepo and metaSubject carry the repository name and subject digest of a
	// Referrers API request from Resolve to Fetch, so Fetch can compose the
	// referrers fallback-tag URL without re-parsing the path.
	metaRepo    = "_repo"
	metaSubject = "_subject"
)

// ociIndexAccept is the default Accept offered when a client did not negotiate a
// media type on a Referrers API request. The Referrers API (and its fallback
// tag) return an OCI image index.
const ociIndexAccept = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json"

// Options configures a docker registry Backend.
type Options struct {
	// Name is the route identifier (e.g. "dockerhub"). Required.
	Name string
	// UpstreamURL is the registry base URL, e.g. "https://registry-1.docker.io"
	// for Docker Hub or "https://ghcr.io". Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected in place
	// of the bare *upstream.Client to add registry-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream registry's token
	// endpoint. Optional; public images pull anonymously.
	Credentials upstream.Credentials
}

// Backend is a Docker Registry v2 pull-through backend implementing
// backends.Backend.
type Backend struct {
	name string
	base *url.URL
	auth *authenticator
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("docker: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("docker %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("docker %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("docker %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("docker %q: upstream client is required", opts.Name)
	}
	return &Backend{
		name: opts.Name,
		base: base,
		auth: newAuthenticator(opts.Client, opts.Credentials),
	}, nil
}

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the distribution-API
// request, derives the upstream URL, the cache key, the expected digest (for
// content-addressed resources), and the cacheability policy.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("docker: nil request")
	}

	ref, ok := parseReference(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Registry v2 path", backends.ErrNotSupported, req.Path)
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}

	resolved := &backends.Resolved{
		Coordinate:  backends.Coordinate{Name: ref.name, Version: ref.reference},
		UpstreamURL: abs.String(),
		Metadata:    map[string]string{"backend": b.name},
	}
	if scope := ref.scope(); scope != "" {
		resolved.Metadata[metaScope] = scope
	}

	switch ref.kind {
	case refBlob:
		// Blobs are always digest-addressed and immutable: cache, verify, and key
		// by digest so identical content shared across repositories is stored once.
		resolved.Digest = ref.reference
		resolved.Cacheable = isRead(req)
		resolved.CacheKey = b.name + ":blobs:" + ref.reference
		resolved.Metadata[metaKind] = "blob"

	case refManifest:
		// Forward Accept so the upstream returns the representation the client
		// negotiated (a multi-arch index or a platform-specific manifest).
		if accept := acceptHeader(req.Header); accept != "" {
			resolved.Metadata[metaAccept] = accept
		}
		resolved.Metadata[metaKind] = "manifest"
		if ref.isDigest {
			// Digest-addressed manifests are immutable: cache, verify, key by digest.
			resolved.Digest = ref.reference
			resolved.Cacheable = isRead(req)
			resolved.CacheKey = b.name + ":manifests:" + ref.reference
		} else {
			// Tag-addressed manifests are mutable: never cache, revalidate live.
			resolved.Cacheable = false
			resolved.CacheKey = b.name + ":manifests:" + ref.name + ":" + ref.reference
		}

	case refReferrers:
		// OCI Distribution v1.1 Referrers API: GET /v2/<name>/referrers/<digest>.
		// The response is a dynamically-assembled OCI image index of the artifacts
		// (signatures, SBOMs, in-toto/SLSA attestations) that reference the subject
		// digest. It is mutable — new referrers may be pushed for the same subject
		// at any time — so it is served live and never cached. The path digest
		// identifies the *subject*, not the response body, so the response is not
		// digest-verified here; the referrer manifests and blobs it points to are
		// digest-addressed and are cached and verified like any other immutable
		// object when they are subsequently fetched.
		if accept := acceptHeader(req.Header); accept != "" {
			resolved.Metadata[metaAccept] = accept
		}
		resolved.Metadata[metaKind] = "referrers"
		resolved.Metadata[metaRepo] = ref.name
		resolved.Metadata[metaSubject] = ref.reference
		resolved.Cacheable = false
		resolved.CacheKey = b.name + ":referrers:" + ref.name + ":" + ref.reference

	default:
		// Probe and listing endpoints: serve live, no digest, no caching.
		resolved.Cacheable = false
		resolved.CacheKey = b.name + ":" + strings.TrimLeft(req.Path, "/")
	}

	return resolved, nil
}

// acceptHeader returns the client's complete content negotiation as a single
// Accept value. A client may send the media types it accepts as one
// comma-separated header or as several Accept header lines; the Docker Engine
// does the latter (one line per manifest media type). http.Header.Get returns
// only the first line, which silently narrowed the negotiation to a single
// media type: a registry that stores an image as an OCI index (ghcr.io) then
// answered a tag lookup with 404 "manifest unknown" because the one forwarded
// type did not match. All lines are therefore folded into one list (RFC 9110
// §5.3: repeated field lines are equivalent to a comma-separated list).
func acceptHeader(h http.Header) string {
	if h == nil {
		return ""
	}
	return strings.Join(h.Values("Accept"), ", ")
}

// Fetch implements backends.Backend. It performs the authenticated upstream
// request (running the token handshake as needed) and, when the resource is
// digest-addressed, wraps the body so the content is verified against its digest
// as it streams to the cache and the client.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("docker: nil resolved")
	}

	header := make(http.Header)
	if accept := resolved.Metadata[metaAccept]; accept != "" {
		header.Set("Accept", accept)
	}

	resp, err := b.auth.do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Header:      header,
		IfNoneMatch: resolved.IfNoneMatch,
	}, resolved.Metadata[metaScope])
	if err != nil {
		return nil, err
	}

	if resp.NotModified {
		return &backends.FetchResult{
			Resolved:    resolved,
			Status:      http.StatusNotModified,
			NotModified: true,
		}, nil
	}

	if !resp.IsSuccess() {
		// OCI Distribution v1.1: a registry that does not implement the Referrers
		// API answers GET /v2/<name>/referrers/<digest> with 404 (or 400). In that
		// case the client must fall back to the referrers fallback-tag schema — an
		// image index pushed under the tag "<algorithm>-<hex>" of the subject
		// digest. Perform that fallback transparently so referrer discovery works
		// uniformly across registries. A fallback that itself fails is surfaced as
		// an error, so callers (the verification gates) fall through to their own
		// discovery schemes rather than seeing a spurious empty index.
		if resolved.Metadata[metaKind] == "referrers" && (resp.Status == http.StatusNotFound || resp.Status == http.StatusBadRequest) {
			drainClose(resp.Body)
			return b.fetchReferrersFallback(ctx, resolved)
		}
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{
			Status: resp.Status,
			URL:    resolved.UpstreamURL,
			Body:   snippet,
		}
	}

	outHeader := make(http.Header)
	upstream.PropagateResponseHeaders(outHeader, resp.Header)
	// PropagateResponseHeaders intentionally drops proxy-owned validator headers;
	// re-attach the upstream's strong validators so conditional revalidation works.
	if resp.ETag != "" {
		outHeader.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		outHeader.Set("Last-Modified", resp.LastModified)
	}

	content := resp.Body
	if resolved.Digest != "" {
		expected, err := ParseDigest(resolved.Digest)
		if err != nil {
			drainClose(resp.Body)
			return nil, err
		}
		// Verify on store and on serve: the wrapped reader feeds both the cache
		// (cold fill) and the client, and aborts the stream on a hash mismatch so
		// poisoned content is neither cached nor served.
		content = newVerifyingReader(resp.Body, expected)
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Digest:    resolved.Digest,
		Header:    outHeader,
		Status:    resp.Status,
	}, nil
}

// fetchReferrersFallback implements the OCI Distribution v1.1 referrers
// fallback-tag schema. When the Referrers API endpoint is unavailable, the index
// of artifacts referencing a subject digest is retrieved from the tag
// "<algorithm>-<hex>" of that digest. The result is returned as the referrers
// response (served live, never cached); the referrer manifests and blobs it
// points to remain digest-addressed and are cached and verified on fetch.
func (b *Backend) fetchReferrersFallback(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	repo := resolved.Metadata[metaRepo]
	tag, ok := referrersFallbackTag(resolved.Metadata[metaSubject])
	if repo == "" || !ok {
		// Without a well-formed repository and subject digest there is no fallback
		// tag to try; report the subject as having no referrers index.
		return nil, &backends.StatusError{
			Status: http.StatusNotFound,
			URL:    resolved.UpstreamURL,
			Body:   "referrers API unavailable and no fallback tag could be derived",
		}
	}

	fallbackURL := b.joinPath("/v2/" + repo + "/manifests/" + tag).String()

	header := make(http.Header)
	if accept := resolved.Metadata[metaAccept]; accept != "" {
		header.Set("Accept", accept)
	} else {
		header.Set("Accept", ociIndexAccept)
	}

	resp, err := b.auth.do(ctx, upstream.Request{
		URL:    fallbackURL,
		Method: http.MethodGet,
		Header: header,
	}, resolved.Metadata[metaScope])
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{
			Status: resp.Status,
			URL:    fallbackURL,
			Body:   snippet,
		}
	}

	outHeader := make(http.Header)
	upstream.PropagateResponseHeaders(outHeader, resp.Header)
	if resp.ETag != "" {
		outHeader.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		outHeader.Set("Last-Modified", resp.LastModified)
	}

	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   resp.Body,
		Size:      resp.ContentLength,
		MediaType: resp.ContentType,
		Header:    outHeader,
		Status:    resp.Status,
	}, nil
}

// referrersFallbackTag maps a subject digest "<algorithm>:<hex>" to the OCI v1.1
// referrers fallback tag "<algorithm>-<hex>". It returns ok=false for a malformed
// digest.
func referrersFallbackTag(digest string) (string, bool) {
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || algo == "" || hex == "" {
		return "", false
	}
	return algo + "-" + hex, true
}

// joinPath appends the inbound v2 API path to the upstream base, preserving any
// base path prefix (e.g. a registry served under "/some/prefix").
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

func isRead(req *backends.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == ""
}

// maxErrorBodySnippet bounds how much of an upstream error body is retained for
// diagnostics.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

func readSnippet(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxErrorBodySnippet))
	return strings.TrimSpace(string(buf))
}
