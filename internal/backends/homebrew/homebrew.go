// Package homebrew implements a pull-through proxy backend for Homebrew, the
// macOS/Linux package manager, bringing it to parity with the
// pip/npm/cargo/dart/nix backends. Homebrew splits across two upstreams, both of
// which this backend fronts:
//
//   - Formula metadata, from the formulae.brew.sh JSON API. The brew client
//     downloads the JWS-signed full index (/api/formula.jws.json, with its cask
//     and tap-migration siblings) and verifies its signature, so those documents
//     are proxied byte-exact. The unsigned full index (/api/formula.json) and
//     per-formula documents (/api/formula/<name>.json) serve other API
//     consumers. All of them enumerate each formula's "bottle" — a precompiled
//     binary tarball — with its download URL and SHA-256, and all are mutable
//     and revalidated live.
//
//   - Bottle tarballs, which Homebrew distributes as OCI blobs in GitHub Packages
//     (ghcr.io). A bottle's download URL is a content-addressed OCI blob
//     reference, https://ghcr.io/v2/<repo>/blobs/sha256:<digest>, accompanied by
//     an OCI image index per formula version at
//     https://ghcr.io/v2/<repo>/manifests/<version>; both are fetched via the
//     Docker Registry v2 bearer-token handshake (see auth.go).
//
// How a bottle download reaches the proxy depends on the client:
//
//   - The brew client cannot be redirected by rewriting metadata (the index it
//     reads is signed). It is pointed at the proxy with
//     HOMEBREW_ARTIFACT_DOMAIN="<publicBase>", whereupon it replaces
//     "https://ghcr.io" in every bottle URL itself and requests the
//     registry-native paths "/v2/<repo>/manifests/<reference>" and
//     "/v2/<repo>/blobs/sha256:<hex>" from the proxy. The backend serves both:
//     the manifest live (forwarding the client's Accept), the blob as a cached,
//     verified bottle.
//
//   - For a consumer of the unsigned formula JSON, every bottle URL in a served
//     document is rewritten to the proxy's own synthetic
//     "/bottle/<name>/<version>/v2/.../blobs/sha256:<hex>" endpoint (under
//     PublicBaseURL), which carries the formula coordinate in its path.
//
// Security model: on either bottle path the backend reconstructs the upstream
// blob URL from the configured bottle-registry base — never from a host named in
// the request — fetches the blob (following the token handshake and any
// blob-storage redirect), and streams it through a verifying reader that
// recomputes its SHA-256 and refuses to cache or serve any bottle whose content
// does not match the hash named in its URL — verify-on-fetch,
// content-addressable caching, with a *DigestMismatchError on failure. Both
// paths share one digest-scoped cache entry.
//
// The admission gates (nameguard, policy, provenance, risk, and the install-hook
// / content-analysis content gates) need a concrete formula coordinate. The
// synthetic path names it. The registry-native path names only a repository and
// a digest, so the formula name is mapped back from the repository (name.go) and
// the version is learned from the image index the client fetches along with the
// bottle, with deterministic fallbacks when that is unavailable (manifest.go,
// flights.go, coordinate.go).
//
// A Homebrew bottle is addressed by an opaque OCI digest, and OSV.dev defines no
// ecosystem keyed by a Homebrew formula coordinate, so coordinate-based OSV
// scanning is not applicable (see internal/vulnscan/purl.go) — like the conda,
// Bazel, Julia, and Nix backends. A formula's underlying source is covered via
// the provenance/commit-scanning paths instead.
//
// Client configuration points Homebrew at the proxy with
// HOMEBREW_API_DOMAIN="<publicBase>/api" and
// HOMEBREW_ARTIFACT_DOMAIN="<publicBase>" (see docs/clients.md). Both are
// required: the first routes the metadata, the second is the only thing that
// routes the brew client's bottle downloads through the proxy.
package homebrew

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They are not persisted to the cache as
// meaningful data.
const (
	metaKind    = "_kind"    // resource-class label, for diagnostics/gates
	metaRewrite = "_rewrite" // "1" when the body is a formula doc to rewrite
	metaBlob    = "_blob"    // OCI blob path for a bottle
	metaRepo    = "_repo"    // OCI repository (bearer-token scope) for a bottle or manifest
	metaDigest  = "_digest"  // expected lowercase-hex SHA-256 for a bottle
	metaName    = "_name"    // formula name for a bottle
	metaVersion = "_version" // formula version for a bottle
	metaAccept  = "_accept"  // the client's Accept header, forwarded for a manifest
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaDigestVerified records "sha256" when a bottle's content was verified
	// against the content address named in its URL.
	MetaDigestVerified = "homebrew.digestVerified"
	// MetaFormula records the formula name a bottle was admitted under.
	MetaFormula = "homebrew.formula"
	// MetaVersion records the formula version a bottle is pinned to.
	MetaVersion = "homebrew.version"
	// MetaVersionSource records how that version was established: "url" (carried
	// by the synthetic bottle endpoint), "manifest" (learned from the OCI image
	// index), "formula-api" (recovered from the formula JSON API), or "digest"
	// (unknown; MetaVersion is then the "sha256:<hex>" stand-in).
	MetaVersionSource = "homebrew.versionSource"
)

// defaultBottleRegistry is the OCI registry Homebrew's core bottles live in.
const defaultBottleRegistry = "https://ghcr.io"

// Size bounds for the documents the backend buffers on the pull path.
const (
	// maxFormulaBytes bounds a formula document fetch. The full index
	// (/api/formula.json) is large (tens of MiB) but bounded; the cap stops a
	// hostile upstream returning an unbounded body.
	maxFormulaBytes = 128 << 20 // 128 MiB
	// maxErrorBodySnippet bounds how much of an upstream error body is retained.
	maxErrorBodySnippet = 2 << 10 // 2 KiB
)

// Options configures a Homebrew Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "homebrew").
	// Required.
	Name string
	// UpstreamURL is the formulae API base URL, e.g. "https://formulae.brew.sh".
	// The backend appends "/api/..." protocol paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/homebrew". It is used to
	// rewrite bottle download URLs in served formula metadata so bottle downloads
	// route back through the proxy. When empty, rewritten links fall back to the
	// root-relative "/v1/<name>" form.
	PublicBaseURL string
	// BottleRegistryURL is the OCI registry base Homebrew bottles are fetched
	// from, e.g. "https://ghcr.io". It is the only registry the backend ever
	// contacts for a manifest or a bottle: registry-native "/v2/..." requests are
	// served from it, and only bottle URLs on its host are rewritten through the
	// proxy in formula documents (others are left pointing at their origin,
	// fail-open). Defaults to https://ghcr.io.
	BottleRegistryURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstreams. Optional; public
	// Homebrew bottles pull anonymously (the bottle registry still issues an
	// anonymous bearer token). A private tap may require a token.
	Credentials upstream.Credentials
	// Offline keeps Resolve free of network I/O. When a bottle is requested on
	// the registry-native path and its formula version was not learned from a
	// manifest, the backend normally recovers it from the formula JSON API during
	// resolution; in a sealed (air-gapped) deployment that lookup must not
	// happen, so the digest-derived version is used directly instead.
	Offline bool
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Homebrew pull-through backend implementing backends.Backend.
type Backend struct {
	name         string
	base         *url.URL
	publicBase   string
	bottleBase   *url.URL
	registryHost string
	client       upstream.Doer
	auth         *authenticator
	creds        upstream.Credentials
	metrics      *Metrics

	// index is the bounded record of (repository, digest) -> formula coordinate
	// learned from manifests and the formula API.
	index *bottleIndex
	// flights tracks manifest fetches in progress, so a bottle request that
	// raced ahead of its manifest can wait for it.
	flights *manifestFlights
	// manifestWait bounds that wait (manifestWaitTimeout).
	manifestWait time.Duration
	// offline disables the Resolve-time formula-API lookup.
	offline bool
	// lookupTimeout bounds one formula-API recovery (formulaLookupTimeout).
	lookupTimeout time.Duration
	// now is the clock, injectable for tests.
	now func() time.Time
	// lookupResume is the UnixNano time before which formula-API recovery is
	// suspended after a failure (0 = not suspended).
	lookupResume atomic.Int64
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("homebrew: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("homebrew %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("homebrew %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("homebrew %q: upstream client is required", opts.Name)
	}

	registryURL := strings.TrimSpace(opts.BottleRegistryURL)
	if registryURL == "" {
		registryURL = defaultBottleRegistry
	}
	bottleBase, err := url.Parse(strings.TrimRight(registryURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: invalid bottle registry URL: %w", opts.Name, err)
	}
	if bottleBase.Scheme != "http" && bottleBase.Scheme != "https" {
		return nil, fmt.Errorf("homebrew %q: bottle registry URL must be http(s), got %q", opts.Name, bottleBase.Scheme)
	}

	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		// Fall back to the root-relative mount; the client resolves a relative
		// bottle URL against the request URL.
		publicBase = "/v1/" + opts.Name
	}

	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}

	b := &Backend{
		name:          opts.Name,
		base:          base,
		publicBase:    publicBase,
		bottleBase:    bottleBase,
		registryHost:  bottleBase.Host,
		client:        opts.Client,
		auth:          newAuthenticator(opts.Client, opts.Credentials, m.incTokensFetched),
		creds:         opts.Credentials,
		metrics:       m,
		flights:       newManifestFlights(),
		manifestWait:  manifestWaitTimeout,
		offline:       opts.Offline,
		lookupTimeout: formulaLookupTimeout,
		now:           time.Now,
	}
	// The index reads the backend's clock, so the two can never disagree.
	b.index = newBottleIndex(defaultBottleIndexSize, func() time.Time { return b.now() })
	return b, nil
}

// Metrics returns the backend's telemetry counters so the cmd wiring can bridge
// them into the central Prometheus collector.
func (b *Backend) Metrics() *Metrics { return b.metrics }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.name }

// Resolve implements backends.Backend. It classifies the inbound path against
// the Homebrew layout, derives the upstream URL and cache key, attaches the
// formula coordinate for the admission gates, and decides cacheability (only a
// bottle blob is cached).
//
// Resolve is immediate and free of network I/O with one exception: a bottle
// requested on the registry-native path whose formula version is not yet known.
// The gates that run between Resolve and Fetch need that version, so Resolve
// first waits (bounded) for a manifest fetch in progress on the same repository,
// and failing that looks the bottle up in the formula JSON API (a small,
// bounded, memoized metadata request) — see coordinate.go. Options.Offline
// disables the API lookup.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("homebrew: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Homebrew path", backends.ErrNotSupported, req.Path)
	}

	resolved := &backends.Resolved{
		Cacheable: res.cacheable() && isRead(req),
		CacheKey:  b.cacheKey(res, req.Path),
		Metadata: map[string]string{
			"backend": b.name,
			metaKind:  res.kindLabel(),
		},
		Artifact: res.artifact(),
	}

	if res.isBottle() {
		source := versionSourceURL
		if res.registryNative {
			// The registry-native blob URL names no version (and spells the name the
			// way the registry does): establish the coordinate the gates will see.
			res.name, res.version, source = b.bottleCoordinate(ctx, res)
			if err := ctx.Err(); err != nil {
				// The request was abandoned while its coordinate was being
				// established; do not hand the gates a stand-in for it.
				return nil, err
			}
			b.metrics.incVersionSource(source)
		}
		// The bottle's upstream URL is reconstructed from the configured registry
		// base and the OCI blob path carried in the request — never a host taken
		// from untrusted input.
		resolved.UpstreamURL = b.registryURL(res.blobPath)
		resolved.MediaType = "application/gzip"
		resolved.Coordinate = backends.Coordinate{Name: res.name, Version: res.version}
		resolved.Metadata[metaBlob] = res.blobPath
		resolved.Metadata[metaRepo] = res.repo
		resolved.Metadata[metaDigest] = res.digest
		resolved.Metadata[metaName] = res.name
		resolved.Metadata[metaVersion] = res.version
		resolved.Metadata[MetaFormula] = res.name
		resolved.Metadata[MetaVersion] = res.version
		resolved.Metadata[MetaVersionSource] = source
		return resolved, nil
	}

	if res.kind == kindManifest {
		// Like a bottle, a manifest is only ever fetched from the configured
		// registry, at a path rebuilt from validated components. It is mutable (a
		// tag can be re-pushed), so it is served live and carries a name but no
		// version: it is metadata, not the payload the version gates apply to.
		resolved.UpstreamURL = b.registryURL(ociAPIPrefix + "/" + res.repo + "/" + ociManifestMarker + "/" + res.reference)
		resolved.Coordinate = backends.Coordinate{Name: res.name}
		resolved.Metadata[metaRepo] = res.repo
		// Forward the client's media-type negotiation: brew asks for the OCI image
		// index, and the registry answers a tag with whichever representation the
		// Accept header admits.
		if accept := manifestAccept(req.Header); accept != "" {
			resolved.Metadata[metaAccept] = accept
		}
		return resolved, nil
	}

	abs := b.joinPath(req.Path)
	if enc := req.Query.Encode(); enc != "" {
		abs.RawQuery = enc
	}
	resolved.UpstreamURL = abs.String()
	if res.rewrites() {
		resolved.Metadata[metaRewrite] = "1"
	}
	if res.kind == kindFormula {
		resolved.Coordinate = backends.Coordinate{Name: res.name}
	}
	return resolved, nil
}

// Fetch implements backends.Backend. A bottle is fetched via the ghcr token
// handshake and streamed through a verifying reader so a SHA-256 mismatch aborts
// the cache write and client stream. A manifest is fetched via the same
// handshake and served unmodified, after the backend has read the bottle
// versions out of it. A formula document is buffered and its bottle URLs
// rewritten through the proxy. Other metadata is proxied byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("homebrew: nil resolved")
	}
	switch resolved.Metadata[metaKind] {
	case "bottle":
		return b.fetchBottle(ctx, resolved)
	case "manifest":
		return b.fetchManifest(ctx, resolved)
	default:
		return b.fetchMetadata(ctx, resolved)
	}
}

// fetchManifest fetches an OCI manifest or image index from the bottle registry
// through the bearer-token handshake, forwarding the client's Accept header so
// the registry returns the representation the client negotiated, and serves the
// body byte-exact with the registry's own media type. On the way through it
// records the bottle versions the document describes (learnManifest), which is
// how the bottle request that follows gets its coordinate.
func (b *Backend) fetchManifest(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	repo := resolved.Metadata[metaRepo]
	// Announce the fetch for as long as it takes to learn from it, so a bottle
	// request brew sent in parallel waits for this manifest instead of resolving
	// its coordinate without it (see flights.go).
	defer b.flights.begin(repo)()

	accept := resolved.Metadata[metaAccept]
	if accept == "" {
		accept = defaultManifestAccept
	}
	resp, err := b.auth.do(ctx, upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
		Header:      http.Header{"Accept": {accept}},
	}, "repository:"+repo+":pull")
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: reading manifest: %w", b.name, err)
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("homebrew %q: manifest exceeds %d bytes", b.name, maxManifestBytes)
	}

	b.learnManifest(repo, data)
	b.metrics.incManifestsServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(data)),
		Size:      int64(len(data)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// manifestAccept returns the Accept value to forward to the registry for a
// manifest request, or "" when the client expressed no preference and the
// default set (defaultManifestAccept) should be offered instead. A bare "*/*" —
// what curl sends unprompted — counts as no preference: ghcr does not expand a
// wildcard to the OCI image-index type and would answer 404, whereas naming the
// manifest types explicitly is exactly what a client that accepts anything
// asked for.
func manifestAccept(h http.Header) string {
	accept := strings.TrimSpace(strings.Join(h.Values("Accept"), ", "))
	if accept == "*/*" {
		return ""
	}
	return accept
}

// learnManifest records, for every bottle an OCI document from repo describes,
// its formula version (and the formula's true name, when the document's title
// annotation is consistent with the repository) in the bottle index. A document
// that describes no bottle teaches nothing.
func (b *Backend) learnManifest(repo string, data []byte) {
	facts, ok := parseBottleManifest(data)
	if !ok {
		return
	}
	tap, image := splitRepo(repo)
	// An absent or inconsistent title leaves the name to the repository path.
	name, _ := formulaNameFromTitle(tap, image, facts.title)
	for _, bottle := range facts.bottles {
		b.index.put(bottleKey{repo: repo, digest: bottle.digest}, bottleFact{
			name:    name,
			version: bottle.version,
			source:  versionSourceManifest,
		})
	}
}

// fetchBottle fetches a bottle OCI blob through the registry bearer-token
// handshake and streams it through a verifying reader keyed on the SHA-256
// content address named in its URL.
func (b *Backend) fetchBottle(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	scope := "repository:" + resolved.Metadata[metaRepo] + ":pull"
	req := upstream.Request{
		URL:         resolved.UpstreamURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: resolved.IfNoneMatch,
		Header:      http.Header{"Accept": {"application/octet-stream"}},
	}
	resp, err := b.auth.do(ctx, req, scope)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}
	if !resp.IsSuccess() {
		return nil, b.statusError(resp, resolved.UpstreamURL)
	}

	b.metrics.incBottlesServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}

	expected := resolved.Metadata[metaDigest]
	resolved.Metadata[MetaDigestVerified] = "sha256"
	content := newBottleVerifier(resp.Body, expected,
		resolved.Metadata[metaName], resolved.Metadata[metaVersion], resolved.UpstreamURL,
		func(ok bool) {
			if ok {
				b.metrics.incBottlesVerified()
			} else {
				b.metrics.incBottleHashMismatch()
			}
		})
	header.Set("X-Content-Hash-Verified", "sha256")

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/gzip"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		Digest:    "sha256:" + expected,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchMetadata fetches a formulae.brew.sh document. A formula document (the
// full index or a per-formula document) is buffered so its bottle URLs can be
// rewritten through the proxy; other metadata is proxied byte-exact.
func (b *Backend) fetchMetadata(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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

	if resolved.Metadata[metaRewrite] == "1" {
		return b.fetchFormula(resolved, resp, header)
	}

	b.metrics.incMetadataServed()
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
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

// fetchFormula buffers a formula document and rewrites its bottle URLs to the
// proxy's bottle endpoint. A document that does not parse as JSON is served
// unchanged (fail-open), so a non-standard metadata document still reaches the
// client.
func (b *Backend) fetchFormula(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFormulaBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("homebrew %q: reading formula document: %w", b.name, err)
	}
	if int64(len(data)) > maxFormulaBytes {
		return nil, fmt.Errorf("homebrew %q: formula document exceeds %d bytes", b.name, maxFormulaBytes)
	}

	rewritten, n := rewriteBottleURLs(data, b.publicBase, b.registryHost)
	if n > 0 {
		b.metrics.incFormulaRewritten()
		data = rewritten
	}
	// A rewrite changes the body length; let the serving layer recompute it.
	header.Del("Content-Length")
	header.Del("ETag")

	b.metrics.incFormulaServed()
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/json"
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(string(data))),
		Size:      int64(len(data)),
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// registryURL reconstructs an upstream OCI URL (a blob or a manifest) from the
// configured bottle registry base and a "v2/..." path. The scheme and host
// always come from configuration, so no request can steer the backend at
// another registry.
func (b *Backend) registryURL(ociPath string) string {
	out := *b.bottleBase
	basePath := strings.TrimRight(b.bottleBase.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(ociPath, "/")
	out.RawPath = ""
	return out.String()
}

// get performs a GET against the formulae API with the backend's credentials.
func (b *Backend) get(ctx context.Context, rawURL, ifNoneMatch string) (*upstream.Response, error) {
	return b.client.Do(ctx, upstream.Request{
		URL:         rawURL,
		Method:      http.MethodGet,
		Creds:       b.creds,
		IfNoneMatch: ifNoneMatch,
		Header:      http.Header{"Accept": {"application/json"}},
	})
}

// statusError drains the body and returns a StatusError carrying a diagnostic
// snippet.
func (b *Backend) statusError(resp *upstream.Response, url string) error {
	snippet := readSnippet(resp.Body)
	drainClose(resp.Body)
	return &backends.StatusError{Status: resp.Status, URL: url, Body: snippet}
}

// joinPath appends the inbound formulae-API path to the upstream base,
// preserving any base-path prefix.
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key. A bottle embeds its SHA-256 content
// address, so a digest-scoped key is content-addressable across formulae — and
// across the two bottle paths, so a bottle cached through the synthetic endpoint
// is a hit for the registry-native one and vice versa; metadata and manifests
// (never cached) key on their layout path.
func (b *Backend) cacheKey(res resource, path string) string {
	if res.isBottle() {
		return b.name + ":bottle:sha256:" + res.digest
	}
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
