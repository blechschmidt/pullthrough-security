// Package nix implements a pull-through proxy backend for a Nix / Flakes binary
// cache (the public default is https://cache.nixos.org, and any HTTP binary
// cache produced by `nix copy --to`), bringing Nix to parity with the
// pip/npm/cargo/go/bazel/julia backends.
//
// A Nix binary cache is a small, mostly content-addressed HTTP tree
// (https://nixos.org/manual/nix/stable/package-management/binary-cache-substituter):
//
//	GET /nix-cache-info             cache descriptor (StoreDir, Priority, ...)  (live)
//	GET /<storehash>.narinfo        signed metadata for one store path         (live, sig-verified)
//	GET /nar/<hash>.nar[.ext]       the (compressed) NAR archive               (immutable, verified)
//
// Two independent integrity controls protect a store path:
//
//   - Signature. Each narinfo carries one or more ed25519 "Sig:" fields over a
//     canonical fingerprint of the StorePath, NarHash, NarSize and References.
//     The backend verifies this against the configured trusted public keys
//     (nix.trustedPublicKeys) before serving the narinfo — the trust anchor for
//     the store path, and the hash (NarHash) the Nix client itself enforces after
//     decompression. With no keys configured, narinfos are served unverified
//     (annotated), matching how the apt/yum backends treat an absent GPG key.
//
//   - Content address. A NAR's file name is a Nix base-32 SHA-256:
//     /nar/<hash>.nar[.ext]. Caches differ in what it is the hash of — the file
//     as stored (the narinfo's FileHash) or the NAR itself, uncompressed (its
//     NarHash, which cache.nixos.org uses for the zstd NARs of current
//     channels). On a cache miss the backend recomputes both as the file
//     streams through and refuses to cache or serve bytes whose name is
//     neither (see verify.go). Nothing is buffered.
//
// The narinfo "URL:" field is rewritten to route NAR downloads back through the
// proxy. The signature does not cover the URL (or FileHash), so this rewrite
// never invalidates it — and, for the same reason, a narinfo whose URL would
// send the client to another host is refused rather than passed on.
//
// Nix store paths are addressed by an opaque truncated store hash and by the
// NAR's SHA-256, never by an OSV package coordinate, so coordinate-based OSV
// scanning is not applicable (see internal/vulnscan/purl.go) — like the Bazel and
// Julia backends. A store path's underlying source is covered via the
// provenance/commit-scanning paths instead.
//
// Client configuration points Nix at the proxied cache with a substituters entry
// "<publicBase>/v1/<name>" and the cache's public key as a trusted-public-keys
// entry (see docs/clients.md).
package nix

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
// Julia, Dart, and Hex backends and are not persisted to the cache as meaningful
// data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/gates
	metaVerify   = "_verify"   // "1" when the NAR's name is a SHA-256 to verify it against
	metaFilename = "_filename" // final path component
	metaFileHash = "_filehash" // expected Nix base-32 SHA-256 recorded in the NAR URL
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaFileHashVerified records "sha256" when a NAR's content was verified
	// against the content address named in its URL, "unsupported" when the URL
	// carries a hash whose length the backend cannot verify as SHA-256, or "none"
	// for the non-content-addressed resources.
	MetaFileHashVerified = "nix.fileHashVerified"
	// MetaSignatureVerified records "trusted:<name>" when a narinfo's signature
	// verified against a configured trusted key, "unverified" when no trusted keys
	// are configured, or "none" for non-narinfo resources.
	MetaSignatureVerified = "nix.signatureVerified"
	// MetaStorePath records the store path a narinfo describes, for provenance.
	MetaStorePath = "nix.storePath"
)

// maxErrorBodySnippet bounds how much of an upstream error body is retained.
const maxErrorBodySnippet = 2 << 10 // 2 KiB

// SignatureError reports that a narinfo failed signature verification against the
// configured trusted public keys. It is surfaced in place of serving the
// unverified document so a tampered or untrusted narinfo never reaches a client.
type SignatureError struct {
	StorePath string
	URL       string
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("nix: narinfo for %s (%s) has no valid signature from a trusted public key", e.StorePath, e.URL)
}

// LocationError reports that a narinfo names a NAR location the proxy cannot
// route through itself and that would send the client to another host. It is
// surfaced in place of serving the document, so a client is never pointed at a
// NAR that bypasses the proxy.
type LocationError struct {
	StorePath string
	URL       string
}

func (e *LocationError) Error() string {
	return fmt.Sprintf("nix: narinfo for %s (%s) locates its NAR outside this cache; it is not served, because the client would fetch the NAR without it passing through the proxy", e.StorePath, e.URL)
}

// narURLLeavesProxy reports whether a narinfo URL value the proxy could not
// rewrite would be fetched from somewhere other than the proxy. Nix resolves a
// value that begins with "http://", "https://" or "file://" as it stands and
// every other value relative to the cache it is talking to — the proxy. Any
// value that carries a scheme, or that does not parse at all, is treated as
// leaving: what a client other than Nix makes of it is not knowable here.
func narURLLeavesProxy(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if strings.Contains(s, "://") {
		return true
	}
	u, err := url.Parse(s)
	if err != nil {
		return true
	}
	return u.Scheme != "" || u.Host != ""
}

// Options configures a Nix Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "nix"). Required.
	Name string
	// UpstreamURL is the binary-cache base URL, e.g. "https://cache.nixos.org".
	// The backend appends "/nix-cache-info", "/<storehash>.narinfo" and
	// "/nar/..." protocol paths. Required.
	UpstreamURL string
	// PublicBaseURL is the externally reachable base URL under which this backend
	// is served, e.g. "https://proxy.example.com/v1/nix". It is used to rewrite a
	// narinfo's URL field so NAR downloads route back through the proxy. When
	// empty, rewritten links fall back to the root-relative "/v1/<name>" form.
	PublicBaseURL string
	// TrustedPublicKeys are the Nix binary-cache signing keys (each in Nix's
	// "name:base64" form, e.g. "cache.nixos.org-1:6NCHdD59...") a narinfo's
	// ed25519 signature is verified against. When empty, narinfos are served
	// without signature verification (annotated as unverified).
	TrustedPublicKeys []string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected to add
	// remote-mirror failover transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the upstream cache. Optional; the
	// public cache.nixos.org is unauthenticated, while a private cache may require
	// a token (e.g. an S3/Attic-backed cache behind auth).
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Nix binary-cache pull-through backend implementing
// backends.Backend.
type Backend struct {
	name       string
	base       *url.URL
	publicBase string
	trusted    map[string]publicKey
	client     upstream.Doer
	creds      upstream.Credentials
	metrics    *Metrics
}

var _ backends.Backend = (*Backend)(nil)

// New validates opts and constructs a Backend.
func New(opts Options) (*Backend, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, errors.New("nix: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("nix %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("nix %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("nix %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("nix %q: upstream client is required", opts.Name)
	}
	trusted, err := parseTrustedKeys(opts.TrustedPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("nix %q: %w", opts.Name, err)
	}
	publicBase := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if publicBase == "" {
		// Fall back to the root-relative mount; Nix resolves a relative narinfo URL
		// against the request URL, so this still routes NAR downloads through the
		// proxy.
		publicBase = "/v1/" + opts.Name
	}
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Backend{
		name:       opts.Name,
		base:       base,
		publicBase: publicBase,
		trusted:    trusted,
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

// Resolve implements backends.Backend. It classifies the inbound path against the
// binary-cache layout, derives the upstream URL and cache key, attaches the
// store/content-hash coordinate for the admission gates, and decides
// cacheability (only the immutable, content-addressed NAR archives are cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("nix: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Nix binary-cache path", backends.ErrNotSupported, req.Path)
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

	// Attach the best available coordinate so nameguard, policy, provenance, and
	// risk can identify the artifact. A binary cache exposes only an opaque store
	// hash (narinfo) or the NAR's SHA-256 (nar), never a name/semver.
	//
	// The hash is used as BOTH name and version. That is the honest reading of a
	// content address — it names one immutable build and nothing else — and it is
	// what makes the coordinate "concrete": the admission gates that key on a
	// name+version pair (the admission policy and its provenance pins, the
	// dependency firewall, break-glass approvals) skip a coordinate without a
	// version, so a name-only coordinate left every store path ungated. An
	// operator pins or denies a store path by its hash, e.g.
	//   {ecosystem: nix, name: n5glp21rsz314qssw9fbvfswgy3kc68f}
	// A refused narinfo is what stops a path: without it the client never learns
	// the NAR's location, references or signature.
	switch res.kind {
	case kindNarInfo:
		resolved.Coordinate = backends.Coordinate{Name: res.storeHash, Version: res.storeHash}
	case kindNar:
		resolved.Coordinate = backends.Coordinate{Name: res.fileHash, Version: res.fileHash}
		resolved.MediaType = "application/x-nix-nar"
		if res.verifiable() {
			resolved.Metadata[metaVerify] = "1"
			resolved.Metadata[metaFileHash] = res.fileHash
		}
	}

	return resolved, nil
}

// Fetch implements backends.Backend. A NAR is verified against the SHA-256 named
// in its URL — streaming, so a mismatch aborts the cache write and client stream
// without buffering the archive. A narinfo is buffered to verify its ed25519
// signature against the trusted keys and to rewrite its URL field through the
// proxy. The nix-cache-info descriptor is proxied byte-exact.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("nix: nil resolved")
	}

	switch resolved.Metadata[metaKind] {
	case "narinfo":
		return b.fetchNarInfo(ctx, resolved)
	case "cache-info":
		return b.fetchPassthrough(ctx, resolved, "cache-info")
	default:
		return b.fetchNar(ctx, resolved)
	}
}

// fetchNar fetches a NAR archive and, when the content address is a SHA-256,
// streams it through a verifying reader so a hash mismatch aborts the cache write
// and the client stream.
func (b *Backend) fetchNar(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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

	b.metrics.incNarsServed()

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}

	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "application/x-nix-nar"
	}

	content := resp.Body
	if resolved.Metadata[metaVerify] == "1" {
		expected := resolved.Metadata[metaFileHash]
		resolved.Metadata[MetaFileHashVerified] = "sha256"
		_, ext, _ := parseNarName(resolved.Metadata[metaFilename])
		content = newFileHashVerifier(resp.Body, expected, resolved.Metadata[metaFilename], resolved.UpstreamURL, ext, func(ok bool, how string) {
			switch {
			case !ok:
				b.metrics.incFileHashMismatch()
			case how == verifiedByContent:
				b.metrics.incNarsVerified()
				b.metrics.incNarsVerifiedByContent()
			default:
				b.metrics.incNarsVerified()
			}
		})
		header.Set("X-Content-Hash-Verified", "sha256")
	} else {
		b.metrics.incFileHashMissing()
		resolved.Metadata[MetaFileHashVerified] = "unsupported"
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

// fetchNarInfo fetches a narinfo, verifies its signature against the trusted
// keys (rejecting it when keys are configured and none match), rewrites its URL
// field through the proxy, and serves the rewritten bytes.
func (b *Backend) fetchNarInfo(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxNarInfoBytes+1))
	drainClose(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("nix %q: reading narinfo: %w", b.name, err)
	}
	if int64(len(data)) > maxNarInfoBytes {
		return nil, fmt.Errorf("nix %q: narinfo exceeds %d bytes", b.name, maxNarInfoBytes)
	}

	ni, perr := parseNarInfo(data)
	if perr != nil {
		return nil, fmt.Errorf("nix %q: parsing narinfo %s: %w", b.name, resolved.UpstreamURL, perr)
	}
	resolved.Metadata[MetaStorePath] = ni.StorePath

	// Signature verification is the trust anchor. When trusted keys are configured
	// a narinfo must carry a valid signature from one of them or it is refused;
	// with no keys configured the document is served but annotated as unverified.
	if len(b.trusted) > 0 {
		signer, ok := verifySignature(ni, b.trusted)
		if !ok {
			b.metrics.incNarInfoSigInvalid()
			return nil, &SignatureError{StorePath: ni.StorePath, URL: resolved.UpstreamURL}
		}
		b.metrics.incNarInfoSigValid()
		resolved.Metadata[MetaSignatureVerified] = "trusted:" + signer
	} else {
		b.metrics.incNarInfoUnverified()
		resolved.Metadata[MetaSignatureVerified] = "unverified"
	}

	// Rewrite the NAR location so the client's download routes through the proxy.
	// The signature covers neither URL nor FileHash, so this is sound.
	//
	// For the same reason the URL is the one field of a narinfo a cache can set
	// to anything without invalidating its signature — and Nix honours an
	// absolute "http(s)://" (or "file://") URL there, fetching the NAR from that
	// location directly. A narinfo whose NAR location cannot be routed through
	// the proxy and would take the client elsewhere is therefore not served: the
	// NAR is this backend's only payload, and handing out a pointer to a copy of
	// it that passes no cache, no content verification and no gate would undo
	// every one of them. (A relative location outside nar/ stays on the proxy,
	// which refuses the path: that one is passed on unchanged.)
	if proxied, ok := b.proxiedNarURL(ni.URL); ok {
		ni.rewriteURL(proxied)
		b.metrics.incNarInfoRewritten()
	} else if narURLLeavesProxy(ni.URL) {
		b.metrics.incNarInfoLocationRefused()
		return nil, &LocationError{StorePath: ni.StorePath, URL: resolved.UpstreamURL}
	}
	body := []byte(ni.reemit())

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	// The body length changed under rewriting; let the serving layer recompute it.
	header.Del("Content-Length")
	header.Del("ETag")
	if resolved.Metadata[MetaSignatureVerified] != "" {
		header.Set("X-Signature-Verified", resolved.Metadata[MetaSignatureVerified])
	}

	b.metrics.incNarInfoServed()
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(strings.NewReader(string(body))),
		Size:      int64(len(body)),
		MediaType: "text/x-nix-narinfo",
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// fetchPassthrough proxies a resource (nix-cache-info) byte-exact.
func (b *Backend) fetchPassthrough(ctx context.Context, resolved *backends.Resolved, kind string) (*backends.FetchResult, error) {
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

	if kind == "cache-info" {
		b.metrics.incCacheInfoServed()
	}

	header := make(http.Header)
	upstream.PropagateResponseHeaders(header, resp.Header)
	if resp.ETag != "" {
		header.Set("ETag", resp.ETag)
	}
	if resp.LastModified != "" {
		header.Set("Last-Modified", resp.LastModified)
	}
	mediaType := resp.ContentType
	if mediaType == "" {
		mediaType = "text/plain; charset=utf-8"
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

// proxiedNarURL rewrites a narinfo URL value (relative "nar/<file>" or an
// absolute URL) to route through the proxy's mount. It returns ok=false when the
// value does not carry a "nar/" path component (or carries a ".."): the caller
// then passes a relative value on unchanged — the client asks the proxy for it,
// and the proxy refuses a path outside the layout — and refuses to serve the
// narinfo when the value would take the client to another host (see
// narURLLeavesProxy).
func (b *Backend) proxiedNarURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	p := u.Path
	if p == "" {
		// A bare relative reference ("nar/xxx.nar.xz") parses with an empty Path
		// and the value in Opaque/the original string.
		p = s
	}
	// Match the "nar/" path segment precisely (a leading "nar/" or an embedded
	// "/nar/"), not an arbitrary substring, so a stray "foonar/" cannot be
	// mistaken for the NAR directory.
	var narRel string
	switch {
	case strings.HasPrefix(p, "nar/"):
		narRel = p
	case strings.Contains(p, "/nar/"):
		narRel = p[strings.Index(p, "/nar/")+1:]
	default:
		return "", false
	}
	// Guard against traversal smuggled into the rewritten location.
	if strings.Contains(narRel, "..") {
		return "", false
	}
	return b.publicBase + "/" + narRel, true
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

// joinPath appends the inbound binary-cache path to the upstream base, preserving
// any base-path prefix (e.g. a cache served under a sub-path).
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A NAR path embeds its content-address hash, so the path alone is a content-
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
