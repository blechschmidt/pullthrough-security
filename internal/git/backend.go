package git

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// maxUploadPackRequest bounds the size of a client's git-upload-pack request
// body (the wants/haves negotiation), so a hostile client cannot stream an
// unbounded body into the proxy. Real negotiation requests are kilobytes.
const maxUploadPackRequest = 16 << 20 // 16 MiB

// Backend serves a single configured Git upstream over the smart HTTP protocol.
// It implements backends.Backend (for registration and readiness) and
// backends.HTTPHandler (the proxy delegates raw HTTP to it because the smart
// protocol does not fit the Resolve/Fetch model).
type Backend struct {
	up          *Upstream
	mirror      *Mirror // nil → HTTPS pass-through mode
	cache       cache.Cache
	infoRefsTTL time.Duration
	logger      *slog.Logger

	// Git LFS pull-through (Task 123). lfs is nil when LFS proxying is disabled.
	lfs *lfsProxy
}

var (
	_ backends.Backend     = (*Backend)(nil)
	_ backends.HTTPHandler = (*Backend)(nil)
)

// BackendOptions configures a git Backend.
type BackendOptions struct {
	Upstream *Upstream
	// Mirror, when non-nil, enables mirror-mode serving (objects/packs are cached
	// in the local bare mirror). When nil the backend streams smart-HTTP requests
	// straight to the HTTPS upstream.
	Mirror *Mirror
	// Cache backs short-TTL caching of ref advertisements in pass-through mode.
	// Optional.
	Cache cache.Cache
	// InfoRefsTTL is how long a ref advertisement is cached in pass-through mode.
	// 0 disables advertisement caching.
	InfoRefsTTL time.Duration
	Logger      *slog.Logger

	// LFS, when non-nil and LFS.Enabled, turns on transparent Git LFS
	// pull-through: the /info/lfs/objects/batch API is negotiated with upstream
	// and LFS blobs are streamed through the content-addressable cache keyed by
	// their sha256 OID. Requires a Cache.
	LFS LFSOptions
}

// LFSOptions configures the Git LFS large-object pull-through (Task 123).
type LFSOptions struct {
	// Enabled turns on LFS proxying for this backend.
	Enabled bool
	// MaxObjectBytes caps the size of a single LFS object the proxy will fetch and
	// cache. 0 selects the package default (defaultLFSMaxObjectBytes).
	MaxObjectBytes int64
	// ScanMaxBytes bounds how many bytes of a freshly-fetched blob are handed to
	// the content gate. 0 selects the package default (defaultLFSScanMaxBytes).
	ScanMaxBytes int64
	// BlockOnFindings refuses (and evicts) an object whose content-gate scan
	// yields any finding, rather than serving it with the finding recorded.
	BlockOnFindings bool
	// Gate, when non-nil, inspects freshly-fetched LFS blobs (bounded by
	// ScanMaxBytes) via the commit-scan content gates. May be set after
	// construction with SetLFSContentGate.
	Gate LFSContentGate
}

// NewBackend constructs a git Backend.
func NewBackend(opts BackendOptions) (*Backend, error) {
	if opts.Upstream == nil {
		return nil, errors.New("git: backend requires an upstream")
	}
	if opts.Mirror == nil && opts.Upstream.Transport != TransportHTTPS {
		return nil, fmt.Errorf("git upstream %q: SSH-transport upstreams require mirror mode (set git.mirrorDir and install git)", opts.Upstream.Name)
	}
	if opts.Mirror == nil && opts.Upstream.client == nil {
		return nil, fmt.Errorf("git upstream %q: pass-through mode requires an HTTP client", opts.Upstream.Name)
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	b := &Backend{
		up:          opts.Upstream,
		mirror:      opts.Mirror,
		cache:       opts.Cache,
		infoRefsTTL: opts.InfoRefsTTL,
		logger:      logger,
	}
	if opts.LFS.Enabled {
		if opts.Cache == nil {
			return nil, fmt.Errorf("git upstream %q: LFS proxying requires a cache", opts.Upstream.Name)
		}
		if opts.Upstream.client == nil {
			return nil, fmt.Errorf("git upstream %q: LFS proxying requires an HTTP client (http(s) transport)", opts.Upstream.Name)
		}
		b.lfs = newLFSProxy(b, opts.LFS)
	}
	return b, nil
}

// SetLFSContentGate installs (or replaces) the content gate run against
// freshly-fetched LFS blobs. It is a no-op when LFS proxying is disabled. It is
// intended to be called once during startup wiring, before the backend serves
// traffic, so it is not synchronized.
func (b *Backend) SetLFSContentGate(gate LFSContentGate) {
	if b.lfs != nil {
		b.lfs.gate = gate
	}
}

// LFSMetrics returns a snapshot of the LFS pull-through counters, or the zero
// snapshot when LFS proxying is disabled. It is safe for concurrent use.
func (b *Backend) LFSMetrics() LFSSnapshot {
	if b.lfs == nil {
		return LFSSnapshot{}
	}
	return b.lfs.metrics.snapshot()
}

func (b *Backend) lfsEnabled() bool { return b.lfs != nil }

// Name implements backends.Backend.
func (b *Backend) Name() string { return b.up.Name }

// Resolve implements backends.Backend. Git traffic is handled via
// ServeBackendHTTP, so Resolve is never invoked by the proxy core; it reports
// that the request is not handled through the Resolve/Fetch path.
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	return nil, backends.ErrNotSupported
}

// Fetch implements backends.Backend; see Resolve.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	return nil, backends.ErrNotSupported
}

// ServeBackendHTTP implements backends.HTTPHandler, serving the Git smart HTTP
// protocol for one repository endpoint.
func (b *Backend) ServeBackendHTTP(w http.ResponseWriter, r *http.Request, repoPath string) {
	// Git LFS endpoints are checked first: they carry their own path shape
	// ("<repo>/info/lfs/objects/...") that never collides with the smart-protocol
	// suffixes, and they are only served when LFS proxying is enabled.
	if rawRepo, lfsEP, oid, ok := splitLFSEndpoint(repoPath); ok && b.lfsEnabled() {
		repo, err := sanitizeRepoPath(rawRepo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch lfsEP {
		case lfsEndpointBatch:
			b.handleLFSBatch(w, r, repo)
		case lfsEndpointObject:
			b.handleLFSObject(w, r, repo, oid)
		default:
			http.Error(w, "unsupported git lfs endpoint", http.StatusNotFound)
		}
		return
	}

	rawRepo, endpoint, ok := splitRepoEndpoint(repoPath)
	if !ok {
		// Not a recognized smart-protocol endpoint. The dumb protocol is not
		// supported by this read-only proxy.
		http.Error(w, "unsupported git endpoint", http.StatusNotFound)
		return
	}

	repo, err := sanitizeRepoPath(rawRepo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch endpoint {
	case endpointInfoRefs:
		b.handleInfoRefs(w, r, repo)
	case endpointUploadPack:
		b.handleUploadPack(w, r, repo)
	case endpointReceivePack:
		http.Error(w, ErrPushRejected.Error(), http.StatusForbidden)
	default:
		http.Error(w, "unsupported git endpoint", http.StatusNotFound)
	}
}

// handleInfoRefs serves "GET <repo>/info/refs?service=git-upload-pack".
func (b *Backend) handleInfoRefs(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	service := r.URL.Query().Get("service")
	canonical, err := validateService(service)
	if err != nil {
		b.writeServiceError(w, err)
		return
	}

	if b.mirror != nil {
		b.infoRefsFromMirror(w, r, repo, canonical)
		return
	}
	b.infoRefsPassthrough(w, r, repo, canonical)
}

// handleUploadPack serves "POST <repo>/git-upload-pack".
func (b *Backend) handleUploadPack(w http.ResponseWriter, r *http.Request, repo string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != ctUploadPackRequest {
		http.Error(w, "unexpected content-type for git-upload-pack", http.StatusUnsupportedMediaType)
		return
	}

	if b.mirror != nil {
		b.uploadPackFromMirror(w, r, repo)
		return
	}
	b.uploadPackPassthrough(w, r, repo)
}

// --- Mirror mode ---------------------------------------------------------

func (b *Backend) infoRefsFromMirror(w http.ResponseWriter, r *http.Request, repo, service string) {
	dir, err := b.mirror.Ensure(r.Context(), b.up, repo)
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}
	adv, err := b.mirror.AdvertiseRefs(r.Context(), dir, clientProtocol(r))
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}

	h := w.Header()
	h.Set("Content-Type", ctUploadPackAdvertisement)
	noCache(h)
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, serviceAdvertisementHeader(service)); err != nil {
		return
	}
	_, _ = w.Write(adv)
}

func (b *Backend) uploadPackFromMirror(w http.ResponseWriter, r *http.Request, repo string) {
	dir, err := b.mirror.Ensure(r.Context(), b.up, repo)
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}

	body, err := decompressIfGzip(r)
	if err != nil {
		http.Error(w, "invalid request encoding", http.StatusBadRequest)
		return
	}
	limited := io.LimitReader(body, maxUploadPackRequest)

	h := w.Header()
	h.Set("Content-Type", ctUploadPackResult)
	noCache(h)
	w.WriteHeader(http.StatusOK)

	if err := b.mirror.UploadPackStateless(r.Context(), dir, limited, w, clientProtocol(r)); err != nil {
		// Headers are already sent; we can only log. A client sees a truncated
		// stream and retries.
		b.logger.Warn("git upload-pack (mirror) failed mid-stream",
			"upstream", b.up.Name, "repo", repo, "error", err)
	}
}

// --- Pass-through mode ---------------------------------------------------

func (b *Backend) infoRefsPassthrough(w http.ResponseWriter, r *http.Request, repo, service string) {
	q := url.Values{"service": {service}}
	target, err := b.up.upstreamHTTPURL(repo, "/info/refs", q)
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}

	proto := clientProtocol(r)
	if cached, ok := b.cachedAdvertisement(r.Context(), repo, service, proto); ok {
		h := w.Header()
		h.Set("Content-Type", ctUploadPackAdvertisement)
		noCache(h)
		h.Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cached)
		return
	}

	reqHeader := http.Header{"Accept": {ctUploadPackAdvertisement}}
	if proto := clientProtocol(r); proto != "" {
		reqHeader.Set("Git-Protocol", proto)
	}
	resp, err := b.up.client.Do(r.Context(), upstream.Request{
		URL:    target,
		Method: http.MethodGet,
		Header: reqHeader,
		Creds:  b.up.creds,
	})
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}
	defer resp.Body.Close()
	if !resp.IsSuccess() {
		b.writeUpstreamStatus(w, repo, resp.Status)
		return
	}

	h := w.Header()
	h.Set("Content-Type", firstNonEmpty(resp.ContentType, ctUploadPackAdvertisement))
	noCache(h)
	h.Set("X-Cache", "MISS")
	w.WriteHeader(http.StatusOK)

	// Cache the (small) advertisement when a TTL is configured; otherwise stream.
	if b.cache != nil && b.infoRefsTTL > 0 {
		buf, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexBytes))
		if err != nil {
			return
		}
		_, _ = w.Write(buf)
		b.storeAdvertisement(r.Context(), repo, service, proto, buf)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (b *Backend) uploadPackPassthrough(w http.ResponseWriter, r *http.Request, repo string) {
	target, err := b.up.upstreamHTTPURL(repo, "/git-upload-pack", nil)
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}

	header := http.Header{
		"Content-Type": {ctUploadPackRequest},
		"Accept":       {ctUploadPackResult},
	}
	if enc := r.Header.Get("Content-Encoding"); enc != "" {
		header.Set("Content-Encoding", enc)
	}
	// Forward the negotiated wire protocol. The ref advertisement was fetched
	// with the client's "Git-Protocol" header (see infoRefsPassthrough), so a
	// protocol-v2 client follows up with a v2 command request ("command=ls-refs",
	// "command=fetch"). Without the same header on this POST the upstream parses
	// that body as a v0 want/have negotiation and rejects it (GitHub answers 400),
	// which broke every clone from a modern git client (v2 is the default since
	// git 2.26).
	if proto := clientProtocol(r); proto != "" {
		header.Set("Git-Protocol", proto)
	}

	resp, err := b.up.client.Do(r.Context(), upstream.Request{
		URL:    target,
		Method: http.MethodPost,
		Header: header,
		Creds:  b.up.creds,
		Body:   io.LimitReader(r.Body, maxUploadPackRequest),
	})
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		return
	}
	defer resp.Body.Close()
	if !resp.IsSuccess() {
		b.writeUpstreamStatus(w, repo, resp.Status)
		return
	}

	h := w.Header()
	h.Set("Content-Type", firstNonEmpty(resp.ContentType, ctUploadPackResult))
	noCache(h)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, resp.Body)
}

// --- helpers -------------------------------------------------------------

// maxIndexBytes bounds a cached ref advertisement.
const maxIndexBytes = 8 << 20 // 8 MiB

func (b *Backend) advCacheKey(repo, service, protocol string) string {
	if protocol == "" {
		protocol = "v0"
	}
	return "git-inforefs:" + b.up.Name + ":" + repo + ":" + service + ":" + protocol
}

func (b *Backend) cachedAdvertisement(ctx context.Context, repo, service, protocol string) ([]byte, bool) {
	if b.cache == nil || b.infoRefsTTL <= 0 {
		return nil, false
	}
	entry, err := b.cache.Get(ctx, b.advCacheKey(repo, service, protocol))
	if err != nil || entry == nil {
		return nil, false
	}
	defer entry.Content.Close()
	if ts := entry.Stat.Metadata[metaAdvFetchedAt]; ts != "" {
		if fetched, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			if clock().Sub(fetched) > b.infoRefsTTL {
				return nil, false
			}
		}
	}
	buf, err := io.ReadAll(io.LimitReader(entry.Content, maxIndexBytes))
	if err != nil {
		return nil, false
	}
	return buf, true
}

func (b *Backend) storeAdvertisement(ctx context.Context, repo, service, protocol string, buf []byte) {
	if b.cache == nil || b.infoRefsTTL <= 0 {
		return
	}
	meta := map[string]string{metaAdvFetchedAt: clock().UTC().Format(time.RFC3339Nano)}
	if _, err := b.cache.Put(ctx, b.advCacheKey(repo, service, protocol), strings.NewReader(string(buf)), meta); err != nil {
		b.logger.Debug("caching git advertisement failed", "repo", repo, "error", err)
	}
}

const metaAdvFetchedAt = "git_adv_fetched_at"

func (b *Backend) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrPushRejected):
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (b *Backend) writeUpstreamError(w http.ResponseWriter, repo string, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	b.logger.Error("git upstream error", "upstream", b.up.Name, "repo", repo, "error", err)
	http.Error(w, "upstream git error", http.StatusBadGateway)
}

func (b *Backend) writeUpstreamStatus(w http.ResponseWriter, repo string, status int) {
	b.logger.Warn("git upstream returned status", "upstream", b.up.Name, "repo", repo, "status", status)
	// Map upstream auth/not-found onto equivalent client status; everything else
	// is a bad gateway.
	switch status {
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		http.Error(w, fmt.Sprintf("upstream returned status %d", status), status)
	default:
		http.Error(w, fmt.Sprintf("upstream returned status %d", status), http.StatusBadGateway)
	}
}

// clientProtocol extracts the negotiated Git wire protocol from the request's
// "Git-Protocol" header (e.g. "version=2"), so the served advertisement and
// pack responses match what the client expects. Empty selects git's default.
func clientProtocol(r *http.Request) string {
	return r.Header.Get("Git-Protocol")
}

func noCache(h http.Header) {
	h.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
}

// decompressIfGzip returns a reader over the request body, transparently
// decompressing it when the client sent "Content-Encoding: gzip" (git clients
// gzip the upload-pack request body for large negotiations). The mirror's
// "git upload-pack --stateless-rpc" expects the raw, decompressed request.
func decompressIfGzip(r *http.Request) (io.Reader, error) {
	if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		return r.Body, nil
	}
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	return gz, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
