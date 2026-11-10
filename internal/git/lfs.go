package git

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Git LFS protocol constants. The batch API and transfer adapter are specified
// at https://github.com/git-lfs/git-lfs/blob/main/docs/api/.
const (
	// ctLFSJSON is the media type of a Git LFS batch request/response body.
	ctLFSJSON = "application/vnd.git-lfs+json"
	// lfsTransferBasic is the only transfer adapter the proxy implements: a plain
	// HTTP GET of the object at the download action's href. We always rewrite the
	// negotiated transfer to "basic" because the proxy re-serves objects itself.
	lfsTransferBasic = "basic"

	// maxLFSBatchRequest bounds a client's batch-API request body. Real requests
	// list a handful of objects and are kilobytes; this caps a hostile client.
	maxLFSBatchRequest = 8 << 20 // 8 MiB
	// maxLFSBatchResponse bounds the upstream batch response we will parse.
	maxLFSBatchResponse = 64 << 20 // 64 MiB

	// defaultLFSMaxObjectBytes caps a single cached LFS object when the operator
	// does not configure git.lfs.maxObjectBytes.
	defaultLFSMaxObjectBytes = 5 << 30 // 5 GiB
	// defaultLFSScanMaxBytes bounds how many bytes of a blob are content-scanned.
	defaultLFSScanMaxBytes = 5 << 20 // 5 MiB
)

// errLFSOIDMismatch is returned by the verifying reader when a fetched blob's
// sha256 does not equal the requested OID (tampering or a mis-serving upstream).
var errLFSOIDMismatch = errors.New("git lfs: object content does not match its oid")

// errLFSSizeMismatch is returned when a fetched blob's length does not match the
// size the upstream batch API declared for the OID.
var errLFSSizeMismatch = errors.New("git lfs: object content length does not match its declared size")

// errLFSTooLarge is returned when a blob exceeds the configured size cap.
var errLFSTooLarge = errors.New("git lfs: object exceeds the configured maximum size")

// LFSObjectInfo identifies a Git LFS blob handed to a content gate.
type LFSObjectInfo struct {
	// OID is the object's sha256 content address (lowercase hex, 64 chars).
	OID string
	// Size is the object's length in bytes.
	Size int64
	// Repo is the sanitized repository path the object was requested through.
	Repo string
	// Upstream is the configured upstream name serving the repository.
	Upstream string
}

// LFSContentGate inspects a freshly-fetched Git LFS blob through the commit-scan
// content gates (e.g. deterministic secret detection). It is invoked only on a
// cache miss, with at most ScanMaxBytes of content buffered. Implementations
// must be safe for concurrent use and must not retain the content slice.
//
// The return value is the number of findings. A non-nil error signals an
// internal gate failure and is treated as fail-open (the object is still
// served) so a scanner outage never breaks clones; whether findings block the
// object is decided by the backend's BlockOnFindings policy.
type LFSContentGate interface {
	InspectLFSObject(ctx context.Context, info LFSObjectInfo, content []byte) (findings int, err error)
}

// lfsProxy holds the per-backend Git LFS state: size caps, the optional content
// gate, and the metrics counters.
type lfsProxy struct {
	b               *Backend
	maxObjectBytes  int64
	scanMaxBytes    int64
	blockOnFindings bool
	gate            LFSContentGate
	metrics         lfsMetrics
}

func newLFSProxy(b *Backend, opts LFSOptions) *lfsProxy {
	maxObj := opts.MaxObjectBytes
	if maxObj <= 0 {
		maxObj = defaultLFSMaxObjectBytes
	}
	scanMax := opts.ScanMaxBytes
	if scanMax <= 0 {
		scanMax = defaultLFSScanMaxBytes
	}
	return &lfsProxy{
		b:               b,
		maxObjectBytes:  maxObj,
		scanMaxBytes:    scanMax,
		blockOnFindings: opts.BlockOnFindings,
		gate:            opts.Gate,
	}
}

// --- metrics -------------------------------------------------------------

// lfsMetrics holds the cumulative Git LFS counters as atomics, read live at
// scrape time. All fields count monotonically.
type lfsMetrics struct {
	batchRequests  atomic.Int64 // batch-API negotiations handled
	batchObjects   atomic.Int64 // objects negotiated across all batch requests
	objectRequests atomic.Int64 // per-object transfer (download) requests handled
	cacheHits      atomic.Int64 // object requests served from the cache
	cacheMisses    atomic.Int64 // object requests that triggered an upstream fetch
	bytesFetched   atomic.Int64 // object bytes downloaded from upstream
	bytesServed    atomic.Int64 // object bytes written to clients (full + partial)
	oidMismatches  atomic.Int64 // fetches rejected because content != oid
	sizeMismatches atomic.Int64 // fetches rejected because length != declared size
	gateFindings   atomic.Int64 // content-gate findings across all scanned blobs
	gateBlocked    atomic.Int64 // objects refused because of a content-gate finding
	errors         atomic.Int64 // upstream/transport/other errors on the LFS path
	rejectedUpload atomic.Int64 // batch "upload" operations rejected (read-only)
}

// LFSSnapshot is an immutable view of the Git LFS counters.
type LFSSnapshot struct {
	BatchRequests  int64
	BatchObjects   int64
	ObjectRequests int64
	CacheHits      int64
	CacheMisses    int64
	BytesFetched   int64
	BytesServed    int64
	OIDMismatches  int64
	SizeMismatches int64
	GateFindings   int64
	GateBlocked    int64
	Errors         int64
	RejectedUpload int64
}

func (m *lfsMetrics) snapshot() LFSSnapshot {
	return LFSSnapshot{
		BatchRequests:  m.batchRequests.Load(),
		BatchObjects:   m.batchObjects.Load(),
		ObjectRequests: m.objectRequests.Load(),
		CacheHits:      m.cacheHits.Load(),
		CacheMisses:    m.cacheMisses.Load(),
		BytesFetched:   m.bytesFetched.Load(),
		BytesServed:    m.bytesServed.Load(),
		OIDMismatches:  m.oidMismatches.Load(),
		SizeMismatches: m.sizeMismatches.Load(),
		GateFindings:   m.gateFindings.Load(),
		GateBlocked:    m.gateBlocked.Load(),
		Errors:         m.errors.Load(),
		RejectedUpload: m.rejectedUpload.Load(),
	}
}

// --- batch-API JSON model ------------------------------------------------

type lfsRef struct {
	Name string `json:"name,omitempty"`
}

type lfsPointer struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

type lfsBatchRequest struct {
	Operation string       `json:"operation"`
	Transfers []string     `json:"transfers,omitempty"`
	Ref       *lfsRef      `json:"ref,omitempty"`
	Objects   []lfsPointer `json:"objects"`
	HashAlgo  string       `json:"hash_algo,omitempty"`
}

type lfsAction struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header,omitempty"`
	ExpiresAt string            `json:"expires_at,omitempty"`
	ExpiresIn int               `json:"expires_in,omitempty"`
}

type lfsObjectError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type lfsResponseObject struct {
	OID           string               `json:"oid"`
	Size          int64                `json:"size"`
	Authenticated *bool                `json:"authenticated,omitempty"`
	Actions       map[string]lfsAction `json:"actions,omitempty"`
	Error         *lfsObjectError      `json:"error,omitempty"`
}

type lfsBatchResponse struct {
	Transfer string              `json:"transfer,omitempty"`
	Objects  []lfsResponseObject `json:"objects"`
	HashAlgo string              `json:"hash_algo,omitempty"`
}

// --- batch endpoint ------------------------------------------------------

// handleLFSBatch serves "POST <repo>/info/lfs/objects/batch". It negotiates the
// batch API with upstream and rewrites every download action so its href points
// back at this proxy's per-object endpoint; the client then fetches each object
// from the proxy (which streams it through the cache). Upload operations are
// rejected: the proxy is a read-only pull-through.
func (b *Backend) handleLFSBatch(w http.ResponseWriter, r *http.Request, repo string) {
	lfs := b.lfs
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	lfs.metrics.batchRequests.Add(1)

	body, err := io.ReadAll(io.LimitReader(r.Body, maxLFSBatchRequest+1))
	if err != nil {
		http.Error(w, "reading lfs batch request", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > maxLFSBatchRequest {
		http.Error(w, "lfs batch request too large", http.StatusRequestEntityTooLarge)
		return
	}

	var req lfsBatchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		b.writeLFSError(w, http.StatusBadRequest, "invalid lfs batch request json")
		return
	}
	switch req.Operation {
	case "download":
		// proceed
	case "upload":
		lfs.metrics.rejectedUpload.Add(1)
		b.writeLFSError(w, http.StatusForbidden, "git lfs upload is not permitted by the read-only proxy")
		return
	default:
		b.writeLFSError(w, http.StatusUnprocessableEntity, "unsupported lfs operation")
		return
	}
	lfs.metrics.batchObjects.Add(int64(len(req.Objects)))

	// Negotiate with upstream for the requested objects.
	upResp, status, err := b.lfsUpstreamBatch(r.Context(), repo, req)
	if err != nil {
		b.writeUpstreamError(w, repo, err)
		lfs.metrics.errors.Add(1)
		return
	}
	if status < 200 || status >= 300 {
		lfs.metrics.errors.Add(1)
		b.writeUpstreamStatus(w, repo, status)
		return
	}

	// Rewrite download actions to proxy-local hrefs and strip upstream auth.
	out := lfsBatchResponse{Transfer: lfsTransferBasic, HashAlgo: upResp.HashAlgo}
	for _, obj := range upResp.Objects {
		ro := lfsResponseObject{OID: obj.OID, Size: obj.Size, Error: obj.Error}
		if obj.Error == nil {
			if _, ok := obj.Actions["download"]; ok || len(obj.Actions) == 0 {
				ro.Actions = map[string]lfsAction{
					"download": {Href: b.lfsObjectProxyURL(r, repo, obj.OID, obj.Size)},
				}
			} else {
				// No download action and no error: the object is unavailable for
				// download (e.g. upstream returned only upload). Surface a 404.
				ro.Error = &lfsObjectError{Code: http.StatusNotFound, Message: "object not available for download"}
			}
		}
		out.Objects = append(out.Objects, ro)
	}

	h := w.Header()
	h.Set("Content-Type", ctLFSJSON)
	noCache(h)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(out)
}

// lfsUpstreamBatch POSTs a batch request to the upstream LFS endpoint and parses
// the response. The outbound request flows through the egress-guarded upstream
// client, so the upstream host is subject to the SSRF/egress allowlist.
func (b *Backend) lfsUpstreamBatch(ctx context.Context, repo string, req lfsBatchRequest) (*lfsBatchResponse, int, error) {
	// Normalize the request we forward: force the download operation and advertise
	// only the basic transfer we can re-serve.
	fwd := lfsBatchRequest{
		Operation: "download",
		Transfers: []string{lfsTransferBasic},
		Ref:       req.Ref,
		Objects:   req.Objects,
		HashAlgo:  req.HashAlgo,
	}
	payload, err := json.Marshal(fwd)
	if err != nil {
		return nil, 0, err
	}

	target, err := b.up.upstreamHTTPURL(repo, lfsObjectsInfix+"batch", nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := b.up.client.Do(ctx, upstream.Request{
		URL:    target,
		Method: http.MethodPost,
		Header: http.Header{
			"Accept":       {ctLFSJSON},
			"Content-Type": {ctLFSJSON},
		},
		Creds: b.up.creds,
		Body:  strings.NewReader(string(payload)),
	})
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if !resp.IsSuccess() {
		return nil, resp.Status, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxLFSBatchResponse))
	if err != nil {
		return nil, resp.Status, err
	}
	var parsed lfsBatchResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, resp.Status, fmt.Errorf("parsing upstream lfs batch response: %w", err)
	}
	return &parsed, resp.Status, nil
}

// lfsObjectProxyURL builds the absolute, proxy-local download URL for an LFS
// object, derived from the incoming batch request's own path so it is correct
// regardless of the route prefix. The declared size is carried as a query
// parameter so the per-object handler can re-negotiate upstream and verify it.
func (b *Backend) lfsObjectProxyURL(r *http.Request, repo, oid string, size int64) string {
	// The batch path ends in ".../info/lfs/objects/batch"; the object path shares
	// its prefix with the oid substituted for "batch".
	base := strings.TrimSuffix(r.URL.Path, "batch")
	if !strings.HasSuffix(base, lfsObjectsInfix) {
		// Fallback: reconstruct from the route path we were dispatched with.
		base = "/" + strings.TrimPrefix(r.URL.Path, "/")
		if i := strings.LastIndex(base, lfsObjectsInfix); i >= 0 {
			base = base[:i+len(lfsObjectsInfix)]
		}
	}
	u := url.URL{
		Scheme:   requestScheme(r),
		Host:     r.Host,
		Path:     base + oid,
		RawQuery: "size=" + strconv.FormatInt(size, 10),
	}
	return u.String()
}

// requestScheme reports the scheme a client used to reach the proxy, honoring a
// terminating reverse proxy's X-Forwarded-Proto before falling back to the TLS
// state of the direct connection.
func requestScheme(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-Proto"); xf != "" {
		if i := strings.IndexByte(xf, ','); i >= 0 {
			xf = xf[:i]
		}
		return strings.TrimSpace(xf)
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// --- object transfer endpoint -------------------------------------------

// validLFSOID reports whether s is a syntactically valid sha256 object id: 64
// lowercase hex digits.
func validLFSOID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// lfsCacheKey is the content-addressable cache key for an LFS object. It is the
// canonical "sha256:<oid>" form so the object shares the cache's read-time
// integrity verification, self-healing, and single-flight coalescing.
func lfsCacheKey(oid string) string { return "sha256:" + oid }

// handleLFSObject serves "GET <repo>/info/lfs/objects/<oid>": the per-object
// transfer. On a cache miss it re-negotiates the batch API upstream to resolve a
// fresh download href, streams the blob through the cache verifying its OID and
// size, runs the content gate, and serves it with full HTTP range support.
func (b *Backend) handleLFSObject(w http.ResponseWriter, r *http.Request, repo, oid string) {
	lfs := b.lfs
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validLFSOID(oid) {
		http.Error(w, "invalid lfs object id", http.StatusBadRequest)
		return
	}
	lfs.metrics.objectRequests.Add(1)

	// A size hint from the batch-rewritten href lets us re-negotiate upstream and
	// enforce the cap before fetching; the authoritative size comes from the
	// upstream batch response.
	var sizeHint int64
	if s := r.URL.Query().Get("size"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
			sizeHint = n
		}
	}
	if sizeHint > 0 && sizeHint > lfs.maxObjectBytes {
		b.writeLFSError(w, http.StatusRequestEntityTooLarge, "lfs object exceeds the configured maximum size")
		return
	}

	key := lfsCacheKey(oid)
	ctx := r.Context()

	// Detect hit vs miss so metrics and the content gate only trigger on the
	// fetch path. GetOrLoad coalesces concurrent misses.
	hit := false
	if _, err := b.cache.Stat(ctx, key); err == nil {
		hit = true
	}

	entry, err := b.cache.GetOrLoad(ctx, key, b.lfsLoader(repo, oid, sizeHint))
	if err != nil {
		b.handleLFSLoadError(w, repo, oid, err)
		return
	}

	if hit {
		lfs.metrics.cacheHits.Add(1)
	} else {
		lfs.metrics.cacheMisses.Add(1)
		// Content gate runs once on the fetch path. A block evicts the object and
		// refuses the request.
		if blocked := b.lfsRunContentGate(ctx, repo, oid, entry.Stat.Size); blocked {
			entry.Content.Close()
			_ = b.cache.Delete(ctx, key)
			b.writeLFSError(w, http.StatusForbidden, "lfs object rejected by content policy")
			return
		}
	}

	b.serveLFSObject(w, r, oid, entry)
}

// serveLFSObject writes the cached blob to the client with full HTTP range
// support (delegating to http.ServeContent when the body is seekable, which it
// is for the filesystem and memory caches as well as the integrity-verifying
// wrapper). Bytes written are metered.
func (b *Backend) serveLFSObject(w http.ResponseWriter, r *http.Request, oid string, entry *cache.Entry) {
	defer entry.Content.Close()

	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("ETag", `"`+oid+`"`)
	h.Set("Accept-Ranges", "bytes")

	cw := &countingResponseWriter{ResponseWriter: w}
	if seeker, ok := entry.Content.(io.ReadSeeker); ok {
		// http.ServeContent handles Range, If-Range, 206, and 416. The modtime is
		// zero (content-addressed data is immutable), so it emits no Last-Modified.
		http.ServeContent(cw, r, oid, entry.Stat.ModTime, seeker)
	} else {
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.Copy(cw, entry.Content)
		}
	}
	b.lfs.metrics.bytesServed.Add(cw.n)
}

// lfsLoader returns a cache.Loader that resolves the upstream download href for
// an LFS object (via the batch API) and streams the blob back through a verifier
// that fails the load on an OID, size, or size-cap violation — so a corrupt or
// oversized object is never committed to the cache.
func (b *Backend) lfsLoader(repo, oid string, sizeHint int64) cache.Loader {
	return func(ctx context.Context) (io.Reader, map[string]string, error) {
		action, declaredSize, err := b.lfsResolveDownload(ctx, repo, oid, sizeHint)
		if err != nil {
			return nil, nil, err
		}
		if declaredSize > b.lfs.maxObjectBytes {
			return nil, nil, fmt.Errorf("%w: %d > %d", errLFSTooLarge, declaredSize, b.lfs.maxObjectBytes)
		}

		header := http.Header{}
		for k, v := range action.Header {
			header.Set(k, v)
		}
		// The download href is upstream-controlled; fetching it through the
		// egress-guarded client applies the SSRF/egress allowlist to the host.
		resp, err := b.up.client.Do(ctx, upstream.Request{
			URL:    action.Href,
			Method: http.MethodGet,
			Header: header,
			// Only inject proxy credentials when upstream did not already supply an
			// authorization header for the (often pre-signed) object store href.
			Creds: b.lfsDownloadCreds(action),
		})
		if err != nil {
			return nil, nil, err
		}
		if !resp.IsSuccess() {
			resp.Body.Close()
			return nil, nil, fmt.Errorf("upstream lfs object fetch returned status %d", resp.Status)
		}

		vr := &lfsVerifyReader{
			src:          resp.Body,
			hash:         sha256.New(),
			expectOID:    oid,
			declaredSize: declaredSize,
			maxBytes:     b.lfs.maxObjectBytes,
			onFetched:    func(n int64) { b.lfs.metrics.bytesFetched.Add(n) },
		}
		meta := map[string]string{
			cache.MetaOrigin:      b.up.redactedCloneURL(repo),
			cache.MetaContentType: "application/octet-stream",
			cache.MetaDigest:      lfsCacheKey(oid),
			"git_lfs_oid":         oid,
			"git_lfs_size":        strconv.FormatInt(declaredSize, 10),
		}
		return vr, meta, nil
	}
}

// lfsResolveDownload re-negotiates the batch API upstream for a single object
// and returns its download action plus authoritative size. It errors when the
// object is missing, carries an upstream error, or has no download action.
func (b *Backend) lfsResolveDownload(ctx context.Context, repo, oid string, sizeHint int64) (lfsAction, int64, error) {
	req := lfsBatchRequest{
		Operation: "download",
		Transfers: []string{lfsTransferBasic},
		Objects:   []lfsPointer{{OID: oid, Size: sizeHint}},
	}
	resp, status, err := b.lfsUpstreamBatch(ctx, repo, req)
	if err != nil {
		return lfsAction{}, 0, err
	}
	if status < 200 || status >= 300 {
		return lfsAction{}, 0, fmt.Errorf("upstream lfs batch returned status %d", status)
	}
	for _, obj := range resp.Objects {
		if obj.OID != oid {
			continue
		}
		if obj.Error != nil {
			return lfsAction{}, 0, fmt.Errorf("upstream lfs object error: code=%d %s", obj.Error.Code, obj.Error.Message)
		}
		action, ok := obj.Actions["download"]
		if !ok {
			return lfsAction{}, 0, fmt.Errorf("upstream lfs object has no download action")
		}
		if strings.TrimSpace(action.Href) == "" {
			return lfsAction{}, 0, fmt.Errorf("upstream lfs download action has no href")
		}
		return action, obj.Size, nil
	}
	return lfsAction{}, 0, fmt.Errorf("upstream lfs batch did not return the requested object")
}

// lfsDownloadCreds returns the proxy's upstream credentials only when the batch
// download action did not already carry its own Authorization header (object
// stores typically return a pre-signed href that must not be overridden).
func (b *Backend) lfsDownloadCreds(action lfsAction) upstream.Credentials {
	for k := range action.Header {
		if strings.EqualFold(k, "Authorization") {
			return upstream.Credentials{}
		}
	}
	return b.up.creds
}

// lfsRunContentGate inspects a freshly-fetched blob through the content gate,
// bounded by ScanMaxBytes. It reports whether the object must be blocked (a
// finding under the BlockOnFindings policy). Gate errors fail open.
func (b *Backend) lfsRunContentGate(ctx context.Context, repo, oid string, size int64) bool {
	lfs := b.lfs
	if lfs.gate == nil || size <= 0 || size > lfs.scanMaxBytes {
		return false
	}
	entry, err := b.cache.Get(ctx, lfsCacheKey(oid))
	if err != nil {
		return false
	}
	content, err := io.ReadAll(io.LimitReader(entry.Content, lfs.scanMaxBytes))
	entry.Content.Close()
	if err != nil {
		return false
	}
	findings, gerr := lfs.gate.InspectLFSObject(ctx, LFSObjectInfo{
		OID:      oid,
		Size:     size,
		Repo:     repo,
		Upstream: b.up.Name,
	}, content)
	if gerr != nil {
		b.logger.Warn("git lfs content gate failed (failing open)",
			"upstream", b.up.Name, "repo", repo, "oid", oid, "error", gerr)
		return false
	}
	if findings > 0 {
		lfs.metrics.gateFindings.Add(int64(findings))
		b.logger.Warn("git lfs blob content-gate findings",
			"upstream", b.up.Name, "repo", repo, "oid", oid, "findings", findings,
			"blocked", lfs.blockOnFindings)
		if lfs.blockOnFindings {
			lfs.metrics.gateBlocked.Add(1)
			return true
		}
	}
	return false
}

// handleLFSLoadError maps a loader failure onto a client status, incrementing
// the matching metric. OID/size mismatches are integrity failures (502): the
// proxy refuses to serve content it could not verify.
func (b *Backend) handleLFSLoadError(w http.ResponseWriter, repo, oid string, err error) {
	lfs := b.lfs
	switch {
	case errors.Is(err, errLFSOIDMismatch):
		lfs.metrics.oidMismatches.Add(1)
		b.logger.Error("git lfs oid mismatch", "upstream", b.up.Name, "repo", repo, "oid", oid)
		http.Error(w, "lfs object failed integrity verification", http.StatusBadGateway)
	case errors.Is(err, errLFSSizeMismatch):
		lfs.metrics.sizeMismatches.Add(1)
		b.logger.Error("git lfs size mismatch", "upstream", b.up.Name, "repo", repo, "oid", oid)
		http.Error(w, "lfs object failed integrity verification", http.StatusBadGateway)
	case errors.Is(err, errLFSTooLarge):
		lfs.metrics.errors.Add(1)
		b.writeLFSError(w, http.StatusRequestEntityTooLarge, "lfs object exceeds the configured maximum size")
	default:
		lfs.metrics.errors.Add(1)
		b.writeUpstreamError(w, repo, err)
	}
}

// writeLFSError writes a Git LFS batch-API error document with the given status.
func (b *Backend) writeLFSError(w http.ResponseWriter, status int, message string) {
	h := w.Header()
	h.Set("Content-Type", ctLFSJSON)
	noCache(h)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Message string `json:"message"`
	}{Message: message})
}

// --- verifying reader ----------------------------------------------------

// lfsVerifyReader streams an upstream LFS blob while accumulating its sha256 and
// byte count. On EOF it fails the read (rather than signalling EOF) when the
// digest does not equal the expected OID, when the length does not match the
// declared size, or when the size cap is exceeded. Because the cache commits an
// entry only after reading to EOF, a failed verification aborts the Put and the
// object is never cached — the integrity guarantee for LFS fetches.
type lfsVerifyReader struct {
	src          io.ReadCloser
	hash         hash.Hash
	expectOID    string
	declaredSize int64 // authoritative size from the batch API; <0 to skip
	maxBytes     int64
	read         int64
	onFetched    func(n int64)
	done         bool
}

func (v *lfsVerifyReader) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		v.read += int64(n)
		if v.maxBytes > 0 && v.read > v.maxBytes {
			return 0, fmt.Errorf("%w: exceeded %d bytes", errLFSTooLarge, v.maxBytes)
		}
		_, _ = v.hash.Write(p[:n])
	}
	if errors.Is(err, io.EOF) && !v.done {
		v.done = true
		if verr := v.verify(); verr != nil {
			return n, verr
		}
		if v.onFetched != nil {
			v.onFetched(v.read)
		}
	}
	return n, err
}

// Close closes the underlying upstream body. The cache calls it after the Put
// completes (success or failure), releasing the upstream connection.
func (v *lfsVerifyReader) Close() error { return v.src.Close() }

func (v *lfsVerifyReader) verify() error {
	sum := hex.EncodeToString(v.hash.Sum(nil))
	if sum != v.expectOID {
		return fmt.Errorf("%w: got sha256:%s, want sha256:%s", errLFSOIDMismatch, sum, v.expectOID)
	}
	if v.declaredSize >= 0 && v.read != v.declaredSize {
		return fmt.Errorf("%w: got %d, want %d", errLFSSizeMismatch, v.read, v.declaredSize)
	}
	return nil
}

// --- small helpers -------------------------------------------------------

// countingResponseWriter counts the body bytes written to the client so the
// serve path can meter exactly what was delivered (including partial ranges).
type countingResponseWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}
