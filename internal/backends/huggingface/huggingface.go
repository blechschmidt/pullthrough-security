// Package huggingface implements a pull-through proxy backend for the Hugging
// Face Hub model/dataset/space "resolve" protocol, bringing the ML-model
// ecosystem to parity with the package-manager backends: repository blobs are
// proxied and cached content-addressably beneath their immutable commit, Git LFS
// weight files served through the Hub's CDN redirect are verified against the
// SHA-256 the resolve response advertises before they are cached or served, and
// the repository coordinate (model/dataset id + revision) is attached for the
// admission gates — including the ML-specific weight-scanning gate
// (internal/mlguard) that refuses pickle-based weights carrying unsafe opcodes.
//
// Protocol mapping (see path.go for the full route table):
//
//	GET /{repo}/resolve/{revision}/{path}                 model file (immutable when {revision} is a commit SHA)
//	GET /datasets/{repo}/resolve/{revision}/{path}        dataset file
//	GET /spaces/{repo}/resolve/{revision}/{path}          space file
//	GET /api/models/{repo}[/revision/{rev}]               model metadata (revalidated)
//	GET /api/datasets/{repo}                              dataset metadata (revalidated)
//
// Security model: a resolve pinned to a 40-hex Git commit SHA is immutable, so
// the cache key (which embeds it) is itself content-addressable and the blob is
// cached indefinitely. A resolve against a branch/tag ("main") is mutable and
// normally revalidated — but a weight file is cached even on a branch (the cache
// key embeds the revision) so that the SHA-256 verification and the ML
// pickle-scanning gate, which run only on the cacheable serve path, apply to every
// weight pull; commit-pinning is recommended when branch freshness matters.
// Large weight files are stored in Git LFS and served from a CDN via
// a redirect the HTTP client follows transparently; the resolve response
// advertises the object's SHA-256 out-of-band (X-Linked-Etag), which the backend
// verifies the delivered bytes against — streaming, so multi-GB weights are never
// buffered — so a tampered mirror or CDN can neither poison the cache nor reach a
// client. git-lfs pointer bodies returned in place of content are recognized so
// their declared oid/size are surfaced and the ML gate never mistakes the tiny
// pointer text for a real pickle.
//
// Client configuration points the Hugging Face endpoint at
// "<publicBase>/v1/<name>" (see docs/clients.md):
// `HF_ENDPOINT=<publicBase>/v1/<name> huggingface-cli download ...`.
package huggingface

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Internal metadata keys carry per-request decisions from Resolve into Fetch
// (which only receives the *Resolved). They are not persisted as meaningful cache
// data.
const (
	metaKind     = "_kind"     // resource-class label, for diagnostics/metrics
	metaResolve  = "_resolve"  // "1" when the resource is a blob download
	metaFilename = "_filename" // base filename of a resolved blob
)

// Persisted (caller-meaningful) metadata keys surfaced to downstream gates and
// the admission pipeline.
const (
	// MetaRepoType records the repository class ("model"|"dataset"|"space").
	MetaRepoType = "huggingface.repoType"
	// MetaRepoID records the bare repository id "owner/name".
	MetaRepoID = "huggingface.repoId"
	// MetaRevision records the requested revision (branch, tag, or commit SHA).
	MetaRevision = "huggingface.revision"
	// MetaCommit records the resolved commit SHA from the X-Repo-Commit response
	// header, when the upstream provides it.
	MetaCommit = "huggingface.commit"
	// MetaPath records the repository-relative path of a resolved blob.
	MetaPath = "huggingface.path"
	// MetaFormat records the weight-file format label ("safetensors"|"pickle"|
	// "gguf"|"weights"|""), surfaced to the ML weight-scanning gate.
	MetaFormat = "huggingface.format"
	// MetaLFS is "1" when the resolved blob was a Git LFS object (a content SHA-256
	// was advertised).
	MetaLFS = "huggingface.lfs"
	// MetaOID records the object's SHA-256 (from X-Linked-Etag or a parsed LFS
	// pointer) when known.
	MetaOID = "huggingface.oid"
	// MetaSize records the object's declared size when known.
	MetaSize = "huggingface.size"
	// MetaChecksumVerified records "sha256" when a blob was verified against its
	// advertised SHA-256, or "none" when no content hash was available.
	MetaChecksumVerified = "huggingface.checksumVerified"
	// MetaPointer is "1" when the resolve returned a git-lfs pointer file rather
	// than the object content.
	MetaPointer = "huggingface.pointer"
)

const maxErrorBodySnippet = 2 << 10 // 2 KiB

// Options configures a Hugging Face Backend.
type Options struct {
	// Name is the route identifier and cache-key prefix (e.g. "huggingface").
	// Required.
	Name string
	// UpstreamURL is the Hub base URL, e.g. "https://huggingface.co". The backend
	// appends the resolve/api paths. Required.
	UpstreamURL string
	// Client is the shared upstream request executor. Required. It is an
	// upstream.Doer so a health-aware multi-mirror pool can be injected, and it
	// follows the Hub's CDN redirect for LFS objects transparently.
	Client upstream.Doer
	// Credentials authenticate the proxy to the Hub (a user access token for gated
	// or private repositories). Optional; public repositories pull anonymously.
	Credentials upstream.Credentials
	// Metrics, when set, records supply-chain telemetry. Optional.
	Metrics *Metrics
}

// Backend is a Hugging Face Hub pull-through backend implementing
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
		return nil, errors.New("huggingface: name is required")
	}
	if strings.TrimSpace(opts.UpstreamURL) == "" {
		return nil, fmt.Errorf("huggingface %q: upstream URL is required", opts.Name)
	}
	base, err := url.Parse(strings.TrimRight(opts.UpstreamURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("huggingface %q: invalid upstream URL: %w", opts.Name, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("huggingface %q: upstream URL must be http(s), got %q", opts.Name, base.Scheme)
	}
	if opts.Client == nil {
		return nil, fmt.Errorf("huggingface %q: upstream client is required", opts.Name)
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
// Hub layout, derives the upstream URL and cache key, attaches the repository
// coordinate for the admission gates, and decides cacheability (only a resolve
// pinned to an immutable commit SHA is cached).
func (b *Backend) Resolve(ctx context.Context, req *backends.Request) (*backends.Resolved, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errors.New("huggingface: nil request")
	}

	res, ok := classify(req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a Hugging Face Hub path", backends.ErrNotSupported, req.Path)
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
			MetaRepoType: res.repoType.label(),
			MetaRepoID:   res.repoID,
		},
	}
	if res.revision != "" {
		resolved.Metadata[MetaRevision] = res.revision
	}

	// Attach the coordinate so nameguard, policy, the ML weight-scanning gate,
	// vulnscan, license, and policyengine can identify the repository/revision.
	resolved.Coordinate = backends.Coordinate{Name: res.coordinateName(), Version: res.revision}

	if res.isResolve() {
		resolved.Metadata[metaResolve] = "1"
		resolved.Metadata[metaFilename] = res.baseFilename()
		resolved.Metadata[MetaPath] = res.filepath
		if f := weightFormat(res.baseFilename()); f != "" {
			resolved.Metadata[MetaFormat] = f
		}
	}

	return resolved, nil
}

// Fetch implements backends.Backend. For a blob resolve it follows the Hub's CDN
// redirect transparently, recognizes a git-lfs pointer body, and verifies the
// delivered bytes against the SHA-256 the resolve response advertises
// (X-Linked-Etag) — streaming for large weights, so they are never buffered.
// Metadata documents are proxied directly.
func (b *Backend) Fetch(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	if resolved == nil {
		return nil, errors.New("huggingface: nil resolved")
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
	if commit := resp.Header.Get("X-Repo-Commit"); commit != "" {
		resolved.Metadata[MetaCommit] = commit
		header.Set("X-Repo-Commit", commit)
	}
	// The Hub client (huggingface_hub, and through it transformers/datasets)
	// reads a file's identity from response headers and rejects a resolve
	// response without X-Repo-Commit as "not served by a Hugging Face Hub
	// endpoint". A commit-pinned file is cached and later served from the cache
	// entry, so these headers are declared part of the artifact: the gateway
	// replays them on every serve, hit or miss.
	for _, name := range hubIdentityHeaders {
		backends.SetResponseHeader(resolved.Metadata, name, resp.Header.Get(name))
	}

	// Metadata documents (/api/...) are proxied without content verification.
	if resolved.Metadata[metaResolve] != "1" {
		b.metrics.incMetadataServed()
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   resp.Body,
			Size:      resp.ContentLength,
			MediaType: b.mediaType(resolved, resp.ContentType),
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	return b.fetchBlob(resolved, resp, header)
}

// hubIdentityHeaders are the Hub response headers a client uses to identify a
// resolved file: the commit the revision resolved to, and — for an LFS/Xet
// object, whose bytes come from a CDN — the content's own ETag (its SHA-256) and
// size. X-Linked-Etag takes precedence over ETag in the client, so it must
// survive caching for a weight file's checksum to be the one the client checks.
var hubIdentityHeaders = []string{"X-Repo-Commit", "X-Linked-Etag", "X-Linked-Size"}

// fetchBlob serves a resolved repository blob: it peeks the leading bytes to
// recognize a git-lfs pointer, otherwise streams the real content through a
// SHA-256 verifying reader when the resolve response advertised a content hash.
func (b *Backend) fetchBlob(resolved *backends.Resolved, resp *upstream.Response, header http.Header) (*backends.FetchResult, error) {
	b.metrics.incFilesServed()
	b.recordFormatMetric(resolved)

	// The Hub advertises the LFS object's SHA-256 out-of-band; prefer the dedicated
	// header, falling back to an ETag that is itself a bare SHA-256.
	expected, haveChecksum := normalizeLinkedETag(resp.Header.Get("X-Linked-Etag"))
	if !haveChecksum {
		expected, haveChecksum = normalizeLinkedETag(resp.ETag)
	}
	if size := resp.Header.Get("X-Linked-Size"); size != "" {
		resolved.Metadata[MetaSize] = size
	} else if resp.ContentLength >= 0 {
		resolved.Metadata[MetaSize] = strconv.FormatInt(resp.ContentLength, 10)
	}

	// Peek enough to recognize a git-lfs pointer file (returned in place of content
	// by some mirrors / the raw endpoint) without consuming a real weight stream.
	head, eof := readAtMost(resp.Body, maxPointerBytes)
	if eof && strings.HasPrefix(string(head), pointerPrefix) {
		if ptr, ok := parsePointer(head); ok {
			drainClose(resp.Body)
			return b.servePointer(resolved, header, ptr)
		}
	}

	mediaType := b.mediaType(resolved, resp.ContentType)
	content := reattach(head, resp.Body)

	if haveChecksum {
		b.metrics.incLFSResolved()
		resolved.Metadata[MetaLFS] = "1"
		resolved.Metadata[MetaOID] = expected
		resolved.Metadata[MetaChecksumVerified] = "sha256"
		header.Set("X-Checksum-Verified", "sha256")
		verified := newVerifyingReader(content, expected, resolved.Metadata[metaFilename], resolved.UpstreamURL, func(ok bool) {
			if ok {
				b.metrics.incFilesVerified()
			} else {
				b.metrics.incChecksumMismatch()
			}
		})
		return &backends.FetchResult{
			Resolved:  resolved,
			Content:   verified,
			Size:      resp.ContentLength,
			MediaType: mediaType,
			Header:    header,
			Status:    resp.Status,
		}, nil
	}

	// No advertised content hash (a small non-LFS file, e.g. config.json): served
	// unverified, which is observable via the metric.
	b.metrics.incChecksumMissing()
	resolved.Metadata[MetaChecksumVerified] = "none"
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   content,
		Size:      resp.ContentLength,
		MediaType: mediaType,
		Header:    header,
		Status:    resp.Status,
	}, nil
}

// servePointer returns a recognized git-lfs pointer body as-is, surfacing its
// declared oid/size so the ML gate does not mistake the tiny text blob for a real
// weight file.
func (b *Backend) servePointer(resolved *backends.Resolved, header http.Header, ptr lfsPointer) (*backends.FetchResult, error) {
	b.metrics.incPointersSeen()
	body := b.pointerText(ptr)
	resolved.Metadata[MetaPointer] = "1"
	resolved.Metadata[MetaOID] = ptr.oid
	resolved.Metadata[MetaSize] = strconv.FormatInt(ptr.size, 10)
	resolved.Metadata[MetaChecksumVerified] = "none"
	header.Set("Content-Type", "text/plain; charset=utf-8")
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(body)),
		Size:      int64(len(body)),
		MediaType: "text/plain; charset=utf-8",
		Header:    header,
		Status:    http.StatusOK,
	}, nil
}

// pointerText re-renders the canonical git-lfs pointer body from a parsed pointer.
func (b *Backend) pointerText(ptr lfsPointer) []byte {
	return []byte(fmt.Sprintf("%s\noid sha256:%s\nsize %d\n", pointerPrefix, ptr.oid, ptr.size))
}

// recordFormatMetric counts served weight files by format for observability.
func (b *Backend) recordFormatMetric(resolved *backends.Resolved) {
	switch resolved.Metadata[MetaFormat] {
	case formatSafetensors:
		b.metrics.incSafetensorsServed()
	case formatPickle:
		b.metrics.incPickleServed()
	}
}

// mediaType selects the response content type.
func (b *Backend) mediaType(resolved *backends.Resolved, upstreamCT string) string {
	if resolved.Metadata[metaResolve] != "1" {
		if upstreamCT != "" {
			return upstreamCT
		}
		return "application/json"
	}
	name := strings.ToLower(resolved.Metadata[metaFilename])
	switch {
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case strings.HasSuffix(name, ".txt"), strings.HasSuffix(name, ".md"):
		return "text/plain; charset=utf-8"
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

// joinPath appends the inbound Hub path to the upstream base.
func (b *Backend) joinPath(path string) *url.URL {
	out := *b.base
	basePath := strings.TrimRight(b.base.EscapedPath(), "/")
	out.Path = basePath + "/" + strings.TrimLeft(path, "/")
	out.RawPath = ""
	return &out
}

// cacheKey derives a stable cache key from the backend name and the layout path.
// A resolve path pinned to a commit SHA embeds that content hash, so the path
// alone is a content-addressable key; query parameters are incidental and
// excluded.
func (b *Backend) cacheKey(path string) string {
	return b.name + ":" + strings.TrimLeft(path, "/")
}

func isRead(req *backends.Request) bool {
	return req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == ""
}

// readAtMost reads up to n bytes from r, reporting whether EOF was reached within
// that bound (so a small body is fully captured while a large stream is only
// peeked).
func readAtMost(r io.Reader, n int) ([]byte, bool) {
	buf := make([]byte, 0, n)
	tmp := make([]byte, 512)
	for len(buf) < n {
		want := n - len(buf)
		if want > len(tmp) {
			want = len(tmp)
		}
		m, err := r.Read(tmp[:want])
		buf = append(buf, tmp[:m]...)
		if err == io.EOF {
			return buf, true
		}
		if err != nil {
			return buf, false
		}
	}
	return buf, false
}

// reattach reconstructs a ReadCloser from an already-peeked prefix and the
// remaining body, closing the original body on Close.
func reattach(head []byte, body io.ReadCloser) io.ReadCloser {
	return &reattached{Reader: io.MultiReader(bytes.NewReader(head), body), closer: body}
}

type reattached struct {
	io.Reader
	closer io.Closer
}

func (r *reattached) Close() error { return r.closer.Close() }

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
