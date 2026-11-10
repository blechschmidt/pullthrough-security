package helm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// The repository index is needed in two places: it is served to clients
// (rewritten), and it is consulted on every chart cache miss (to find the
// archive's upstream location and its digest). Parsing it is the expensive part
// — a full YAML parse costs on the order of 50 ms and 10-15 MiB of transient
// heap per MiB of index (measured: about 1.2 s and 270 MiB for Bitnami's 27 MiB
// index; see BenchmarkRewriteIndex) — and doing that per request, as the digest
// lookup used to, does not scale to the indexes real repositories publish.
//
// So the backend keeps one working copy of the index per upstream: the parsed
// lookup table and the rewritten document, both derived from one parse. The
// copy is never trusted on age alone; it is revalidated against the upstream,
// and rebuilt only when the upstream document actually changed:
//
//   - revalidation is a conditional request carrying the validators of the copy
//     we hold, so an unchanged index costs a 304 and no transfer;
//   - an upstream that ignores validators and resends the document is caught by
//     comparing its SHA-256 with the copy's, so an unchanged index is still not
//     parsed again;
//   - a document that cannot be accepted is remembered too (by the same hash),
//     so a persistently broken index is not re-parsed on every request either.
//
// Memory is bounded by construction. Refreshes are serialized, so at most one
// index is being downloaded and parsed at a time per upstream no matter how
// many clients ask; and every client is served from the same immutable
// rewritten copy, so serving costs no per-request buffer. What stays resident
// is one rewritten document (about the size of the upstream index, itself
// capped at maxIndexBytes) plus the lookup table (a few hundred bytes per chart
// version). Holding the document is what makes an unchanged index free to
// serve; dropping it would turn every `helm repo update` back into a full
// download, and concurrent ones into concurrent copies.

// indexLookupMaxAge is how long a revalidated index may be used to resolve
// archive requests before it is revalidated again. An index request always
// revalidates; this window only lets a burst of chart pulls (a `helm dependency
// build`, a CI fan-out) share one revalidation. A lookup that misses in a copy
// older than the request revalidates regardless, so a version published a
// moment ago is found; the window therefore only delays noticing that an
// existing entry was changed in place.
const indexLookupMaxAge = 30 * time.Second

// indexRefreshTimeout bounds one download of the upstream index. Refreshes are
// serialized, so without a bound an upstream that stalls mid-body would hold up
// every request that needs the index for as long as the first caller is willing
// to wait. It is far above what any index needs on a working connection.
const indexRefreshTimeout = 5 * time.Minute

// indexSnapshot is one revalidated state of the upstream index. It is immutable
// once published, so readers share it without locking.
type indexSnapshot struct {
	// checked is when the upstream last confirmed this is its current index.
	checked time.Time
	// etag and lastModified are the upstream's validators for the document, sent
	// back on the next revalidation.
	etag         string
	lastModified time.Time
	// sum is the SHA-256 of the upstream document, identifying it when the
	// upstream offers no validators (or ignores them).
	sum [sha256.Size]byte

	// err, when set, is why the upstream document was refused; the remaining
	// fields are then empty.
	err error
	// index is the lookup table parsed from the document.
	index *Index
	// body is the document as served to clients (chart URLs rewritten) and
	// bodyETag its validator. The upstream's own ETag names different bytes, and
	// must not be handed out for these.
	body     []byte
	bodyETag string
	// contentType and cacheControl are relayed from the upstream response.
	contentType  string
	cacheControl string
}

// currentIndex returns the index as of notBefore or later: the copy held, if
// the upstream confirmed it at or after notBefore, and otherwise a freshly
// revalidated one. Callers that can tolerate a slightly older answer pass a
// time in the past; passing the current time forces a revalidation.
//
// Concurrent callers share one refresh: whoever finds a refresh in flight waits
// for it and uses its result, since it completes after the caller asked.
func (b *Backend) currentIndex(ctx context.Context, notBefore time.Time) (*indexSnapshot, error) {
	usable := func(s *indexSnapshot) bool { return s != nil && !s.checked.Before(notBefore) }

	snap := b.indexSnap.Load()
	if !usable(snap) {
		select {
		case b.indexRefresh <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		defer func() { <-b.indexRefresh }()

		if snap = b.indexSnap.Load(); !usable(snap) {
			next, err := b.refreshIndex(ctx, snap)
			if err != nil {
				return nil, err
			}
			b.indexSnap.Store(next)
			snap = next
		}
	}
	if snap.err != nil {
		return nil, snap.err
	}
	return snap, nil
}

// refreshIndex revalidates prev (nil when there is none) against the upstream
// and returns the resulting snapshot. The upstream document is parsed only when
// it differs from the one prev was built from.
func (b *Backend) refreshIndex(ctx context.Context, prev *indexSnapshot) (*indexSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, indexRefreshTimeout)
	defer cancel()

	req := upstream.Request{URL: b.indexURL(), Method: http.MethodGet, Creds: b.creds}
	if prev != nil {
		req.IfNoneMatch = prev.etag
		req.IfModifiedSince = prev.lastModified
	}
	resp, err := b.client.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.NotModified {
		if prev == nil {
			return nil, fmt.Errorf("helm %q: upstream answered an unconditional index request with 304", b.name)
		}
		next := *prev
		next.checked = b.now()
		return &next, nil
	}
	if !resp.IsSuccess() {
		snippet := readSnippet(resp.Body)
		drainClose(resp.Body)
		return nil, &backends.StatusError{Status: resp.Status, URL: req.URL, Body: snippet}
	}

	body, err := readIndexBody(resp)
	if err != nil {
		return nil, fmt.Errorf("helm %q: %w", b.name, err)
	}

	next := &indexSnapshot{sum: sha256.Sum256(body)}
	if prev != nil && prev.sum == next.sum {
		// The same document, resent: keep everything derived from it.
		*next = *prev
	} else {
		b.buildIndex(next, body)
	}
	next.checked = b.now()
	next.etag = resp.ETag
	next.lastModified = time.Time{}
	if t, err := http.ParseTime(resp.LastModified); err == nil {
		next.lastModified = t
	}
	next.contentType = resp.ContentType
	next.cacheControl = resp.Header.Get("Cache-Control")
	return next, nil
}

// buildIndex parses the upstream document and fills in what is derived from it:
// the lookup table and the rewritten document. A document that cannot be
// accepted is recorded as such instead — it is never served as-is, because an
// index the backend cannot account for may carry chart URLs it did not rewrite.
func (b *Backend) buildIndex(snap *indexSnapshot, body []byte) {
	doc, err := scanIndex(body)
	var rewritten []byte
	if err == nil {
		rewritten, err = doc.rewrite(body, b.links)
	}
	if err != nil {
		b.metrics.incIndexErrors()
		snap.err = fmt.Errorf("helm %q: refusing the upstream index: %w", b.name, err)
		return
	}
	b.metrics.incIndexParsed()
	snap.index = doc.index()
	snap.body = rewritten
	sum := sha256.Sum256(rewritten)
	snap.bodyETag = `"` + hex.EncodeToString(sum[:16]) + `"`
}

// indexPreallocMax caps how much buffer is reserved up front on the strength of
// an upstream's declared Content-Length; a larger body still fits, it just grows
// the buffer as the bytes actually arrive.
const indexPreallocMax = 32 << 20 // 32 MiB

// readIndexBody reads an index response body, bounded by maxIndexBytes.
func readIndexBody(resp *upstream.Response) ([]byte, error) {
	defer drainClose(resp.Body)
	var buf bytes.Buffer
	if n := resp.ContentLength; n > 0 && n <= indexPreallocMax {
		buf.Grow(int(n) + bytes.MinRead)
	}
	if _, err := buf.ReadFrom(io.LimitReader(resp.Body, maxIndexBytes+1)); err != nil {
		return nil, fmt.Errorf("reading index.yaml: %w", err)
	}
	if buf.Len() > maxIndexBytes {
		return nil, fmt.Errorf("index.yaml exceeds %d bytes", maxIndexBytes)
	}
	return buf.Bytes(), nil
}

// lookupIndex runs find against the index. It uses the copy held when that was
// revalidated within indexLookupMaxAge; when find reports a miss in a copy that
// predates the call, it revalidates and tries once more, so an entry the
// upstream published since is found.
func (b *Backend) lookupIndex(ctx context.Context, find func(*Index) bool) error {
	asked := b.now()
	snap, err := b.currentIndex(ctx, asked.Add(-indexLookupMaxAge))
	if err != nil {
		return err
	}
	if find(snap.index) || !snap.checked.Before(asked) {
		return nil
	}
	if snap, err = b.currentIndex(ctx, asked); err != nil {
		return err
	}
	find(snap.index)
	return nil
}

// fetchIndex serves the repository index: revalidated against the upstream on
// every request (it is mutable, and clients expect a just-published chart to
// show up), with every chart URL rewritten to lead back through this mount.
func (b *Backend) fetchIndex(ctx context.Context, resolved *backends.Resolved) (*backends.FetchResult, error) {
	snap, err := b.currentIndex(ctx, b.now())
	if err != nil {
		return nil, err
	}
	if etagMatches(resolved.IfNoneMatch, snap.bodyETag) {
		return &backends.FetchResult{Resolved: resolved, Status: http.StatusNotModified, NotModified: true}, nil
	}

	b.metrics.incIndexServed()
	header := make(http.Header)
	header.Set("ETag", snap.bodyETag)
	if !snap.lastModified.IsZero() {
		header.Set("Last-Modified", snap.lastModified.UTC().Format(http.TimeFormat))
	}
	if snap.cacheControl != "" {
		header.Set("Cache-Control", snap.cacheControl)
	}
	return &backends.FetchResult{
		Resolved:  resolved,
		Content:   io.NopCloser(bytes.NewReader(snap.body)),
		Size:      int64(len(snap.body)),
		MediaType: snap.contentType,
		Header:    header,
		Status:    http.StatusOK,
	}, nil
}

// etagMatches reports whether a client's If-None-Match header names etag,
// using the weak comparison If-None-Match calls for (RFC 9110 §13.1.2).
func etagMatches(ifNoneMatch, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "" || etag == "" {
		return false
	}
	if ifNoneMatch == "*" {
		return true
	}
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimPrefix(strings.TrimSpace(candidate), "W/") == etag {
			return true
		}
	}
	return false
}
