package cachefed

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

// BasePath is the HTTP path at which a proxy exposes its peer cache-federation
// endpoint. Siblings issue GET/HEAD with the cache key in the "key" query
// parameter, e.g. GET /internal/cachefed/v1/blob?key=sha256%3Aabcd...
const BasePath = "/internal/cachefed/v1/blob"

// Protocol response headers. They are prefixed to avoid colliding with any
// pass-through artifact headers and to make a federated fill self-describing.
const (
	headerDigest      = "X-Cachefed-Digest"
	headerContentType = "X-Cachefed-Content-Type"
	headerOrigin      = "X-Cachefed-Origin"
	headerPeerSize    = "X-Cachefed-Size"
)

// ServeGuard decides whether a cache entry may be handed to a sibling. It is
// given the entry's key and metadata, never its content, and returns nil to
// allow. A non-nil error refuses the entry (the sibling is answered 403 and
// falls back to the upstream).
type ServeGuard func(ctx context.Context, key string, stat *cache.Stat) error

// Handler returns the HTTP handler a proxy mounts at BasePath to answer sibling
// HEAD/GET requests from its local content cache. It only ever serves bytes that
// are already present in the local cache.
//
// The cache is not a set of admitted artifacts. An artifact is in it from the
// moment it is fetched until a gate that refuses it evicts it — for a scan that
// takes time, that is a while — and a gate in an observe-only mode leaves a
// flagged artifact there for good. The receiving proxy runs its own admission
// gates over whatever it is handed, which is the real defense; the guards are
// this proxy declining to hand out what it has itself refused. Every guard is
// consulted for HEAD and GET alike, before any byte is written.
//
// When serving is disabled (federation off, Serve false, or no auth token
// configured) the handler rejects every request so a misconfiguration fails
// closed rather than exposing an unauthenticated cache endpoint.
func (f *Federation) Handler(c cache.Cache, guards ...ServeGuard) http.Handler {
	refused := func(w http.ResponseWriter, r *http.Request, key string, stat *cache.Stat) bool {
		for _, guard := range guards {
			if guard == nil {
				continue
			}
			if err := guard(r.Context(), key, stat); err != nil {
				f.metrics.recordServedRefused()
				w.Header().Set("X-Policy-Decision", "block")
				http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
				return true
			}
		}
		return false
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !f.servingEnabled() || c == nil {
			http.Error(w, "cache federation serving is disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !f.authorized(r) {
			f.metrics.recordUnauthorized()
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		key := r.URL.Query().Get("key")
		if strings.TrimSpace(key) == "" {
			http.Error(w, "missing key parameter", http.StatusBadRequest)
			return
		}

		// HEAD: existence + metadata only, no body (and no LRU-distorting read).
		if r.Method == http.MethodHead {
			stat, err := c.Stat(r.Context(), key)
			if err != nil {
				if errors.Is(err, cache.ErrNotFound) {
					f.metrics.recordServedMiss()
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				http.Error(w, "cache error", http.StatusInternalServerError)
				return
			}
			if refused(w, r, key, stat) {
				return
			}
			writeBlobHeaders(w, stat)
			f.metrics.recordServed()
			w.WriteHeader(http.StatusOK)
			return
		}

		// GET: stream the content to the sibling.
		entry, err := c.Get(r.Context(), key)
		if err != nil {
			if errors.Is(err, cache.ErrNotFound) {
				f.metrics.recordServedMiss()
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, "cache error", http.StatusInternalServerError)
			return
		}
		defer entry.Content.Close()
		if refused(w, r, key, &entry.Stat) {
			return
		}
		writeBlobHeaders(w, &entry.Stat)
		f.metrics.recordServed()
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, entry.Content)
	})
}

// writeBlobHeaders populates the protocol response headers from a cache Stat.
func writeBlobHeaders(w http.ResponseWriter, stat *cache.Stat) {
	if stat.Size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(stat.Size, 10))
		w.Header().Set(headerPeerSize, strconv.FormatInt(stat.Size, 10))
	}
	if stat.Metadata != nil {
		if d := stat.Metadata[cache.MetaDigest]; d != "" {
			w.Header().Set(headerDigest, d)
		}
		if ct := stat.Metadata[cache.MetaContentType]; ct != "" {
			w.Header().Set(headerContentType, ct)
			w.Header().Set("Content-Type", ct)
		}
		if o := stat.Metadata[cache.MetaOrigin]; o != "" {
			w.Header().Set(headerOrigin, o)
		}
	}
}

// authorized performs a constant-time comparison of the request's bearer token
// against the configured shared secret. An empty configured token means serving
// is disabled, which servingEnabled already gates, so this is never reached with
// an empty token.
func (f *Federation) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	presented := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(presented), []byte(f.cfg.AuthToken)) == 1
}

// peerBlobURL builds the sibling blob URL for a cache key.
func peerBlobURL(base *url.URL, key string) string {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + BasePath
	q := u.Query()
	q.Set("key", key)
	u.RawQuery = q.Encode()
	return u.String()
}

// peerGet issues a GET to one peer for a cache key under ctx. It returns the raw
// HTTP response (the caller inspects the status and, on 200, wraps the body in a
// digest verifier). Non-2xx responses are returned with their body drained and
// closed so the caller only ever streams a verified 200.
func (f *Federation) peerGet(ctx context.Context, p *peerState, key string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerBlobURL(p.base, key), nil)
	if err != nil {
		return nil, err
	}
	if f.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+f.cfg.AuthToken)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// Drain and close so the connection can be reused; surface a typed error.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		return nil, &peerStatusError{status: resp.StatusCode}
	}
	return resp, nil
}

// peerStatusError reports a non-200 response from a peer.
type peerStatusError struct{ status int }

func (e *peerStatusError) Error() string {
	return "cachefed: peer returned HTTP " + strconv.Itoa(e.status)
}

// peerDeclined reports whether a peer request failed because the peer, working
// as intended, had nothing to give: it does not hold the key (404) or declines
// to serve it (403: a ServeGuard refused the entry). An authentication failure
// (401) is not among them — that is a misconfiguration worth a tripped breaker.
func peerDeclined(err error) bool {
	var se *peerStatusError
	if !errors.As(err, &se) {
		return false
	}
	return se.status == http.StatusNotFound || se.status == http.StatusForbidden
}
