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

// Handler returns the HTTP handler a proxy mounts at BasePath to answer sibling
// HEAD/GET requests from its local content cache. It only ever serves bytes that
// are already present in the local cache — and the local cache, by construction,
// holds only artifacts that passed this proxy's admission gates (a blocked or
// quarantined artifact is evicted) — so federation never leaks ungated content
// between peers.
//
// When serving is disabled (federation off, Serve false, or no auth token
// configured) the handler rejects every request so a misconfiguration fails
// closed rather than exposing an unauthenticated cache endpoint.
func (f *Federation) Handler(c cache.Cache) http.Handler {
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
