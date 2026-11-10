package upstream

import "net/http"

// proxyOwnedResponseHeaders are headers the proxy computes itself from the
// cache entry or the freshly fetched content; upstream values for them must not
// be blindly forwarded or they would conflict with what the proxy sets.
var proxyOwnedResponseHeaders = map[string]bool{
	"content-length":    true,
	"content-type":      true,
	"etag":              true,
	"last-modified":     true,
	"content-encoding":  true, // the proxy stores decoded bytes; re-advertising would mislead clients
	"transfer-encoding": true,
}

// PropagateResponseHeaders copies safe-to-forward upstream response headers from
// src into dst, skipping hop-by-hop headers and headers the proxy manages
// itself. It is used both when serving freshly fetched content and when
// recording which upstream headers a backend wants preserved.
func PropagateResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		lk := canonicalLower(k)
		if hopByHop[lk] || proxyOwnedResponseHeaders[lk] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func canonicalLower(h string) string {
	// http.Header keys are canonicalized; lowercasing is enough for our maps.
	b := []byte(h)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
