package proxy

import (
	"context"
	"io"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// fetchFromPeer attempts to satisfy a local cache miss for resolved from a
// sibling proxy via the cache-federation layer (Task 143). On a verified peer
// hit it returns the peer's (digest-verifying) content stream and the cache
// metadata to persist, so the gateway's normal cache-fill path stores and then
// admission-gates the bytes exactly as it would an upstream fetch. It returns
// ok=false (and the caller falls through to the upstream) when federation is
// disabled, no healthy peer holds the artifact, or any peer error occurs.
//
// The artifact's canonical origin is recorded as the resolved upstream URL (not
// the serving peer), so a federated fill is indistinguishable from a direct
// upstream fill in the cache index and downstream provenance.
func (g *Gateway) fetchFromPeer(ctx context.Context, resolved *backends.Resolved) (io.Reader, map[string]string, bool) {
	fed := g.deps.CacheFed
	if !fed.Enabled() {
		return nil, nil, false
	}

	fctx, span := g.startSpan(ctx, "cachefed.fetch",
		tracing.String("pullthrough.cache.key", resolved.CacheKey))
	defer span.End()

	res, err := fed.Fetch(fctx, resolved.CacheKey, resolved.Digest)
	if err != nil {
		span.SetAttributes(tracing.String("pullthrough.cachefed.status", "miss"))
		return nil, nil, false
	}
	span.SetAttributes(
		tracing.String("pullthrough.cachefed.status", "hit"),
		tracing.String("pullthrough.cachefed.peer", res.Peer),
	)

	meta := make(map[string]string, len(resolved.Metadata)+2)
	for k, v := range resolved.Metadata {
		meta[k] = v
	}
	meta[cache.MetaOrigin] = resolved.UpstreamURL
	ct := resolved.MediaType
	if ct == "" {
		ct = res.ContentType
	}
	if ct != "" {
		meta[cache.MetaContentType] = ct
	}
	// res.Content is a digest-verifying read-closer: reading it to EOF confirms
	// the peer's bytes match the expected digest and, on mismatch, aborts the
	// cache fill with an error rather than committing tampered content.
	return res.Content, meta, true
}
