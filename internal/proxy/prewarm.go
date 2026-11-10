package proxy

import (
	"context"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// PullEvent describes one artifact successfully served on the cacheable pull
// path. It is reported to a PullObserver so the predictive cache pre-warming
// subsystem (Task 134) can learn historical pull patterns and attribute later
// cache hits to prior pre-warms.
type PullEvent struct {
	// Backend is the backend route name (e.g. "pip", "npm").
	Backend string
	// Ecosystem is the resolved ecosystem for the backend.
	Ecosystem string
	// Name and Version are the resolved package coordinate (may be empty for
	// resources a backend cannot express as a coordinate).
	Name    string
	Version string
	// Path is the backend-relative request path (the portion after
	// /v1/<backend>), which a pre-warm replays with a substituted version.
	Path string
	// Tenant is the team the pull was billed to (empty when unscoped).
	Tenant string
	// CacheHit reports whether the artifact was served from cache (HIT or
	// COALESCED-HIT) rather than freshly fetched (MISS).
	CacheHit bool
	// Size is the served artifact size in bytes.
	Size int64
	// At is the serve time.
	At time.Time
}

// PullObserver receives a notification for each artifact successfully served to
// a client on the cacheable pull path. It is best-effort and must never block or
// fail a pull. The predictive pre-warming subsystem implements it (via a thin
// adapter in the server binary). Synthetic pre-warm requests are never reported.
//
// When nil, no pull telemetry is collected.
type PullObserver interface {
	ObservePull(ev PullEvent)
}

// prewarmContextKey marks a request as a synthetic predictive-pre-warm fetch, so
// the pull observer does not mistake it for genuine client demand (which would
// let pre-warming bootstrap predictions off its own activity) and the serve-path
// hit attribution ignores it.
type prewarmContextKey struct{}

// WithPrewarmMarker tags ctx as belonging to a synthetic pre-warm fetch. The
// server binary's pre-warm fetcher sets this on the requests it drives through
// the gateway.
func WithPrewarmMarker(ctx context.Context) context.Context {
	return context.WithValue(ctx, prewarmContextKey{}, true)
}

// isPrewarmRequest reports whether r originates from the pre-warming subsystem.
func isPrewarmRequest(r *http.Request) bool {
	v, _ := r.Context().Value(prewarmContextKey{}).(bool)
	return v
}

// prewarmTeam is the pseudo-tenant synthetic pre-warm fetches are attributed to
// in audit/metering when the fetcher does not pin a specific target tenant,
// keeping pre-warm activity clearly separate from real client tenants.
const prewarmTeam = "(prewarm)"

// PrewarmHandler returns an http.Handler that drives the full gated pull
// pipeline for synthetic predictive-pre-warm requests (Task 134). Every
// supply-chain admission gate runs exactly as for a client pull — so an artifact
// that fails a gate is refused and quarantined, never served — while client
// access-control and rate limiting are bypassed: pre-warming is a trusted,
// internally rate-bounded actor rather than an external client. Requests it
// serves carry the pre-warm marker so the pull observer never mistakes a
// pre-warm for genuine client demand.
//
// The fetcher may attach a principal (pinning the target tenant) to the request
// context so, under per-tenant cache namespacing, the warmed cache key matches
// the one a later client read will hit; otherwise a dedicated pre-warm identity
// is used.
func (g *Gateway) PrewarmHandler() http.Handler {
	return g.withTracing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithPrewarmMarker(r.Context())
		if _, ok := auth.FromContext(ctx); !ok {
			ctx = auth.WithPrincipal(ctx, &auth.Principal{Subject: "prewarm", Team: prewarmTeam, Method: "internal"})
		}
		g.handleBackend(w, r.WithContext(ctx))
	}))
}

// observePull reports a successfully-served cacheable pull to the configured
// observer. It is a no-op when no observer is wired or when the request is a
// synthetic pre-warm fetch. Best-effort: it never affects serving.
func (g *Gateway) observePull(r *http.Request, backend string, resolved *backends.Resolved, cacheStatus string, size int64) {
	if g.deps.PullObserver == nil || resolved == nil {
		return
	}
	if isPrewarmRequest(r) {
		return
	}
	tenant := ""
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant = p.Team
	}
	g.deps.PullObserver.ObservePull(PullEvent{
		Backend:   backend,
		Ecosystem: g.ecosystemFor(backend),
		Name:      resolved.Coordinate.Name,
		Version:   resolved.Coordinate.Version,
		Path:      r.URL.Path,
		Tenant:    tenant,
		CacheHit:  cacheStatus != "MISS",
		Size:      size,
		At:        time.Now(),
	})
}
