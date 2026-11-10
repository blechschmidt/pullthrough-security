package proxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/coalesce"
)

// NewCoalescer constructs a pull-path coalescer bound to the proxy's upstream
// error classifier (which knows how to map backends.StatusError onto
// negative-caching verdicts). It is the constructor the wiring layer uses so the
// classifier stays internal to this package.
func NewCoalescer(cfg coalesce.Config) *coalesce.Coalescer[*cache.Entry] {
	return coalesce.New[*cache.Entry](cfg, classifyUpstreamError)
}

// disabledCoalescer is the pass-through used when no coalescer is wired, so the
// pull path never needs a nil check. Its Do simply runs the load.
var disabledCoalescer = coalesce.New[*cache.Entry](coalesce.Config{Enabled: false}, nil)

// coalescer returns the configured pull-path coalescer, or a disabled
// pass-through when none is wired.
func (g *Gateway) coalescer() *coalesce.Coalescer[*cache.Entry] {
	if g.deps.Coalescer != nil {
		return g.deps.Coalescer
	}
	return disabledCoalescer
}

// coalesceKey derives the request-coalescing / negative-cache key for a resolved
// artifact. It always prefixes the cache key with the caller's tenant namespace
// (independent of cache namespacing) so that:
//
//   - concurrent misses for a private artifact are only coalesced among callers
//     of the same tenant — one tenant's authenticated fetch is never shared with
//     another's, and
//   - a negative result (e.g. a 403 seen with one tenant's credentials) never
//     suppresses another tenant's possibly-authorized fetch.
//
// The NUL separator cannot appear in a team namespace (sanitized to [a-z0-9-_])
// so the scope and key can never be confused across a boundary.
func (g *Gateway) coalesceKey(r *http.Request, cacheKey string) string {
	scope := auth.TeamNamespace("")
	if p, ok := auth.FromContext(r.Context()); ok {
		scope = p.Namespace()
	}
	return scope + "\x00" + cacheKey
}

// classifyUpstreamError maps a load/fetch failure onto a negative-caching
// verdict. Terminal "the artifact is not here / you may not have it" conditions
// (404/410/auth) are cached for the standard negative TTL; transient conditions
// (5xx, throttling, and non-HTTP/network errors) use a jittered backoff window
// so retries against a recovering upstream are spread out. Client cancellations
// are never cached (they say nothing about the artifact).
func classifyUpstreamError(err error) coalesce.Verdict {
	if err == nil {
		return coalesce.Verdict{}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return coalesce.Verdict{Cache: false}
	}
	if se, ok := backends.AsStatusError(err); ok {
		switch {
		case se.Status == http.StatusNotFound:
			return coalesce.Verdict{Cache: true, Kind: "not_found"}
		case se.Status == http.StatusGone:
			return coalesce.Verdict{Cache: true, Kind: "gone"}
		case se.Status == http.StatusUnauthorized, se.Status == http.StatusForbidden:
			return coalesce.Verdict{Cache: true, Kind: "auth"}
		case se.Status == http.StatusTooManyRequests:
			return coalesce.Verdict{Cache: true, Retryable: true, Kind: "throttled"}
		case se.Status >= 500:
			return coalesce.Verdict{Cache: true, Retryable: true, Kind: "server"}
		default:
			// Other 4xx are request-shaped and not worth caching.
			return coalesce.Verdict{Cache: false}
		}
	}
	// A non-HTTP error (DNS, dial, TLS, read timeout): transient, short backoff.
	return coalesce.Verdict{Cache: true, Retryable: true, Kind: "error"}
}
