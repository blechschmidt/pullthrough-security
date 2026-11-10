package proxy

import (
	"math"
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/ratelimit"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// withRateLimit enforces the per-tenant and global rate-limit, concurrency, and
// byte-quota policies (Task 24) for backend traffic. It runs inside the access-
// control envelope, so the authenticated principal is already on the request
// context and the tenant key can be resolved from it.
//
// On admission it acquires a Reservation (holding any concurrency slot) that is
// released when the handler returns, and meters the served bytes against the
// tenant's byte quota. A rejected request is answered with 429 Too Many Requests
// and, where meaningful, a Retry-After hint; it never reaches the upstream or the
// cache. The middleware is a no-op when no limiter is configured.
func (g *Gateway) withRateLimit(next http.Handler) http.Handler {
	if g.deps.RateLimit == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := tenantFromContext(r)

		rlCtx, rlSpan := g.startSpan(r.Context(), "ratelimit.admit",
			tracing.StringIf("pullthrough.tenant", tenant))
		res, dec := g.deps.RateLimit.Admit(rlCtx, tenant)
		rlSpan.SetAttributes(tracing.Bool("pullthrough.ratelimit.allowed", dec.Allowed))
		if !dec.Allowed {
			rlSpan.SetAttributes(tracing.StringIf("pullthrough.ratelimit.reason", string(dec.Type)))
			rlSpan.SetStatus(tracing.StatusError, "throttled")
		}
		rlSpan.End()
		if !dec.Allowed {
			writeRateLimited(w, dec)
			return
		}
		defer res.Release()

		bw := &byteMeter{ResponseWriter: w}
		next.ServeHTTP(bw, r)

		// Account the served bytes against the tenant (and global) byte quota.
		res.RecordBytes(bw.bytes)
	})
}

// tenantFromContext resolves the rate-limit tenant key from the request's
// authenticated principal. It falls back to the empty key (which maps to the
// default policy) when access control is disabled or the principal carries no
// team.
func tenantFromContext(r *http.Request) string {
	if p, ok := auth.FromContext(r.Context()); ok {
		return p.Team
	}
	return ""
}

// writeRateLimited renders a 429 response for a throttled request, attaching a
// Retry-After header (in whole seconds, rounded up) when the decision carries a
// hint, plus an X-RateLimit-Limit marker identifying the violated dimension.
func writeRateLimited(w http.ResponseWriter, dec ratelimit.Decision) {
	if dec.RetryAfter > 0 {
		secs := int(math.Ceil(dec.RetryAfter.Seconds()))
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	if dec.Type != "" {
		w.Header().Set("X-RateLimit-Limit", string(dec.Type))
	}
	msg := dec.Reason
	if msg == "" {
		msg = http.StatusText(http.StatusTooManyRequests)
	}
	http.Error(w, msg, http.StatusTooManyRequests)
}

// byteMeter wraps a ResponseWriter to count body bytes written, for byte-quota
// accounting. It mirrors countingWriter but is intentionally minimal: the
// rate-limit middleware only needs the byte total.
type byteMeter struct {
	http.ResponseWriter
	bytes int64
}

func (w *byteMeter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}
