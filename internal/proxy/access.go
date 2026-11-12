package proxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// withAccessControl authenticates and authorizes a backend request, enforces the
// caller's team quota, records a tamper-evident audit trail, and (on success)
// attaches the resulting principal to the request context before delegating to
// next. Denied requests never reach the upstream or the cache.
//
// The middleware is a no-op for access control when no Enforcer is configured,
// but still audits traffic when an Audit logger is present, so an operator can
// enable audit logging independently of authentication.
func (g *Gateway) withAccessControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, _, ok := splitBackendPath(r.URL.Path)
		if !ok {
			// Malformed path: let the downstream handler emit the 400 without
			// consuming quota or producing an authz record for a non-route.
			next.ServeHTTP(w, r)
			return
		}
		ecosystem := g.ecosystemFor(name)

		authCtx, authSpan := g.startSpan(r.Context(), "auth.check")
		res := g.checkAccess(authCtx, r, name, ecosystem)
		authSpan.SetAttributes(
			tracing.Bool("pullthrough.auth.allowed", res.Allowed),
			tracing.StringIf("pullthrough.auth.stage", string(res.Stage)),
		)
		if res.Principal != nil {
			authSpan.SetAttributes(
				tracing.StringIf("enduser.id", res.Principal.Subject),
				tracing.StringIf("pullthrough.tenant", res.Principal.Team),
			)
			// Enrich the request-level span with the resolved tenant so traces are
			// filterable by tenant regardless of which stage later fails.
			tracing.SpanFromContext(r.Context()).SetAttributes(
				tracing.StringIf("pullthrough.tenant", res.Principal.Team))
		}
		if !res.Allowed {
			authSpan.SetStatus(tracing.StatusError, "denied")
		}
		authSpan.End()
		if !res.Allowed {
			g.auditDecision(r, name, ecosystem, res)
			writeAccessError(w, res, g.authChallenge(name, ecosystem))
			return
		}

		// A request identified by a personal link (Task 177): note that the link
		// was used, and from where — what its owner looks at to tell their own
		// use from someone else's.
		g.deps.UserLinks.Touch(res.Principal, clientIP(r), r.UserAgent())

		ctx := auth.WithPrincipal(r.Context(), res.Principal)
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK, start: time.Now()}
		next.ServeHTTP(cw, r.WithContext(ctx))

		// Account served bytes against the tenant quota and record the pull.
		g.deps.Enforcer.RecordBytes(res.Principal, cw.bytes)
		g.auditPull(r, name, ecosystem, res.Principal, cw)
	})
}

// ecosystemFor returns the ecosystem type for a backend name, falling back to
// the name itself when no mapping is configured.
func (g *Gateway) ecosystemFor(name string) string {
	if g.deps.Ecosystems != nil {
		if eco, ok := g.deps.Ecosystems[name]; ok && eco != "" {
			return eco
		}
	}
	return name
}

// auditDecision records a denied (or errored) access-control decision.
func (g *Gateway) auditDecision(r *http.Request, backend, ecosystem string, res auth.Result) {
	if g.deps.Audit == nil {
		return
	}
	ev := audit.Event{
		Type:       eventTypeForStage(res.Stage),
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Status:     res.Status,
		Decision:   audit.DecisionDeny,
		Reason:     res.Reason,
		Detail:     map[string]any{"stage": string(res.Stage)},
	}
	if res.Principal != nil {
		ev.Subject = res.Principal.Subject
		ev.Team = res.Principal.Team
		// Record how the caller authenticated (token|oidc|mtls|anonymous) so an
		// auditor can attribute a denial to a workload-identity certificate as
		// readily as to a token. For mTLS the Subject already carries the SPIFFE ID.
		if res.Principal.Method != "" {
			ev.Detail["authMethod"] = res.Principal.Method
		}
		// A refused personal link that is a known one — expired, revoked — is
		// named, so "the revoked link was still being used from this address" can
		// be read off the trail.
		if link := personalLinkID(res.Principal); link != "" {
			ev.Detail["link"] = link
		}
	}
	g.logAudit(r.Context(), ev)
}

// auditPull records an allowed pull, including the cache result (HIT/MISS/
// BYPASS, read from the X-Cache header the serve handlers set), HTTP status, and
// bytes served.
func (g *Gateway) auditPull(r *http.Request, backend, ecosystem string, p *auth.Principal, cw *countingWriter) {
	if g.deps.Audit == nil {
		return
	}
	cacheResult := cw.Header().Get("X-Cache")
	ev := audit.Event{
		Type:       audit.EventPull,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Status:     cw.status,
		Decision:   audit.DecisionAllow,
		Detail: map[string]any{
			"cache":      cacheResult,
			"bytes":      cw.bytes,
			"durationMs": time.Since(cw.start).Milliseconds(),
		},
	}
	if p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
		if p.Method != "" {
			ev.Detail["authMethod"] = p.Method
		}
		if link := personalLinkID(p); link != "" {
			ev.Detail["link"] = link
		}
	}
	// Name the package the request resolved to, so the audit trail (and a SIEM
	// fed from it) can be searched by coordinate and not only by request path.
	if name, version, ok := pullRecordFrom(r.Context()).coordinate(); ok {
		ev.Detail["package"] = name
		if version != "" {
			ev.Detail["version"] = version
		}
	}
	g.logAudit(r.Context(), ev)
}

// logAudit writes an event, logging (but not failing the request on) an audit
// sink error: a pull must not be silently dropped because the audit log is
// momentarily unavailable, but the failure must be visible to operators.
func (g *Gateway) logAudit(ctx context.Context, ev audit.Event) {
	if err := g.deps.Audit.Log(ctx, ev); err != nil {
		g.deps.Logger.Error("audit log write failed", "type", ev.Type, "error", err)
	}
}

// eventTypeForStage maps a denial stage to its audit event type.
func eventTypeForStage(stage auth.Stage) audit.EventType {
	switch stage {
	case auth.StageAuthn:
		return audit.EventAuth
	case auth.StageQuota:
		return audit.EventQuota
	default:
		return audit.EventAuthorization
	}
}

// The challenges a 401 can carry. The proxy takes a client's token as a bearer
// token or as the user name or password of HTTP Basic (auth.CandidateTokens).
const (
	challengeBearer = `Bearer realm="pullthrough"`
	challengeBasic  = `Basic realm="pullthrough"`
)

// authChallenge is the WWW-Authenticate challenge of a 401 answered for a
// request to backend. It is "Bearer" — except for the two kinds of client that
// can do nothing with that:
//
//   - A container client (the Docker Engine, containerd, podman) reads a Bearer
//     challenge as the address of a token service to fetch a token from, and
//     gives up on a realm that is not a URL. Challenged with Basic, it presents
//     what `docker login` stored — which may be an API token or a personal
//     link's token (Task 177) as the password.
//   - Git answers a challenge only with a credential it holds for it: for Basic,
//     the one in the URL, from a credential helper, or typed at its prompt.
func (g *Gateway) authChallenge(backend, ecosystem string) string {
	if rr := g.opts.RegistryRoot; rr != nil && rr.has(backend) {
		return challengeBasic
	}
	switch ecosystem {
	case "docker", "oci", "git":
		return challengeBasic
	}
	return challengeBearer
}

// writeAccessError writes a denial response. The body is intentionally terse
// and free of internal detail. challenge is the WWW-Authenticate value of a 401
// (see authChallenge).
func writeAccessError(w http.ResponseWriter, res auth.Result, challenge string) {
	if res.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	if res.Status == http.StatusServiceUnavailable {
		// The check could not be made (the personal-link registry is
		// unreachable); nothing is wrong with the request, which may be repeated.
		w.Header().Set("Retry-After", "5")
	}
	msg := res.Reason
	if msg == "" {
		msg = http.StatusText(res.Status)
	}
	http.Error(w, msg, res.Status)
}

// clientIP returns the address a request is attributed to. For a request that
// came in through the client-facing handler chain this is the address resolved
// once at the edge (withClientSource): the transport peer, or — when the peer is
// a configured trusted proxy — the client that proxy forwarded the request for.
// Forwarding headers are client-controlled and are honored from no other peer.
// For any other request it is the transport peer address.
func clientIP(r *http.Request) string {
	if rec := pullRecordFrom(r.Context()); rec != nil && rec.source.Client != "" {
		return rec.source.Client
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// countingWriter wraps a ResponseWriter to capture the status code and the
// number of body bytes written, for quota accounting and audit logging.
type countingWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	start       time.Time
	wroteHeader bool
}

func (w *countingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}
