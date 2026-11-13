package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

// AdminEventLogger is the narrow write surface the admin server uses to record
// authenticated admin mutations in the tamper-evident audit log. *audit.Logger
// satisfies it.
type AdminEventLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// requiredCapability maps an admin request (method + path relative to the mount
// prefix, e.g. "/api/policyengine/reload") to the capability it requires.
//
// The baseline is "GET reads, everything else operates"; the exceptions encode
// the task's policy: approvers grant break-glass, only admins mutate
// policy/config, and read-only dry-run POSTs need only read.
func requiredCapability(method, relPath string) adminauth.Capability {
	// Runtime profiling (Task 105) is a GET surface, but capturing a CPU profile
	// or execution trace holds the profiler and consumes runtime resources for
	// its requested duration, and the endpoints expose detailed internals. Treat
	// it as an operational action rather than a plain read, so a bare viewer
	// cannot trigger it.
	if strings.HasPrefix(relPath, "/api/debug/pprof") {
		return adminauth.CapOperate
	}

	// The gRPC/Connect security API (Task 159) is a POST-only subtree (Connect
	// dispatches every RPC, including the read-only ones, as a POST to
	// "/api/grpc/<pkg.Service>/<Method>"). Every RPC it exposes is strictly
	// read-only — it projects the same security data model as the GraphQL and MCP
	// surfaces — so the whole subtree requires only the read capability.
	if strings.HasPrefix(relPath, "/api/grpc/") {
		return adminauth.CapRead
	}

	switch method {
	case http.MethodGet, http.MethodHead:
		return adminauth.CapRead
	}

	switch relPath {
	// Break-glass approvals are the approver's remit.
	case "/api/approvals/approve", "/api/approvals/deny":
		return adminauth.CapApprove

	// Policy- and config-mutating endpoints are admin-only. Freezing or rolling
	// back the whole organization to a snapshot changes what every client may pull,
	// so it is the administrator's remit.
	case "/api/policyengine/reload", "/api/ratelimit/policy",
		"/api/snapshots/freeze", "/api/snapshots/unfreeze", "/api/snapshots/rollback",
		// Engaging or clearing the emergency lockdown (Task 74) tightens or relaxes
		// the proxy's posture org-wide; it is the administrator's remit.
		"/api/lockdown/engage", "/api/lockdown/clear",
		// Mutating the SSRF / egress allowlist (Task 89) changes which outbound
		// destinations are reachable — a security-policy change, admin-only.
		"/api/egress/allowlist",
		// Applying a curated compliance preset (Task 88) rewrites the on-disk
		// configuration across many gates; it is the administrator's remit.
		"/api/presets/apply",
		// Forcing a GitOps sync or rolling back to the last-known-good revision
		// (Task 93) rewrites the on-disk configuration from the source of truth; it
		// is the administrator's remit.
		"/api/gitops/sync", "/api/gitops/rollback",
		// Issuing a personal cache link (Task 177) mints a credential for an
		// identity — and with roles — of the caller's choosing. (Revoking one only
		// takes access away, and is an operational action like any other.)
		"/api/userlinks/issue",
		// Registering a repository (Task 180) makes the proxy fetch from the
		// URL given, with the credentials it names, as the tenant it names;
		// removing one ends its tracking. Both are the administrator's remit.
		// (Syncing a repository or pinning a release is operational.)
		"/api/repos", "/api/repos/remove":
		return adminauth.CapAdminister

	// Managing one's own passkeys and running the step-up ceremonies (Task 161)
	// are self-service: any authenticated identity may enroll, assert, and manage
	// its own credentials regardless of operational role. These POSTs must also
	// never themselves require a step-up token (they are how a token is obtained),
	// so they are deliberately not among the protected actions.
	case "/api/webauthn/register/begin", "/api/webauthn/register/finish",
		"/api/webauthn/assert/begin", "/api/webauthn/assert/finish",
		"/api/webauthn/credential":
		return adminauth.CapRead

	// Dry-run evaluations and the read-only federated query (a POST only because
	// the query is a structured document) mutate nothing; a viewer may run them.
	case "/api/policyengine/test", "/api/simreplay/simulate", "/api/query",
		// The MCP endpoint (Task 79) is a POST only because the JSON-RPC message is
		// a structured document; every tool it exposes is strictly read-only.
		"/api/mcp",
		// Configuration preflight (Task 85) is a POST only because the candidate
		// config is a structured document; it validates and mutates nothing.
		"/api/config/validate",
		// The egress dry-run (Task 89) is a POST only because the candidate URL is a
		// structured document; it evaluates the policy and mutates nothing.
		"/api/egress/test":
		return adminauth.CapRead
	}

	// All remaining non-GET endpoints are operational mutations.
	return adminauth.CapOperate
}

// rbac wraps next with authentication + per-endpoint authorization when an
// adminauth.Service is configured. Static dashboard assets and the OIDC auth
// endpoints pass through untouched (assets carry no secrets; the auth endpoints
// guard themselves). Every authenticated mutation is recorded in the audit log
// so it is attributable to a real identity.
func (s *Server) rbac(svc *adminauth.Service, next http.Handler) http.Handler {
	apiPrefix := s.prefix + "/api/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, apiPrefix) {
			next.ServeHTTP(w, r)
			return
		}

		id, err := svc.Authenticate(r.Context(), r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pullthrough-admin"`)
			if lp := svc.LoginPath(); lp != "" {
				// Lets the SPA know where to send an unauthenticated browser.
				w.Header().Set("X-Login-URL", lp)
			}
			s.writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		relPath := strings.TrimPrefix(r.URL.Path, s.prefix)
		cap := requiredCapability(r.Method, relPath)
		if !svc.Authorize(id, cap) {
			s.auditAdmin(r, id, cap, audit.DecisionDeny)
			s.writeError(w, http.StatusForbidden,
				"insufficient permissions: this endpoint requires the '"+cap.String()+"' capability")
			return
		}

		// WebAuthn/passkey step-up (Task 161): the most sensitive mutations require
		// a fresh, short-TTL assertion token in addition to RBAC. This runs before
		// the allow-audit so a request blocked for a missing/invalid token is never
		// recorded as an admitted admin mutation. The webauthn subsystem records its
		// own EventStepUpAuth allow/deny entry.
		if s.opts.WebAuthn != nil && s.opts.WebAuthn.StepUpRequired(relPath) {
			token := r.Header.Get(StepUpTokenHeader)
			if err := s.opts.WebAuthn.VerifyStepUp(r.Context(), id.Subject, relPath, token, clientIP(r)); err != nil {
				w.Header().Set(StepUpRequiredHeader, "webauthn")
				s.writeError(w, http.StatusUnauthorized,
					"this action requires a fresh passkey step-up assertion: "+err.Error())
				return
			}
		}

		// Attribute every mutation to the authenticated identity.
		if cap != adminauth.CapRead {
			s.auditAdmin(r, id, cap, audit.DecisionAllow)
		}

		next.ServeHTTP(w, r.WithContext(adminauth.WithIdentity(r.Context(), id)))
	})
}

// auditAdmin records an admin authorization decision in the audit log. It is a
// no-op when no audit logger is wired.
func (s *Server) auditAdmin(r *http.Request, id *adminauth.Identity, cap adminauth.Capability, decision audit.Decision) {
	if s.opts.AuditLog == nil {
		return
	}
	reason := "admin:" + cap.String()
	if decision == audit.DecisionDeny {
		reason = "admin:denied:" + cap.String()
	}
	ev := audit.Event{
		Type:       audit.EventAdmin,
		Method:     r.Method,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     reason,
		Subject:    id.Subject,
		Detail: map[string]any{
			"roles":      id.RoleStrings(),
			"capability": cap.String(),
			"authMethod": id.Method,
		},
	}
	if id.Issuer != "" {
		ev.Detail["issuer"] = id.Issuer
	}
	if err := s.opts.AuditLog.Log(r.Context(), ev); err != nil {
		s.logger.Error("admin: audit log write failed", "error", err, "resource", r.URL.Path)
	}
}

// clientIP extracts a best-effort client address for audit entries, honoring a
// single X-Forwarded-For hop when present.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	return r.RemoteAddr
}
