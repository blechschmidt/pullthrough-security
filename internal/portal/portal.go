// Package portal implements the tenant self-service read-only security portal
// (Task 71): a non-admin surface, distinct from the privileged admin UI, that
// lets a developer/team see the supply-chain security posture of only their own
// tenant's pulls.
//
// It reuses the adminauth (Task 51) OIDC/static authentication but requires the
// dedicated tenant-viewer capability (adminauth.CapTenantViewer), which carries
// no admin-API permission at all. Every response is HARD-SCOPED to the caller's
// own tenant at the handler layer: the tenant is taken from the authenticated
// identity (never from a request parameter), so a caller can never read another
// tenant's verdicts, findings, quarantine queue, attestations, or SARIF.
//
// Surfaces (all tenant-scoped):
//
//   - recent pull verdicts (admit/block/warn) with the explainable reason from
//     the risk-scoring engine;
//   - why a specific coordinate was flagged and what to do about it (findings
//     remediation + a pointer to the break-glass approval request);
//   - the tenant's quarantined items / open break-glass requests;
//   - attestation (DSSE) and SARIF downloads for the tenant's own artifacts;
//   - onboarding config snippets (reusing the shared onboard generators).
package portal

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/attestbundle"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/metering"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// VerdictSource exposes the recent, explainable risk assessments. The riskscore
// Engine satisfies it. Recent returns assessments across all tenants; the portal
// filters them to the caller's tenant.
type VerdictSource interface {
	Recent(limit int) []riskscore.Assessment
}

// FindingsSource exposes the per-(tenant,coordinate) findings store. The findings
// Store satisfies it; both methods are already tenant-scoped.
type FindingsSource interface {
	Documents(tenant, q string) []findings.Document
	Get(tenant, pkg string) (findings.Document, bool)
}

// ApprovalsSource exposes the quarantine-review / break-glass workflow. The
// approvals Service satisfies it. List returns requests across all tenants; the
// portal filters them to the caller's tenant.
type ApprovalsSource interface {
	Enabled() bool
	List(status string, limit int) []approvals.Request
}

// AttestSource exposes the per-(tenant,coordinate) attestation bundle store. The
// attestbundle Service satisfies it; Get is already tenant-scoped.
type AttestSource interface {
	Get(tenant, pkg string) (*attestbundle.Bundle, bool)
}

// MeteringSource exposes per-tenant usage/chargeback reports (Task 84). The
// metering Meter satisfies it. Report is scoped to whatever tenant the request
// carries; the portal forces that tenant from the caller's identity so a
// tenant-viewer sees only their own usage.
type MeteringSource interface {
	Enabled() bool
	Report(req metering.ReportRequest) metering.UsageReport
}

// Options configures a Server.
type Options struct {
	Logger *slog.Logger
	// PathPrefix is the UI mount path (default "/portal"). The JSON API is mounted
	// at "/api"+PathPrefix (i.e. "/api/portal" by default).
	PathPrefix string
	// Auth identifies the caller and yields the tenant scope. Required: without it
	// the portal cannot enforce tenant isolation, so New returns an error.
	Auth *adminauth.Service

	// ProxyBaseURL is the externally reachable proxy base (e.g.
	// "https://proxy.example.com"), used to render onboarding snippets.
	ProxyBaseURL string
	// Backends is the set of configured upstreams onboarding snippets target.
	Backends []onboard.Backend
	// Version is the build version recorded in generated SARIF.
	Version string

	// Data sources. Any may be nil; the corresponding surface degrades to
	// "not available" rather than failing.
	Verdicts  VerdictSource
	Findings  FindingsSource
	Approvals ApprovalsSource
	Attest    AttestSource
	Metering  MeteringSource
}

// Server serves the tenant self-service portal: its read-only JSON API and a
// small self-contained dependency-free front-end page.
type Server struct {
	opts      Options
	logger    *slog.Logger
	uiPrefix  string
	apiPrefix string
	mux       *http.ServeMux
}

// New constructs a Server. It requires an adminauth Service (the source of the
// tenant scope); without it the portal cannot guarantee tenant isolation.
func New(opts Options) (*Server, error) {
	if opts.Auth == nil {
		return nil, errors.New("portal: an adminauth Service is required to scope responses by tenant")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	ui := strings.TrimRight(opts.PathPrefix, "/")
	if ui == "" {
		ui = "/portal"
	}
	s := &Server{
		opts:      opts,
		logger:    opts.Logger,
		uiPrefix:  ui,
		apiPrefix: "/api" + ui,
	}
	s.mux = s.routes()
	return s, nil
}

// UIPrefix is the path the front-end page is mounted under (e.g. "/portal").
func (s *Server) UIPrefix() string { return s.uiPrefix }

// APIPrefix is the path the JSON API is mounted under (e.g. "/api/portal").
func (s *Server) APIPrefix() string { return s.apiPrefix }

// Handler returns the portal's HTTP handler. It registers absolute paths under
// both the UI prefix and the API prefix, so the gateway mounts it at both.
func (s *Server) Handler() http.Handler { return s.mux }

// routes wires the static page and the scoped JSON API. API routes are guarded
// so every response is tenant-scoped; the page and userinfo are reachable
// unauthenticated so the browser can render a login affordance.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Front-end page (single, self-contained). The bare prefix redirects to the
	// trailing-slash form; everything under it serves the embedded assets.
	mux.HandleFunc("GET "+s.uiPrefix, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.uiPrefix+"/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET "+s.uiPrefix+"/", s.handleStatic)

	// userinfo reports the caller's identity (or that they are unauthenticated)
	// plus whether they hold the tenant-viewer capability — no guard, always 200.
	mux.HandleFunc("GET "+s.apiPrefix+"/userinfo", s.handleUserinfo)

	// Scoped, read-only JSON API. Every handler below is wrapped by guard, which
	// authenticates, requires CapTenantViewer, and binds the caller's tenant into
	// the request context as the immutable scope for the response.
	mux.HandleFunc("GET "+s.apiPrefix+"/summary", s.guard(s.handleSummary))
	mux.HandleFunc("GET "+s.apiPrefix+"/verdicts", s.guard(s.handleVerdicts))
	mux.HandleFunc("GET "+s.apiPrefix+"/coordinate", s.guard(s.handleCoordinate))
	mux.HandleFunc("GET "+s.apiPrefix+"/quarantine", s.guard(s.handleQuarantine))
	mux.HandleFunc("GET "+s.apiPrefix+"/onboarding", s.guard(s.handleOnboarding))
	mux.HandleFunc("GET "+s.apiPrefix+"/findings/sarif", s.guard(s.handleSARIF))
	mux.HandleFunc("GET "+s.apiPrefix+"/attestation", s.guard(s.handleAttestation))
	mux.HandleFunc("GET "+s.apiPrefix+"/usage", s.guard(s.handleUsage))

	return mux
}

// tenantContextKey carries the authorized tenant scope through the request.
type tenantContextKey struct{}

// identityContextKey carries the authenticated identity for handlers that want
// the subject/method for display.
type identityContextKey struct{}

// guard authenticates the caller, requires the tenant-viewer capability, and
// binds the caller's own tenant into the request context as the hard scope.
//
// This is the single chokepoint enforcing tenant isolation: handlers read the
// tenant ONLY from the context value guard sets — never from a query parameter —
// so a caller cannot ask for another tenant's data. A caller with no tenant
// bound to their identity is denied (their requests cannot be scoped).
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.opts.Auth.Authenticate(r.Context(), r)
		if err != nil || id == nil {
			if lp := s.opts.Auth.LoginPath(); lp != "" {
				w.Header().Set("X-Login-URL", lp)
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="portal"`)
			s.writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !id.Can(adminauth.CapTenantViewer) {
			s.writeError(w, http.StatusForbidden, "the tenant-viewer capability is required for the self-service portal")
			return
		}
		tenant := strings.TrimSpace(id.Tenant)
		if tenant == "" {
			s.writeError(w, http.StatusForbidden, "your identity is not bound to a tenant; the portal cannot be scoped")
			return
		}
		ctx := context.WithValue(r.Context(), tenantContextKey{}, tenant)
		ctx = context.WithValue(ctx, identityContextKey{}, id)
		next(w, r.WithContext(ctx))
	}
}

// tenantOf returns the authorized tenant scope bound by guard. It is the only
// sanctioned source of the tenant for a handler.
func tenantOf(r *http.Request) string {
	t, _ := r.Context().Value(tenantContextKey{}).(string)
	return t
}

// identityOf returns the authenticated identity bound by guard, if any.
func identityOf(r *http.Request) *adminauth.Identity {
	id, _ := r.Context().Value(identityContextKey{}).(*adminauth.Identity)
	return id
}

// sameTenant reports whether a record's tenant matches the caller's scope. The
// comparison is case-insensitive to match the case-folding the findings/attest
// stores apply to their tenant keys, so scoping is consistent across sources.
func sameTenant(scope, recordTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(scope), strings.TrimSpace(recordTenant))
}
