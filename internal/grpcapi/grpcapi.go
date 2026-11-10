// Package grpcapi implements a read-only, Connect-compatible gRPC API over the
// proxy's supply-chain security data model. A single Connect handler speaks the
// gRPC, gRPC-Web, and Connect (HTTP/JSON) protocols, so operators can reach the
// same facts from a gRPC client, a browser, or curl.
//
// The surface is the proto-defined SecurityQueryService (see
// proto/pullthrough/security/v1/security.proto): coordinate dossier lookup,
// risk verdicts, aggregated findings, provenance-graph edges, the compliance
// scorecard, and ad-hoc federated corpus queries (unary and server-streaming).
// It exposes exactly the same read-only data model as the Task 67 GraphQL
// federated query API and the Task 79 MCP server, reusing the identical
// read-access layer — the federated query engine plus the per-subsystem detail
// providers — rather than duplicating any query logic.
//
// The handler is mounted on the admin server mux (see internal/admin/grpc.go)
// behind the observability.grpc config flag, so it inherits the admin OIDC/RBAC
// enforcement (Task 51): every RPC requires the read capability and is
// hard-scoped to the caller's tenant. A tenant-bound identity cannot widen its
// scope via a request's tenant field; a global (org-wide) identity may target a
// tenant with it, matching the GraphQL/MCP semantics.
package grpcapi

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/grpcapi/gen/securityv1/securityv1connect"
)

// DefaultMaxDetailItems bounds the number of detail records (findings,
// vulnerabilities, dependents, risk contributions) any single RPC returns, so a
// hostile or careless call cannot make the proxy marshal an unbounded payload.
const DefaultMaxDetailItems = 100

// Config constructs a Server. Backend is required (it powers QueryCorpus and
// every RPC's base projection); the detail providers and bounds are optional.
type Config struct {
	// Backend is the federated query engine the service projects over. Required.
	Backend Backend
	// Version is the proxy build version, reported in responses that carry a
	// version. Defaults to "dev".
	Version string
	// MaxDetailItems bounds per-RPC detail payloads. Defaults to
	// DefaultMaxDetailItems when <= 0.
	MaxDetailItems int

	// Optional detail providers. Each is consulted only when non-nil; an RPC
	// degrades to the query summary when its provider is absent.
	Dossier    DossierProvider
	Findings   FindingsProvider
	Provgraph  ProvenanceProvider
	Attest     AttestProvider
	Vuln       VulnProvider
	Risk       RiskProvider
	Compliance ComplianceProvider
}

// Server implements securityv1connect.SecurityQueryServiceHandler. It is safe
// for concurrent use: it holds no mutable per-request state beyond the metrics
// counters, which are synchronized.
type Server struct {
	backend   Backend
	version   string
	maxDetail int

	dossier    DossierProvider
	findings   FindingsProvider
	provgraph  ProvenanceProvider
	attest     AttestProvider
	vuln       VulnProvider
	risk       RiskProvider
	compliance ComplianceProvider

	metrics metrics
}

var _ securityv1connect.SecurityQueryServiceHandler = (*Server)(nil)

// New constructs a Server from cfg. It returns nil when no backend is supplied,
// so callers can treat a disabled/unwired gRPC surface uniformly via Enabled.
func New(cfg Config) *Server {
	if cfg.Backend == nil {
		return nil
	}
	s := &Server{
		backend:    cfg.Backend,
		version:    strings.TrimSpace(cfg.Version),
		maxDetail:  cfg.MaxDetailItems,
		dossier:    cfg.Dossier,
		findings:   cfg.Findings,
		provgraph:  cfg.Provgraph,
		attest:     cfg.Attest,
		vuln:       cfg.Vuln,
		risk:       cfg.Risk,
		compliance: cfg.Compliance,
	}
	if s.version == "" {
		s.version = "dev"
	}
	if s.maxDetail <= 0 {
		s.maxDetail = DefaultMaxDetailItems
	}
	return s
}

// Enabled reports whether the server is usable.
func (s *Server) Enabled() bool { return s != nil && s.backend != nil }

// Handler builds the Connect HTTP handler for the service and returns the
// service's base RPC path (e.g. "/pullthrough.security.v1.SecurityQueryService/")
// alongside it. The caller mounts handler at a mux prefix so the path becomes a
// subtree beneath the admin API (inheriting its auth/RBAC). The single handler
// speaks the gRPC, gRPC-Web, and Connect (HTTP/JSON) protocols.
//
// It returns ("", nil) when the server is not enabled.
func (s *Server) Handler() (string, http.Handler) {
	if !s.Enabled() {
		return "", nil
	}
	return securityv1connect.NewSecurityQueryServiceHandler(s)
}

// Snapshot returns the server's cumulative per-RPC telemetry.
func (s *Server) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{RPCCalls: map[string]int64{}, RPCErrors: map[string]int64{}}
	}
	return s.metrics.snapshot()
}
