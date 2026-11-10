package admin

import "net/http"

// GRPCHandler is the read-only gRPC/Connect security API surface (Task 159): a
// Connect-compatible handler (speaking gRPC, gRPC-Web, and HTTP/JSON) that
// projects the same security data model as the GraphQL federated query API
// (Task 67) and the MCP server (Task 79). The *grpcapi.Server satisfies it.
type GRPCHandler interface {
	Enabled() bool
	// Handler returns the service's RPC base path (e.g.
	// "/pullthrough.security.v1.SecurityQueryService/") and the Connect handler
	// serving it.
	Handler() (string, http.Handler)
}

// grpcMountPrefix is the admin-API subpath the gRPC/Connect handler is mounted
// under, so Connect's canonical "/pkg.Service/Method" procedure paths live
// beneath the admin "/api/" subtree and inherit its OIDC/RBAC enforcement. See
// requiredCapability in authz.go, which grants the read capability to this
// subtree (every RPC is strictly read-only).
const grpcMountPrefix = "/api/grpc"

// registerGRPC mounts the gRPC/Connect service on the admin mux, when enabled.
// The Connect handler is registered as a subtree under grpcMountPrefix; the
// prefix is stripped before dispatch so the handler sees the canonical Connect
// procedure path it expects. RBAC authentication/authorization and per-tenant
// scoping are enforced by the surrounding admin middleware (the handler reads
// the authenticated identity from the request context), exactly like the MCP
// and dossier endpoints.
func (s *Server) registerGRPC(mux *http.ServeMux) {
	if s.opts.GRPC == nil || !s.opts.GRPC.Enabled() {
		return
	}
	rpcPath, handler := s.opts.GRPC.Handler()
	if rpcPath == "" || handler == nil {
		return
	}
	mountPrefix := s.prefix + grpcMountPrefix
	// Pattern e.g. "/admin/api/grpc/pullthrough.security.v1.SecurityQueryService/"
	// — a trailing-slash subtree that matches every RPC method beneath it.
	mux.Handle(mountPrefix+rpcPath, http.StripPrefix(mountPrefix, handler))
}
