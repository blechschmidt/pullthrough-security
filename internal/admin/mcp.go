package admin

import (
	"context"
	"io"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/mcpserver"
)

// MCPInspector is the read-only Model Context Protocol surface (Task 79): an MCP
// (JSON-RPC 2.0) endpoint that exposes the proxy's security knowledge to AI
// agents. The *mcpserver.Server satisfies it.
type MCPInspector interface {
	Enabled() bool
	// ServeMessage dispatches a JSON-RPC message scoped to tenant, returning the
	// marshaled response body and the HTTP status to send.
	ServeMessage(ctx context.Context, tenant string, body []byte) ([]byte, int)
	// Info returns the tool catalog and server metadata for the GET endpoint.
	Info() mcpserver.ServerInfo
}

// maxMCPBody bounds an accepted MCP message so a hostile client cannot stream an
// unbounded body into the decoder.
const maxMCPBody = mcpserver.MaxRequestBody

// mcpTenant resolves the hard tenant scope for an MCP request. When the request
// carries an authenticated identity (the RBAC layer is active), a tenant-bound
// identity is locked to its own tenant — a query parameter cannot widen it. A
// global identity (no tenant bound, e.g. an org-wide admin) or an unauthenticated
// trusted-network call may target a tenant via the "tenant" query parameter; an
// empty result queries across tenants, matching the federated query API.
func mcpTenant(r *http.Request) string {
	if id, ok := adminauth.IdentityFromContext(r.Context()); ok && id != nil && id.Tenant != "" {
		return id.Tenant
	}
	return r.URL.Query().Get("tenant")
}

// handleMCP serves the MCP JSON-RPC endpoint (POST). It is strictly read-only —
// every tool only reads the security data model — and is guarded by the read
// capability (see authz.go). The request is hard-scoped to the caller's tenant.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if s.opts.MCP == nil || !s.opts.MCP.Enabled() {
		s.writeError(w, http.StatusNotFound, "the MCP server is not enabled")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPBody))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}
	resp, status := s.opts.MCP.ServeMessage(r.Context(), mcpTenant(r), body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if len(resp) > 0 {
		_, _ = w.Write(resp)
	}
}

// handleMCPInfo serves the MCP tool catalog and server metadata (GET), so an
// operator or onboarding script can discover the available tools without
// speaking JSON-RPC.
func (s *Server) handleMCPInfo(w http.ResponseWriter, r *http.Request) {
	if s.opts.MCP == nil || !s.opts.MCP.Enabled() {
		s.writeError(w, http.StatusNotFound, "the MCP server is not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.MCP.Info())
}
