package grpcapi

import (
	"context"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
)

// tenantScope resolves the hard tenant scope for an RPC. It mirrors the rule the
// GraphQL query API and the MCP server enforce:
//
//   - When the request carries an authenticated identity bound to a tenant (the
//     RBAC layer injected it into the context), that tenant wins — a value in the
//     request message cannot widen it. This is the hard per-tenant isolation.
//   - A global identity (no tenant bound, e.g. an org-wide admin) or an
//     unauthenticated trusted-network call may target a tenant via the request's
//     tenant field; an empty result queries across tenants.
func tenantScope(ctx context.Context, requested string) string {
	if id, ok := adminauth.IdentityFromContext(ctx); ok && id != nil && strings.TrimSpace(id.Tenant) != "" {
		return id.Tenant
	}
	return strings.TrimSpace(requested)
}
