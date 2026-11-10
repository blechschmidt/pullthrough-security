package adminauth

import (
	"context"
	"sort"
)

// Identity is an authenticated admin caller: a stable subject, the canonical
// roles it holds, the effective capability set those roles grant, and how it
// authenticated. It is immutable once produced by the Service.
type Identity struct {
	// Subject is the stable identifier of the caller (the IdP "sub"/configured
	// subject claim, or the static token's name).
	Subject string
	// Roles are the canonical RBAC roles the caller holds (a subset of
	// viewer/operator/approver/admin).
	Roles []Role
	// Method records how the caller authenticated, for audit/metrics:
	// "oidc-session", "oidc-bearer", "static", or "static-legacy".
	Method string
	// Issuer is the OIDC issuer that vouched for the caller (empty for static).
	Issuer string
	// Tenant is the tenant (team) the caller belongs to, taken from the configured
	// tenant claim (OIDC) or the static token binding. It is the hard scope of the
	// self-service portal: every portal response is restricted to this tenant, and
	// a caller with no tenant is denied portal access (it cannot be scoped).
	Tenant string

	caps map[Capability]struct{}
}

// newIdentity builds an Identity, computing its effective capability set from
// its roles so authorization checks are O(1).
func newIdentity(subject, method, issuer, tenant string, roles []Role) *Identity {
	roles = canonicalize(roles)
	return &Identity{
		Subject: subject,
		Roles:   roles,
		Method:  method,
		Issuer:  issuer,
		Tenant:  tenant,
		caps:    capabilitiesFor(roles),
	}
}

// Can reports whether the identity holds the given capability.
func (id *Identity) Can(c Capability) bool {
	if id == nil {
		return false
	}
	_, ok := id.caps[c]
	return ok
}

// HasRole reports whether the identity holds the named canonical role.
func (id *Identity) HasRole(r Role) bool {
	if id == nil {
		return false
	}
	for _, held := range id.Roles {
		if held == r {
			return true
		}
	}
	return false
}

// RoleStrings returns the identity's roles as plain strings (for JSON, audit
// detail, and metrics labels).
func (id *Identity) RoleStrings() []string {
	if id == nil {
		return nil
	}
	out := make([]string, len(id.Roles))
	for i, r := range id.Roles {
		out[i] = string(r)
	}
	return out
}

// canonicalize de-duplicates and sorts a role slice for stable output.
func canonicalize(roles []Role) []Role {
	seen := make(map[Role]struct{}, len(roles))
	out := make([]Role, 0, len(roles))
	for _, r := range roles {
		if r == "" {
			continue
		}
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// identityContextKey is the unexported context key type for the Identity.
type identityContextKey struct{}

// WithIdentity returns a copy of ctx carrying the identity.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext returns the identity attached to ctx, if any.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityContextKey{}).(*Identity)
	return id, ok
}
