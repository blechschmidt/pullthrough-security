// Package adminauth implements enterprise single-sign-on (OIDC/OAuth2) and
// fine-grained role-based access control (RBAC) for the proxy's admin API and
// dashboard.
//
// It supports three, composable, authentication mechanisms:
//
//   - OIDC/OAuth2 authorization-code login with PKCE for the admin *UI*. A
//     browser is redirected to the configured identity provider, returns with an
//     authorization code, and the proxy exchanges it for an ID token, validates
//     it, and mints a short-lived signed session cookie.
//   - OIDC/JWT bearer-token validation for the admin *API* (CI, scripts), reusing
//     the JWKS-backed verifier from internal/auth (signature + exp/nbf/iss/aud,
//     RS*/ES* only, JWKS caching/rotation, clock-skew leeway).
//   - Static bearer tokens mapped to roles, for air-gapped / disconnected
//     operation where no IdP is reachable.
//
// Identities carry a set of roles drawn from a small, fixed vocabulary
// (viewer, operator, approver, admin). Each role grants a set of capabilities;
// the admin server maps every endpoint to the capability it requires and denies
// any request whose identity lacks it ("deny by default").
package adminauth

import (
	"sort"
	"strings"
)

// Role is one of the fixed admin RBAC roles. The vocabulary is deliberately
// small so it maps cleanly onto IdP groups/claims without bespoke policy.
type Role string

const (
	// RoleViewer may read every admin surface but mutate nothing.
	RoleViewer Role = "viewer"
	// RoleOperator may perform operational mutations (release a quarantine,
	// trigger a re-scan/backup/GC, drain a mirror) in addition to reading.
	RoleOperator Role = "operator"
	// RoleApprover may grant/deny break-glass approvals in addition to reading.
	RoleApprover Role = "approver"
	// RoleAdmin holds every capability, including mutating policy and config.
	RoleAdmin Role = "admin"
	// RoleTenantViewer grants read-only access to the tenant self-service portal
	// only — it carries no admin-API capability at all. Every portal response is
	// hard-scoped to the caller's own tenant, so this role is safe to hand to
	// developers/teams without exposing the privileged admin surface.
	RoleTenantViewer Role = "tenant-viewer"
)

// Capability is a single permission an endpoint can require.
type Capability uint8

const (
	// CapRead permits reading admin status/inventory endpoints and read-only
	// dry-run evaluations (which mutate nothing).
	CapRead Capability = iota
	// CapOperate permits operational mutations that do not change policy/config.
	CapOperate
	// CapApprove permits granting/denying break-glass approvals.
	CapApprove
	// CapAdminister permits mutating policy and runtime configuration.
	CapAdminister
	// CapTenantViewer permits reading the tenant self-service portal, whose every
	// response is hard-scoped to the caller's own tenant. It is deliberately
	// disjoint from the admin capabilities above: a tenant-viewer can never reach
	// the privileged admin API, and an admin/operator does not implicitly gain
	// portal access (the two surfaces are separate by design).
	CapTenantViewer
)

// String renders a capability for logs, audit, and metrics labels.
func (c Capability) String() string {
	switch c {
	case CapRead:
		return "read"
	case CapOperate:
		return "operate"
	case CapApprove:
		return "approve"
	case CapAdminister:
		return "administer"
	case CapTenantViewer:
		return "tenant-viewer"
	default:
		return "unknown"
	}
}

// roleCapabilities is the authoritative role→capability grant table. An
// identity's effective capabilities are the union over the roles it holds.
var roleCapabilities = map[Role][]Capability{
	RoleViewer:       {CapRead},
	RoleOperator:     {CapRead, CapOperate},
	RoleApprover:     {CapRead, CapApprove},
	RoleAdmin:        {CapRead, CapOperate, CapApprove, CapAdminister},
	RoleTenantViewer: {CapTenantViewer},
}

// canonicalRoles is the set of recognized roles, used to validate config and
// reject role bindings that point at an unknown role.
var canonicalRoles = map[Role]struct{}{
	RoleViewer:       {},
	RoleOperator:     {},
	RoleApprover:     {},
	RoleAdmin:        {},
	RoleTenantViewer: {},
}

// IsCanonicalRole reports whether name is one of the four recognized roles.
func IsCanonicalRole(name string) bool {
	_, ok := canonicalRoles[Role(strings.TrimSpace(strings.ToLower(name)))]
	return ok
}

// ParseRole normalizes name and returns the matching canonical role. The bool
// is false for unrecognized roles, which callers must drop rather than trust.
func ParseRole(name string) (Role, bool) {
	r := Role(strings.TrimSpace(strings.ToLower(name)))
	if _, ok := canonicalRoles[r]; ok {
		return r, true
	}
	return "", false
}

// capabilitiesFor returns the de-duplicated capability set granted by the given
// roles.
func capabilitiesFor(roles []Role) map[Capability]struct{} {
	caps := make(map[Capability]struct{}, 4)
	for _, r := range roles {
		for _, c := range roleCapabilities[r] {
			caps[c] = struct{}{}
		}
	}
	return caps
}

// normalizeRoles de-duplicates, sorts, and drops blank role names. Non-canonical
// names are preserved here (the caller maps/filters them) so this is a pure
// string cleanup.
func normalizeRoles(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
