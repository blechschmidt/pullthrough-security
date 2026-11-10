// Package auth implements enterprise access control for the pull-through proxy:
// client authentication (static API tokens and OIDC/JWT bearer tokens),
// per-team namespaces and quotas, and role-based authorization governing which
// upstreams and ecosystems a client may pull from. It is designed so the
// gateway can enforce "deny by default": an unauthenticated or unauthorized
// request never reaches an upstream.
package auth

import (
	"context"
	"sort"
	"strings"
)

// Principal is an authenticated client identity together with the team it
// belongs to and the roles it holds. It is attached to the request context
// after authentication and consulted by the authorizer and quota manager.
//
// A Principal is immutable once produced by an Authenticator.
type Principal struct {
	// Subject is the stable identifier of the caller (token name, or the OIDC
	// "sub"/configured subject claim).
	Subject string
	// Team is the tenant the caller belongs to. It selects the namespace and
	// quota bucket. May be empty for principals not bound to a team (such
	// principals are subject to the default/anonymous quota and only roles that
	// do not require a team).
	Team string
	// Roles are the role names granted to the caller; the authorizer resolves
	// them to ecosystem/upstream permissions.
	Roles []string
	// Method records how the caller authenticated ("token" or "oidc"), for
	// audit purposes.
	Method string
	// Attributes carries non-sensitive claims worth auditing (e.g. OIDC issuer).
	Attributes map[string]string
}

// HasRole reports whether the principal holds the named role.
func (p *Principal) HasRole(name string) bool {
	for _, r := range p.Roles {
		if r == name {
			return true
		}
	}
	return false
}

// Namespace returns the storage/cache namespace for the principal's team. It is
// the team name sanitized to a path-safe token; the empty team maps to the
// shared "_shared" namespace.
func (p *Principal) Namespace() string {
	return TeamNamespace(p.Team)
}

// TeamNamespace maps a team name to a path-safe namespace segment used to
// partition cache keys and storage per tenant. It lowercases and replaces any
// character outside [a-z0-9-_] so a tenant cannot escape its namespace via path
// traversal or collide with another tenant through case folding.
func TeamNamespace(team string) string {
	team = strings.TrimSpace(team)
	if team == "" {
		return "_shared"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(team) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "_shared"
	}
	return out
}

// principalContextKey is the unexported context key type for the Principal.
type principalContextKey struct{}

// WithPrincipal returns a copy of ctx carrying the principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, p)
}

// FromContext returns the principal attached to ctx, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(*Principal)
	return p, ok
}

// dedupeSorted returns a sorted, de-duplicated copy of in (dropping blanks).
func dedupeSorted(in []string) []string {
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
