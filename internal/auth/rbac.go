package auth

import (
	"fmt"
	"strings"
)

// Wildcard matches any ecosystem or upstream in a Role grant.
const Wildcard = "*"

// Role grants pull access to a set of ecosystems and/or named upstreams. A
// request for upstream U (of ecosystem E) is permitted by a role when E is in
// Ecosystems (or Ecosystems contains "*") AND U is in Upstreams (or Upstreams
// contains "*").
//
// Both lists are required to be non-empty for the role to grant anything: an
// empty list matches nothing. This enforces least privilege — a role must
// explicitly opt into "*" to grant broad access, rather than acquiring it by
// omission. Use Ecosystems:["*"], Upstreams:["*"] for an unrestricted role.
type Role struct {
	Name       string
	Ecosystems []string
	Upstreams  []string
}

// permits reports whether the role allows pulling the given upstream/ecosystem.
func (r Role) permits(upstream, ecosystem string) bool {
	return matchAny(r.Ecosystems, ecosystem) && matchAny(r.Upstreams, upstream)
}

// matchAny reports whether value is permitted by list: true if the list
// contains "*" or the (case-insensitive) value. An empty list matches nothing.
func matchAny(list []string, value string) bool {
	for _, item := range list {
		if item == Wildcard {
			return true
		}
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

// Authorizer makes RBAC decisions from a static set of named roles. It is
// immutable after construction and safe for concurrent use.
type Authorizer struct {
	roles map[string]Role
}

// NewAuthorizer builds an Authorizer from the given roles, keyed by name.
// Duplicate or unnamed roles are rejected.
func NewAuthorizer(roles []Role) (*Authorizer, error) {
	m := make(map[string]Role, len(roles))
	for _, role := range roles {
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return nil, fmt.Errorf("auth: role has empty name")
		}
		if _, dup := m[name]; dup {
			return nil, fmt.Errorf("auth: duplicate role %q", name)
		}
		role.Ecosystems = dedupeSorted(role.Ecosystems)
		role.Upstreams = dedupeSorted(role.Upstreams)
		m[name] = role
	}
	return &Authorizer{roles: m}, nil
}

// Authorize reports whether the principal may pull the given upstream (of the
// given ecosystem). Access is granted when ANY role held by the principal
// permits it. A principal with no matching role is denied. The returned reason
// is suitable for audit logging (it names the granting role on allow, or
// explains the denial).
func (a *Authorizer) Authorize(p *Principal, upstream, ecosystem string) (allowed bool, reason string) {
	if p == nil {
		return false, "no authenticated principal"
	}
	if len(p.Roles) == 0 {
		return false, "principal has no roles"
	}
	for _, name := range p.Roles {
		role, ok := a.roles[name]
		if !ok {
			// An unknown role grants nothing; skip it (and surface in reason if
			// nothing else matches).
			continue
		}
		if role.permits(upstream, ecosystem) {
			return true, "granted by role " + name
		}
	}
	return false, fmt.Sprintf("no role of %v grants %s upstream %q", p.Roles, ecosystem, upstream)
}

// KnownRole reports whether a role name is defined.
func (a *Authorizer) KnownRole(name string) bool {
	_, ok := a.roles[name]
	return ok
}

// RoleNames returns the sorted names of all defined roles.
func (a *Authorizer) RoleNames() []string {
	names := make([]string, 0, len(a.roles))
	for n := range a.roles {
		names = append(names, n)
	}
	return dedupeSorted(names)
}
