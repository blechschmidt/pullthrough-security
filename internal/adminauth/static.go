package adminauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// StaticToken is a bearer token bound to a set of admin roles, used in the
// documented offline/static mode where no IdP is reachable.
type StaticToken struct {
	// Name is the subject recorded for the token in audit entries.
	Name string
	// Tenant binds the token to a tenant (team). It scopes the self-service portal
	// to that tenant; required for a tenant-viewer token to be useful.
	Tenant string
	// Roles are the canonical roles granted to the token holder.
	Roles []string
	// Secret is the plaintext token (mutually exclusive with Hash). It must carry
	// at least 16 bytes of entropy.
	Secret string
	// Hash is a precomputed "sha256:<hex>" digest so the plaintext need not touch
	// disk (mutually exclusive with Secret).
	Hash string
}

// staticAuth validates static bearer tokens and maps each to canonical roles. It
// reuses internal/auth's constant-time, SHA-256-indexed token authenticator and
// additionally honors an optional legacy single admin token (granting the admin
// role) for backward compatibility with observability.adminToken.
type staticAuth struct {
	tokens      *auth.TokenAuthenticator
	rolesBySub  map[string][]Role
	tenantBySub map[string]string

	legacyWant  []byte // "Bearer <legacyToken>"; nil when unset
	legacyToken string
}

// newStaticAuth builds a staticAuth from role-bearing tokens and an optional
// legacy admin token. It returns (nil, nil) when neither is configured.
func newStaticAuth(tokens []StaticToken, legacyAdminToken string) (*staticAuth, error) {
	sa := &staticAuth{rolesBySub: make(map[string][]Role), tenantBySub: make(map[string]string)}

	entries := make([]auth.TokenEntry, 0, len(tokens))
	for i, t := range tokens {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			return nil, fmt.Errorf("adminauth: static token %d: name is required", i)
		}
		roles, err := canonicalizeStrings(t.Roles)
		if err != nil {
			return nil, fmt.Errorf("adminauth: static token %q: %w", name, err)
		}
		if len(roles) == 0 {
			return nil, fmt.Errorf("adminauth: static token %q: at least one role is required", name)
		}
		sa.rolesBySub[name] = roles
		sa.tenantBySub[name] = strings.TrimSpace(t.Tenant)
		entries = append(entries, auth.TokenEntry{
			Name:   name,
			Team:   strings.TrimSpace(t.Tenant),
			Roles:  rolesToStrings(roles),
			Secret: t.Secret,
			Hash:   t.Hash,
		})
	}
	if len(entries) > 0 {
		ta, err := auth.NewTokenAuthenticator(entries)
		if err != nil {
			return nil, fmt.Errorf("adminauth: static tokens: %w", err)
		}
		sa.tokens = ta
	}

	if lt := strings.TrimSpace(legacyAdminToken); lt != "" {
		sa.legacyToken = lt
		sa.legacyWant = []byte("Bearer " + lt)
	}

	if sa.tokens == nil && sa.legacyWant == nil {
		return nil, nil
	}
	return sa, nil
}

// authenticate attempts static-token authentication. It returns
// auth.ErrUnauthenticated when no static credential is present so the caller can
// fall through to other mechanisms.
func (s *staticAuth) authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	// Legacy single admin token: constant-time match on the Authorization header,
	// granting the admin role. Checked first so a deployment that only sets the
	// legacy token keeps working unchanged.
	if s.legacyWant != nil {
		got := []byte(r.Header.Get("Authorization"))
		if len(got) == len(s.legacyWant) && subtle.ConstantTimeCompare(got, s.legacyWant) == 1 {
			return newIdentity("admin-token", "static-legacy", "", "", []Role{RoleAdmin}), nil
		}
	}

	if s.tokens != nil {
		p, err := s.tokens.Authenticate(ctx, r)
		if err == nil && p != nil {
			roles := s.rolesBySub[p.Subject]
			if len(roles) == 0 {
				// Roles travel with the principal too; fall back to those.
				roles = parseRoles(p.Roles)
			}
			tenant := s.tenantBySub[p.Subject]
			if tenant == "" {
				// The tenant travels with the principal too (TokenEntry.Team).
				tenant = p.Team
			}
			return newIdentity(p.Subject, "static", "", tenant, roles), nil
		}
	}
	return nil, auth.ErrUnauthenticated
}

// canonicalizeStrings normalizes role names and rejects any that are not one of
// the four canonical roles.
func canonicalizeStrings(in []string) ([]Role, error) {
	out := make([]Role, 0, len(in))
	for _, s := range normalizeRoles(in) {
		r, ok := ParseRole(s)
		if !ok {
			return nil, fmt.Errorf("unknown role %q (want viewer|operator|approver|admin)", s)
		}
		out = append(out, r)
	}
	return out, nil
}

// parseRoles maps a slice of strings to canonical roles, dropping unknowns.
func parseRoles(in []string) []Role {
	out := make([]Role, 0, len(in))
	for _, s := range in {
		if r, ok := ParseRole(s); ok {
			out = append(out, r)
		}
	}
	return out
}

func rolesToStrings(in []Role) []string {
	out := make([]string, len(in))
	for i, r := range in {
		out[i] = string(r)
	}
	return out
}
