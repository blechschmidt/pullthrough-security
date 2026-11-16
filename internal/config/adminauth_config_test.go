package config

import (
	"strings"
	"testing"
)

func TestAdminAuthDisabledSkipsValidation(t *testing.T) {
	// An enabled:false block need not be internally consistent.
	path := writeConfig(t, `
adminAuth:
  enabled: false
  oidc:
    enabled: true
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("disabled adminAuth should not validate, got %v", err)
	}
}

func TestAdminAuthRequiresMechanism(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "at least one of oidc") {
		t.Fatalf("expected mechanism-required error, got %v", err)
	}
}

func TestAdminAuthRejectsUnknownRoleBinding(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  roleBindings:
    grp: superuser
  staticTokens:
    - name: t
      roles: ["admin"]
      token: a-sufficiently-long-admin-token
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown role") {
		t.Fatalf("expected unknown-role error, got %v", err)
	}
}

func TestAdminAuthOIDCRequiresSessionKey(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  oidc:
    enabled: true
    issuer: https://idp.example.com
    clientId: pullthrough
    redirectUrl: https://proxy.example.com/admin/auth/callback
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "sessionKey") {
		t.Fatalf("expected sessionKey error, got %v", err)
	}
}

func TestAdminAuthOIDCRequiresIssuer(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  sessionKey: 0123456789abcdef0123456789abcdef
  oidc:
    enabled: true
    clientId: pullthrough
    redirectUrl: https://proxy.example.com/admin/auth/callback
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected issuer error, got %v", err)
	}
}

func TestAdminAuthStaticTokenRequiresExactlyOneSecret(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  staticTokens:
    - name: t
      roles: ["viewer"]
      token: a-sufficiently-long-viewer-token
      tokenHash: "sha256:deadbeef"
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("expected exactly-one error, got %v", err)
	}
}

func TestAdminAuthStaticTokenRequiresRole(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  staticTokens:
    - name: t
      token: a-sufficiently-long-viewer-token
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "at least one role") {
		t.Fatalf("expected role-required error, got %v", err)
	}
}

func TestAdminAuthValidStaticOnly(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  roleBindings:
    admins: admin
  defaultRole: viewer
  staticTokens:
    - name: break-glass
      roles: ["admin"]
      token: a-sufficiently-long-admin-token
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("valid static-only adminAuth should load, got %v", err)
	}
}

// The self-service portal's role (Task 71) is accepted wherever a role is
// named: docs/self-service-portal.md configures it with a role binding and a
// tenant-bound static token, and a configuration that follows it must load.
func TestAdminAuthAcceptsTheTenantViewerRole(t *testing.T) {
	path := writeConfig(t, `
adminAuth:
  enabled: true
  roleBindings:
    pullthrough-developers: tenant-viewer
  staticTokens:
    - name: acme-portal
      tenant: acme
      roles: ["tenant-viewer"]
      token: a-sufficiently-long-portal-token
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a tenant-viewer binding and token should load, got %v", err)
	}
	if got := cfg.AdminAuth.StaticTokens[0].Roles; len(got) != 1 || got[0] != "tenant-viewer" {
		t.Fatalf("roles %v", got)
	}
}
