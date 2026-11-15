package config

import (
	"strings"
	"testing"
)

// adminSSOYAML is a deployment shaped like the hosted instance: the console
// and the personal-links page sign users in at Microsoft Entra ID, through one
// redirect URI registered for the proxy's origin.
const adminSSOYAML = `
server:
  httpAddr: ":8889"
  publicUrl: https://proxy.example.com:8889
cache:
  backend: filesystem
  dir: /var/lib/pullthrough/cache
upstreams:
  npm: {type: npm, url: "https://registry.npmjs.org"}
observability:
  admin: true
adminAuth:
  enabled: true
  sessionKey: 0123456789abcdef0123456789abcdef
  subjectBindings:
    Alice@Contoso.Example: admin
  oidc:
    enabled: true
    issuer: https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0
    discoveryUrl: https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0/.well-known/openid-configuration
    clientId: 55555555-6666-7777-8888-999999999999
    redirectUrl: ADMIN_REDIRECT
    subjectClaim: preferred_username
userLinks:
  enabled: true
  sessionKey: 0123456789abcdef0123456789abcdef0123456789abcdef
  oidc:
    enabled: true
    issuer: https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0
    clientId: 55555555-6666-7777-8888-999999999999
    redirectUrl: LINKS_REDIRECT
`

func loadSSO(t *testing.T, admin, links string, extra string) (*Config, error) {
	t.Helper()
	doc := strings.NewReplacer("ADMIN_REDIRECT", admin, "LINKS_REDIRECT", links).Replace(adminSSOYAML) + extra
	return Load(writeConfig(t, doc))
}

func TestSubjectBindingsAreValidated(t *testing.T) {
	cfg, err := loadSSO(t, "https://proxy.example.com:8889/auth/oidc", "https://proxy.example.com:8889/auth/oidc", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.AdminAuth.SubjectBindings["Alice@Contoso.Example"]; got != "admin" {
		t.Fatalf("subjectBindings = %v", cfg.AdminAuth.SubjectBindings)
	}

	for name, tc := range map[string]struct{ doc, want string }{
		"unknown role": {`
adminAuth:
  enabled: true
  sessionKey: 0123456789abcdef0123456789abcdef
  subjectBindings: {alice@example.com: root}
  oidc: {enabled: true, issuer: "https://idp.example.com", clientId: c, redirectUrl: "https://p.example.com/admin/auth/callback"}
`, "unknown role"},
		"empty subject": {`
adminAuth:
  enabled: true
  sessionKey: 0123456789abcdef0123456789abcdef
  subjectBindings: {"": admin}
  oidc: {enabled: true, issuer: "https://idp.example.com", clientId: c, redirectUrl: "https://p.example.com/admin/auth/callback"}
`, "empty subject"},
		"without oidc": {`
adminAuth:
  enabled: true
  subjectBindings: {alice@example.com: admin}
  staticTokens: [{name: t, roles: [admin], token: a-sufficiently-long-admin-token}]
`, "need adminAuth.oidc.enabled"},
	} {
		if _, err := Load(writeConfig(t, tc.doc)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

// A redirect URL is either the surface's own callback, or a path the gateway
// can serve at its root: one no other mount claims. The console and the page
// may share such a path.
func TestSignInCallbackPaths(t *testing.T) {
	const origin = "https://proxy.example.com:8889"
	ok := []struct{ admin, links string }{
		{origin + "/admin/auth/callback", origin + "/links/callback"}, // both their own
		{origin + "/auth/oidc", origin + "/auth/oidc"},                // one shared path
		{origin + "/auth/oidc", origin + "/links/callback"},
		{origin + "/sso/admin", origin + "/sso/links"},
	}
	for _, tc := range ok {
		if _, err := loadSSO(t, tc.admin, tc.links, ""); err != nil {
			t.Errorf("admin %s, links %s: %v", tc.admin, tc.links, err)
		}
	}

	bad := []struct{ admin, links, want string }{
		{origin + "/v1/npm/cb", origin + "/links/callback", "the package-source mounts"},
		{origin + "/v2/cb", origin + "/links/callback", "the container registry alias"},
		{origin + "/healthz", origin + "/links/callback", "the health endpoint"},
		{origin + "/admin/sso", origin + "/links/callback", "the admin surface"},
		{origin + "/links/callback", origin + "/links/callback", "the personal-links page"},
		{origin + "/u/cb", origin + "/links/callback", "the personal cache links"},
		{origin + "/webhooks/cb", origin + "/links/callback", "push webhook"},
		{origin + "/", origin + "/links/callback", "no callback path"},
		{origin + "/admin/auth/callback", origin + "/admin/auth/callback", "the admin surface"},
		{origin + "/admin/auth/callback", origin + "/links/other", "the personal-links page"},
		{origin + "/admin/auth/callback", origin + "/v1/cb", "the package-source mounts"},
		{origin + "/admin/auth/callback", "/relative/cb", "absolute http(s) URL"},
	}
	for _, tc := range bad {
		if _, err := loadSSO(t, tc.admin, tc.links, ""); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("admin %s, links %s: err = %v, want %q", tc.admin, tc.links, err, tc.want)
		}
	}
}
