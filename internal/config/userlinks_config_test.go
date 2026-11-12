package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadUserLinksYAML(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const userLinksBaseYAML = `
server:
  httpAddr: ":8080"
  publicUrl: https://proxy.example.com
cache:
  backend: filesystem
  dir: /var/lib/pullthrough/cache
upstreams:
  npm: {type: npm, url: "https://registry.npmjs.org"}
`

const userLinksOIDCYAML = `
  sessionKey: 0123456789abcdef0123456789abcdef
  oidc:
    enabled: true
    issuer: https://idp.example.com/realms/corp
    clientId: pullthrough-cache
`

// Personal links are off until an operator turns them on; the defaults are what
// then applies.
func TestUserLinksDefaults(t *testing.T) {
	def := Default().UserLinks
	if def.Enabled || def.OIDC.Enabled {
		t.Fatal("personal links must be off by default")
	}
	if def.PathPrefix != "/u" || def.UIPath != "/links" || def.LinkTTL != 90*24*time.Hour ||
		def.SessionTTL != time.Hour || def.SyncInterval != 15*time.Second || def.MaxLinksPerUser != 0 {
		t.Fatalf("defaults = %+v", def)
	}
	cfg, err := loadUserLinksYAML(t, userLinksBaseYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserLinks.Enabled || cfg.UserLinks.LinkTTL != def.LinkTTL {
		t.Fatalf("a config without a userLinks section = %+v", cfg.UserLinks)
	}
}

func TestUserLinksYAML(t *testing.T) {
	t.Setenv("LINKS_CLIENT_SECRET", "from-the-environment")
	cfg, err := loadUserLinksYAML(t, userLinksBaseYAML+`
auth:
  enabled: true # personal links are the only way to authenticate here
  roles:
    - {name: reader, ecosystems: ["*"], upstreams: ["*"]}
    - {name: builder, ecosystems: ["npm"], upstreams: ["*"]}
userLinks:
  enabled: true
  pathPrefix: /me
  uiPath: /account/links
  linkTtl: 0s
  maxLinksPerUser: -1
  sessionTtl: 30m
  sessionKey: 0123456789abcdef0123456789abcdef
  syncInterval: 5s
  store:
    backend: s3
    s3: {bucket: links, prefix: registry/, usePathStyle: true}
  oidc:
    enabled: true
    issuer: https://idp.example.com/realms/corp
    clientId: pullthrough-cache
    clientSecret: ${LINKS_CLIENT_SECRET}
    redirectUrl: https://proxy.example.com/account/links/callback
    scopes: [openid, email, groups]
    subjectClaim: preferred_username
    groupsClaim: roles
    allowUnverifiedEmail: true
  defaultTeam: everyone
  defaultRoles: [reader]
  roleMap: {engineering: builder}
  allowedGroups: [cache-users]
  allowedEmailDomains: [example.com, "@example.org"]
`)
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.UserLinks
	if !u.Enabled || u.PathPrefix != "/me" || u.UIPath != "/account/links" || u.LinkTTL != 0 || u.MaxLinksPerUser != -1 ||
		u.SessionTTL != 30*time.Minute || u.SyncInterval != 5*time.Second {
		t.Fatalf("parsed = %+v", u)
	}
	if u.Store.Backend != "s3" || u.Store.S3.Bucket != "links" || u.Store.S3.Prefix != "registry/" || !u.Store.S3.UsePathStyle {
		t.Fatalf("store = %+v", u.Store)
	}
	if !u.OIDC.Enabled || u.OIDC.ClientSecret != "from-the-environment" || u.OIDC.SubjectClaim != "preferred_username" ||
		u.OIDC.GroupsClaim != "roles" || !u.OIDC.AllowUnverifiedEmail || len(u.OIDC.Scopes) != 3 {
		t.Fatalf("oidc = %+v", u.OIDC)
	}
	if u.DefaultTeam != "everyone" || len(u.DefaultRoles) != 1 || u.RoleMap["engineering"] != "builder" ||
		len(u.AllowedGroups) != 1 || len(u.AllowedEmailDomains) != 2 {
		t.Fatalf("identity mapping = %+v", u)
	}
}

func TestUserLinksValidation(t *testing.T) {
	enabled := "\nuserLinks:\n  enabled: true\n"
	cases := []struct {
		name string
		doc  string
		// want is a fragment of the expected error; empty means the document is
		// valid.
		want string
	}{
		{"minimal, with sign-in", userLinksBaseYAML + enabled + userLinksOIDCYAML, ""},
		{"without an identity provider (links issued by an administrator)", userLinksBaseYAML + enabled, ""},
		{"no public URL", strings.Replace(userLinksBaseYAML, "  publicUrl: https://proxy.example.com\n", "", 1) + enabled, "server.publicUrl"},
		{"a public URL without a scheme", strings.Replace(userLinksBaseYAML, "https://proxy.example.com", "proxy.example.com", 1) + enabled, "server.publicUrl"},

		{"a prefix of two segments", userLinksBaseYAML + enabled + "  pathPrefix: /a/b\n", "userLinks.pathPrefix"},
		{"an upper-case prefix", userLinksBaseYAML + enabled + "  pathPrefix: /Users\n", "userLinks.pathPrefix"},
		{"the prefix shadows the mounts", userLinksBaseYAML + enabled + "  pathPrefix: /v1\n", "collides with the package-source mounts"},
		{"the prefix shadows the registry alias", userLinksBaseYAML + enabled + "  pathPrefix: v2\n", "collides with the container registry alias"},
		{"the prefix shadows the health endpoint", userLinksBaseYAML + enabled + "  pathPrefix: /healthz\n", "collides"},
		{"the prefix shadows the admin surface", userLinksBaseYAML + "observability: {admin: true}\n" + enabled + "  pathPrefix: /admin\n", "collides with the admin surface"},
		{"the prefix shadows a moved admin surface", userLinksBaseYAML + "observability: {admin: true, adminPathPrefix: /ops/console}\n" + enabled + "  pathPrefix: /ops\n", "collides with the admin surface"},
		{"the page shadows the metrics", userLinksBaseYAML + "observability: {metrics: true}\n" + enabled + "  uiPath: /metrics\n", "collides with the metrics endpoint"},
		{"the page shadows the mounts", userLinksBaseYAML + enabled + "  uiPath: /v1/links\n", "collides"},
		{"a relative page path", userLinksBaseYAML + enabled + "  uiPath: links\n", "userLinks.uiPath"},
		{"page and prefix share a segment", userLinksBaseYAML + enabled + "  pathPrefix: /me\n  uiPath: /me/links\n", "must not share"},
		{"the page shadows the admin surface, which is on by default", userLinksBaseYAML + enabled + "  uiPath: /admin\n", "collides with the admin surface"},
		{"the admin prefix is free when the admin surface is off", userLinksBaseYAML + "observability: {admin: false}\n" + enabled + "  uiPath: /admin\n", ""},

		{"a negative lifetime", userLinksBaseYAML + enabled + "  linkTtl: -1h\n", "userLinks.linkTtl"},
		{"links that do not expire", userLinksBaseYAML + enabled + "  linkTtl: 0s\n", ""},
		{"an impossible link limit", userLinksBaseYAML + enabled + "  maxLinksPerUser: -2\n", "userLinks.maxLinksPerUser"},
		{"a refresh faster than a second", userLinksBaseYAML + enabled + "  syncInterval: 100ms\n", "userLinks.syncInterval"},

		{"an unknown store", userLinksBaseYAML + enabled + "  store: {backend: redis}\n", "userLinks.store.backend"},
		{"a directory store without a directory", strings.Replace(userLinksBaseYAML, "  backend: filesystem\n  dir: /var/lib/pullthrough/cache\n", "  backend: memory\n  dir: \"\"\n", 1) +
			enabled + "  store: {backend: filesystem}\n", "userLinks.store.dir"},
		{"a directory store with its own directory", strings.Replace(userLinksBaseYAML, "  backend: filesystem\n  dir: /var/lib/pullthrough/cache\n", "  backend: memory\n  dir: \"\"\n", 1) +
			enabled + "  store: {backend: filesystem, dir: /var/lib/pullthrough/links}\n", ""},
		{"an s3 store without a bucket", userLinksBaseYAML + enabled + "  store: {backend: s3}\n", "userLinks.store.s3.bucket"},
		{"a memory store", userLinksBaseYAML + enabled + "  store: {backend: memory}\n", ""},

		{"sign-in without an issuer", userLinksBaseYAML + enabled + "  sessionKey: 0123456789abcdef0123456789abcdef\n  oidc: {enabled: true, clientId: c}\n", "userLinks.oidc.issuer"},
		{"sign-in without a client", userLinksBaseYAML + enabled + "  sessionKey: 0123456789abcdef0123456789abcdef\n  oidc: {enabled: true, issuer: \"https://idp\"}\n", "userLinks.oidc.clientId"},
		{"sign-in without a session key", userLinksBaseYAML + enabled + "  oidc: {enabled: true, issuer: \"https://idp\", clientId: c}\n", "userLinks.sessionKey"},
		{"sign-in with a short session key", userLinksBaseYAML + enabled + "  sessionKey: too-short\n  oidc: {enabled: true, issuer: \"https://idp\", clientId: c}\n", "userLinks.sessionKey"},
		{"a relative redirect URL", userLinksBaseYAML + enabled + userLinksOIDCYAML + "    redirectUrl: /links/callback\n", "userLinks.oidc.redirectUrl"},

		{"a default role that does not exist", userLinksBaseYAML + "auth: {enabled: true, roles: [{name: reader, ecosystems: [\"*\"], upstreams: [\"*\"]}]}\n" +
			enabled + "  defaultRoles: [raeder]\n", "userLinks.defaultRoles[0]"},
		{"a mapped role that does not exist", userLinksBaseYAML + "auth: {enabled: true, roles: [{name: reader, ecosystems: [\"*\"], upstreams: [\"*\"]}]}\n" +
			enabled + "  roleMap: {eng: builder}\n", "userLinks.roleMap"},
		{"roles are not checked while access control is off", userLinksBaseYAML + enabled + "  defaultRoles: [anything]\n", ""},
		{"a domain that is an address", userLinksBaseYAML + enabled + "  allowedEmailDomains: [\"alice@example.com\"]\n", "userLinks.allowedEmailDomains[0]"},

		{"everything is ignored while the feature is off", userLinksBaseYAML + "\nuserLinks:\n  pathPrefix: /v1\n  linkTtl: -1h\n  store: {backend: redis}\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadUserLinksYAML(t, tc.doc)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("a valid configuration was refused: %v", err)
			case tc.want != "" && err == nil:
				t.Fatalf("accepted; want an error mentioning %q", tc.want)
			case tc.want != "" && !strings.Contains(err.Error(), tc.want):
				t.Fatalf("error = %v; want it to mention %q", err, tc.want)
			}
		})
	}
}

// The store follows the cache unless it is told otherwise.
func TestUserLinksStoreBackend(t *testing.T) {
	for _, tc := range []struct{ configured, cache, want string }{
		{"", "filesystem", "filesystem"},
		{"", "", "filesystem"},
		{"", "s3", "s3"},
		{"", "memory", "memory"},
		{"S3 ", "filesystem", "s3"},
		{"memory", "s3", "memory"},
		{"filesystem", "s3", "filesystem"},
	} {
		u := UserLinksConfig{Store: UserLinksStoreConfig{Backend: tc.configured}}
		if got := u.StoreBackend(tc.cache); got != tc.want {
			t.Errorf("StoreBackend(configured %q, cache %q) = %q, want %q", tc.configured, tc.cache, got, tc.want)
		}
	}
}

// The preflight check says what a schema cannot: configurations that load but
// do not do what whoever wrote them expects.
func TestUserLinksPreflightWarnings(t *testing.T) {
	warningsOf := func(t *testing.T, doc string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		report, err := CheckFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !report.OK {
			t.Fatalf("the configuration does not load: %+v", report.Issues)
		}
		var b strings.Builder
		for _, is := range report.Issues {
			if is.Severity == SeverityWarning {
				b.WriteString(is.Path + ": " + is.Message + "\n")
			}
		}
		return b.String()
	}
	enabled := "\nuserLinks:\n  enabled: true\n"

	clean := warningsOf(t, userLinksBaseYAML+enabled+userLinksOIDCYAML)
	if strings.Contains(clean, "userLinks") {
		t.Errorf("a sound configuration is warned about:\n%s", clean)
	}
	for name, tc := range map[string]struct{ doc, want string }{
		"no identity provider": {userLinksBaseYAML + enabled, "userLinks.oidc.enabled"},
		"users without a role": {userLinksBaseYAML + "auth: {enabled: true, roles: [{name: reader, ecosystems: [\"*\"], upstreams: [\"*\"]}], tokens: [{name: ci, roles: [reader], token: \"0123456789abcdef0123\"}]}\n" +
			enabled + userLinksOIDCYAML, "userLinks.defaultRoles"},
		"plain HTTP":                  {strings.Replace(userLinksBaseYAML, "https://", "http://", 1) + enabled + userLinksOIDCYAML, "server.publicUrl"},
		"a registry in memory":        {userLinksBaseYAML + enabled + userLinksOIDCYAML + "  store: {backend: memory}\n", "userLinks.store.backend"},
		"links that never expire":     {userLinksBaseYAML + enabled + userLinksOIDCYAML + "  linkTtl: 0s\n", "userLinks.linkTtl"},
		"replicas, each with its own": {userLinksBaseYAML + "coordination: {enabled: true, mode: file, dir: /var/lib/pullthrough/leases}\n" + enabled + userLinksOIDCYAML, "userLinks.store:"},
	} {
		if got := warningsOf(t, tc.doc); !strings.Contains(got, tc.want) {
			t.Errorf("%s: no warning about %s:\n%s", name, tc.want, got)
		}
	}

	// Plain HTTP is only a warning where a link would cross a network: a proxy
	// reached on loopback — a test set-up, a sidecar — is not on one.
	for _, host := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		doc := strings.Replace(userLinksBaseYAML, "https://proxy.example.com", host, 1) + enabled + userLinksOIDCYAML
		if got := warningsOf(t, doc); strings.Contains(got, "server.publicUrl") {
			t.Errorf("a plain-HTTP public URL on loopback (%s) is warned about:\n%s", host, got)
		}
	}
}

// The feature's secrets are secrets everywhere secrets are handled: they are
// not part of the configuration fingerprint, and a change of one is not drift.
func TestUserLinksSecretsAreRedacted(t *testing.T) {
	load := func(key, secret string) *Config {
		t.Helper()
		cfg, err := loadUserLinksYAML(t, userLinksBaseYAML+"\nuserLinks:\n  enabled: true\n  sessionKey: "+key+
			"\n  oidc: {enabled: true, issuer: \"https://idp\", clientId: c, clientSecret: "+secret+"}\n"+
			"  store: {backend: s3, s3: {bucket: b, accessKeyId: AKIA"+secret+", secretAccessKey: "+key+"}}\n")
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	a := load("0123456789abcdef0123456789abcdef", "first-secret")
	b := load("fedcba9876543210fedcba9876543210", "second-secret")
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("rotating the session key or the client secret changes the configuration fingerprint")
	}
	red := redactedClone(a)
	for name, value := range map[string]string{
		"sessionKey":      red.UserLinks.SessionKey,
		"clientSecret":    red.UserLinks.OIDC.ClientSecret,
		"accessKeyId":     red.UserLinks.Store.S3.AccessKeyID,
		"secretAccessKey": red.UserLinks.Store.S3.SecretAccessKey,
	} {
		if value != redactionMarker {
			t.Errorf("userLinks %s is not redacted: %q", name, value)
		}
	}
}

// A session key given as a secret reference is checked once it is resolved
// (when the service is built), not by the length of the reference.
func TestUserLinksSessionKeyAsASecretReference(t *testing.T) {
	doc := userLinksBaseYAML + "userLinks:\n  enabled: true\n  sessionKey: env://PT_USERLINKS_SESSION_KEY\n" +
		"  oidc:\n    enabled: true\n    issuer: https://idp.example.com/realms/corp\n    clientId: pullthrough-cache\n"
	if _, err := loadUserLinksYAML(t, doc); err != nil {
		t.Fatalf("a session key given as a secret reference: %v", err)
	}
	short := userLinksBaseYAML + "userLinks:\n  enabled: true\n  sessionKey: too-short\n" +
		"  oidc:\n    enabled: true\n    issuer: https://idp.example.com/realms/corp\n    clientId: pullthrough-cache\n"
	if _, err := loadUserLinksYAML(t, short); err == nil || !strings.Contains(err.Error(), "userLinks.sessionKey") {
		t.Fatalf("a short literal session key: %v", err)
	}
}
