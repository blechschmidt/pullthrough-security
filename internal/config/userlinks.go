package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// UserLinksConfig configures personal cache links (Task 177): cache users sign
// in through an OIDC identity provider and are handed their own address for
// every package source — the ordinary one under a path prefix that names them,
//
//	https://proxy.example.com/u/ptl1…/v1/npm/
//
// so that the download log (Task 176) attributes a download to a person and not
// only to a client address. See docs/user-links.md.
//
// It composes with client authentication (auth) rather than replacing it. With
// authentication off, a personal link adds an identity to requests that carry
// one and everything else stays anonymous. With authentication on, a link is
// one more way to authenticate: its user holds RBAC roles (defaultRoles,
// roleMap) and is subject to their team's quotas like any other caller.
type UserLinksConfig struct {
	// Enabled turns the feature on: the personal path prefix is served, a link's
	// token is accepted as a credential, and — with oidc — the self-service page
	// is mounted. Requires server.publicUrl.
	Enabled bool `yaml:"enabled"`
	// PathPrefix is the first path segment of a personal URL (default "/u"): one
	// segment of lower-case letters, digits, "-" and "_".
	PathPrefix string `yaml:"pathPrefix"`
	// UIPath is where the self-service page — sign in, create and revoke links —
	// is served (default "/links").
	UIPath string `yaml:"uiPath"`
	// LinkTTL is how long a link works (default 2160h, ninety days). "0s" makes
	// links that do not expire; they then end only by being revoked.
	LinkTTL time.Duration `yaml:"linkTtl"`
	// MaxLinksPerUser bounds how many working links one user may hold — one per
	// machine is the idea. Zero uses the built-in default (10); -1 removes the
	// bound.
	MaxLinksPerUser int `yaml:"maxLinksPerUser"`
	// SessionTTL is how long a sign-in on the self-service page lasts (default
	// 1h). It has no bearing on how long a link works.
	SessionTTL time.Duration `yaml:"sessionTtl"`
	// SessionKey signs the sign-in cookies (HMAC-SHA256). Required with oidc; at
	// least 32 bytes. Every replica must be given the same key. Supports ${ENV},
	// enc:v1: and secret references.
	SessionKey string `yaml:"sessionKey"`
	// InsecureCookies drops the Secure attribute from the sign-in cookies, for a
	// proxy reached over plain HTTP in a test set-up.
	InsecureCookies bool `yaml:"insecureCookies"`
	// SyncInterval is how often a replica refreshes the link registry from its
	// store (default 15s) — and so how long a revocation performed on one
	// replica can take to reach another.
	SyncInterval time.Duration `yaml:"syncInterval"`
	// Store is where the link registry is kept.
	Store UserLinksStoreConfig `yaml:"store"`
	// OIDC is the identity provider cache users sign in at.
	OIDC UserLinksOIDCConfig `yaml:"oidc"`

	// DefaultTeam is the team of a signed-in user whose ID token names none.
	DefaultTeam string `yaml:"defaultTeam"`
	// DefaultRoles are RBAC roles (auth.roles) every signed-in user holds. With
	// auth.enabled a user needs a role to pull anything: set this, or map groups
	// with roleMap.
	DefaultRoles []string `yaml:"defaultRoles"`
	// RoleMap maps a group of the identity provider to an RBAC role. A group
	// named like a role in auth.roles needs no entry.
	RoleMap map[string]string `yaml:"roleMap"`
	// AllowedGroups, when set, restricts sign-in to members of at least one of
	// these groups.
	AllowedGroups []string `yaml:"allowedGroups"`
	// AllowedEmailDomains, when set, restricts sign-in to users whose e-mail
	// address is in one of these domains.
	AllowedEmailDomains []string `yaml:"allowedEmailDomains"`
}

// UserLinksStoreConfig says where the link registry is kept. Every replica of
// a multi-replica deployment must use the same store: a link created on one
// replica has to work on the next request, which may reach another.
type UserLinksStoreConfig struct {
	// Backend selects the store: "filesystem" (a directory — on one host, or on
	// a volume all replicas mount), "s3" (an S3-compatible bucket), or "memory"
	// (lost on restart; for trying the feature out). Empty follows the cache:
	// the cache's bucket for cache.backend "s3", a directory next to the cache
	// otherwise.
	Backend string `yaml:"backend"`
	// Dir is the directory of the filesystem store. Empty means
	// "<cache.dir>/userlinks".
	Dir string `yaml:"dir"`
	// S3 configures the s3 store. Every connection field left empty is taken
	// from cache.s3, so a deployment on the shared s3 cache needs nothing here;
	// the registry lives in the same bucket under its own prefix.
	S3 UserLinksS3Config `yaml:"s3"`
}

// UserLinksS3Config holds the object-store connection settings of the link
// registry. Unset connection fields fall back to the cache S3 backend
// (cache.s3).
type UserLinksS3Config struct {
	Endpoint string `yaml:"endpoint"`
	Region   string `yaml:"region"`
	Bucket   string `yaml:"bucket"`
	// Prefix is the key prefix of the registry's objects. Empty means the
	// cache's prefix followed by "userlinks/".
	Prefix             string `yaml:"prefix"`
	AccessKeyID        string `yaml:"accessKeyId"`
	SecretAccessKey    string `yaml:"secretAccessKey"`
	SessionToken       string `yaml:"sessionToken"`
	UsePathStyle       bool   `yaml:"usePathStyle"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
	MaxRetries         int    `yaml:"maxRetries"`
}

// UserLinksOIDCConfig configures the OIDC identity provider cache users sign in
// at (authorization-code flow with PKCE).
type UserLinksOIDCConfig struct {
	// Enabled turns sign-in on. Without it, links can only be issued by an
	// administrator (ptctl userlinks issue).
	Enabled bool `yaml:"enabled"`
	// Issuer is the provider's issuer URL, exactly as in the "iss" claim of its
	// tokens. Required when enabled.
	Issuer string `yaml:"issuer"`
	// ClientID is the OAuth2 client the proxy is registered as. Required when
	// enabled.
	ClientID string `yaml:"clientId"`
	// ClientSecret authenticates a confidential client at the token endpoint
	// (empty: a public client, PKCE only). Supports ${ENV}, enc:v1: and secret
	// references.
	ClientSecret string `yaml:"clientSecret"`
	// RedirectURL is the callback URL registered with the provider. Empty means
	// "<server.publicUrl><uiPath>/callback".
	RedirectURL string `yaml:"redirectUrl"`
	// Scopes are requested at sign-in (default "openid profile email").
	Scopes []string `yaml:"scopes"`

	// DiscoveryURL overrides where the provider's metadata is read from. With
	// AuthorizationEndpoint, TokenEndpoint and a key source (JWKSURL or JWKS) all
	// set, no discovery takes place.
	DiscoveryURL          string `yaml:"discoveryUrl"`
	AuthorizationEndpoint string `yaml:"authorizationEndpoint"`
	TokenEndpoint         string `yaml:"tokenEndpoint"`
	JWKSURL               string `yaml:"jwksUrl"`
	// JWKS is an inline JWK Set document: the provider's signing keys, pinned.
	JWKS string `yaml:"jwks"`

	// SubjectClaim names the ID-token claim users are called by in the download
	// log and the audit trail (default "email"; "sub" when the token lacks it).
	SubjectClaim string `yaml:"subjectClaim"`
	// NameClaim, TeamClaim and GroupsClaim name the claims for the display name
	// (default "name"), the team (default "team") and group membership (default
	// "groups").
	NameClaim   string `yaml:"nameClaim"`
	TeamClaim   string `yaml:"teamClaim"`
	GroupsClaim string `yaml:"groupsClaim"`
	// AllowUnverifiedEmail accepts an e-mail address the provider marks as
	// unverified ("email_verified": false). Off by default.
	AllowUnverifiedEmail bool `yaml:"allowUnverifiedEmail"`

	// JWKSCacheTTL bounds caching of the provider's signing keys (default 15m);
	// Leeway is the clock skew tolerated on a token's validity (default 60s).
	JWKSCacheTTL time.Duration `yaml:"jwksCacheTtl"`
	Leeway       time.Duration `yaml:"leeway"`
}

// defaultUserLinks returns the user-links defaults. The feature is off; the
// values are what applies once it is switched on.
func defaultUserLinks() UserLinksConfig {
	return UserLinksConfig{
		PathPrefix:   userlinks.DefaultPathPrefix,
		UIPath:       userlinks.DefaultUIPath,
		LinkTTL:      userlinks.DefaultLinkTTL,
		SessionTTL:   userlinks.DefaultSessionTTL,
		SyncInterval: userlinks.DefaultSyncInterval,
	}
}

// StoreBackend resolves the registry's store backend: the configured one; left
// empty, the one the store block describes (a dir, a bucket); without either,
// the one that follows the cache.
func (u UserLinksConfig) StoreBackend(cacheBackend string) string {
	if b := strings.ToLower(strings.TrimSpace(u.Store.Backend)); b != "" {
		return b
	}
	// A store that is configured says which one it is: a directory, or a
	// bucket. Following the cache instead would put the registry somewhere
	// the operator did not point it — with several replicas, somewhere they
	// do not share.
	switch {
	case strings.TrimSpace(u.Store.Dir) != "":
		return "filesystem"
	case strings.TrimSpace(u.Store.S3.Bucket) != "" || strings.TrimSpace(u.Store.S3.Endpoint) != "":
		return "s3"
	}
	switch strings.ToLower(strings.TrimSpace(cacheBackend)) {
	case "s3":
		return "s3"
	case "memory":
		return "memory"
	default:
		return "filesystem"
	}
}

// validateUserLinks checks the personal-links configuration (Task 177).
func (c *Config) validateUserLinks() error {
	u := c.UserLinks
	if !u.Enabled {
		return nil
	}

	pub, err := url.Parse(strings.TrimSpace(c.Server.PublicURL))
	if err != nil || pub.Host == "" || (pub.Scheme != "https" && pub.Scheme != "http") {
		return fmt.Errorf("config: userLinks.enabled requires server.publicUrl (an http(s) URL): personal links are built from it")
	}

	prefix, err := userlinks.NormalizePathPrefix(u.PathPrefix)
	if err != nil {
		return fmt.Errorf("config: userLinks.pathPrefix: %w", err)
	}
	uiPath, err := userlinks.NormalizeUIPath(u.UIPath)
	if err != nil {
		return fmt.Errorf("config: userLinks.uiPath: %w", err)
	}
	// Neither may shadow — or be shadowed by — another surface of the gateway.
	reserved := map[string]string{
		"v1":       "the package-source mounts",
		"v2":       "the container registry alias",
		"healthz":  "the health endpoint",
		"readyz":   "the readiness endpoint",
		"internal": "the cache federation protocol",
	}
	addReserved := func(path, what string) {
		if seg := firstPathSegment(path); seg != "" {
			reserved[seg] = what
		}
	}
	if c.Observability.Admin {
		addReserved(orDefaultString(c.Observability.AdminPathPrefix, "/admin"), "the admin surface (observability.adminPathPrefix)")
	}
	if c.Observability.Metrics {
		addReserved(orDefaultString(c.Observability.MetricsPath, "/metrics"), "the metrics endpoint (observability.metricsPath)")
	}
	if c.Observability.Portal {
		addReserved(c.Observability.PortalPrefixOrDefault(), "the self-service portal (observability.portalPathPrefix)")
		addReserved("/api", "the self-service portal API")
	}
	addReserved(orDefaultString(c.Scanning.Watch.WebhookPath, "/webhooks/git"), "the commit scanner's push webhook (scanning.watch.webhookPath)")
	if what, taken := reserved[firstPathSegment(prefix)]; taken {
		return fmt.Errorf("config: userLinks.pathPrefix %q collides with %s", prefix, what)
	}
	if what, taken := reserved[firstPathSegment(uiPath)]; taken {
		return fmt.Errorf("config: userLinks.uiPath %q collides with %s", uiPath, what)
	}
	if firstPathSegment(uiPath) == firstPathSegment(prefix) {
		return fmt.Errorf("config: userLinks.uiPath %q and userLinks.pathPrefix %q must not share their first path segment", uiPath, prefix)
	}

	if u.LinkTTL < 0 {
		return fmt.Errorf("config: userLinks.linkTtl must not be negative (\"0s\" makes links that do not expire)")
	}
	if u.MaxLinksPerUser < -1 {
		return fmt.Errorf("config: userLinks.maxLinksPerUser must be -1 (no bound), 0 (the default) or positive")
	}
	if u.SessionTTL < 0 {
		return fmt.Errorf("config: userLinks.sessionTtl must not be negative")
	}
	if u.SyncInterval < 0 || (u.SyncInterval > 0 && u.SyncInterval < time.Second) {
		return fmt.Errorf("config: userLinks.syncInterval must be at least 1s")
	}

	switch backend := u.StoreBackend(c.Cache.Backend); backend {
	case "memory":
	case "filesystem":
		if strings.TrimSpace(u.Store.Dir) == "" && strings.TrimSpace(c.Cache.Dir) == "" {
			return fmt.Errorf("config: userLinks.store.dir is required (there is no cache.dir to put the link registry next to)")
		}
	case "s3":
		if strings.TrimSpace(u.Store.S3.Bucket) == "" && strings.TrimSpace(c.Cache.S3.Bucket) == "" {
			return fmt.Errorf("config: userLinks.store.s3.bucket is required (there is no cache.s3.bucket to inherit)")
		}
	default:
		return fmt.Errorf("config: userLinks.store.backend %q is not one of filesystem, s3, memory", backend)
	}

	if o := u.OIDC; o.Enabled {
		if strings.TrimSpace(o.Issuer) == "" {
			return fmt.Errorf("config: userLinks.oidc.issuer is required when oidc is enabled")
		}
		if strings.TrimSpace(o.ClientID) == "" {
			return fmt.Errorf("config: userLinks.oidc.clientId is required when oidc is enabled")
		}
		// A secret reference (vault://, env://, file://) is resolved after the
		// configuration is loaded; the key it names is checked then, when the
		// service is built (userlinks.New). Its spelling says nothing about it.
		if !secrets.IsRef(u.SessionKey) && len(u.SessionKey) < userlinks.MinSessionKeyBytes {
			return fmt.Errorf("config: userLinks.sessionKey must be at least %d bytes when oidc is enabled", userlinks.MinSessionKeyBytes)
		}
		if raw := strings.TrimSpace(o.RedirectURL); raw != "" {
			if ru, err := url.Parse(raw); err != nil || ru.Host == "" || (ru.Scheme != "https" && ru.Scheme != "http") {
				return fmt.Errorf("config: userLinks.oidc.redirectUrl must be an absolute http(s) URL")
			}
		}
		if o.JWKSCacheTTL < 0 || o.Leeway < 0 {
			return fmt.Errorf("config: userLinks.oidc.jwksCacheTtl and leeway must not be negative")
		}
	}

	// A role a user is given must be one the proxy defines: a typo here would
	// leave every signed-in user without access, or with less than intended.
	if c.Auth.Enabled {
		defined := make(map[string]struct{}, len(c.Auth.Roles))
		for _, role := range c.Auth.Roles {
			defined[strings.TrimSpace(role.Name)] = struct{}{}
		}
		for i, role := range u.DefaultRoles {
			if _, ok := defined[strings.TrimSpace(role)]; !ok {
				return fmt.Errorf("config: userLinks.defaultRoles[%d] %q is not a role defined in auth.roles", i, role)
			}
		}
		for group, role := range u.RoleMap {
			if _, ok := defined[strings.TrimSpace(role)]; !ok {
				return fmt.Errorf("config: userLinks.roleMap[%q] %q is not a role defined in auth.roles", group, role)
			}
		}
	}
	for i, domain := range u.AllowedEmailDomains {
		d := strings.TrimPrefix(strings.TrimSpace(domain), "@")
		if d == "" || strings.ContainsAny(d, "@/ ") {
			return fmt.Errorf("config: userLinks.allowedEmailDomains[%d] %q is not a domain", i, domain)
		}
	}
	return nil
}

// firstPathSegment returns the first segment of an absolute path, lower-cased.
func firstPathSegment(p string) string {
	p = strings.TrimLeft(strings.TrimSpace(p), "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}

func orDefaultString(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
