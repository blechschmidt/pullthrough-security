package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/backends/pkgmgr"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/clientip"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// mountLinks remembers which backends were told the public address of their own
// mount — and therefore write links to it into the documents they serve: an npm
// packument's tarball URLs, a PyPI page's file links, a Terraform provider's
// download URL.
//
// The personal-link edge (Task 177) has to give exactly those links the
// personal prefix, and must leave the documents of every other backend byte for
// byte as they are (an APT index, a signed Hackage snapshot). Rather than keep a
// second list of "backends that rewrite" next to the code that wires them, the
// fact is recorded where it is established: a backend is handed its public
// mount through publicMount, and that is what puts it in the set.
var mountLinks = &mountLinkSet{names: map[string]bool{}}

type mountLinkSet struct {
	mu    sync.Mutex
	names map[string]bool
}

func (s *mountLinkSet) add(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.names[name] = true
}

// snapshot returns a copy of the set.
func (s *mountLinkSet) snapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.names))
	for name := range s.names {
		out[name] = true
	}
	return out
}

// publicMount returns the externally reachable address of a backend's mount
// ("<server.publicUrl>/v1/<name>") for a backend that writes it into what it
// serves, and records that this backend does so.
func publicMount(cfg *config.Config, name string) string {
	mountLinks.add(name)
	return pkgmgr.PublicBase(cfg.Server.PublicURL, name)
}

// buildUserLinks constructs the personal-links subsystem (Task 177): cache
// users sign in through an OIDC identity provider and are handed personal cache
// links, so that downloads are attributed to a person. It returns nil — the
// feature switched off — when userLinks.enabled is false.
//
// The service is built even when the identity provider or the registry's store
// cannot be reached at this moment: sign-in then fails until the provider is
// back, links are refused as unverifiable until the store is, and neither keeps
// the proxy from serving packages.
func buildUserLinks(cfg *config.Config, auditLog *audit.Logger, resolver *clientip.Resolver, logger *slog.Logger) (*userlinks.Service, error) {
	u := cfg.UserLinks
	if !u.Enabled {
		return nil, nil
	}

	store, where, err := buildUserLinksStore(cfg)
	if err != nil {
		return nil, err
	}

	svcCfg := userlinks.Config{
		PathPrefix:      u.PathPrefix,
		UIPath:          u.UIPath,
		PublicURL:       cfg.Server.PublicURL,
		Store:           store,
		LinkTTL:         u.LinkTTL,
		MaxLinksPerUser: u.MaxLinksPerUser,
		SyncInterval:    u.SyncInterval,
		Node:            userLinksNode(cfg),
		SessionKey:      []byte(u.SessionKey),
		SessionTTL:      u.SessionTTL,
		InsecureCookies: u.InsecureCookies,

		SubjectClaim:         u.OIDC.SubjectClaim,
		NameClaim:            u.OIDC.NameClaim,
		TeamClaim:            u.OIDC.TeamClaim,
		GroupsClaim:          u.OIDC.GroupsClaim,
		AllowUnverifiedEmail: u.OIDC.AllowUnverifiedEmail,
		DefaultTeam:          u.DefaultTeam,
		DefaultRoles:         u.DefaultRoles,
		RoleMap:              u.RoleMap,
		AllowedGroups:        u.AllowedGroups,
		AllowedEmailDomains:  u.AllowedEmailDomains,

		// The token of a link is accepted as a credential in every mode, but a
		// client only sends one when asked — so the page offers that way of
		// configuring a client only where the proxy asks.
		TokenSnippets: cfg.Auth.Enabled,
		ClientIP:      func(r *http.Request) string { return resolver.Resolve(r).Client },
		Logger:        logger,
	}
	// The configuration says "0s" for links that do not expire; the registry
	// reads zero as "use the default" and a negative lifetime as "none".
	if u.LinkTTL == 0 {
		svcCfg.LinkTTL = -1
	}
	if auditLog != nil {
		svcCfg.Audit = auditLog
	}
	for _, role := range cfg.Auth.Roles {
		svcCfg.KnownRoles = append(svcCfg.KnownRoles, role.Name)
	}
	names := make([]string, 0, len(cfg.Upstreams))
	for name, up := range cfg.Upstreams {
		if up.IsEnabled() {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		up := cfg.Upstreams[name]
		svcCfg.Backends = append(svcCfg.Backends, onboard.Backend{Name: name, Type: up.Type, URL: up.URL})
	}
	if o := u.OIDC; o.Enabled {
		svcCfg.OIDC = &userlinks.OIDCConfig{
			Issuer:                o.Issuer,
			ClientID:              o.ClientID,
			ClientSecret:          o.ClientSecret,
			RedirectURL:           o.RedirectURL,
			Scopes:                o.Scopes,
			DiscoveryURL:          o.DiscoveryURL,
			AuthorizationEndpoint: o.AuthorizationEndpoint,
			TokenEndpoint:         o.TokenEndpoint,
			JWKSURL:               o.JWKSURL,
			JWKS:                  o.JWKS,
			JWKSCacheTTL:          o.JWKSCacheTTL,
			Leeway:                o.Leeway,
		}
	}

	svc, err := userlinks.New(svcCfg)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("building personal links: %w", err)
	}
	st := svc.Registry().Stats()
	attrs := []any{
		"pathPrefix", svc.PathPrefix(),
		"page", svc.PageURL(),
		"signIn", svc.SignInEnabled(),
		"store", where,
		"links", st.Active,
		"users", st.Users,
	}
	if ttl := svc.Registry().LinkTTL(); ttl > 0 {
		attrs = append(attrs, "linkTtl", ttl.String())
	} else {
		attrs = append(attrs, "linkTtl", "none")
	}
	if u.OIDC.Enabled {
		attrs = append(attrs, "issuer", u.OIDC.Issuer)
	}
	logger.Info("personal cache links enabled", attrs...)
	return svc, nil
}

// buildUserLinksStore opens the link registry's store, and describes where it
// is for the log.
//
// Left unconfigured, the store follows the cache: a multi-replica deployment
// that already shares its cache through an S3-compatible bucket gets a registry
// all replicas share without configuring anything — in the same bucket, under a
// prefix of its own — and a single host gets a directory next to its cache.
func buildUserLinksStore(cfg *config.Config) (userlinks.Store, string, error) {
	u := cfg.UserLinks
	switch backend := u.StoreBackend(cfg.Cache.Backend); backend {
	case "memory":
		return userlinks.NewMemoryStore(), "memory", nil

	case "filesystem":
		dir := strings.TrimSpace(u.Store.Dir)
		if dir == "" {
			dir = filepath.Join(cfg.Cache.Dir, "userlinks")
		}
		store, err := userlinks.NewDirStore(dir)
		if err != nil {
			return nil, "", fmt.Errorf("personal links (userLinks.store.dir %q): %w", dir, err)
		}
		return store, dir, nil

	case "s3":
		own, inherited := u.Store.S3, cfg.Cache.S3
		// The cache's bucket settings are inherited only for the cache's own
		// service. A store at another endpoint gets nothing of them — least of
		// all the cache's credentials, or its InsecureSkipVerify: link records
		// carry identities and roles, and must come from where they are meant
		// to.
		if ep := strings.TrimSpace(own.Endpoint); ep != "" && ep != strings.TrimSpace(inherited.Endpoint) {
			inherited = config.S3CacheConfig{}
		}
		pick := func(a, b string) string {
			if strings.TrimSpace(a) != "" {
				return a
			}
			return b
		}
		s3cfg := cache.S3ClientConfig{
			Endpoint:           pick(own.Endpoint, inherited.Endpoint),
			Region:             pick(own.Region, inherited.Region),
			Bucket:             pick(own.Bucket, inherited.Bucket),
			AccessKeyID:        pick(own.AccessKeyID, inherited.AccessKeyID),
			SecretAccessKey:    pick(own.SecretAccessKey, inherited.SecretAccessKey),
			SessionToken:       pick(own.SessionToken, inherited.SessionToken),
			UsePathStyle:       own.UsePathStyle || inherited.UsePathStyle,
			InsecureSkipVerify: own.InsecureSkipVerify || inherited.InsecureSkipVerify,
			MaxRetries:         own.MaxRetries,
		}
		if s3cfg.MaxRetries == 0 {
			s3cfg.MaxRetries = inherited.MaxRetries
		}
		prefix := strings.TrimSpace(own.Prefix)
		if prefix == "" {
			// Next to the cache's own objects ("<prefix>blobs/", "<prefix>meta/"),
			// never among them.
			prefix = strings.TrimSpace(inherited.Prefix)
			if prefix != "" && !strings.HasSuffix(prefix, "/") {
				prefix += "/"
			}
			prefix += "userlinks/"
		}
		store, err := userlinks.NewS3Store(s3cfg, prefix)
		if err != nil {
			return nil, "", fmt.Errorf("personal links (userLinks.store.s3): %w", err)
		}
		return store, "s3://" + s3cfg.Bucket + "/" + strings.TrimLeft(prefix, "/"), nil

	default:
		return nil, "", fmt.Errorf("personal links: unsupported userLinks.store.backend %q", backend)
	}
}

// userLinksNode names this replica for the registry: the name of the object it
// records link usage in. It should survive a restart — the coordination layer's
// default node ID ends in the process ID and does not — so the configured node
// ID is used when there is one, and the host name otherwise.
func userLinksNode(cfg *config.Config) string {
	if id := strings.TrimSpace(cfg.Coordination.NodeID); id != "" {
		return id
	}
	if host, err := os.Hostname(); err == nil && strings.TrimSpace(host) != "" {
		return host
	}
	return "node"
}

// bindUserLinksMetrics surfaces the personal-links telemetry (Task 177): how
// many links and users there are, what became of the requests that carried a
// link, how sign-ins went, and whether the registry can reach its store.
func bindUserLinksMetrics(c *metrics.Collector, svc *userlinks.Service) {
	if c == nil || !svc.Enabled() {
		return
	}
	c.BindGaugeVec("pullthrough_userlinks_links",
		"Number of personal cache links the registry holds, by state (active, expired, revoked).",
		[]string{"state"},
		func() []metrics.LabeledValue {
			st := svc.Registry().Stats()
			return []metrics.LabeledValue{
				{Labels: []string{"active"}, Value: float64(st.Active)},
				{Labels: []string{"expired"}, Value: float64(st.Expired)},
				{Labels: []string{"revoked"}, Value: float64(st.Revoked)},
			}
		})
	c.BindGauge("pullthrough_userlinks_users",
		"Number of distinct users holding at least one working personal cache link.",
		func() float64 { return float64(svc.Registry().Stats().Users) })
	c.BindCounterVec("pullthrough_userlinks_requests_total",
		"Total requests that carried a personal cache link, by how the link was presented (path, credential) and what became of it (ok, malformed, unknown, expired, revoked, unavailable).",
		[]string{"via", "outcome"},
		func() []metrics.LabeledValue {
			m := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(m.Resolved))
			for _, r := range m.Resolved {
				out = append(out, metrics.LabeledValue{Labels: []string{r.Via, r.Outcome}, Value: float64(r.Count)})
			}
			return out
		})
	c.BindCounterVec("pullthrough_userlinks_signins_total",
		"Total sign-ins at the personal-links page, by result (started, completed, failed, denied).",
		[]string{"result"},
		func() []metrics.LabeledValue {
			m := svc.Metrics()
			return []metrics.LabeledValue{
				{Labels: []string{"started"}, Value: float64(m.SignInsStarted)},
				{Labels: []string{"completed"}, Value: float64(m.SignInsCompleted)},
				{Labels: []string{"failed"}, Value: float64(m.SignInsFailed)},
				{Labels: []string{"denied"}, Value: float64(m.SignInsDenied)},
			}
		})
	c.BindCounter("pullthrough_userlinks_issued_total",
		"Total personal cache links created by this replica.",
		func() float64 { return float64(svc.Registry().Stats().Issued) })
	c.BindCounter("pullthrough_userlinks_revoked_total",
		"Total personal cache links revoked individually by this replica.",
		func() float64 { return float64(svc.Registry().Stats().RevokedTotal) })
	c.BindCounter("pullthrough_userlinks_user_revocations_total",
		"Total times everything issued to a user was revoked at once by this replica.",
		func() float64 { return float64(svc.Registry().Stats().UserRevocations) })
	c.BindGauge("pullthrough_userlinks_registry_synced",
		"1 when the personal-link registry has been read from its store; 0 while it has not, during which every link is refused as unverifiable.",
		func() float64 {
			if svc.Registry().Stats().Synced {
				return 1
			}
			return 0
		})
	c.BindCounter("pullthrough_userlinks_sync_errors_total",
		"Total refreshes of the personal-link registry from its store that failed.",
		func() float64 { return float64(svc.Registry().Stats().SyncErrors) })
	c.BindCounter("pullthrough_userlinks_store_errors_total",
		"Total failed operations on the personal-link registry's store.",
		func() float64 { return float64(svc.Registry().Stats().StoreErrors) })
	c.BindCounter("pullthrough_userlinks_store_lookups_total",
		"Total link tokens looked up in the store because this replica did not know them yet.",
		func() float64 { return float64(svc.Registry().Stats().StoreLookups) })
}

// bindPersonalLinkEdgeMetrics surfaces what the gateway's personal-link edge
// does to responses (Task 177). The gateway is constructed after the collector,
// so this is called from main once both exist.
func bindPersonalLinkEdgeMetrics(c *metrics.Collector, gw *proxy.Gateway, svc *userlinks.Service) {
	if c == nil || gw == nil || !svc.Enabled() {
		return
	}
	c.BindCounter("pullthrough_userlinks_personal_responses_total",
		"Total responses to requests that came in through a personal path prefix.",
		func() float64 { return float64(gw.PersonalLinkMetrics().Requests) })
	c.BindCounter("pullthrough_userlinks_rewritten_responses_total",
		"Total index documents whose links to the mount were searched for and given the personal prefix.",
		func() float64 { return float64(gw.PersonalLinkMetrics().Rewritten) })
	c.BindCounter("pullthrough_userlinks_rewritten_links_total",
		"Total links to a mount that were given the personal prefix.",
		func() float64 { return float64(gw.PersonalLinkMetrics().Links) })
}
