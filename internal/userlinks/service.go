package userlinks

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
)

// MethodPersonalLink is the auth method recorded for a request that was
// identified by a personal link: Principal.Method, and with it the authMethod of
// download-log entries and audit records.
const MethodPersonalLink = "personal-link"

// Attribute keys of the principal of such a request.
const (
	// AttrLink is the identifier of the link the request came through.
	AttrLink = "link"
	// AttrVia says how the link was presented: ViaPath or ViaCredential.
	AttrVia = "via"
)

// How a link's token reached the proxy.
const (
	// ViaPath: as the personal prefix of the request path ("/u/<token>/v1/…").
	ViaPath = "path"
	// ViaCredential: as an HTTP credential — a bearer token, or the password of
	// HTTP Basic.
	ViaCredential = "credential"
)

// Defaults of a Service.
const (
	// DefaultPathPrefix is the first path segment of a personal URL.
	DefaultPathPrefix = "/u"
	// DefaultUIPath is where the self-service page is served.
	DefaultUIPath = "/links"
	// DefaultSessionTTL is how long a sign-in on the self-service page lasts.
	DefaultSessionTTL = time.Hour
	// MinSessionKeyBytes is the least key material the cookie signatures accept.
	MinSessionKeyBytes = 32
	// flowTTL is how long a started sign-in may take to come back.
	flowTTL = 10 * time.Minute
)

// AuditLogger is where the service records sign-ins and what happens to links.
// *audit.Logger satisfies it.
type AuditLogger interface {
	Log(ctx context.Context, ev audit.Event) error
}

// Config configures a Service.
type Config struct {
	// PathPrefix is the first path segment of a personal URL (default "/u"):
	// one segment, lower-case letters, digits, "-" and "_".
	PathPrefix string
	// UIPath is the path of the self-service page (default "/links").
	UIPath string
	// PublicURL is the proxy's externally reachable base URL. The links shown
	// to users are built from it. Required.
	PublicURL string

	// Store holds the registry. Required.
	Store Store
	// LinkTTL, MaxLinksPerUser, SyncInterval and Node configure the registry;
	// see RegistryConfig.
	LinkTTL         time.Duration
	MaxLinksPerUser int
	SyncInterval    time.Duration
	Node            string

	// OIDC is the identity provider users sign in at. Nil leaves sign-in off:
	// links can then only be issued by an administrator.
	OIDC *OIDCConfig
	// SessionKey signs the sign-in cookies. Required with OIDC; at least
	// MinSessionKeyBytes bytes. Every replica must be given the same key.
	SessionKey []byte
	// SessionTTL is how long a sign-in lasts (default one hour).
	SessionTTL time.Duration
	// InsecureCookies drops the Secure attribute from the cookies, for a proxy
	// reached over plain HTTP in a test set-up.
	InsecureCookies bool

	// SubjectClaim names the ID-token claim users are called by (default
	// "email"). When the token lacks it, "sub" is used.
	SubjectClaim string
	// NameClaim, TeamClaim and GroupsClaim name the claims for the display name
	// (default "name"), the team (default "team") and group membership (default
	// "groups").
	NameClaim   string
	TeamClaim   string
	GroupsClaim string
	// AllowUnverifiedEmail accepts an e-mail address the provider itself marks
	// as unverified ("email_verified": false). Off by default.
	AllowUnverifiedEmail bool
	// DefaultTeam is the team of a user whose token names none.
	DefaultTeam string
	// DefaultRoles are RBAC roles every signed-in user holds.
	DefaultRoles []string
	// RoleMap maps a group of the identity provider to an RBAC role. A group
	// whose name is that of a role in KnownRoles needs no entry.
	RoleMap map[string]string
	// KnownRoles are the RBAC roles the proxy defines (auth.roles).
	KnownRoles []string
	// AllowedGroups, when set, restricts sign-in to members of at least one of
	// these groups; AllowedEmailDomains to users with an e-mail address in one
	// of these domains.
	AllowedGroups       []string
	AllowedEmailDomains []string

	// Backends are the configured upstreams; the page shows a personal URL and
	// a client configuration snippet for each.
	Backends []onboard.Backend
	// TokenSnippets also offers the configuration that presents the link's
	// token as an HTTP credential. It only makes sense where the proxy asks
	// clients to authenticate, because most clients send a credential only when
	// asked.
	TokenSnippets bool

	// Audit, when set, records sign-ins and link changes.
	Audit AuditLogger
	// ClientIP resolves the address a request to the page came from. Nil means
	// the TCP peer.
	ClientIP func(*http.Request) string
	// Logger receives diagnostics. Nil means slog.Default.
	Logger *slog.Logger
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Service is the personal-links subsystem: the registry, the sign-in, the
// self-service page, and the resolution of a request's token to its user.
//
// A nil *Service is the feature switched off: its methods are no-ops, and
// Authenticate declines every request.
type Service struct {
	cfg       Config
	prefix    string
	uiPath    string
	publicURL string
	// pagePath is the path of the page as the browser sees it: uiPath behind
	// the path of the public URL, when the proxy is reached under one
	// ("https://example.com/pt" → "/pt/links"). Cookies are scoped to it and
	// redirects go to it; uiPath is where the gateway mounts the page.
	pagePath string

	registry   *Registry
	oidc       *oidcClient
	codec      *cookieCodec
	sessionTTL time.Duration
	secure     bool

	groupRoles     map[string]string
	knownRoles     map[string]struct{}
	allowedGroups  map[string]struct{}
	allowedDomains map[string]struct{}

	audit    AuditLogger
	clientIP func(*http.Request) string
	logger   *slog.Logger
	now      func() time.Time
	mux      *http.ServeMux
	creation *creationLimiter

	counters serviceCounters
}

// serviceCounters are the service's cumulative counters.
type serviceCounters struct {
	// resolved counts requests that carried a link token, by how it was
	// presented and what became of it. Index: [via][outcome].
	resolved [2][numOutcomes]atomic.Uint64
	// signIns counts sign-in attempts by result.
	signInsStarted   atomic.Uint64
	signInsCompleted atomic.Uint64
	signInsFailed    atomic.Uint64
	signInsDenied    atomic.Uint64
}

// Outcomes of resolving a request's link token, as counted.
const (
	outcomeOK = iota
	outcomeMalformed
	outcomeUnknown
	outcomeExpired
	outcomeRevoked
	outcomeUnavailable
	numOutcomes
)

var outcomeNames = [numOutcomes]string{"ok", "malformed", "unknown", "expired", "revoked", "unavailable"}

func outcomeOf(reason Reason) int {
	switch reason {
	case ReasonMalformed:
		return outcomeMalformed
	case ReasonExpired:
		return outcomeExpired
	case ReasonRevoked:
		return outcomeRevoked
	case ReasonUnavailable:
		return outcomeUnavailable
	default:
		return outcomeUnknown
	}
}

// New builds the service. It fails on a configuration that cannot work; it
// does not fail because the identity provider or the store is unreachable at
// this moment (see oidcClient and NewRegistry).
func New(cfg Config) (*Service, error) {
	prefix, err := NormalizePathPrefix(cfg.PathPrefix)
	if err != nil {
		return nil, err
	}
	uiPath, err := NormalizeUIPath(cfg.UIPath)
	if err != nil {
		return nil, err
	}
	publicURL := strings.TrimRight(strings.TrimSpace(cfg.PublicURL), "/")
	pub, err := url.Parse(publicURL)
	if err != nil || pub.Host == "" || (pub.Scheme != "https" && pub.Scheme != "http") {
		return nil, errors.New("userlinks: the public URL of the proxy must be set to an http(s) URL: personal links are built from it")
	}
	if cfg.Store == nil {
		return nil, errors.New("userlinks: a store is required")
	}

	s := &Service{
		cfg:            cfg,
		prefix:         prefix,
		uiPath:         uiPath,
		publicURL:      publicURL,
		pagePath:       strings.TrimRight(pub.EscapedPath(), "/") + uiPath,
		sessionTTL:     cfg.SessionTTL,
		secure:         !cfg.InsecureCookies,
		groupRoles:     map[string]string{},
		knownRoles:     map[string]struct{}{},
		allowedGroups:  map[string]struct{}{},
		allowedDomains: map[string]struct{}{},
		audit:          cfg.Audit,
		clientIP:       cfg.ClientIP,
		logger:         cfg.Logger,
		now:            cfg.Now,
		creation:       newCreationLimiter(),
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.clientIP == nil {
		s.clientIP = peerAddress
	}
	if s.sessionTTL <= 0 {
		s.sessionTTL = DefaultSessionTTL
	}
	for group, role := range cfg.RoleMap {
		group, role = strings.TrimSpace(group), strings.TrimSpace(role)
		if group != "" && role != "" {
			s.groupRoles[group] = role
		}
	}
	for _, role := range cfg.KnownRoles {
		if role = strings.TrimSpace(role); role != "" {
			s.knownRoles[role] = struct{}{}
		}
	}
	for _, group := range cfg.AllowedGroups {
		if group = strings.TrimSpace(group); group != "" {
			s.allowedGroups[group] = struct{}{}
		}
	}
	for _, domain := range cfg.AllowedEmailDomains {
		if domain = lowerASCII(strings.TrimPrefix(strings.TrimSpace(domain), "@")); domain != "" {
			s.allowedDomains[domain] = struct{}{}
		}
	}

	if cfg.OIDC != nil {
		if len(cfg.SessionKey) < MinSessionKeyBytes {
			return nil, fmt.Errorf("userlinks: the session key must be at least %d bytes", MinSessionKeyBytes)
		}
		oidcCfg := *cfg.OIDC
		if strings.TrimSpace(oidcCfg.RedirectURL) == "" {
			oidcCfg.RedirectURL = publicURL + uiPath + "/callback"
		}
		if oidcCfg.Now == nil {
			oidcCfg.Now = s.now
		}
		if s.oidc, err = newOIDCClient(oidcCfg); err != nil {
			return nil, err
		}
		s.codec = newCookieCodec(cfg.SessionKey, s.now)
	}

	s.registry, err = NewRegistry(RegistryConfig{
		Store:           cfg.Store,
		LinkTTL:         cfg.LinkTTL,
		MaxLinksPerUser: cfg.MaxLinksPerUser,
		SyncInterval:    cfg.SyncInterval,
		SessionTTL:      s.sessionTTL,
		Node:            cfg.Node,
		Now:             s.now,
		Logger:          s.logger,
	})
	if err != nil {
		return nil, err
	}
	s.mux = s.routes()
	return s, nil
}

// NormalizePathPrefix validates the first path segment of personal URLs and
// returns it with its leading slash. The empty string yields the default.
func NormalizePathPrefix(raw string) (string, error) {
	seg := strings.Trim(strings.TrimSpace(raw), "/")
	if seg == "" {
		return DefaultPathPrefix, nil
	}
	if len(seg) > 32 {
		return "", fmt.Errorf("userlinks: the path prefix %q is too long", raw)
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		// The characters of a container repository path component: the prefix is
		// one, in "<host>/<prefix>/<token>/<upstream>/<repository>".
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && !((c == '-' || c == '_') && i > 0 && i < len(seg)-1) {
			return "", fmt.Errorf("userlinks: the path prefix %q must be one path segment of lower-case letters, digits, '-' and '_'", raw)
		}
	}
	return "/" + seg, nil
}

// NormalizeUIPath validates the path of the self-service page and returns it
// without a trailing slash. The empty string yields the default.
func NormalizeUIPath(raw string) (string, error) {
	p := strings.TrimRight(strings.TrimSpace(raw), "/")
	if p == "" {
		return DefaultUIPath, nil
	}
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#\\ ") || strings.Contains(p, "//") || strings.Contains(p, "/.") {
		return "", fmt.Errorf("userlinks: the page path %q must be an absolute path", raw)
	}
	return p, nil
}

func peerAddress(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Enabled reports whether the feature is on.
func (s *Service) Enabled() bool { return s != nil }

// PathPrefix returns the first path segment of personal URLs, "/u".
func (s *Service) PathPrefix() string {
	if s == nil {
		return ""
	}
	return s.prefix
}

// UIPath returns the path of the self-service page, "/links".
func (s *Service) UIPath() string {
	if s == nil {
		return ""
	}
	return s.uiPath
}

// SignInEnabled reports whether users can sign in (an identity provider is
// configured).
func (s *Service) SignInEnabled() bool { return s != nil && s.oidc != nil }

// PageURL returns the public URL of the self-service page.
func (s *Service) PageURL() string {
	if s == nil {
		return ""
	}
	return s.publicURL + s.uiPath + "/"
}

// PersonalBase returns the public base URL of the personal link with the given
// token: what stands before "/v1/<upstream>".
func (s *Service) PersonalBase(token string) string {
	return s.publicURL + s.prefix + "/" + token
}

// Registry returns the link registry.
func (s *Service) Registry() *Registry {
	if s == nil {
		return nil
	}
	return s.registry
}

// Run keeps the registry current until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if s == nil {
		return
	}
	s.registry.Run(ctx)
}

// Close writes down what is only in memory and closes the store.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.registry.Close()
	return s.cfg.Store.Close()
}

// --- resolving a request ----------------------------------------------------

type pathTokenKey struct{}

// WithPathToken returns a context that carries the token a request presented
// as its personal path prefix. The gateway attaches it when it strips the
// prefix; Authenticate reads it from there.
func WithPathToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, pathTokenKey{}, token)
}

// PathToken returns the token attached by WithPathToken.
func PathToken(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(pathTokenKey{}).(string)
	return token, ok
}

// AuthError is returned by Authenticate for a request that presented a link
// token that cannot be honoured. It is deliberately not auth.ErrUnauthenticated:
// such a request must be refused, never served as if it had carried nothing —
// the user believes their downloads are recorded under their name, and a
// revoked link that kept working anonymously would not be revoked.
type AuthError struct {
	Reason Reason
	// Link is the link the token belongs to, when it is a known one.
	Link *Link
	// Via is how the token was presented.
	Via string
	// PageURL is where a user gets a new link.
	PageURL string
}

func (e *AuthError) Error() string {
	msg := (&ResolveError{Reason: e.Reason}).Error()
	switch {
	case e.Reason == ReasonUnavailable:
		return msg + "; try again shortly"
	case e.PageURL != "":
		return msg + "; sign in at " + e.PageURL + " to create a new one"
	}
	return msg
}

// Status is the HTTP status the request is refused with.
//
//   - 503 when the registry could not be consulted: nothing is wrong with the
//     link, and the client should simply retry.
//   - 403 for a link in the path. The link is the request's address, not a
//     credential the client could replace: a 401 would have pip and git prompt
//     for a user name and password that no one has, and a 404 would let a
//     GOPROXY list fall through to the next entry — past the proxy.
//   - 401 for a token presented as a credential, which is what a wrong
//     credential is.
func (e *AuthError) Status() int {
	switch {
	case e.Reason == ReasonUnavailable:
		return http.StatusServiceUnavailable
	case e.Via == ViaPath:
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

// Authenticate resolves the personal link a request carries to the principal it
// stands for.
//
// A token is looked for in the request's path prefix (attached by the gateway,
// see WithPathToken) and, failing that, among its credentials: a bearer token,
// the password or user name of HTTP Basic, the X-Api-Token / X-Auth-Token
// headers. Only text that starts like a link token ("ptl1…") is considered —
// anything else is someone else's credential.
//
// It returns auth.ErrUnauthenticated for a request that carries no link token,
// and an *AuthError for one that carries a token that is not good.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*auth.Principal, error) {
	if s == nil {
		return nil, auth.ErrUnauthenticated
	}
	token, inPath := PathToken(ctx)
	via, viaIdx := ViaPath, 0
	if !inPath {
		via, viaIdx = ViaCredential, 1
		// A credential spelled like a link is a link. One that starts like a
		// link and is not one — cut short in a copy-paste, mistyped — was meant
		// as one, and is refused as a link that is not good: passed on as
		// "not mine", it would be served anonymously where authentication is
		// off, with the user believing the download is theirs.
		attempted := ""
		for _, candidate := range auth.CandidateTokens(r) {
			if WellFormed(candidate) {
				token = candidate
				break
			}
			if attempted == "" && strings.HasPrefix(candidate, TokenPrefix) {
				attempted = candidate
			}
		}
		if token == "" {
			if attempted == "" {
				return nil, auth.ErrUnauthenticated
			}
			token = attempted
		}
	}

	link, err := s.registry.Resolve(ctx, token)
	if err != nil {
		var re *ResolveError
		if !errors.As(err, &re) {
			re = &ResolveError{Reason: ReasonUnavailable}
		}
		s.counters.resolved[viaIdx][outcomeOf(re.Reason)].Add(1)
		return nil, &AuthError{Reason: re.Reason, Link: re.Link, Via: via, PageURL: s.PageURL()}
	}
	s.counters.resolved[viaIdx][outcomeOK].Add(1)

	p := &auth.Principal{
		Subject:    link.Subject,
		Team:       link.Team,
		Roles:      link.Roles,
		Method:     MethodPersonalLink,
		Attributes: map[string]string{AttrLink: link.ID, AttrVia: via},
	}
	if link.Issuer != "" {
		p.Attributes["issuer"] = link.Issuer
	}
	return p, nil
}

// Touch notes that the link behind p — a principal returned by Authenticate —
// was used for a request from addr by the client tool agent.
func (s *Service) Touch(p *auth.Principal, addr, agent string) {
	if s == nil || p == nil || p.Method != MethodPersonalLink {
		return
	}
	if id := p.Attributes[AttrLink]; id != "" {
		s.registry.Touch(id, addr, agent)
	}
}

// --- management (the admin API) ---------------------------------------------

// Links lists the links f selects.
func (s *Service) Links(f Filter) []Info {
	if s == nil {
		return nil
	}
	return s.registry.List(f)
}

// Issue creates a link for id on an administrator's behalf — for a service
// account, or where no identity provider is configured — and returns its token
// and the personal base URL.
func (s *Service) Issue(ctx context.Context, id Identity, opts IssueOptions) (token, base string, info Info, err error) {
	if s == nil {
		return "", "", Info{}, errors.New("userlinks: personal links are not enabled")
	}
	// The link records the address it was created from, not the connection: an
	// administrator's "10.0.0.5:51234" is "10.0.0.5" to the user who reads it.
	from := opts.From
	if host, _, splitErr := net.SplitHostPort(from); splitErr == nil && host != "" {
		opts.From = host
	}
	token, info, err = s.registry.Issue(ctx, id, opts)
	if err != nil {
		return "", "", Info{}, err
	}
	s.record(ctx, audit.Event{
		Type: audit.EventAuth, Subject: info.Subject, Team: info.Team, Decision: audit.DecisionAllow,
		Reason:     "userlinks: link issued",
		RemoteAddr: from,
		Detail:     linkDetail(info, map[string]any{"issuedBy": opts.IssuedBy}),
	})
	return token, s.PersonalBase(token), info, nil
}

// Revoke revokes one link. by is who does it.
func (s *Service) Revoke(ctx context.Context, id, by, reason, from string) (Info, error) {
	if s == nil {
		return Info{}, ErrNoSuchLink
	}
	before, _ := s.registry.Get(id)
	info, err := s.registry.Revoke(ctx, id, by, reason)
	if err != nil {
		return Info{}, err
	}
	if before.State != StateRevoked {
		s.record(ctx, audit.Event{
			Type: audit.EventAuth, Subject: info.Subject, Team: info.Team, Decision: audit.DecisionAllow,
			Reason:     "userlinks: link revoked",
			RemoteAddr: from,
			Detail:     linkDetail(info, map[string]any{"by": by, "why": cleanText(reason, maxReasonLen)}),
		})
	}
	return info, nil
}

// RevokeUser ends everything issued to subject so far: all links, and the
// sign-in sessions. It returns how many working links that ended.
func (s *Service) RevokeUser(ctx context.Context, subject, by, reason, from string) (int, time.Time, error) {
	if s == nil {
		return 0, time.Time{}, errors.New("userlinks: personal links are not enabled")
	}
	n, notBefore, err := s.registry.RevokeUser(ctx, subject, by, reason)
	if err != nil {
		return 0, time.Time{}, err
	}
	s.record(ctx, audit.Event{
		Type: audit.EventAuth, Subject: strings.TrimSpace(subject), Decision: audit.DecisionAllow,
		Reason:     "userlinks: all links revoked",
		RemoteAddr: from,
		Detail:     map[string]any{"by": by, "links": n, "why": cleanText(reason, maxReasonLen)},
	})
	return n, notBefore, nil
}

func linkDetail(info Info, extra map[string]any) map[string]any {
	d := map[string]any{"link": info.ID}
	if info.Label != "" {
		d["label"] = info.Label
	}
	if info.ExpiresAt != nil {
		d["expires"] = info.ExpiresAt.UTC().Format(time.RFC3339)
	}
	for k, v := range extra {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		d[k] = v
	}
	return d
}

// record writes an audit event; an audit sink that fails is logged, and does
// not fail what was done.
func (s *Service) record(ctx context.Context, ev audit.Event) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Log(ctx, ev); err != nil {
		s.logger.Error("personal links: audit log write failed", "error", err)
	}
}

// --- who a signed-in user is ------------------------------------------------

// signInDenied is returned for a user the identity provider vouched for but the
// proxy's own rules do not admit.
type signInDenied struct{ why string }

func (e *signInDenied) Error() string { return e.why }

// identityFromClaims maps the claims of a verified ID token onto an Identity,
// applying the sign-in restrictions.
func (s *Service) identityFromClaims(claims map[string]any) (Identity, error) {
	email := lowerASCII(claimString(claims, "email"))
	sub := claimString(claims, "sub")

	subjectClaim := strings.TrimSpace(s.cfg.SubjectClaim)
	if subjectClaim == "" {
		subjectClaim = "email"
	}
	subject := claimString(claims, subjectClaim)
	usesEmail := subjectClaim == "email"
	if usesEmail {
		subject = email
	}
	if subject == "" {
		// The provider did not release the claim. Its own identifier for the
		// user is always there, and always stable.
		subject, usesEmail = sub, false
	}
	if subject == "" {
		return Identity{}, &signInDenied{"the identity provider did not say who you are (no subject claim)"}
	}

	// An address the provider itself calls unverified is one the user may have
	// typed in; it must not become the name downloads are recorded under, nor
	// satisfy a domain restriction.
	if (usesEmail || len(s.allowedDomains) > 0) && !s.cfg.AllowUnverifiedEmail && explicitlyFalse(claims["email_verified"]) {
		return Identity{}, &signInDenied{"your e-mail address is not verified at the identity provider"}
	}
	if len(s.allowedDomains) > 0 {
		_, domain, ok := strings.Cut(email, "@")
		if _, allowed := s.allowedDomains[domain]; !ok || !allowed {
			return Identity{}, &signInDenied{"your account is not in a domain that may use the cache"}
		}
	}

	groups := claimStrings(claims, orDefault(s.cfg.GroupsClaim, "groups"))
	if len(s.allowedGroups) > 0 {
		member := false
		for _, g := range groups {
			if _, ok := s.allowedGroups[g]; ok {
				member = true
				break
			}
		}
		if !member {
			return Identity{}, &signInDenied{"your account is not in a group that may use the cache"}
		}
	}

	roles := append([]string(nil), s.cfg.DefaultRoles...)
	for _, g := range groups {
		if role, ok := s.groupRoles[g]; ok {
			roles = append(roles, role)
		} else if _, ok := s.knownRoles[g]; ok {
			roles = append(roles, g)
		}
	}

	name := claimString(claims, orDefault(s.cfg.NameClaim, "name"))
	if name == "" {
		name = claimString(claims, "preferred_username")
	}
	team := claimString(claims, orDefault(s.cfg.TeamClaim, "team"))
	if team == "" {
		team = strings.TrimSpace(s.cfg.DefaultTeam)
	}
	id, err := Identity{
		Subject:     subject,
		Name:        name,
		Email:       email,
		Team:        team,
		Roles:       roles,
		Issuer:      claimString(claims, "iss"),
		OIDCSubject: sub,
	}.normalize()
	if err != nil {
		return Identity{}, &signInDenied{"the identity provider's name for you cannot be used as one"}
	}
	return id, nil
}

// explicitlyFalse reports whether a claim says "false" — as a boolean, or as
// the string some providers send instead.
func explicitlyFalse(v any) bool {
	switch t := v.(type) {
	case bool:
		return !t
	case string:
		return strings.EqualFold(strings.TrimSpace(t), "false")
	}
	return false
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// --- metrics ----------------------------------------------------------------

// ResolveCount is how many requests carried a link token that was presented a
// given way and met a given fate.
type ResolveCount struct {
	Via     string
	Outcome string
	Count   uint64
}

// Metrics is a snapshot of the service's counters.
type Metrics struct {
	Registry Stats
	// Resolved counts the requests that carried a link token.
	Resolved []ResolveCount
	// SignIns counts sign-in attempts: started, completed, failed (the exchange
	// with the provider went wrong) and denied (the user is not admitted).
	SignInsStarted   uint64
	SignInsCompleted uint64
	SignInsFailed    uint64
	SignInsDenied    uint64
}

// Outcomes lists the outcomes Resolved is broken down by.
func Outcomes() []string { return append([]string(nil), outcomeNames[:]...) }

// Metrics returns a snapshot of the service's counters.
func (s *Service) Metrics() Metrics {
	if s == nil {
		return Metrics{}
	}
	m := Metrics{
		Registry:         s.registry.Stats(),
		SignInsStarted:   s.counters.signInsStarted.Load(),
		SignInsCompleted: s.counters.signInsCompleted.Load(),
		SignInsFailed:    s.counters.signInsFailed.Load(),
		SignInsDenied:    s.counters.signInsDenied.Load(),
	}
	for vi, via := range [...]string{ViaPath, ViaCredential} {
		for oi, outcome := range outcomeNames {
			m.Resolved = append(m.Resolved, ResolveCount{Via: via, Outcome: outcome, Count: s.counters.resolved[vi][oi].Load()})
		}
	}
	return m
}

// sortedBackends returns the configured upstreams in name order.
func (s *Service) sortedBackends() []onboard.Backend {
	out := append([]onboard.Backend(nil), s.cfg.Backends...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
