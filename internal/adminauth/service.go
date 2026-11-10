package adminauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
)

// Default cookie/session parameters.
const (
	defaultCookieName = "pts_admin_session"
	flowCookieSuffix  = "_flow"
	defaultSessionTTL = 8 * time.Hour
	flowTTL           = 10 * time.Minute
)

// Options configures a Service.
type Options struct {
	// Prefix is the admin mount path (e.g. "/admin"); auth routes and cookie
	// scopes derive from it. Required.
	Prefix string
	// SessionKey signs session and login-flow cookies (HMAC-SHA256). Required
	// when OIDC is enabled; at least 16 bytes.
	SessionKey []byte
	// SessionTTL bounds an admin session's lifetime (default 8h).
	SessionTTL time.Duration
	// CookieName overrides the session cookie name.
	CookieName string
	// SecureCookies sets the Secure flag on issued cookies (default true). Set
	// false only for plain-HTTP local/testing deployments.
	SecureCookies bool
	// CookiePath overrides the path scope of issued session/flow cookies. It
	// defaults to the admin Prefix. Set it to "/" when a second, separately-mounted
	// surface (the tenant self-service portal, Task 71) must share the same SSO
	// session, so the cookie is sent to both path subtrees.
	CookiePath string

	// OIDC, when non-nil, enables SSO login and bearer-JWT validation.
	OIDC *OIDCConfig
	// StaticTokens enable the documented offline/static mode.
	StaticTokens []StaticToken
	// LegacyAdminToken preserves backward compatibility with the previous single
	// observability.adminToken (granting the admin role).
	LegacyAdminToken string

	// RoleBindings map IdP group/role names to canonical roles. A group whose
	// name is already a canonical role needs no binding.
	RoleBindings map[string]string
	// DefaultRole is granted when an authenticated caller matches no binding
	// (empty denies such callers).
	DefaultRole string

	Logger *slog.Logger
	Now    func() time.Time
}

// Service authenticates admin callers (session cookie, OIDC bearer JWT, or
// static token) and authorizes them by capability. It also serves the OIDC
// login/callback/logout/userinfo endpoints.
type Service struct {
	opts           Options
	codec          *sessionCodec
	oidc           *oidcProvider
	static         *staticAuth
	bindings       map[string]Role
	defaultRole    Role
	metrics        *Metrics
	now            func() time.Time
	logger         *slog.Logger
	cookieName     string
	flowCookieName string
	cookiePath     string // admin prefix; used to build login/logout/return URLs
	cookieScope    string // Path attribute of issued cookies (may be broader, e.g. "/")
	secure         bool
	sessionTTL     time.Duration
}

// New constructs a Service. It returns an error if the configuration is
// inconsistent (e.g. OIDC enabled without a session key) and (nil, nil) when no
// authentication mechanism is configured at all (the caller then leaves the
// admin surface in its prior open/legacy state).
func New(opts Options) (*Service, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	prefix := strings.TrimRight(opts.Prefix, "/")
	if prefix == "" {
		prefix = "/admin"
	}
	cookieName := opts.CookieName
	if cookieName == "" {
		cookieName = defaultCookieName
	}
	sessionTTL := opts.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = defaultSessionTTL
	}
	cookieScope := strings.TrimSpace(opts.CookiePath)
	if cookieScope == "" {
		cookieScope = prefix
	}

	s := &Service{
		opts:           opts,
		metrics:        newMetrics(),
		now:            now,
		logger:         opts.Logger,
		cookieName:     cookieName,
		flowCookieName: cookieName + flowCookieSuffix,
		cookiePath:     prefix,
		cookieScope:    cookieScope,
		secure:         opts.SecureCookies,
		sessionTTL:     sessionTTL,
		bindings:       make(map[string]Role),
		defaultRole:    "",
	}

	// Role bindings.
	for group, roleName := range opts.RoleBindings {
		r, ok := ParseRole(roleName)
		if !ok {
			return nil, fmt.Errorf("adminauth: role binding %q -> %q: unknown role", group, roleName)
		}
		s.bindings[strings.TrimSpace(group)] = r
	}
	if rn := strings.TrimSpace(opts.DefaultRole); rn != "" {
		r, ok := ParseRole(rn)
		if !ok {
			return nil, fmt.Errorf("adminauth: defaultRole %q: unknown role", rn)
		}
		s.defaultRole = r
	}

	// Static tokens / legacy admin token.
	static, err := newStaticAuth(opts.StaticTokens, opts.LegacyAdminToken)
	if err != nil {
		return nil, err
	}
	s.static = static

	// OIDC.
	if opts.OIDC != nil {
		if len(opts.SessionKey) < 16 {
			return nil, fmt.Errorf("adminauth: a sessionKey of at least 16 bytes is required when OIDC is enabled")
		}
		s.codec = newSessionCodec(opts.SessionKey, now)
		prov, err := newOIDCProvider(*opts.OIDC)
		if err != nil {
			return nil, err
		}
		s.oidc = prov
	}

	if s.oidc == nil && s.static == nil {
		return nil, nil
	}
	return s, nil
}

// OIDCEnabled reports whether SSO login/bearer validation is active.
func (s *Service) OIDCEnabled() bool { return s != nil && s.oidc != nil }

// Metrics returns the live metrics for bridging into Prometheus.
func (s *Service) Metrics() *Metrics {
	if s == nil {
		return nil
	}
	return s.metrics
}

// LoginPath returns the absolute path of the SSO login endpoint (empty when OIDC
// is disabled).
func (s *Service) LoginPath() string {
	if !s.OIDCEnabled() {
		return ""
	}
	return s.cookiePath + "/auth/login"
}

// Authenticate resolves the caller's identity from (in order) a session cookie,
// an OIDC bearer JWT, or a static token. It returns auth.ErrUnauthenticated when
// no usable credential is present or a presented credential is invalid.
func (s *Service) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	// 1) Session cookie (browser, post-login).
	if s.oidc != nil {
		if c, err := r.Cookie(s.cookieName); err == nil && c.Value != "" {
			if id, derr := s.codec.decodeSession(c.Value); derr == nil {
				s.metrics.recordAuthSuccess(id.Method, id.Roles)
				return id, nil
			}
			// An invalid/expired session cookie is treated as "no session"; the
			// caller will be steered back to login.
		}
	}

	// 2) OIDC bearer JWT (API/CI), distinguished from static tokens by shape.
	if s.oidc != nil {
		if tok := bearerToken(r); tok != "" && looksLikeJWT(tok) {
			cl, err := s.oidc.validateBearer(ctx, r)
			if err != nil {
				s.metrics.recordAuthFailure("invalid_bearer")
				return nil, auth.ErrUnauthenticated
			}
			id, ok := s.identityFromClaims(cl, "oidc-bearer")
			if !ok {
				s.metrics.recordAuthFailure("no_roles")
				return nil, auth.ErrUnauthenticated
			}
			s.metrics.recordAuthSuccess(id.Method, id.Roles)
			return id, nil
		}
	}

	// 3) Static token (offline/air-gapped mode, plus legacy admin token).
	if s.static != nil {
		if id, err := s.static.authenticate(ctx, r); err == nil {
			s.metrics.recordAuthSuccess(id.Method, id.Roles)
			return id, nil
		}
	}

	s.metrics.recordAuthFailure("no_credential")
	return nil, auth.ErrUnauthenticated
}

// Authorize reports whether the identity holds the required capability and
// records the decision in metrics.
func (s *Service) Authorize(id *Identity, c Capability) bool {
	allowed := id.Can(c)
	s.metrics.recordAuthz(c, allowed)
	return allowed
}

// identityFromClaims maps OIDC groups to canonical roles and builds an Identity.
// The bool is false when the caller ends up with no roles (denied).
func (s *Service) identityFromClaims(cl *claims, method string) (*Identity, bool) {
	roles := s.mapGroups(cl.groups)
	if len(roles) == 0 {
		return nil, false
	}
	return newIdentity(cl.subject, method, cl.issuer, cl.tenant, roles), true
}

// mapGroups translates IdP group/role names into canonical roles via the
// configured bindings (falling back to direct canonical-role names), applying
// the default role when nothing matches.
func (s *Service) mapGroups(groups []string) []Role {
	out := make([]Role, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if r, ok := s.bindings[g]; ok {
			out = append(out, r)
			continue
		}
		if r, ok := ParseRole(g); ok {
			out = append(out, r)
		}
	}
	roles := canonicalize(out)
	if len(roles) == 0 && s.defaultRole != "" {
		return []Role{s.defaultRole}
	}
	return roles
}

// --- HTTP handlers ----------------------------------------------------------

// HandleLogin starts the OIDC authorization-code+PKCE flow.
func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.OIDCEnabled() {
		http.Error(w, "SSO login is not enabled", http.StatusNotFound)
		return
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		s.metrics.recordLogin(false)
		http.Error(w, "login initialization failed", http.StatusInternalServerError)
		return
	}
	state, err1 := randToken(24)
	nonce, err2 := randToken(24)
	if err1 != nil || err2 != nil {
		s.metrics.recordLogin(false)
		http.Error(w, "login initialization failed", http.StatusInternalServerError)
		return
	}
	flow := flowClaims{
		State:    state,
		Verifier: verifier,
		Nonce:    nonce,
		ReturnTo: s.sanitizeReturn(r.URL.Query().Get("return")),
	}
	cookieVal, err := s.codec.encodeFlow(flow, flowTTL)
	if err != nil {
		s.metrics.recordLogin(false)
		http.Error(w, "login initialization failed", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, s.flowCookieName, cookieVal, flowTTL)
	http.Redirect(w, r, s.oidc.authCodeURL(state, nonce, challenge), http.StatusFound)
}

// HandleCallback completes the OIDC flow: it validates state, exchanges the
// code, validates the ID token, maps roles, and mints a session cookie.
func (s *Service) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if !s.OIDCEnabled() {
		http.Error(w, "SSO login is not enabled", http.StatusNotFound)
		return
	}
	// Always clear the flow cookie; it is single-use.
	defer s.clearCookie(w, s.flowCookieName)

	c, err := r.Cookie(s.flowCookieName)
	if err != nil || c.Value == "" {
		s.loginError(w, "missing login state; please retry", http.StatusBadRequest)
		return
	}
	flow, err := s.codec.decodeFlow(c.Value)
	if err != nil {
		s.loginError(w, "invalid or expired login state; please retry", http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.loginError(w, "identity provider returned an error: "+e, http.StatusBadRequest)
		return
	}
	gotState := q.Get("state")
	if subtle.ConstantTimeCompare([]byte(gotState), []byte(flow.State)) != 1 {
		s.loginError(w, "state mismatch (possible CSRF); please retry", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.loginError(w, "authorization code missing", http.StatusBadRequest)
		return
	}

	tr, err := s.oidc.exchange(r.Context(), code, flow.Verifier)
	if err != nil {
		s.logger.Warn("adminauth: token exchange failed", "error", err)
		s.loginError(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	cl, err := s.oidc.validateIDToken(r.Context(), tr.IDToken, flow.Nonce)
	if err != nil {
		s.logger.Warn("adminauth: id_token validation failed", "error", err)
		s.loginError(w, "identity token validation failed", http.StatusUnauthorized)
		return
	}
	id, ok := s.identityFromClaims(cl, "oidc-session")
	if !ok {
		s.loginError(w, "your account has no admin roles assigned", http.StatusForbidden)
		return
	}
	sessionVal, err := s.codec.encodeSession(id, s.sessionTTL)
	if err != nil {
		s.loginError(w, "session creation failed", http.StatusInternalServerError)
		return
	}
	s.setCookie(w, s.cookieName, sessionVal, s.sessionTTL)
	s.metrics.recordLogin(true)
	s.logger.Info("adminauth: admin login", "subject", id.Subject, "roles", id.RoleStrings())

	dest := flow.ReturnTo
	if dest == "" {
		dest = s.cookiePath + "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// HandleLogout clears the session cookie.
func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, s.cookieName)
	s.metrics.recordLogout()
	// Prefer an XHR-friendly 204 when called programmatically; redirect a browser
	// navigation back to the dashboard root.
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, s.cookiePath+"/", http.StatusFound)
}

// userinfoResponse is the JSON returned by HandleUserinfo for the dashboard.
type userinfoResponse struct {
	Authenticated bool     `json:"authenticated"`
	Subject       string   `json:"subject,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
	Method        string   `json:"method,omitempty"`
	Tenant        string   `json:"tenant,omitempty"`
	OIDCEnabled   bool     `json:"oidcEnabled"`
	LoginURL      string   `json:"loginUrl,omitempty"`
	LogoutURL     string   `json:"logoutUrl,omitempty"`
}

// HandleUserinfo reports the caller's current identity (or that they are
// unauthenticated) so the dashboard can render a login affordance and gate
// controls by capability. It always responds 200.
func (s *Service) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	resp := userinfoResponse{
		OIDCEnabled: s.OIDCEnabled(),
		LoginURL:    s.LoginPath(),
	}
	if s.OIDCEnabled() {
		resp.LogoutURL = s.cookiePath + "/auth/logout"
	}
	if id, err := s.Authenticate(r.Context(), r); err == nil {
		resp.Authenticated = true
		resp.Subject = id.Subject
		resp.Roles = id.RoleStrings()
		resp.Capabilities = capabilityStrings(id)
		resp.Method = id.Method
		resp.Tenant = id.Tenant
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- helpers ----------------------------------------------------------------

func (s *Service) loginError(w http.ResponseWriter, msg string, code int) {
	s.metrics.recordLogin(false)
	http.Error(w, msg, code)
}

func (s *Service) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     s.cookieScope,
		Expires:  s.now().Add(ttl),
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     s.cookieScope,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// sanitizeReturn keeps post-login redirects on the admin surface to avoid an
// open-redirect: only same-origin paths under the admin prefix are honored.
func (s *Service) sanitizeReturn(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Reject absolute URLs and protocol-relative ("//host") targets.
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return ""
	}
	if !strings.HasPrefix(raw, s.cookiePath+"/") && raw != s.cookiePath {
		return ""
	}
	return raw
}

// capabilityStrings lists an identity's capabilities for the userinfo response.
func capabilityStrings(id *Identity) []string {
	var out []string
	for _, c := range []Capability{CapRead, CapOperate, CapApprove, CapAdminister, CapTenantViewer} {
		if id.Can(c) {
			out = append(out, c.String())
		}
	}
	return out
}

// bearerToken extracts a bearer-style token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	for _, prefix := range []string{"Bearer ", "bearer ", "token ", "Token "} {
		if strings.HasPrefix(h, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(h, prefix))
		}
	}
	return ""
}

// looksLikeJWT reports the three-segment compact-JWS shape.
func looksLikeJWT(tok string) bool {
	return strings.Count(tok, ".") == 2 && !strings.ContainsAny(tok, " ")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
