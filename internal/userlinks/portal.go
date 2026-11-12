package userlinks

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/onboard"
)

// The self-service page: where a user signs in, creates links, sees when each
// was last used and from where, and revokes them.
//
//	GET  <ui>/                    the page
//	GET  <ui>/login               start a sign-in at the identity provider
//	GET  <ui>/callback            the provider sends the browser back here
//	POST <ui>/logout              end the session
//	GET  <ui>/api/session         who is signed in, and what the page needs to know
//	GET  <ui>/api/links           the signed-in user's links
//	POST <ui>/api/links           create a link — the one response that carries a token
//	POST <ui>/api/links/revoke    revoke one of the user's links

//go:embed ui
var uiFiles embed.FS

// uiFS is the embedded page, rooted at its directory.
var uiFS = func() fs.FS {
	sub, err := fs.Sub(uiFiles, "ui")
	if err != nil {
		panic("userlinks: embedding the page: " + err.Error())
	}
	return sub
}()

// Cookie names. Served over HTTPS they carry the __Secure- prefix (see
// cookieName).
const (
	sessionCookie = "pt_links_session"
	flowCookie    = "pt_links_flow"
)

// cookieName returns the name a cookie is set under. With Secure cookies the
// name carries the __Secure- prefix, which a browser accepts only from a secure
// origin and only with the Secure attribute: a sibling host or a response over
// plain HTTP cannot plant a sign-in flow or a session of its choosing.
func (s *Service) cookieName(name string) string {
	if s.secure {
		return "__Secure-" + name
	}
	return name
}

// csrfHeader must accompany every request that changes something. A browser
// lets a page of another origin send a cookie-carrying POST, but not one with a
// header of the page's own choosing — not without asking the proxy first, which
// answers no such question.
const csrfHeader = "X-Pullthrough-Links"

// maxRequestBody bounds the body of an API request.
const maxRequestBody = 8 << 10

// Handler returns the handler of the self-service page. It serves absolute
// paths under UIPath; the gateway mounts it there.
func (s *Service) Handler() http.Handler {
	if s == nil {
		return http.NotFoundHandler()
	}
	return s.mux
}

func (s *Service) routes() *http.ServeMux {
	mux := http.NewServeMux()
	ui := s.uiPath
	page := func(h http.HandlerFunc) http.Handler { return s.withHeaders(h, false) }
	api := func(h http.HandlerFunc) http.Handler { return s.withHeaders(h, true) }

	mux.Handle("GET "+ui, page(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.pagePath+"/", http.StatusPermanentRedirect)
	}))
	mux.Handle("GET "+ui+"/{$}", page(s.asset("index.html")))
	mux.Handle("GET "+ui+"/app.js", page(s.asset("app.js")))
	mux.Handle("GET "+ui+"/styles.css", page(s.asset("styles.css")))

	mux.Handle("GET "+ui+"/login", api(s.handleLogin))
	mux.Handle("GET "+ui+"/callback", api(s.handleCallback))
	mux.Handle("POST "+ui+"/logout", api(s.handleLogout))

	mux.Handle("GET "+ui+"/api/session", api(s.handleSession))
	mux.Handle("GET "+ui+"/api/links", api(s.handleListLinks))
	mux.Handle("POST "+ui+"/api/links", api(s.handleCreateLink))
	mux.Handle("POST "+ui+"/api/links/revoke", api(s.handleRevokeLink))
	return mux
}

// withHeaders sets the headers every response of the page carries.
//
// The page shows a secret — a new link — and manages credentials, so it gets
// the strictest policy that still lets it work: only its own script and style,
// no framing, no referrer, nothing sniffed. Responses that are not static
// assets are never stored: one of them carries a token.
func (s *Service) withHeaders(next http.HandlerFunc, dynamic bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if dynamic {
			h.Set("Cache-Control", "no-store")
		} else {
			h.Set("Cache-Control", "no-cache")
		}
		next(w, r)
	})
}

func (s *Service) asset(name string) http.HandlerFunc {
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(name, ".html"):
		contentType = "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		contentType = "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		contentType = "text/css; charset=utf-8"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(uiFS, name)
		if err != nil {
			http.Error(w, "the page is unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
	}
}

// --- sign-in ----------------------------------------------------------------

// messagePage is the one HTML page the sign-in flow renders itself: what went
// wrong, and the way back. Its text is escaped by the template; some of it
// comes from the query string of a URL anyone can construct.
var messagePage = template.Must(template.New("message").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Title}} — personal cache links</title>
<link rel="stylesheet" href="{{.UI}}/styles.css">
</head>
<body>
<main id="main" class="narrow">
<div class="panel" role="alert">
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
<p><a class="btn" href="{{.UI}}/">Back to your links</a></p>
</div>
</main>
</body>
</html>
`))

func (s *Service) renderMessage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = messagePage.Execute(w, struct{ Title, Message, UI string }{title, message, s.pagePath})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.renderMessage(w, http.StatusNotFound, "Sign-in is not configured",
			"This proxy has no identity provider configured for cache users. Ask your administrator for a personal link.")
		return
	}
	s.counters.signInsStarted.Add(1)
	verifier, challenge, err := newPKCE()
	state, err1 := randomString(24)
	nonce, err2 := randomString(24)
	if err != nil || err1 != nil || err2 != nil {
		s.counters.signInsFailed.Add(1)
		s.renderMessage(w, http.StatusInternalServerError, "Sign-in failed", "The sign-in could not be started. Please try again.")
		return
	}
	target, err := s.oidc.authCodeURL(r.Context(), state, nonce, challenge)
	if err != nil {
		s.counters.signInsFailed.Add(1)
		s.logger.Warn("personal links: the identity provider cannot be used for sign-in", "error", err)
		s.renderMessage(w, http.StatusServiceUnavailable, "Sign-in is unavailable",
			"The identity provider cannot be reached at the moment. Your existing links keep working; please try signing in again shortly.")
		return
	}
	value, err := s.codec.encodeFlow(flowClaims{State: state, Verifier: verifier, Nonce: nonce}, flowTTL)
	if err != nil {
		s.counters.signInsFailed.Add(1)
		s.renderMessage(w, http.StatusInternalServerError, "Sign-in failed", "The sign-in could not be started. Please try again.")
		return
	}
	s.setCookie(w, flowCookie, value, flowTTL)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *Service) handleCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.renderMessage(w, http.StatusNotFound, "Sign-in is not configured", "This proxy has no identity provider configured for cache users.")
		return
	}
	// The flow cookie is for one sign-in; whatever comes of this request, it is
	// spent.
	s.clearCookie(w, flowCookie)
	fail := func(status int, message string, logArgs ...any) {
		s.counters.signInsFailed.Add(1)
		if len(logArgs) > 0 {
			s.logger.Warn("personal links: sign-in failed", logArgs...)
		}
		s.renderMessage(w, status, "Sign-in failed", message)
	}

	c, err := r.Cookie(s.cookieName(flowCookie))
	if err != nil || c.Value == "" {
		fail(http.StatusBadRequest, "This sign-in was not started here, or took too long. Please start again.")
		return
	}
	flow, err := s.codec.decodeFlow(c.Value)
	if err != nil {
		fail(http.StatusBadRequest, "This sign-in took too long or was tampered with. Please start again.")
		return
	}
	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		fail(http.StatusBadRequest, "The answer of the identity provider does not belong to the sign-in you started. Please start again.")
		return
	}
	if e := q.Get("error"); e != "" {
		fail(http.StatusBadRequest, "The identity provider did not sign you in ("+cleanText(e, 64)+").",
			"providerError", cleanText(e, 64), "description", cleanText(q.Get("error_description"), 256))
		return
	}
	code := q.Get("code")
	if code == "" {
		fail(http.StatusBadRequest, "The identity provider sent no authorization code. Please start again.")
		return
	}

	idToken, err := s.oidc.exchange(r.Context(), code, flow.Verifier)
	if err != nil {
		fail(http.StatusBadGateway, "The identity provider could not complete the sign-in. Please try again.", "error", err)
		return
	}
	claims, err := s.oidc.verifyIDToken(r.Context(), idToken, flow.Nonce)
	if err != nil {
		fail(http.StatusBadGateway, "The identity provider's answer could not be verified. Please try again.", "error", err)
		return
	}
	id, err := s.identityFromClaims(claims)
	if err != nil {
		var denied *signInDenied
		if !errors.As(err, &denied) {
			fail(http.StatusInternalServerError, "The sign-in could not be completed.", "error", err)
			return
		}
		s.counters.signInsDenied.Add(1)
		s.record(r.Context(), audit.Event{
			Type: audit.EventAuth, Decision: audit.DecisionDeny,
			Subject:    cleanText(claimString(claims, "email"), maxSubjectLen),
			Reason:     "userlinks: sign-in refused: " + denied.why,
			RemoteAddr: s.clientIP(r), Status: http.StatusForbidden,
			Detail: map[string]any{"issuer": cleanText(claimString(claims, "iss"), maxIssuerLen)},
		})
		s.renderMessage(w, http.StatusForbidden, "You cannot use the cache with this account", "Sign-in was refused: "+denied.why+".")
		return
	}

	value, err := s.codec.encodeSession(id, s.sessionTTL)
	if err != nil {
		fail(http.StatusInternalServerError, "The sign-in could not be completed.", "error", err)
		return
	}
	s.setCookie(w, sessionCookie, value, s.sessionTTL)
	s.counters.signInsCompleted.Add(1)
	s.record(r.Context(), audit.Event{
		Type: audit.EventAuth, Subject: id.Subject, Team: id.Team, Decision: audit.DecisionAllow,
		Reason:     "userlinks: sign-in",
		RemoteAddr: s.clientIP(r), Status: http.StatusOK,
		Detail: map[string]any{"issuer": id.Issuer, "authMethod": "oidc"},
	})
	s.logger.Info("personal links: user signed in", "subject", id.Subject, "team", id.Team)
	http.Redirect(w, r, s.pagePath+"/", http.StatusFound)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.guardWrite(w, r) {
		return
	}
	s.clearCookie(w, sessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(name),
		Value:    value,
		Path:     s.pagePath,
		MaxAge:   int(ttl / time.Second),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(name),
		Value:    "",
		Path:     s.pagePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// signedIn returns who is signed in on a request, and until when.
func (s *Service) signedIn(r *http.Request) (Identity, time.Time, bool) {
	if s.codec == nil {
		return Identity{}, time.Time{}, false
	}
	c, err := r.Cookie(s.cookieName(sessionCookie))
	if err != nil || c.Value == "" {
		return Identity{}, time.Time{}, false
	}
	id, issuedAt, err := s.codec.decodeSession(c.Value)
	if err != nil {
		return Identity{}, time.Time{}, false
	}
	// A session that predates "revoke everything of this user" ended with it.
	if !s.registry.SessionValid(id.Subject, issuedAt) {
		return Identity{}, time.Time{}, false
	}
	return id, issuedAt.Add(s.sessionTTL), true
}

// guardWrite refuses a state-changing request that a page of another origin
// could have caused the browser to send.
func (s *Service) guardWrite(w http.ResponseWriter, r *http.Request) bool {
	ok := r.Header.Get(csrfHeader) != ""
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		ok = false
	}
	if origin := r.Header.Get("Origin"); origin != "" && !s.sameOrigin(origin, r) {
		ok = false
	}
	if !ok {
		s.writeError(w, http.StatusForbidden, "this request did not come from the links page")
	}
	return ok
}

// sameOrigin reports whether an Origin header names this proxy: the host the
// request was addressed to, or the host of the configured public URL. The
// scheme is not compared — behind a TLS-terminating load balancer the proxy
// sees plain HTTP for a page the browser loaded over HTTPS.
func (s *Service) sameOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	pub, err := url.Parse(s.publicURL)
	return err == nil && strings.EqualFold(u.Host, pub.Host)
}

// --- API --------------------------------------------------------------------

func (s *Service) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Service) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// upstreamView is one configured upstream as the page lists it.
type upstreamView struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// URL is the user's personal URL of the upstream. Present only in the
	// response that creates a link.
	URL string `json:"url,omitempty"`
	// Snippets configure the upstream's client tool to use the personal URL;
	// TokenSnippets to present the link's token as a credential instead.
	Snippets      []onboard.Snippet `json:"snippets,omitempty"`
	TokenSnippets []onboard.Snippet `json:"tokenSnippets,omitempty"`
}

// sessionResponse tells the page who is signed in and what it needs to render.
type sessionResponse struct {
	Authenticated bool `json:"authenticated"`
	// SignInEnabled is false when no identity provider is configured.
	SignInEnabled bool      `json:"signInEnabled"`
	SignInURL     string    `json:"signInUrl,omitempty"`
	User          *Identity `json:"user,omitempty"`
	// SessionExpiresAt is when the user has to sign in again.
	SessionExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
	// PublicURL and PathPrefix say what a personal URL looks like.
	PublicURL  string `json:"publicUrl"`
	PathPrefix string `json:"pathPrefix"`
	// LinkTTLSeconds is how long a new link works (0: it does not expire);
	// MaxLinks how many working links a user may hold (0: no bound).
	LinkTTLSeconds int64          `json:"linkTtlSeconds"`
	MaxLinks       int            `json:"maxLinks"`
	Upstreams      []upstreamView `json:"upstreams"`
}

func (s *Service) handleSession(w http.ResponseWriter, r *http.Request) {
	resp := sessionResponse{
		SignInEnabled:  s.oidc != nil,
		PublicURL:      s.publicURL,
		PathPrefix:     s.prefix,
		LinkTTLSeconds: int64(s.registry.LinkTTL() / time.Second),
		MaxLinks:       s.registry.MaxLinksPerUser(),
		Upstreams:      []upstreamView{},
	}
	if s.oidc != nil {
		resp.SignInURL = s.pagePath + "/login"
	}
	if id, expires, ok := s.signedIn(r); ok {
		resp.Authenticated = true
		resp.User = &id
		resp.SessionExpiresAt = &expires
		for _, b := range s.sortedBackends() {
			resp.Upstreams = append(resp.Upstreams, upstreamView{Name: b.Name, Type: b.Type})
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// requireUser returns the signed-in user, or answers 401.
func (s *Service) requireUser(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	id, _, ok := s.signedIn(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "sign in to manage your links")
	}
	return id, ok
}

func (s *Service) handleListLinks(w http.ResponseWriter, r *http.Request) {
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"links": s.registry.List(Filter{Subject: id.Subject})})
}

// createRequest is the body of a request to create a link.
type createRequest struct {
	Label string `json:"label"`
	// TTLDays shortens the link's lifetime. Zero means the configured default.
	TTLDays int `json:"ttlDays"`
}

// createResponse is the one response that carries a link's token. Nothing the
// proxy stores can reproduce it.
type createResponse struct {
	Token string `json:"token"`
	Link  Info   `json:"link"`
	// BaseURL is what stands before "/v1/<upstream>" in the user's personal URLs.
	BaseURL   string         `json:"baseUrl"`
	Upstreams []upstreamView `json:"upstreams"`
}

func (s *Service) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	if !s.guardWrite(w, r) {
		return
	}
	id, sessionEnds, ok := s.signedIn(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "sign in to manage your links")
		return
	}
	var req createRequest
	if !s.readBody(w, r, &req) {
		return
	}
	if req.TTLDays < 0 || req.TTLDays > 3660 {
		s.writeError(w, http.StatusBadRequest, "ttlDays must be between 0 and 3660")
		return
	}
	if !s.creation.allow(id.Subject, s.now()) {
		w.Header().Set("Retry-After", "600")
		s.writeError(w, http.StatusTooManyRequests, "too many links were created in the last hour; try again later")
		return
	}

	from := s.clientIP(r)
	token, info, err := s.registry.Issue(r.Context(), id, IssueOptions{
		Label:           req.Label,
		TTL:             time.Duration(req.TTLDays) * 24 * time.Hour,
		From:            from,
		SessionIssuedAt: sessionEnds.Add(-s.sessionTTL),
	})
	switch {
	case errors.Is(err, ErrSessionEnded):
		s.writeError(w, http.StatusUnauthorized, "sign in to manage your links")
		return
	case errors.Is(err, ErrTooManyLinks):
		s.writeError(w, http.StatusConflict, "you already have the maximum number of links; revoke one you no longer use first")
		return
	case err != nil:
		s.logger.Error("personal links: creating a link failed", "subject", id.Subject, "error", err)
		s.writeError(w, http.StatusServiceUnavailable, "the link could not be created; try again shortly")
		return
	}
	s.record(r.Context(), audit.Event{
		Type: audit.EventAuth, Subject: id.Subject, Team: id.Team, Decision: audit.DecisionAllow,
		Reason:     "userlinks: link issued",
		RemoteAddr: from, Status: http.StatusCreated,
		Detail: linkDetail(info, nil),
	})
	s.logger.Info("personal links: link created", "subject", id.Subject, "link", info.ID)

	resp := createResponse{Token: token, Link: info, BaseURL: s.PersonalBase(token), Upstreams: s.upstreamViews(token)}
	s.writeJSON(w, http.StatusCreated, resp)
}

// upstreamViews renders, for a new link, the personal URL and the client
// configuration of every upstream.
func (s *Service) upstreamViews(token string) []upstreamView {
	host := s.publicURL
	if u, err := url.Parse(s.publicURL); err == nil {
		host = u.Host
	}
	personal := onboard.Context{ProxyBase: s.publicURL, Host: host, Personal: s.prefix + "/" + token}
	credential := onboard.Context{ProxyBase: s.publicURL, Host: host, Token: token}
	views := []upstreamView{}
	for _, b := range s.sortedBackends() {
		v := upstreamView{
			Name:     b.Name,
			Type:     b.Type,
			URL:      s.PersonalBase(token) + "/v1/" + b.Name + "/",
			Snippets: onboard.For(personal, b),
		}
		if s.cfg.TokenSnippets {
			v.TokenSnippets = onboard.For(credential, b)
		}
		views = append(views, v)
	}
	return views
}

func (s *Service) handleRevokeLink(w http.ResponseWriter, r *http.Request) {
	if !s.guardWrite(w, r) {
		return
	}
	id, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !s.readBody(w, r, &req) {
		return
	}
	// A user revokes their own links. Someone else's link is, to them, no link:
	// the answer does not say whether the identifier exists.
	info, found := s.registry.Get(req.ID)
	if !found || info.Subject != id.Subject {
		s.writeError(w, http.StatusNotFound, "you have no such link")
		return
	}
	info, err := s.Revoke(r.Context(), req.ID, id.Subject, "revoked by its owner", s.clientIP(r))
	if err != nil {
		s.logger.Error("personal links: revoking a link failed", "subject", id.Subject, "link", req.ID, "error", err)
		s.writeError(w, http.StatusServiceUnavailable, "the link could not be revoked; try again shortly")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"link": info})
}

// readBody decodes a small JSON request body.
func (s *Service) readBody(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil || len(data) > maxRequestBody {
		s.writeError(w, http.StatusBadRequest, "the request body is too large or unreadable")
		return false
	}
	if len(data) == 0 {
		return true
	}
	if err := json.Unmarshal(data, v); err != nil {
		s.writeError(w, http.StatusBadRequest, "the request body is not valid JSON")
		return false
	}
	return true
}

// --- creation rate ----------------------------------------------------------

// Bounds on how fast one user may create links. A link is cheap, but every one
// is a record that is kept for a while after it ends; a script in a loop must
// not be able to fill the store.
const (
	creationsPerHour     = 20
	maxCreationSubjects  = 8192
	creationWindowLength = time.Hour
)

// creationLimiter counts each user's recent link creations.
type creationLimiter struct {
	mu     sync.Mutex
	recent map[string][]time.Time
}

func newCreationLimiter() *creationLimiter {
	return &creationLimiter{recent: map[string][]time.Time{}}
}

// allow reports whether subject may create another link now, and counts it.
func (l *creationLimiter) allow(subject string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-creationWindowLength)
	kept := l.recent[subject][:0]
	for _, t := range l.recent[subject] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= creationsPerHour {
		l.recent[subject] = kept
		return false
	}
	if len(l.recent) >= maxCreationSubjects {
		// Too many users to remember individually: forget those whose window
		// has passed, and if that is not enough, everyone.
		for subj, times := range l.recent {
			if len(times) == 0 || !times[len(times)-1].After(cutoff) {
				delete(l.recent, subj)
			}
		}
		if len(l.recent) >= maxCreationSubjects {
			l.recent = map[string][]time.Time{}
		}
	}
	l.recent[subject] = append(kept, now)
	return true
}
