package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/userlinks"
)

// UserLinksManager is the operator's surface of personal cache links (Task
// 177): the links users created after signing in through the identity provider,
// who they belong to, when each was last used and from where — and the means to
// end them. *userlinks.Service satisfies it.
type UserLinksManager interface {
	Enabled() bool
	// SignInEnabled reports whether users can sign in and create links
	// themselves (an identity provider is configured).
	SignInEnabled() bool
	// PageURL is the public URL of the self-service page; PathPrefix the first
	// path segment of a personal URL.
	PageURL() string
	PathPrefix() string
	Links(f userlinks.Filter) []userlinks.Info
	Issue(ctx context.Context, id userlinks.Identity, opts userlinks.IssueOptions) (token, base string, info userlinks.Info, err error)
	Revoke(ctx context.Context, id, by, reason, from string) (userlinks.Info, error)
	RevokeUser(ctx context.Context, subject, by, reason, from string) (int, time.Time, error)
	Metrics() userlinks.Metrics
}

// userLinksUser is one user in the listing: how many links they hold and when
// any of them was last used.
type userLinksUser struct {
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
	Team    string `json:"team,omitempty"`
	// Links is how many links the registry holds for the user; Active how many
	// of them work.
	Links  int `json:"links"`
	Active int `json:"active"`
	// LastUsedAt and LastAddr are the most recent use of any of the user's links.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
	LastAddr   string     `json:"lastAddr,omitempty"`
}

// userLinksResponse is the body of GET /api/userlinks.
type userLinksResponse struct {
	// Enabled is false when personal links are switched off (userLinks.enabled);
	// the rest is then empty.
	Enabled bool `json:"enabled"`
	// SignIn reports whether users can sign in themselves; PageURL is where.
	SignIn     bool   `json:"signIn"`
	PageURL    string `json:"pageUrl,omitempty"`
	PathPrefix string `json:"pathPrefix,omitempty"`
	// Registry describes the link registry: how many links and users, and
	// whether it can reach its store.
	Registry userlinks.Stats `json:"registry"`
	// Total is the number of links matching the filter; Links holds at most
	// `limit` of them, newest first.
	Total int              `json:"total"`
	Links []userlinks.Info `json:"links"`
	// Users summarizes the matching links per user, busiest first.
	Users []userLinksUser `json:"users"`
}

// userLinks returns the manager when personal links are wired and enabled.
func (s *Server) userLinks() (UserLinksManager, bool) {
	if s.opts.UserLinks == nil || !s.opts.UserLinks.Enabled() {
		return nil, false
	}
	return s.opts.UserLinks, true
}

// Limits on the listing.
const (
	userLinksDefaultLimit = 200
	userLinksMaxLimit     = 2000
)

// handleUserLinks lists the personal cache links: whose they are, their state,
// and when each was last used and from which address. No response of this
// endpoint contains a token — the proxy does not have them. Guarded by the read
// capability. Query parameters, all optional and ANDed:
//
//	subject  one user's links (exact)
//	state    active | expired | revoked
//	q        free-text search over user, name, team, label, link id and last address
//	limit    how many links to return (default 200, at most 2000)
func (s *Server) handleUserLinks(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.userLinks()
	if !ok {
		s.writeJSON(w, http.StatusOK, userLinksResponse{Links: []userlinks.Info{}, Users: []userLinksUser{}})
		return
	}
	q := r.URL.Query()
	filter := userlinks.Filter{
		Subject: strings.TrimSpace(q.Get("subject")),
		Search:  strings.TrimSpace(q.Get("q")),
	}
	switch state := strings.ToLower(strings.TrimSpace(q.Get("state"))); state {
	case "":
	case string(userlinks.StateActive), string(userlinks.StateExpired), string(userlinks.StateRevoked):
		filter.State = userlinks.State(state)
	default:
		s.writeError(w, http.StatusBadRequest, "unknown state "+strconv.Quote(state)+" (want active, expired or revoked)")
		return
	}
	limit := userLinksDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			s.writeError(w, http.StatusBadRequest, "invalid limit: "+strconv.Quote(raw)+" is not a positive integer")
			return
		}
		limit = min(n, userLinksMaxLimit)
	}

	links := mgr.Links(filter)
	resp := userLinksResponse{
		Enabled:    true,
		SignIn:     mgr.SignInEnabled(),
		PageURL:    mgr.PageURL(),
		PathPrefix: mgr.PathPrefix(),
		Registry:   mgr.Metrics().Registry,
		Total:      len(links),
		Users:      summarizeLinkUsers(links),
	}
	if len(links) > limit {
		links = links[:limit]
	}
	if links == nil {
		links = []userlinks.Info{}
	}
	resp.Links = links
	s.writeJSON(w, http.StatusOK, resp)
}

// summarizeLinkUsers groups links by user: most working links first, then the
// most recently active.
func summarizeLinkUsers(links []userlinks.Info) []userLinksUser {
	byUser := map[string]*userLinksUser{}
	for _, l := range links {
		u := byUser[l.Subject]
		if u == nil {
			u = &userLinksUser{Subject: l.Subject, Name: l.Name, Team: l.Team}
			byUser[l.Subject] = u
		}
		u.Links++
		if l.State == userlinks.StateActive {
			u.Active++
		}
		if l.LastUsedAt != nil && (u.LastUsedAt == nil || l.LastUsedAt.After(*u.LastUsedAt)) {
			at := *l.LastUsedAt
			u.LastUsedAt, u.LastAddr = &at, l.LastAddr
		}
	}
	out := make([]userLinksUser, 0, len(byUser))
	for _, u := range byUser {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Active != b.Active {
			return a.Active > b.Active
		}
		at, bt := time.Time{}, time.Time{}
		if a.LastUsedAt != nil {
			at = *a.LastUsedAt
		}
		if b.LastUsedAt != nil {
			bt = *b.LastUsedAt
		}
		if !at.Equal(bt) {
			return at.After(bt)
		}
		return a.Subject < b.Subject
	})
	return out
}

// userLinksRevokeRequest is the body of POST /api/userlinks/revoke: one link,
// or everything issued to one user.
type userLinksRevokeRequest struct {
	// ID revokes one link.
	ID string `json:"id"`
	// Subject revokes every link of that user, and ends their sign-in sessions
	// on the self-service page. It is how a user who left is cut off: it covers
	// links this replica has not even seen yet.
	Subject string `json:"subject"`
	// Reason is recorded with the revocation.
	Reason string `json:"reason"`
}

// handleUserLinksRevoke revokes one link ({"id": …}) or everything issued to a
// user ({"subject": …}). Guarded by the operate capability.
func (s *Server) handleUserLinksRevoke(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.userLinks()
	if !ok {
		s.writeError(w, http.StatusNotFound, "personal links are not enabled")
		return
	}
	var req userLinksRevokeRequest
	if !s.decodeJSON(w, r, 16<<10, &req) {
		return
	}
	req.ID, req.Subject = strings.TrimSpace(req.ID), strings.TrimSpace(req.Subject)
	actor, from := actorSubject(r), clientIP(r)
	switch {
	case (req.ID == "") == (req.Subject == ""):
		s.writeError(w, http.StatusBadRequest, "name exactly one of id (one link) or subject (everything issued to a user)")

	case req.ID != "":
		info, err := mgr.Revoke(r.Context(), req.ID, actor, req.Reason, from)
		switch {
		case errors.Is(err, userlinks.ErrNoSuchLink):
			s.writeError(w, http.StatusNotFound, "no such link")
		case err != nil:
			s.logger.Error("admin: revoking a personal link failed", "link", req.ID, "error", err)
			s.writeError(w, http.StatusServiceUnavailable, "the link could not be revoked: the link registry's store is unavailable")
		default:
			s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "link": info})
		}

	default:
		n, notBefore, err := mgr.RevokeUser(r.Context(), req.Subject, actor, req.Reason, from)
		if err != nil {
			s.logger.Error("admin: revoking a user's personal links failed", "subject", req.Subject, "error", err)
			s.writeError(w, http.StatusServiceUnavailable, "the user's links could not be revoked: the link registry's store is unavailable")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "subject": req.Subject, "revoked": n, "notBefore": notBefore,
		})
	}
}

// userLinksIssueRequest is the body of POST /api/userlinks/issue.
type userLinksIssueRequest struct {
	// Subject is who the link's downloads are recorded as. Required.
	Subject string   `json:"subject"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Team    string   `json:"team"`
	Roles   []string `json:"roles"`
	// Label names the link; TTLDays shortens its lifetime (0: the configured
	// default).
	Label   string `json:"label"`
	TTLDays int    `json:"ttlDays"`
}

// handleUserLinksIssue creates a link for an identity the administrator names:
// for a service account that cannot sign in, or where no identity provider is
// configured. The response carries the link's token — once.
//
// It mints a credential for an identity of the caller's choosing, with roles of
// the caller's choosing. It therefore requires the administer capability, and
// it is refused outright on an admin surface that authenticates no one: there,
// anyone who can reach the proxy could otherwise write any name into the
// download log and, with access control on, give themselves any role.
func (s *Server) handleUserLinksIssue(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.userLinks()
	if !ok {
		s.writeError(w, http.StatusNotFound, "personal links are not enabled")
		return
	}
	if s.opts.AdminAuth == nil && s.opts.Token == "" {
		s.writeError(w, http.StatusForbidden,
			"issuing a link names the identity it is for, so it needs an authenticated admin surface: set observability.adminToken or adminAuth")
		return
	}
	var req userLinksIssueRequest
	if !s.decodeJSON(w, r, 16<<10, &req) {
		return
	}
	if strings.TrimSpace(req.Subject) == "" {
		s.writeError(w, http.StatusBadRequest, "subject is required: who the link's downloads are recorded as")
		return
	}
	if req.TTLDays < 0 || req.TTLDays > 3660 {
		s.writeError(w, http.StatusBadRequest, "ttlDays must be between 0 and 3660")
		return
	}
	token, base, info, err := mgr.Issue(r.Context(),
		userlinks.Identity{Subject: req.Subject, Name: req.Name, Email: req.Email, Team: req.Team, Roles: req.Roles},
		userlinks.IssueOptions{
			Label:    req.Label,
			TTL:      time.Duration(req.TTLDays) * 24 * time.Hour,
			From:     clientIP(r),
			IssuedBy: actorSubject(r),
		})
	switch {
	case errors.Is(err, userlinks.ErrTooManyLinks):
		s.writeError(w, http.StatusConflict, "the user already has the maximum number of links; revoke one first")
		return
	case errors.Is(err, userlinks.ErrBadSubject):
		s.writeError(w, http.StatusBadRequest, "the subject cannot be used as one (too long, or containing control characters)")
		return
	case err != nil:
		s.logger.Error("admin: issuing a personal link failed", "subject", req.Subject, "error", err)
		s.writeError(w, http.StatusServiceUnavailable, "the link could not be created: the link registry's store is unavailable")
		return
	}
	// The one response that carries a token must not be kept by anything.
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "token": token, "baseUrl": base, "link": info,
	})
}
