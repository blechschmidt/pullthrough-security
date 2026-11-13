package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
)

// RepoRegistry is the repository registry (Task 180): registered repositories,
// their tag histories and their pinned releases. *repos.Service satisfies it.
type RepoRegistry interface {
	List(ctx context.Context, tenant string) ([]repos.RepoView, error)
	Show(ctx context.Context, tenant, name string) (*repos.RepoDetail, error)
	Add(ctx context.Context, r repos.Repo, by string) (repos.Repo, error)
	Remove(ctx context.Context, tenant, name, by string) error
	Sync(ctx context.Context, name, trigger string) (repos.SyncResult, error)
	Repin(ctx context.Context, tenant, name, commit string) error
	TagHistory(ctx context.Context, tenant, name, tag string) ([]repos.TagAssociation, error)
	VerifyHistory(ctx context.Context, tenant, name string) (int, error)
	Releases(ctx context.Context, tenant string, q repos.ReleaseQuery) ([]repos.ReleaseView, error)
	Lookup(ctx context.Context, tenant string, q repos.LookupQuery) ([]repos.ReleaseView, error)
	Stats() repos.Stats
}

// maxRepoBody bounds a registration request.
const maxRepoBody = 64 << 10

func (s *Server) repoRegistry(w http.ResponseWriter) (RepoRegistry, bool) {
	if s.opts.Repos == nil {
		s.writeError(w, http.StatusNotFound, "the repository registry is not enabled (repositories.enabled)")
		return nil, false
	}
	return s.opts.Repos, true
}

// writeRepoError maps the registry's errors onto HTTP statuses.
func (s *Server) writeRepoError(w http.ResponseWriter, err error) {
	var verr *repos.ValidationError
	var cerr *repos.ConflictError
	switch {
	case errors.Is(err, repos.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "no such repository or release")
	case errors.As(err, &verr):
		s.writeError(w, http.StatusBadRequest, verr.Error())
	case errors.As(err, &cerr):
		s.writeError(w, http.StatusConflict, cerr.Error())
	case errors.Is(err, repos.ErrHistoryTampered):
		s.writeError(w, http.StatusConflict, err.Error())
	default:
		s.logger.Error("admin: repository registry", "error", err)
		s.writeError(w, http.StatusInternalServerError, err.Error())
	}
}

// actor names the authenticated identity for the registry's records.
func actor(r *http.Request) string {
	if id, ok := adminauth.IdentityFromContext(r.Context()); ok && id != nil {
		return id.Subject
	}
	return "admin-token"
}

// handleReposList lists the registered repositories. The request is
// hard-scoped to the caller's tenant like the dossier: a tenant-bound identity
// sees its tenant's repositories only.
func (s *Server) handleReposList(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	list, err := reg.List(r.Context(), mcpTenant(r))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"repositories": list, "stats": reg.Stats()})
}

// handleReposAdd registers a repository (administer capability: the proxy
// then fetches from the URL). A tenant-bound identity registers for its own
// tenant only.
func (s *Server) handleReposAdd(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRepoBody))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}
	var repo repos.Repo
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&repo); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid registration: "+err.Error())
		return
	}
	if id, ok := adminauth.IdentityFromContext(r.Context()); ok && id != nil && id.Tenant != "" {
		if repo.Tenant != "" && repo.Tenant != id.Tenant {
			s.writeError(w, http.StatusForbidden, "a tenant-bound identity registers repositories for its own tenant only")
			return
		}
		// The roles decide which upstreams the release pinner may fetch
		// from on the repository's behalf; a tenant's administrator choosing
		// them could grant its tenant upstreams the operator has not.
		if len(repo.Roles) > 0 {
			s.writeError(w, http.StatusForbidden, "a tenant-bound identity cannot choose the roles the release pinner fetches with; the repository uses repositories.roles")
			return
		}
		repo.Tenant = id.Tenant
	}
	added, err := reg.Add(r.Context(), repo, actor(r))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusCreated, added)
}

// handleReposShow returns one repository with its current tags.
func (s *Server) handleReposShow(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	d, err := reg.Show(r.Context(), mcpTenant(r), strings.TrimSpace(r.URL.Query().Get("name")))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, d)
}

// handleReposTags returns a repository's tag history: every commit each tag
// pointed at, with first/last seen and what superseded it.
func (s *Server) handleReposTags(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	name := strings.TrimSpace(qp.Get("name"))
	hist, err := reg.TagHistory(r.Context(), mcpTenant(r), name, strings.TrimSpace(qp.Get("tag")))
	verified := err == nil
	if err != nil && !errors.Is(err, repos.ErrHistoryTampered) {
		s.writeRepoError(w, err)
		return
	}
	out := map[string]any{"repo": name, "verified": verified, "associations": hist}
	if err != nil {
		out["error"] = err.Error()
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleReposVerify verifies a repository's hash-chained tag history.
func (s *Server) handleReposVerify(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	n, err := reg.VerifyHistory(r.Context(), mcpTenant(r), name)
	if err != nil && !errors.Is(err, repos.ErrHistoryTampered) {
		s.writeRepoError(w, err)
		return
	}
	out := map[string]any{"repo": name, "records": n, "verified": err == nil}
	if err != nil {
		out["error"] = err.Error()
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleReposReleases returns releases by repository and tag (the commit the
// tag points at now and every one it pointed at before) or by commit, across
// repositories when no repository is named.
func (s *Server) handleReposReleases(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	q := repos.ReleaseQuery{
		Repo:   strings.TrimSpace(firstQuery(qp.Get("name"), qp.Get("repo"))),
		Tag:    strings.TrimSpace(qp.Get("tag")),
		Commit: strings.TrimSpace(qp.Get("commit")),
		Full:   qp.Get("full") == "1" || qp.Get("full") == "true",
	}
	rel, err := reg.Releases(r.Context(), mcpTenant(r), q)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"releases": rel})
}

// handleReposLookup answers "which releases contain this?" for a coordinate
// ("coordinate=npm/lodash@4.17.21", or type/name/version parameters; without a
// version every version) or a digest ("digest=sha256:…").
func (s *Server) handleReposLookup(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	q := repos.LookupQuery{
		Type:    strings.TrimSpace(firstQuery(qp.Get("type"), qp.Get("ecosystem"))),
		Name:    strings.TrimSpace(qp.Get("name")),
		Version: strings.TrimSpace(qp.Get("version")),
		Digest:  strings.TrimSpace(qp.Get("digest")),
	}
	if c := strings.TrimSpace(qp.Get("coordinate")); c != "" {
		parsed, err := repos.ParseCoordinate(c)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		q.Type, q.Name, q.Version = parsed.Type, parsed.Name, parsed.Version
	}
	rel, err := reg.Lookup(r.Context(), mcpTenant(r), q)
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"releases": rel})
}

// handleReposSync syncs a repository's tags now.
func (s *Server) handleReposSync(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if _, err := reg.Show(r.Context(), mcpTenant(r), name); err != nil {
		s.writeRepoError(w, err)
		return
	}
	res, err := reg.Sync(r.Context(), name, "manual")
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleReposPin queues a release of a repository for pinning now.
func (s *Server) handleReposPin(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	name, commit := strings.TrimSpace(qp.Get("name")), strings.TrimSpace(qp.Get("commit"))
	if err := reg.Repin(r.Context(), mcpTenant(r), name, commit); err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued", "repo": name, "commit": commit})
}

// handleReposRemove stops tracking an API registration; its history,
// releases and pins are kept.
func (s *Server) handleReposRemove(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if err := reg.Remove(r.Context(), mcpTenant(r), name, actor(r)); err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "removed", "repo": name,
		"note": "its tag history, release manifests and pins are kept"})
}
