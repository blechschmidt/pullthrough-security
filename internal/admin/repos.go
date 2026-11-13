package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/adminauth"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
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
	// The dependency scans (Task 181).
	Scan(ctx context.Context, tenant, name, rev, by string) (repos.ScanTicket, error)
	ScanReport(ctx context.Context, tenant, name, rev string) (*repos.ScanReportView, error)
	ScanOverview(ctx context.Context, tenant, name string) (*repos.ScanOverview, error)
	ScanDocuments(ctx context.Context, tenant, name string) ([]findings.Document, error)
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
	case errors.As(err, new(*repos.ScanDisabledError)):
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

// handleReposScan queues a dependency scan of a repository's revision (Task
// 181): ?rev= is a tag, a branch or a commit; without it, the default branch's
// head is fetched and scanned. A tagged release is scanned through its pinned
// objects. The scan runs in the background, under the LLM gate's budget and
// limits; GET /api/repos/scan reads its report.
func (s *Server) handleReposScan(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	name := strings.TrimSpace(qp.Get("name"))
	ticket, err := reg.Scan(r.Context(), mcpTenant(r), name, strings.TrimSpace(qp.Get("rev")), actor(r))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusAccepted, ticket)
}

// handleReposScanReport returns the report of a repository's scan: of the
// revision ?rev= names, or of the default branch's head. ?verdict= narrows the
// dependencies listed to the verdicts named (malicious,suspicious,unscanned).
func (s *Server) handleReposScanReport(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	rep, err := reg.ScanReport(r.Context(), mcpTenant(r), strings.TrimSpace(qp.Get("name")), strings.TrimSpace(qp.Get("rev")))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	if v := strings.TrimSpace(qp.Get("verdict")); v != "" {
		want := map[string]bool{}
		for _, part := range strings.Split(v, ",") {
			want[strings.ToLower(strings.TrimSpace(part))] = true
		}
		kept := rep.Dependencies[:0:0]
		for _, d := range rep.Dependencies {
			if want[d.Verdict] {
				kept = append(kept, d)
			}
		}
		rep.Dependencies = kept
	}
	s.writeJSON(w, http.StatusOK, rep)
}

// handleReposScans returns a repository's scans at a glance: the default
// branch's head and its newest scan, every release scan, what is queued.
func (s *Server) handleReposScans(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	ov, err := reg.ScanOverview(r.Context(), mcpTenant(r), strings.TrimSpace(r.URL.Query().Get("name")))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, ov)
}

// handleReposScanSARIF exports a repository's scan as SARIF 2.1.0 for CI: each
// dependency that is not benign is a result located at the lock file and the
// line that pins it. ?rev= selects a revision's scan (default: the default
// branch's head); ?all=1 exports every current scan — the head and each release.
func (s *Server) handleReposScanSARIF(w http.ResponseWriter, r *http.Request) {
	reg, ok := s.repoRegistry(w)
	if !ok {
		return
	}
	qp := r.URL.Query()
	name := strings.TrimSpace(qp.Get("name"))
	version := "dev"
	if s.opts.Findings != nil {
		version = s.opts.Findings.ToolVersion()
	}
	opts := findings.SARIFOptions{ToolVersion: version}
	if all := qp.Get("all"); all == "1" || all == "true" {
		docs, err := reg.ScanDocuments(r.Context(), mcpTenant(r), name)
		if err != nil {
			s.writeRepoError(w, err)
			return
		}
		s.writeSARIF(w, findings.SARIFFromDocuments(docs, opts))
		return
	}
	rep, err := reg.ScanReport(r.Context(), mcpTenant(r), name, strings.TrimSpace(qp.Get("rev")))
	if err != nil {
		s.writeRepoError(w, err)
		return
	}
	doc := rep.FindingsDocument()
	s.writeSARIF(w, doc.SARIF(opts))
}
