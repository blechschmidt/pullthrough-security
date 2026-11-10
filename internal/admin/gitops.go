package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/gitops"
)

// The admin "GitOps" surface (Task 93) exposes the policy & config synchronization
// subsystem: read the reconciliation status (source of truth, last revision, drift,
// pending change awaiting approval, apply history), force an immediate sync, and
// roll back to the last-known-good applied revision. Sync and rollback rewrite the
// on-disk configuration, so they are administrator-only (see authz.go).

// gitopsResponse is the reconciliation status plus cumulative metrics for the tab.
type gitopsResponse struct {
	Status  gitops.Status   `json:"status"`
	Metrics gitops.Snapshot `json:"metrics"`
}

func (s *Server) gitopsEnabled(w http.ResponseWriter) bool {
	if s.opts.Gitops == nil || !s.opts.Gitops.Enabled() {
		s.writeError(w, http.StatusNotFound, "GitOps policy/config synchronization is not enabled")
		return false
	}
	return true
}

// handleGitops serves the current reconciliation status and metrics.
func (s *Server) handleGitops(w http.ResponseWriter, r *http.Request) {
	if !s.gitopsEnabled(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, gitopsResponse{
		Status:  s.opts.Gitops.Status(),
		Metrics: s.opts.Gitops.Metrics(),
	})
}

// gitopsSyncResponse returns the reconcile outcome alongside the refreshed status.
type gitopsSyncResponse struct {
	Outcome gitops.Outcome `json:"outcome"`
	Status  gitops.Status  `json:"status"`
}

// handleGitopsSync forces an immediate reconcile against the source of truth.
func (s *Server) handleGitopsSync(w http.ResponseWriter, r *http.Request) {
	if !s.gitopsEnabled(w) {
		return
	}
	out, err := s.opts.Gitops.Sync(r.Context(), actorSubject(r))
	if err != nil {
		s.writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.logger.Info("admin: gitops sync",
		"result", out.Result, "revision", out.Revision, "changed", out.Changed,
		"applied", out.Applied, "operator", actorSubject(r))
	s.writeJSON(w, http.StatusOK, gitopsSyncResponse{Outcome: out, Status: s.opts.Gitops.Status()})
}

// gitopsRollbackRequest carries the operator's rollback reason.
type gitopsRollbackRequest struct {
	Reason string `json:"reason"`
}

// gitopsRollbackResponse returns the rollback result alongside the refreshed status.
type gitopsRollbackResponse struct {
	Rollback gitops.RollbackResult `json:"rollback"`
	Status   gitops.Status         `json:"status"`
}

// handleGitopsRollback reverts the most recent apply to the last-known-good config.
func (s *Server) handleGitopsRollback(w http.ResponseWriter, r *http.Request) {
	if !s.gitopsEnabled(w) {
		return
	}
	var req gitopsRollbackRequest
	if r.ContentLength != 0 {
		if !s.decodeJSON(w, r, 64*1024, &req) {
			return
		}
	}
	res, err := s.opts.Gitops.Rollback(r.Context(), actorSubject(r), req.Reason)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Warn("admin: gitops rollback",
		"from", res.RolledBackFrom, "to", res.RestoredTo, "operator", actorSubject(r))
	s.writeJSON(w, http.StatusOK, gitopsRollbackResponse{Rollback: res, Status: s.opts.Gitops.Status()})
}
