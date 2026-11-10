package admin

import (
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backup"
)

// backupStatusResponse is the GET /api/backup payload: whether a schedule is
// configured and the last backup's outcome, including the age that drives RPO
// alerting.
type backupStatusResponse struct {
	Enabled bool            `json:"enabled"`
	Status  backup.Snapshot `json:"status"`
}

// handleBackupStatus reports the disaster-recovery backup status (Task 44): the
// age and outcome of the most recent backup so an operator (or alert) can see
// whether the deployment is within its recovery-point objective.
func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Backup == nil {
		s.writeJSON(w, http.StatusOK, backupStatusResponse{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, backupStatusResponse{
		Enabled: s.opts.Backup.Enabled(),
		Status:  s.opts.Backup.Status(),
	})
}

// backupRunResponse wraps the outcome of an on-demand backup.
type backupRunResponse struct {
	Status backup.Snapshot `json:"status"`
}

// handleBackupRun triggers an on-demand backup into the configured destination
// and returns the resulting status. It requires a destination to be configured
// (backup.dir); without one there is nowhere to write, so the request is refused.
// A long backup is bounded by the request context, so an operator can cancel by
// disconnecting.
func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.Backup == nil {
		s.writeError(w, http.StatusNotFound, "backup is not configured (set backup.dir)")
		return
	}
	start := time.Now()
	if err := s.opts.Backup.RunOnce(r.Context()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "backup failed: "+err.Error())
		return
	}
	s.logger.Info("admin: backup triggered", "duration", time.Since(start))
	s.writeJSON(w, http.StatusOK, backupRunResponse{Status: s.opts.Backup.Status()})
}
