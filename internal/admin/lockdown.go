package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/lockdown"
)

// The admin "Incident" surface (Task 74) exposes the emergency-lockdown / global
// kill-switch incident-response control: read the current posture, engage a
// freeze/strict/targeted-block lockdown (with a mandatory reason + incident ID and
// a TTL), and clear it. Engage/clear are administrator-only (see authz.go).

// lockdownResponse is the current posture plus cumulative metrics for the tab.
type lockdownResponse struct {
	Status  lockdown.Status   `json:"status"`
	Metrics lockdown.Snapshot `json:"metrics"`
}

func (s *Server) lockdownEnabled(w http.ResponseWriter) bool {
	if s.opts.Lockdown == nil || !s.opts.Lockdown.Enabled() {
		s.writeError(w, http.StatusNotFound, "emergency-lockdown control is not enabled")
		return false
	}
	return true
}

// handleLockdown serves the current lockdown posture and metrics.
func (s *Server) handleLockdown(w http.ResponseWriter, r *http.Request) {
	if !s.lockdownEnabled(w) {
		return
	}
	s.writeJSON(w, http.StatusOK, lockdownResponse{
		Status:  s.opts.Lockdown.Status(),
		Metrics: s.opts.Lockdown.Metrics(),
	})
}

// lockdownEngageRequest is the POST body for engaging a lockdown. TTL is a
// human-friendly duration string ("30m", "2h"); 0/empty applies the configured
// default. Targets are required for block mode.
type lockdownEngageRequest struct {
	Mode       string                  `json:"mode"`
	Reason     string                  `json:"reason"`
	IncidentID string                  `json:"incidentId"`
	TTL        string                  `json:"ttl"`
	Targets    []lockdownTargetRequest `json:"targets"`
}

type lockdownTargetRequest struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// handleLockdownEngage engages (or replaces) the org-wide lockdown.
func (s *Server) handleLockdownEngage(w http.ResponseWriter, r *http.Request) {
	if !s.lockdownEnabled(w) {
		return
	}
	var req lockdownEngageRequest
	if !s.decodeJSON(w, r, 64*1024, &req) {
		return
	}
	mode, err := lockdown.ParseMode(req.Mode)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ttl time.Duration
	if t := strings.TrimSpace(req.TTL); t != "" {
		d, perr := time.ParseDuration(t)
		if perr != nil {
			s.writeError(w, http.StatusBadRequest, "invalid ttl: "+perr.Error())
			return
		}
		ttl = d
	}
	targets := make([]lockdown.Coordinate, 0, len(req.Targets))
	for _, t := range req.Targets {
		targets = append(targets, lockdown.Coordinate{
			Ecosystem: t.Ecosystem,
			Name:      t.Name,
			Version:   t.Version,
		})
	}
	status, err := s.opts.Lockdown.Engage(r.Context(), lockdown.EngageInput{
		Mode:       mode,
		Reason:     req.Reason,
		IncidentID: req.IncidentID,
		Operator:   actorSubject(r),
		TTL:        ttl,
		Targets:    targets,
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Warn("admin: emergency lockdown engaged",
		"mode", status.Mode, "incident", status.IncidentID, "operator", actorSubject(r))
	s.writeJSON(w, http.StatusOK, lockdownResponse{Status: status, Metrics: s.opts.Lockdown.Metrics()})
}

// lockdownClearRequest is the POST body for clearing a lockdown.
type lockdownClearRequest struct {
	Reason string `json:"reason"`
}

// handleLockdownClear lifts the active lockdown.
func (s *Server) handleLockdownClear(w http.ResponseWriter, r *http.Request) {
	if !s.lockdownEnabled(w) {
		return
	}
	var req lockdownClearRequest
	if !s.decodeJSON(w, r, 16*1024, &req) {
		return
	}
	status, err := s.opts.Lockdown.Clear(r.Context(), lockdown.ClearInput{
		Reason:   req.Reason,
		Operator: actorSubject(r),
	})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Warn("admin: emergency lockdown cleared", "operator", actorSubject(r))
	s.writeJSON(w, http.StatusOK, lockdownResponse{Status: status, Metrics: s.opts.Lockdown.Metrics()})
}
