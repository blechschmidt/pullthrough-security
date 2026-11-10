package admin

import (
	"context"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/prewarm"
)

// PrewarmController is the predictive cache pre-warming surface the admin API
// exposes (Task 134): the operational status and an on-demand cycle trigger. The
// prewarm.Service satisfies it.
type PrewarmController interface {
	Status() prewarm.Status
	Trigger(ctx context.Context) (prewarm.RunReport, error)
}

// handlePrewarm reports the predictive cache pre-warming status (Task 134), so
// an operator (or `ptctl prewarm status`) can see the learned-history size, the
// last cycle's outcome, leader/kill-switch/window state, and the cumulative
// predicted/fetched/hit-attributed/gate-blocked counters. When the subsystem is
// disabled it returns an Enabled=false status.
func (s *Server) handlePrewarm(w http.ResponseWriter, r *http.Request) {
	if s.opts.Prewarm == nil {
		s.writeJSON(w, http.StatusOK, prewarm.Status{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Prewarm.Status())
}

// handlePrewarmRun triggers an immediate prediction + pre-warm cycle, bypassing
// the off-peak window and HA leader gate (an operator explicitly asked this node
// to run) but still honoring the emergency kill-switch. It returns the cycle's
// report.
func (s *Server) handlePrewarmRun(w http.ResponseWriter, r *http.Request) {
	if s.opts.Prewarm == nil {
		s.writeError(w, http.StatusNotFound, "predictive cache pre-warming is not enabled")
		return
	}
	report, err := s.opts.Prewarm.Trigger(r.Context())
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "pre-warm cycle could not be run: "+err.Error())
		return
	}
	s.logger.Info("admin: predictive pre-warm cycle triggered",
		"predicted", report.Predicted, "fetched", report.Fetched,
		"alreadyCached", report.AlreadyCached, "gateBlocked", report.GateBlocked,
		"errors", report.Errors, "skipped", report.Skipped)
	s.writeJSON(w, http.StatusOK, report)
}
