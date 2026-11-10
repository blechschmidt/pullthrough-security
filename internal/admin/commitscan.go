package admin

import "net/http"

// This file supplies the commit-scan hardening control surface handlers (Task
// 78) registered in routes(): reading the hardening configuration and per-tenant
// cost budgets, adjusting a tenant's budget ceiling, and pruning the verdict
// cache. They are thin adapters over the CommitScanController interface so the
// admin server stays decoupled from the scanner implementation.

// commitScanStatusResponse is the GET /api/commitscan payload: the hardening
// configuration plus the current per-tenant budget ledger.
type commitScanStatusResponse struct {
	Hardening any   `json:"hardening"`
	Budgets   []any `json:"budgets"`
}

// handleCommitScanStatus serves the commit-scan hardening configuration and the
// per-tenant budget snapshot.
func (s *Server) handleCommitScanStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.CommitScan == nil {
		s.writeError(w, http.StatusNotFound, "commit scanning is not enabled")
		return
	}
	budgets := s.opts.CommitScan.BudgetSnapshot()
	out := commitScanStatusResponse{
		Hardening: s.opts.CommitScan.HardeningStatus(),
		Budgets:   make([]any, 0, len(budgets)),
	}
	for i := range budgets {
		out.Budgets = append(out.Budgets, budgets[i])
	}
	s.writeJSON(w, http.StatusOK, out)
}

// commitScanBudgetRequest sets a tenant's monthly budget ceiling in USD (0 =
// unlimited).
type commitScanBudgetRequest struct {
	Tenant     string  `json:"tenant"`
	CeilingUSD float64 `json:"ceilingUsd"`
}

// handleCommitScanSetBudget adjusts a tenant's commit-scan budget ceiling.
func (s *Server) handleCommitScanSetBudget(w http.ResponseWriter, r *http.Request) {
	if s.opts.CommitScan == nil {
		s.writeError(w, http.StatusNotFound, "commit scanning is not enabled")
		return
	}
	var req commitScanBudgetRequest
	if !s.decodeJSON(w, r, 16<<10, &req) {
		return
	}
	if req.Tenant == "" {
		s.writeError(w, http.StatusBadRequest, "tenant is required")
		return
	}
	if req.CeilingUSD < 0 {
		s.writeError(w, http.StatusBadRequest, "ceilingUsd must be >= 0")
		return
	}
	if err := s.opts.CommitScan.SetBudget(req.Tenant, req.CeilingUSD); err != nil {
		s.writeError(w, http.StatusBadRequest, "setting budget: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"tenant":     req.Tenant,
		"ceilingUsd": req.CeilingUSD,
		"status":     "ok",
	})
}

// handleCommitScanPrune evicts expired commit-scan verdicts from the cache,
// returning the number removed.
func (s *Server) handleCommitScanPrune(w http.ResponseWriter, r *http.Request) {
	if s.opts.CommitScan == nil {
		s.writeError(w, http.StatusNotFound, "commit scanning is not enabled")
		return
	}
	removed, err := s.opts.CommitScan.PruneVerdicts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "pruning verdict cache: "+err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"removed": removed, "status": "ok"})
}
