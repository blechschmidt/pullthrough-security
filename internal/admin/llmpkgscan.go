package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
)

// LLMPkgScanInspector exposes the sandboxed LLM package-content scan gate (Task
// 173) to the admin API: its effective configuration and tallies, its budget,
// and the stored verdicts. The verdict readers are tenant-scoped by the gate
// itself — a verdict quotes the package it describes, so a tenant-bound caller
// is given only verdicts on bytes its own tenant has pulled. The
// *llmpkgscan.Service satisfies it.
type LLMPkgScanInspector interface {
	Enabled() bool
	Status() llmpkgscan.Status
	Verdicts(tenant string, limit int) []*llmpkgscan.Verdict
	ForCoordinate(tenant, ecosystem, name, version string) []*llmpkgscan.Verdict
	Standing(v *llmpkgscan.Verdict) llmpkgscan.Standing
}

// Bounds on the verdict listing.
const (
	defaultLLMPkgScanVerdicts = 50
	maxLLMPkgScanVerdicts     = 500
)

// handleLLMPkgScan serves the gate's effective configuration (provider, model,
// action, fail mode, thresholds, limits — never the API key), its cumulative
// tallies and its budget state.
//
// A tenant-bound caller sees its own tenant's budget row only: what the other
// teams have spent is not its business. The shared ceiling's state stays
// visible, because an exhausted global budget is why that tenant's packages are
// going unscanned.
func (s *Server) handleLLMPkgScan(w http.ResponseWriter, r *http.Request) {
	if s.opts.LLMPkgScan == nil || !s.opts.LLMPkgScan.Enabled() {
		s.writeError(w, http.StatusNotFound, "LLM package-content scan gate is not enabled")
		return
	}
	st := s.opts.LLMPkgScan.Status()
	if tenant := mcpTenant(r); tenant != "" {
		own := st.Budget.Tenants[:0:0]
		for _, row := range st.Budget.Tenants {
			if row.Tenant == tenant {
				own = append(own, row)
			}
		}
		st.Budget.Tenants = own
		st.Budget.GlobalSpentUSD = 0
		st.CostUSD = 0
	}
	s.writeJSON(w, http.StatusOK, st)
}

// llmPkgScanVerdictRow is a stored verdict together with how the gate, as
// currently configured, treats it.
type llmPkgScanVerdictRow struct {
	*llmpkgscan.Verdict
	Standing llmpkgscan.Standing `json:"standing"`
}

// llmPkgScanVerdicts is the verdict listing. Reasons, evidence excerpts and
// anomaly text in it are model output and package content: a client must render
// them as inert text.
type llmPkgScanVerdicts struct {
	// Tenant is the scope the listing was restricted to ("" = organization-wide).
	Tenant   string                 `json:"tenant,omitempty"`
	Count    int                    `json:"count"`
	Verdicts []llmPkgScanVerdictRow `json:"verdicts"`
}

// handleLLMPkgScanVerdicts lists stored verdicts, newest first.
//
//	limit=N                 at most N verdicts (default 50, max 500)
//	name=<package>          only verdicts recorded under this package name ...
//	ecosystem=, version=    ... optionally narrowed to an ecosystem and a version
//	tenant=<team>           only honored for a global (non-tenant-bound) identity
//
// The request is hard-scoped to the caller's tenant exactly like the dossier
// and the federated query: a tenant-bound identity cannot widen its scope
// through the query string.
func (s *Server) handleLLMPkgScanVerdicts(w http.ResponseWriter, r *http.Request) {
	if s.opts.LLMPkgScan == nil || !s.opts.LLMPkgScan.Enabled() {
		s.writeError(w, http.StatusNotFound, "LLM package-content scan gate is not enabled")
		return
	}
	qp := r.URL.Query()
	limit := defaultLLMPkgScanVerdicts
	if raw := strings.TrimSpace(qp.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			s.writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > maxLLMPkgScanVerdicts {
		limit = maxLLMPkgScanVerdicts
	}
	tenant := strings.TrimSpace(mcpTenant(r))
	name := strings.TrimSpace(qp.Get("name"))

	var verdicts []*llmpkgscan.Verdict
	if name != "" {
		verdicts = s.opts.LLMPkgScan.ForCoordinate(tenant,
			strings.TrimSpace(firstQuery(qp.Get("ecosystem"), qp.Get("eco"))), name, strings.TrimSpace(qp.Get("version")))
		if len(verdicts) > limit {
			verdicts = verdicts[:limit]
		}
	} else {
		verdicts = s.opts.LLMPkgScan.Verdicts(tenant, limit)
	}

	out := llmPkgScanVerdicts{Tenant: tenant, Count: len(verdicts), Verdicts: make([]llmPkgScanVerdictRow, 0, len(verdicts))}
	for _, v := range verdicts {
		out.Verdicts = append(out.Verdicts, llmPkgScanVerdictRow{Verdict: v, Standing: s.opts.LLMPkgScan.Standing(v)})
	}
	s.writeJSON(w, http.StatusOK, out)
}
