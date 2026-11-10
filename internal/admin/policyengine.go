package admin

import (
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// policyEngineStatusResponse is the GET /api/policyengine payload: the engine's
// mode, policy directory, loaded bundles, and cumulative evaluation metrics.
type policyEngineStatusResponse struct {
	Enabled bool                      `json:"enabled"`
	Mode    string                    `json:"mode"`
	Dir     string                    `json:"dir,omitempty"`
	Bundles []policyengine.BundleInfo `json:"bundles"`
	Metrics policyengine.Snapshot     `json:"metrics"`
}

// policyEngineTestResponse wraps a dry-run evaluation of a caller-supplied input.
type policyEngineTestResponse struct {
	Result policyengine.Result `json:"result"`
}

// policyEngineReloadResponse reports the outcome of an on-demand reload.
type policyEngineReloadResponse struct {
	Reloaded bool                  `json:"reloaded"`
	Metrics  policyengine.Snapshot `json:"metrics"`
}

func (s *Server) handlePolicyEngineStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.PolicyEngine == nil {
		s.writeError(w, http.StatusNotFound, "policy-as-code engine is not enabled")
		return
	}
	pe := s.opts.PolicyEngine
	s.writeJSON(w, http.StatusOK, policyEngineStatusResponse{
		Enabled: true,
		Mode:    string(pe.Mode()),
		Dir:     pe.Dir(),
		Bundles: pe.Bundles(),
		Metrics: pe.Snapshot(),
	})
}

// handlePolicyEngineTest evaluates a caller-supplied admission input document
// against the live policy without enforcing or recording metrics. This lets
// operators validate "would this artifact be denied?" before rolling a bundle
// out, exactly the dry-run affordance the task calls for.
func (s *Server) handlePolicyEngineTest(w http.ResponseWriter, r *http.Request) {
	if s.opts.PolicyEngine == nil {
		s.writeError(w, http.StatusNotFound, "policy-as-code engine is not enabled")
		return
	}
	var in policyengine.Input
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid input document: "+err.Error())
		return
	}
	res := s.opts.PolicyEngine.TestEvaluate(in)
	s.logger.Info("admin: policy test evaluated",
		"tenant", in.Tenant,
		"action", res.Decision.Action,
		"effective", res.EffectiveAction)
	s.writeJSON(w, http.StatusOK, policyEngineTestResponse{Result: res})
}

func (s *Server) handlePolicyEngineReload(w http.ResponseWriter, r *http.Request) {
	if s.opts.PolicyEngine == nil {
		s.writeError(w, http.StatusNotFound, "policy-as-code engine is not enabled")
		return
	}
	if err := s.opts.PolicyEngine.Reload(); err != nil {
		// A reload failure retains the previous policy; report it but do not 500
		// the surface, since the engine is still serving a valid policy.
		s.writeError(w, http.StatusBadRequest, "reload failed (previous policy retained): "+err.Error())
		return
	}
	s.logger.Info("admin: policy reloaded on demand")
	s.writeJSON(w, http.StatusOK, policyEngineReloadResponse{
		Reloaded: true,
		Metrics:  s.opts.PolicyEngine.Snapshot(),
	})
}
