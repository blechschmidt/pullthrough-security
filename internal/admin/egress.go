package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/egress"
)

// egressStatusResponse is the GET /api/egress payload (Task 89): the effective
// SSRF / outbound-egress policy and its per-reason block counters.
type egressStatusResponse struct {
	Enabled bool            `json:"enabled"`
	Policy  egress.Snapshot `json:"policy,omitempty"`
}

// handleEgressStatus reports the effective egress policy (scheme/host allowlist,
// private-network block, redirect cap), the running check/allow/block counters
// partitioned by reason, and the most recent blocked attempts, so an operator can
// see whether the proxy is being steered at internal targets.
func (s *Server) handleEgressStatus(w http.ResponseWriter, r *http.Request) {
	if s.opts.Egress == nil {
		s.writeJSON(w, http.StatusOK, egressStatusResponse{Enabled: false})
		return
	}
	s.writeJSON(w, http.StatusOK, egressStatusResponse{
		Enabled: true,
		Policy:  s.opts.Egress.Snapshot(),
	})
}

// egressTestRequest asks whether a candidate URL would be permitted outbound.
type egressTestRequest struct {
	URL string `json:"url"`
}

// egressTestResponse is the dry-run verdict for a candidate URL.
type egressTestResponse struct {
	URL     string `json:"url"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// handleEgressTest evaluates the egress policy against a candidate URL without
// performing any network I/O — a read-only diagnostic operators use to confirm an
// allowlist change before rolling it out, or to understand why a fetch is blocked.
// It evaluates the URL-level checks (scheme + host allowlist + IP-literal floor);
// hostname destinations that pass here are still re-validated against their
// resolved IPs at connect time.
func (s *Server) handleEgressTest(w http.ResponseWriter, r *http.Request) {
	if s.opts.Egress == nil {
		s.writeError(w, http.StatusNotFound, "the egress guard is not enabled")
		return
	}
	var req egressTestRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	raw := strings.TrimSpace(req.URL)
	if raw == "" {
		s.writeError(w, http.StatusBadRequest, "url is required")
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid url: "+err.Error())
		return
	}

	// CheckURL records the evaluation in the guard's counters; that is acceptable
	// (and useful) for an explicit operator dry-run. The guard is consulted through
	// its concrete type so the read-only Snapshot interface stays narrow.
	guard, ok := s.opts.Egress.(*egress.Guard)
	if !ok {
		// A non-Guard inspector (e.g. a test stub) cannot evaluate a URL; report it.
		s.writeError(w, http.StatusNotImplemented, "egress evaluation is not available")
		return
	}
	resp := egressTestResponse{URL: raw, Allowed: true}
	if be := guard.CheckURL(context.Background(), u); be != nil {
		resp.Allowed = false
		resp.Reason = string(be.Reason)
		resp.Detail = be.Detail
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// egressAllowlistRequest adds or removes a global allowlist entry at runtime.
// Action is "add" or "remove".
type egressAllowlistRequest struct {
	Action string `json:"action"`
	Entry  string `json:"entry"`
}

// handleEgressAllowlist mutates the global egress allowlist at runtime so an
// operator can permit a newly-onboarded registry (or revoke one) without a config
// reload and restart. It is admin-only: changing which outbound destinations are
// reachable is a security-policy change.
func (s *Server) handleEgressAllowlist(w http.ResponseWriter, r *http.Request) {
	if s.opts.Egress == nil {
		s.writeError(w, http.StatusNotFound, "the egress guard is not enabled")
		return
	}
	var req egressAllowlistRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	entry := strings.TrimSpace(req.Entry)
	if entry == "" {
		s.writeError(w, http.StatusBadRequest, "entry is required")
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Action)) {
	case "add":
		if err := s.opts.Egress.AddAllowlistEntry(entry); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Info("admin: egress allowlist entry added", "entry", entry)
		s.writeJSON(w, http.StatusOK, map[string]any{"action": "add", "entry": entry, "ok": true})
	case "remove", "delete":
		removed := s.opts.Egress.RemoveAllowlistEntry(entry)
		s.logger.Info("admin: egress allowlist entry removed", "entry", entry, "present", removed)
		s.writeJSON(w, http.StatusOK, map[string]any{"action": "remove", "entry": entry, "removed": removed})
	default:
		s.writeError(w, http.StatusBadRequest, `action must be "add" or "remove"`)
	}
}
