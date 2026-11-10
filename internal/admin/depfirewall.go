package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
)

// depFirewallResponse is the dependency-firewall gate status plus the configured
// rules (global and, when ?tenant= is given, that tenant's) for the admin tab.
type depFirewallResponse struct {
	depfirewall.Status
	Rules []depfirewall.RuleView `json:"rules"`
}

// handleDepFirewall serves the dependency-firewall gate status and the configured
// rules (Task 65). ?tenant=<id> additionally returns that tenant's rules;
// ?tenant=* returns every tenant's rules alongside the global set.
func (s *Server) handleDepFirewall(w http.ResponseWriter, r *http.Request) {
	if s.opts.DepFirewall == nil || !s.opts.DepFirewall.Enabled() {
		s.writeError(w, http.StatusNotFound, "dependency firewall is not enabled")
		return
	}
	tenant := r.URL.Query().Get("tenant")
	rules := s.opts.DepFirewall.Rules(tenant)
	if rules == nil {
		rules = []depfirewall.RuleView{}
	}
	s.writeJSON(w, http.StatusOK, depFirewallResponse{
		Status: s.opts.DepFirewall.Status(),
		Rules:  rules,
	})
}

// depFirewallRuleRequest is the POST body for creating/updating a rule. An empty
// tenant targets the global rule set.
type depFirewallRuleRequest struct {
	Tenant     string   `json:"tenant"`
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Pinned     []string `json:"pinned"`
	Ranges     []string `json:"ranges"`
	MinVersion string   `json:"minVersion"`
	Denied     []string `json:"denied"`
	Note       string   `json:"note"`
}

// handleDepFirewallSetRule installs or replaces one rule. A malformed range is
// rejected with 400 without mutating state.
func (s *Server) handleDepFirewallSetRule(w http.ResponseWriter, r *http.Request) {
	if s.opts.DepFirewall == nil || !s.opts.DepFirewall.Enabled() {
		s.writeError(w, http.StatusNotFound, "dependency firewall is not enabled")
		return
	}
	var req depFirewallRuleRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Ecosystem) == "" || strings.TrimSpace(req.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "rule requires ecosystem and name")
		return
	}
	rule := depfirewall.Rule{
		Ecosystem:  req.Ecosystem,
		Name:       req.Name,
		Pinned:     req.Pinned,
		Ranges:     req.Ranges,
		MinVersion: req.MinVersion,
		Denied:     req.Denied,
		Note:       req.Note,
		Source:     "admin",
	}
	if err := s.opts.DepFirewall.SetRule(req.Tenant, rule); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": req.Tenant, "rule": rule})
}

// depFirewallDeleteRequest is the POST body for deleting a rule.
type depFirewallDeleteRequest struct {
	Tenant    string `json:"tenant"`
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// handleDepFirewallDeleteRule removes one rule for (ecosystem, name).
func (s *Server) handleDepFirewallDeleteRule(w http.ResponseWriter, r *http.Request) {
	if s.opts.DepFirewall == nil || !s.opts.DepFirewall.Enabled() {
		s.writeError(w, http.StatusNotFound, "dependency firewall is not enabled")
		return
	}
	var req depFirewallDeleteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Ecosystem) == "" || strings.TrimSpace(req.Name) == "" {
		s.writeError(w, http.StatusBadRequest, "delete requires ecosystem and name")
		return
	}
	removed := s.opts.DepFirewall.DeleteRule(req.Tenant, req.Ecosystem, req.Name)
	if !removed {
		s.writeError(w, http.StatusNotFound, "no such rule")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": true})
}

// depFirewallDefaultRequest is the POST body for setting the deny/allow default.
type depFirewallDefaultRequest struct {
	Tenant string `json:"tenant"`
	Action string `json:"action"`
}

// handleDepFirewallDefault sets the deny/allow disposition for ungoverned
// coordinates, globally or for one tenant.
func (s *Server) handleDepFirewallDefault(w http.ResponseWriter, r *http.Request) {
	if s.opts.DepFirewall == nil || !s.opts.DepFirewall.Enabled() {
		s.writeError(w, http.StatusNotFound, "dependency firewall is not enabled")
		return
	}
	var req depFirewallDefaultRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if err := s.opts.DepFirewall.SetDefaultAction(req.Tenant, depfirewall.Action(req.Action)); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": req.Tenant, "action": req.Action})
}

// handleDepFirewallImport imports rules from an uploaded lockfile. The lockfile
// bytes are the request body; ?tenant=, ?format=, and ?mode=replace|merge are
// query parameters (mode defaults to replace, so the lockfile becomes the
// complete allowlist).
func (s *Server) handleDepFirewallImport(w http.ResponseWriter, r *http.Request) {
	if s.opts.DepFirewall == nil || !s.opts.DepFirewall.Enabled() {
		s.writeError(w, http.StatusNotFound, "dependency firewall is not enabled")
		return
	}
	content, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024*1024))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "failed to read lockfile body: "+err.Error())
		return
	}
	if len(content) == 0 {
		s.writeError(w, http.StatusBadRequest, "empty lockfile body")
		return
	}
	tenant := r.URL.Query().Get("tenant")
	format := r.URL.Query().Get("format")
	replace := !strings.EqualFold(r.URL.Query().Get("mode"), "merge")
	res, err := s.opts.DepFirewall.ImportLockfile(tenant, format, content, replace)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}
