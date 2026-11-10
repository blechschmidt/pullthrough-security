package admin

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/presets"
)

// PresetController is the curated-compliance-preset surface (Task 88): list the
// vetted baselines, dry-run a preset against the running configuration, and
// apply one to the on-disk config. *presets.Manager satisfies it.
type PresetController interface {
	// List returns the registered preset summaries.
	List() []presets.Summary
	// Diff dry-runs the named preset against the running configuration.
	Diff(name string) (presets.Diff, error)
	// Apply patches the on-disk configuration with the named preset.
	Apply(name string) (presets.ApplyResult, error)
}

// presetDiffResponse wraps a dry-run diff.
type presetDiffResponse struct {
	Diff presets.Diff `json:"diff"`
}

// presetApplyRequest is the POST body for applying a preset. Confirm guards
// against accidental one-click application from the dashboard.
type presetApplyRequest struct {
	Name    string `json:"name"`
	Confirm bool   `json:"confirm"`
}

// handlePresetsList returns the vetted preset library. Read-only.
func (s *Server) handlePresetsList(w http.ResponseWriter, r *http.Request) {
	if s.opts.Presets == nil {
		s.writeError(w, http.StatusNotFound, "compliance presets are not available")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"presets": s.opts.Presets.List()})
}

// handlePresetsDiff dry-runs a preset against the running configuration and
// returns exactly what it would change, the projected-config validation, and the
// compliance controls it satisfies. It is strictly read-only (it mutates
// nothing) and is guarded by the read capability.
func (s *Server) handlePresetsDiff(w http.ResponseWriter, r *http.Request) {
	if s.opts.Presets == nil {
		s.writeError(w, http.StatusNotFound, "compliance presets are not available")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "the 'name' query parameter is required")
		return
	}
	diff, err := s.opts.Presets.Diff(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, presetDiffResponse{Diff: diff})
}

// handlePresetsApply previews then applies a preset to the on-disk configuration.
// It requires the administer capability (see authz.go) and is recorded in the
// tamper-evident audit log (EventAdmin) attributed to the authenticated
// operator, with the preset name/version and resulting fingerprint in the detail.
func (s *Server) handlePresetsApply(w http.ResponseWriter, r *http.Request) {
	if s.opts.Presets == nil {
		s.writeError(w, http.StatusNotFound, "compliance presets are not available")
		return
	}
	var req presetApplyRequest
	if !s.decodeJSON(w, r, 64*1024, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		s.writeError(w, http.StatusBadRequest, "the 'name' field is required")
		return
	}
	if !req.Confirm {
		s.writeError(w, http.StatusBadRequest, "set 'confirm':true to apply the preset (preview first via /api/presets/diff)")
		return
	}

	result, err := s.opts.Presets.Apply(name)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logger.Warn("admin: compliance preset applied",
		"preset", result.Preset, "version", result.Version,
		"changed", result.Changed, "operator", actorSubject(r), "path", result.Path)

	// Record an explicit, detailed audit event in the Merkle log so the applied
	// baseline is attributable and pinned. (The RBAC middleware also audits the
	// mutation generically; this record carries the preset-specific detail.)
	if s.opts.AuditLog != nil {
		ev := audit.Event{
			Type:       audit.EventAdmin,
			Method:     r.Method,
			Resource:   r.URL.Path,
			RemoteAddr: clientIP(r),
			Decision:   audit.DecisionAllow,
			Reason:     "presets:apply:" + result.Preset,
			Subject:    actorSubject(r),
			Detail: map[string]any{
				"preset":              result.Preset,
				"version":             result.Version,
				"changed":             result.Changed,
				"controls":            result.Controls,
				"proposedFingerprint": result.Diff.ProposedFingerprint,
				"backupPath":          result.BackupPath,
			},
		}
		if err := s.opts.AuditLog.Log(r.Context(), ev); err != nil {
			s.logger.Error("admin: preset apply audit log write failed", "error", err)
		}
	}

	s.writeJSON(w, http.StatusOK, result)
}
