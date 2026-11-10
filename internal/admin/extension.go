package admin

import (
	"net/http"

	"github.com/blechschmidt/pullthrough-security/internal/extension"
)

// extensionReloadResponse reports the outcome of an on-demand module reload.
type extensionReloadResponse struct {
	Reloaded bool               `json:"reloaded"`
	Snapshot extension.Snapshot `json:"snapshot"`
	Error    string             `json:"error,omitempty"`
}

// handleExtensions serves the WASM extensibility snapshot: per-module config,
// load state (and any compile/ABI error), and the cumulative invocation/verdict/
// timeout/fuel/error metrics, for the admin "Extensions" tab.
func (s *Server) handleExtensions(w http.ResponseWriter, r *http.Request) {
	if s.opts.Extension == nil {
		s.writeError(w, http.StatusNotFound, "wasm extension gates are not enabled")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Extension.Snapshot())
}

// handleExtensionsReload hot-reloads the extension modules from disk. A reload
// failure keeps the previously-loaded modules online (the manager retains a
// working sandbox on a bad rebuild), so it is reported as a 400 rather than
// taking the gate offline.
func (s *Server) handleExtensionsReload(w http.ResponseWriter, r *http.Request) {
	if s.opts.Extension == nil {
		s.writeError(w, http.StatusNotFound, "wasm extension gates are not enabled")
		return
	}
	err := s.opts.Extension.Reload(r.Context())
	resp := extensionReloadResponse{Reloaded: err == nil, Snapshot: s.opts.Extension.Snapshot()}
	if err != nil {
		resp.Error = err.Error()
		s.logger.Warn("admin: extension reload reported an error (previous modules retained)", "error", err)
		s.writeJSON(w, http.StatusBadRequest, resp)
		return
	}
	s.logger.Info("admin: wasm extension modules reloaded on demand")
	s.writeJSON(w, http.StatusOK, resp)
}
