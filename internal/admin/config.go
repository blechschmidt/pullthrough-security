package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// ConfigInspector is the configuration validation & drift-detection surface
// (Task 85). It runs the single authoritative validation pass against the live
// configuration or a candidate document, and reports whether the on-disk file
// has drifted from what the process is running. *config.Service satisfies it.
type ConfigInspector interface {
	// Path is the config file backing the running process ("" when none).
	Path() string
	// ValidateLive validates the running configuration.
	ValidateLive() *config.Report
	// ValidateContent validates a candidate configuration supplied as raw YAML.
	ValidateContent(content string) *config.Report
	// ValidatePath validates a candidate configuration file on the server disk.
	ValidatePath(path string) (*config.Report, error)
	// Drift recomputes the on-disk configuration and reports divergence.
	Drift() config.DriftStatus
}

// maxConfigBody bounds an uploaded candidate configuration so a hostile client
// cannot stream an unbounded body into the YAML decoder.
const maxConfigBody = 4 << 20 // 4 MiB

// configValidateRequest is the POST body for the preflight endpoint: a candidate
// configuration supplied inline (content) or as a server-side path. Inline
// content is preferred so a client (ptctl) need not share the proxy's
// filesystem.
type configValidateRequest struct {
	Content string `json:"content,omitempty"`
	Path    string `json:"path,omitempty"`
}

// handleConfigValidate runs the configuration validation/preflight pass. GET
// validates the live running configuration; POST validates a candidate supplied
// in the body (inline content or a server-side path). It is strictly read-only
// — it mutates nothing — and is guarded by the read capability (see authz.go).
// The report carries a stable shape (errors/warnings + per-issue field paths) so
// CI can branch on it.
func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	if s.opts.Config == nil {
		s.writeError(w, http.StatusNotFound, "configuration validation is not available")
		return
	}

	if r.Method == http.MethodGet {
		s.writeJSON(w, http.StatusOK, s.opts.Config.ValidateLive())
		return
	}

	var req configValidateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	switch {
	case strings.TrimSpace(req.Content) != "":
		s.writeJSON(w, http.StatusOK, s.opts.Config.ValidateContent(req.Content))
	case strings.TrimSpace(req.Path) != "":
		report, err := s.opts.Config.ValidatePath(req.Path)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, report)
	default:
		s.writeError(w, http.StatusBadRequest, "request must supply either 'content' (inline YAML) or 'path' (server-side file)")
	}
}

// handleConfigDrift reports whether the on-disk configuration has diverged from
// the running process — the operability signal that pairs with the hot-reload
// subsystems. It always returns 200; the drifted flag is in the body so a
// scraper or a `ptctl config drift` can branch on it.
func (s *Server) handleConfigDrift(w http.ResponseWriter, r *http.Request) {
	if s.opts.Config == nil {
		s.writeError(w, http.StatusNotFound, "configuration drift detection is not available")
		return
	}
	s.writeJSON(w, http.StatusOK, s.opts.Config.Drift())
}
