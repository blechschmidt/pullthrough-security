package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui
var uiFS embed.FS

// dashboardFS is the embedded dashboard rooted at the ui directory.
var dashboardFS = mustSub(uiFS, "ui")

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("admin: embedding ui: " + err.Error())
	}
	return sub
}

// handleStatic serves the embedded dashboard assets. Requests for the prefix
// root (or an unknown path) fall back to index.html so the single-page
// dashboard owns client-side routing.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, s.prefix+"/")
	if rel == "" {
		rel = "index.html"
	}
	data, err := fs.ReadFile(dashboardFS, rel)
	if err != nil {
		// Unknown asset: serve the SPA shell so the dashboard still loads.
		data, err = fs.ReadFile(dashboardFS, "index.html")
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "dashboard unavailable")
			return
		}
		rel = "index.html"
	}
	w.Header().Set("Content-Type", contentTypeFor(rel))
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// writeJSON serializes v as an indented JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("admin: encoding response failed", "error", err)
	}
}

// writeCycloneDX serializes a CycloneDX SBOM with its conventional media type so
// downstream tooling recognizes it.
func (s *Server) writeCycloneDX(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json; version=1.5")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("admin: encoding sbom failed", "error", err)
	}
}

// writeSARIF serializes a SARIF 2.1.0 log with its conventional media type so
// CI tooling (GitHub code scanning, GitLab) recognizes it. HTML escaping is
// disabled so URIs and messages containing characters like "&" or "<" render
// verbatim rather than as \u-escapes.
func (s *Server) writeSARIF(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("admin: encoding sarif failed", "error", err)
	}
}

// writeOCIIndex serializes an OCI image index (the referrers response) with its
// conventional image-index media type so OCI tooling recognizes it.
func (s *Server) writeOCIIndex(w http.ResponseWriter, mediaType string, v any) {
	w.Header().Set("Content-Type", mediaType)
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("admin: encoding oci index failed", "error", err)
	}
}

// writeError emits a JSON error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
