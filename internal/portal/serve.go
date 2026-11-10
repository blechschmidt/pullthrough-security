package portal

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui
var uiFS embed.FS

// portalFS is the embedded front-end rooted at the ui directory.
var portalFS = mustSub(uiFS, "ui")

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic("portal: embedding ui: " + err.Error())
	}
	return sub
}

// handleStatic serves the embedded portal assets. Unknown paths fall back to
// index.html so the single page owns client-side state.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, s.uiPrefix+"/")
	if rel == "" {
		rel = "index.html"
	}
	data, err := fs.ReadFile(portalFS, rel)
	if err != nil {
		data, err = fs.ReadFile(portalFS, "index.html")
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "portal unavailable")
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
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

// writeJSON writes an indented JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("portal: encoding response failed", "error", err)
	}
}

// writeError writes a JSON error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeSARIF writes a SARIF 2.1.0 log with HTML escaping disabled (URLs/identifiers).
func (s *Server) writeSARIF(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/sarif+json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		s.logger.Debug("portal: encoding sarif failed", "error", err)
	}
}
