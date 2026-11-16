package locate

import (
	"encoding/json"
	"strings"
	"time"
)

// This file exports the pieces of the locators the full-mirror feed adapters
// (Task 190) reuse: they read package metadata through the proxy, as the
// release pinner reads an index, and must name the same backend paths for
// what they find there.

// ProxyPath maps a URL an index document handed out — rewritten by the
// backend to point back through the proxy ("<public>/v1/<upstream>/…" or the
// root-relative "/v1/<upstream>/…"), or still pointing beneath one of the
// upstream's URLs — to the backend-relative path the proxy serves it at.
func ProxyPath(up Upstream, raw string) (string, bool) { return proxyPath(up, raw) }

// PipFile is one distribution file a PyPI simple page lists, with the
// backend path it is served at.
type PipFile struct {
	// Filename is the distribution file's name; Version the project version
	// it belongs to, read from the file name (empty when the name does not
	// parse as a wheel or sdist of the project).
	Filename string
	Version  string
	// Path is the backend-relative path; empty when the page lists the file
	// at a location the upstream does not serve.
	Path string
	// SHA256 is the digest the page states (lower-case hex), Size the size
	// and Uploaded the upload time when the page states them (PEP 700).
	SHA256   string
	Size     int64
	Uploaded time.Time
	// Yanked reports a file the index marks yanked (PEP 592).
	Yanked bool
}

// PipFiles reads a project's simple page (PEP 691 JSON or PEP 503 HTML, as
// the backend served it from page, the backend-relative path it was read
// at) and returns its files with the backend paths they are served at — the
// same mapping locatePip applies to a lock file's dependency. The JSON page
// also lists the project's versions (PEP 700), including versions that have
// no file left; they are returned in the page's order.
func PipFiles(up Upstream, project, page string, doc Document) ([]PipFile, []string, error) {
	name := pipNormalize(project)
	body := strings.TrimSpace(string(doc.Body))
	if strings.Contains(strings.ToLower(doc.ContentType), "json") || strings.HasPrefix(body, "{") {
		var p struct {
			Versions []string `json:"versions"`
			Files    []struct {
				Filename string            `json:"filename"`
				URL      string            `json:"url"`
				Hashes   map[string]string `json:"hashes"`
				Size     *int64            `json:"size"`
				Uploaded string            `json:"upload-time"`
				Yanked   json.RawMessage   `json:"yanked"`
			} `json:"files"`
		}
		if err := json.Unmarshal(doc.Body, &p); err != nil {
			return nil, nil, err
		}
		out := make([]PipFile, 0, len(p.Files))
		for _, f := range p.Files {
			if f.Filename == "" || f.URL == "" {
				continue
			}
			pf := PipFile{Filename: f.Filename, SHA256: strings.ToLower(f.Hashes["sha256"])}
			if v, ok := pipFileVersion(name, f.Filename); ok {
				pf.Version = v
			}
			if p, ok := pipFilePath(up, page, f.URL); ok {
				pf.Path = p
			}
			if f.Size != nil && *f.Size > 0 {
				pf.Size = *f.Size
			}
			if t, err := time.Parse(time.RFC3339Nano, f.Uploaded); err == nil {
				pf.Uploaded = t
			}
			y := strings.TrimSpace(string(f.Yanked))
			pf.Yanked = y != "" && y != "false" && y != "null"
			out = append(out, pf)
		}
		return out, p.Versions, nil
	}
	files := parseSimpleHTML(string(doc.Body))
	out := make([]PipFile, 0, len(files))
	for _, f := range files {
		pf := PipFile{Filename: f.Filename, SHA256: f.SHA256, Yanked: f.Yanked}
		if v, ok := pipFileVersion(name, f.Filename); ok {
			pf.Version = v
		}
		if p, ok := pipFilePath(up, page, f.URL); ok {
			pf.Path = p
		}
		out = append(out, pf)
	}
	return out, nil, nil
}

// PipNormalize is PEP 503 project-name normalization.
func PipNormalize(name string) string { return pipNormalize(name) }

// PipSameVersion reports whether two PEP 440 version strings name the same
// version (1.0 and 1.0.0 do).
func PipSameVersion(a, b string) bool { return pipSameVersion(a, b) }
