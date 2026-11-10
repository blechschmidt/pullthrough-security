package admin

import (
	"net/http"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
)

// provgraphStatsResponse reports the supply-chain graph's size and shape.
type provgraphStatsResponse struct {
	Enabled bool                `json:"enabled"`
	Stats   *provgraph.Snapshot `json:"stats,omitempty"`
}

// handleProvgraphStats reports graph-size metrics (node/edge counts by kind).
func (s *Server) handleProvgraphStats(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provgraph == nil {
		s.writeJSON(w, http.StatusOK, provgraphStatsResponse{Enabled: false})
		return
	}
	snap := s.opts.Provgraph.Snapshot()
	s.writeJSON(w, http.StatusOK, provgraphStatsResponse{Enabled: true, Stats: &snap})
}

// handleProvgraphExport serves the whole graph as a JSON document — consumed by
// the force-directed visualization and usable for offline analysis.
func (s *Server) handleProvgraphExport(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provgraph == nil {
		s.writeError(w, http.StatusNotFound, "supply-chain graph is not enabled")
		return
	}
	doc := s.opts.Provgraph.Export()
	s.writeJSON(w, http.StatusOK, doc)
}

// handleProvgraphBlast answers a blast-radius query: which cached artifacts are
// affected by a CVE (type=cve) or built from / downstream of a commit
// (type=commit). The seed id is passed as ?id=.
func (s *Server) handleProvgraphBlast(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provgraph == nil {
		s.writeError(w, http.StatusNotFound, "supply-chain graph is not enabled")
		return
	}
	q := r.URL.Query()
	id := strings.TrimSpace(q.Get("id"))
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing id parameter")
		return
	}
	kind := provgraph.SeedKind(strings.ToLower(strings.TrimSpace(q.Get("type"))))
	switch kind {
	case "":
		// Infer from the id shape: a CVE/GHSA/OSV advisory id vs a commit SHA.
		kind = inferSeedKind(id)
	case provgraph.SeedCVE, provgraph.SeedCommit:
	default:
		s.writeError(w, http.StatusBadRequest, "type must be 'cve' or 'commit'")
		return
	}
	res, err := s.opts.Provgraph.BlastRadius(kind, id)
	if err != nil {
		if err == provgraph.ErrNotFound {
			// A well-formed query for an unknown seed is a successful empty result,
			// not an error: the CVE/commit simply touches nothing we have cached.
			s.writeJSON(w, http.StatusOK, res)
			return
		}
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleProvgraphReverse answers a reverse-dependency query for an artifact
// identified by ?ecosystem=&name=&version=.
func (s *Server) handleProvgraphReverse(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provgraph == nil {
		s.writeError(w, http.StatusNotFound, "supply-chain graph is not enabled")
		return
	}
	eco, name, version, ok := artifactQuery(r)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "missing name and version parameters")
		return
	}
	res, err := s.opts.Provgraph.ReverseDependencies(eco, name, version)
	if err != nil {
		if err == provgraph.ErrNotFound {
			s.writeJSON(w, http.StatusOK, res)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// handleProvgraphPath answers a path-to-commit query for an artifact identified
// by ?ecosystem=&name=&version=.
func (s *Server) handleProvgraphPath(w http.ResponseWriter, r *http.Request) {
	if s.opts.Provgraph == nil {
		s.writeError(w, http.StatusNotFound, "supply-chain graph is not enabled")
		return
	}
	eco, name, version, ok := artifactQuery(r)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "missing name and version parameters")
		return
	}
	res, err := s.opts.Provgraph.PathToCommit(eco, name, version)
	if err != nil {
		if err == provgraph.ErrNotFound {
			s.writeJSON(w, http.StatusOK, res)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, res)
}

// artifactQuery extracts the (ecosystem, name, version) coordinate from the
// request, requiring at least a name and version.
func artifactQuery(r *http.Request) (ecosystem, name, version string, ok bool) {
	q := r.URL.Query()
	name = strings.TrimSpace(q.Get("name"))
	version = strings.TrimSpace(q.Get("version"))
	ecosystem = strings.TrimSpace(q.Get("ecosystem"))
	if name == "" || version == "" {
		return "", "", "", false
	}
	return ecosystem, name, version, true
}

// inferSeedKind guesses whether a blast-radius seed id is a vulnerability
// advisory or a commit SHA, so the type parameter can be omitted for the common
// case. Advisory ids carry an alphabetic prefix and a hyphen (CVE-, GHSA-,
// OSV-, ...); a bare hex string is treated as a commit.
func inferSeedKind(id string) provgraph.SeedKind {
	upper := strings.ToUpper(id)
	if strings.HasPrefix(upper, "CVE-") || strings.HasPrefix(upper, "GHSA-") ||
		strings.HasPrefix(upper, "OSV-") || strings.HasPrefix(upper, "PYSEC-") ||
		strings.HasPrefix(upper, "RUSTSEC-") || strings.HasPrefix(upper, "GO-") {
		return provgraph.SeedCVE
	}
	if isHex(id) {
		return provgraph.SeedCommit
	}
	return provgraph.SeedCVE
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
