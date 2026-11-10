package swift

import (
	"encoding/json"
	"strings"
)

// Swift release metadata (the JSON a registry returns for
// GET /{scope}/{name}/{version}) carries a "resources" array in which the
// source archive is recorded as a "source-archive" entry with a SHA-256
// "checksum". That checksum is the ecosystem's own integrity record for the
// archive, which the backend uses to verify fetched bytes before they are
// cached or served (see checksum.go). The optional "metadata.repositoryURLs"
// field names the artifact's source repositories, which the backend surfaces so
// the provenance subsystem can associate the package with its Git commit.
//
// Only the fields the proxy needs are modeled; unknown fields are ignored so a
// richer or future registry response still parses.
type releaseMetadata struct {
	Resources []releaseResource `json:"resources"`
	Metadata  struct {
		RepositoryURLs []string `json:"repositoryURLs"`
	} `json:"metadata"`
}

type releaseResource struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Checksum string `json:"checksum"`
}

// sourceArchiveName is the resource name the registry assigns to a release's
// source archive within the "resources" array.
const sourceArchiveName = "source-archive"

// parseReleaseMetadata decodes a release metadata JSON body. A nil error with a
// zero value is returned for an empty body; a decode error is surfaced so a
// malformed document is treated as "no usable checksum" by the caller rather
// than silently trusted.
func parseReleaseMetadata(body []byte) (releaseMetadata, error) {
	var rm releaseMetadata
	if len(body) == 0 {
		return rm, nil
	}
	if err := json.Unmarshal(body, &rm); err != nil {
		return releaseMetadata{}, err
	}
	return rm, nil
}

// sourceArchiveChecksum returns the lowercase hex SHA-256 the metadata records
// for the release's source archive, and ok=false when no well-formed checksum is
// present (so the archive is served unverified, fail-open, rather than blocked
// on a registry that omits the field).
func (rm releaseMetadata) sourceArchiveChecksum() (string, bool) {
	for _, res := range rm.Resources {
		if res.Name != sourceArchiveName {
			continue
		}
		if hex, ok := normalizeDigest(res.Checksum); ok {
			return hex, true
		}
	}
	return "", false
}

// repositoryURL returns the first source-repository URL the metadata advertises,
// for provenance association. Empty when none is present.
func (rm releaseMetadata) repositoryURL() string {
	for _, u := range rm.Metadata.RepositoryURLs {
		if s := strings.TrimSpace(u); s != "" {
			return s
		}
	}
	return ""
}
