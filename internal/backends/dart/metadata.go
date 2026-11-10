package dart

import (
	"encoding/json"
	"strings"
)

// The pub list-versions document (the JSON a repository returns for
// GET /api/packages/{package}) carries a "latest" release object and a
// "versions" array. Each release records the archive location ("archive_url")
// and its content hash ("archive_sha256"), plus the package's "pubspec". The
// backend rewrites every "archive_url" so the client downloads through the
// proxy (see rewriteArchiveURLs), and on an archive request re-reads this
// document to recover the real upstream archive URL, the content hash to verify
// against, and the pubspec's repository URL for provenance association.

// versionList models the fields the proxy needs from a list-versions document.
// Unknown fields are ignored on this view; the serve-time rewrite preserves them
// (see rewriteArchiveURLs).
type versionList struct {
	Name     string         `json:"name"`
	Latest   *versionEntry  `json:"latest"`
	Versions []versionEntry `json:"versions"`
}

type versionEntry struct {
	Version       string          `json:"version"`
	ArchiveURL    string          `json:"archive_url"`
	ArchiveSha256 string          `json:"archive_sha256"`
	Pubspec       json.RawMessage `json:"pubspec"`
}

// parseVersionList decodes a list-versions JSON body. A nil error with a zero
// value is returned for an empty body; a decode error is surfaced so a malformed
// document is treated as "version not found" by the caller rather than trusted.
func parseVersionList(body []byte) (versionList, error) {
	var vl versionList
	if len(body) == 0 {
		return vl, nil
	}
	if err := json.Unmarshal(body, &vl); err != nil {
		return versionList{}, err
	}
	return vl, nil
}

// archiveFor returns the release entry for a given version (checking "latest"
// and the "versions" array), and ok=false when the version is absent.
func (vl versionList) archiveFor(version string) (versionEntry, bool) {
	if vl.Latest != nil && vl.Latest.Version == version {
		return *vl.Latest, true
	}
	for _, e := range vl.Versions {
		if e.Version == version {
			return e, true
		}
	}
	return versionEntry{}, false
}

// repository returns the source-repository URL the entry's pubspec advertises
// (preferring "repository" over "homepage"), for provenance association. Empty
// when the pubspec names none.
func (e versionEntry) repository() string {
	if len(e.Pubspec) == 0 {
		return ""
	}
	var ps struct {
		Repository string `json:"repository"`
		Homepage   string `json:"homepage"`
	}
	if err := json.Unmarshal(e.Pubspec, &ps); err != nil {
		return ""
	}
	if s := strings.TrimSpace(ps.Repository); s != "" {
		return s
	}
	return strings.TrimSpace(ps.Homepage)
}

// rewriteArchiveURLs rewrites the "archive_url" of every release (the "latest"
// object and each "versions" entry) to the proxy URL that proxyURL returns for
// that release's version, so the client downloads archives back through the
// proxy. All other fields — including the full pubspec and any top-level fields
// the proxy does not model (isDiscontinued, replacedBy, advisoriesUpdated) — are
// preserved byte-for-byte by round-tripping through json.RawMessage. A body that
// does not parse as an object is returned unchanged with the decode error, so
// the caller can fall back to proxying it untouched.
func rewriteArchiveURLs(body []byte, proxyURL func(version string) string) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return body, err
	}
	if raw, ok := top["latest"]; ok {
		if nr := rewriteEntry(raw, proxyURL); nr != nil {
			top["latest"] = nr
		}
	}
	if raw, ok := top["versions"]; ok {
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err == nil {
			for i, e := range entries {
				if nr := rewriteEntry(e, proxyURL); nr != nil {
					entries[i] = nr
				}
			}
			if nb, err := json.Marshal(entries); err == nil {
				top["versions"] = nb
			}
		}
	}
	out, err := json.Marshal(top)
	if err != nil {
		return body, err
	}
	return out, nil
}

// rewriteEntry rewrites a single release object's "archive_url" based on its
// "version". It returns nil (leave the entry unchanged) when the object cannot
// be parsed, carries no version, or proxyURL declines the version.
func rewriteEntry(raw json.RawMessage, proxyURL func(version string) string) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	vraw, ok := obj["version"]
	if !ok {
		return nil
	}
	var version string
	if err := json.Unmarshal(vraw, &version); err != nil || version == "" {
		return nil
	}
	newURL := proxyURL(version)
	if newURL == "" {
		return nil
	}
	enc, err := json.Marshal(newURL)
	if err != nil {
		return nil
	}
	obj["archive_url"] = enc
	nb, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return nb
}
