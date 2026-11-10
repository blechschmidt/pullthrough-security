package ansible

import (
	"encoding/json"
	"strings"
)

// The Galaxy v3 version-detail document (the JSON a registry returns for
// GET .../collections/index/<ns>/<name>/versions/<version>/) carries an
// "artifact" object with the published tarball's "sha256", "size", and
// "filename", plus a "download_url" and the collection metadata the proxy does
// not need. The backend reads this document on a collection-artifact miss to
// recover the published SHA-256 and verify the fetched bytes against it.

// versionDetail models the fields the proxy needs from a version-detail
// document. Unknown fields are ignored.
type versionDetail struct {
	Artifact struct {
		SHA256   string `json:"sha256"`
		Size     int64  `json:"size"`
		Filename string `json:"filename"`
	} `json:"artifact"`
	DownloadURL string `json:"download_url"`
}

// parseVersionDetail decodes a version-detail JSON body. A nil error with a zero
// value is returned for an empty body; a decode error is surfaced so a malformed
// document is treated as "no checksum available" by the caller rather than
// trusted.
func parseVersionDetail(body []byte) (versionDetail, error) {
	var vd versionDetail
	if len(body) == 0 {
		return vd, nil
	}
	if err := json.Unmarshal(body, &vd); err != nil {
		return versionDetail{}, err
	}
	return vd, nil
}

// sha256 returns the lowercase hex SHA-256 the version-detail document declares
// for the artifact, and ok=false when it is absent or malformed.
func (vd versionDetail) sha256() (hex string, ok bool) {
	return normalizeSHA256(vd.Artifact.SHA256)
}

// rewriteMetadata rewrites every absolute upstream URL embedded in a metadata
// document so it routes back through the proxy. It walks the decoded JSON and
// replaces any string value that begins with the upstream origin (e.g.
// "https://galaxy.ansible.com") with the proxy's PublicBaseURL, preserving the
// path and query. It returns changed=false (and the original bytes) when the
// body does not parse as JSON or contains no such URL, so a non-JSON or link-
// free document is served byte-for-byte. Notably this rewrites a version
// detail's absolute "download_url" so the client's artifact download flows back
// through the proxy (and its content gates and checksum verification).
func rewriteMetadata(body []byte, upstreamOrigin, publicBase string) (out []byte, changed bool) {
	if upstreamOrigin == "" {
		return body, false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return body, false
	}
	rewrote := false
	var walk func(node any) any
	walk = func(node any) any {
		switch t := node.(type) {
		case string:
			if strings.HasPrefix(t, upstreamOrigin) {
				rewrote = true
				return publicBase + strings.TrimPrefix(t, upstreamOrigin)
			}
			return t
		case []any:
			for i, e := range t {
				t[i] = walk(e)
			}
			return t
		case map[string]any:
			for k, e := range t {
				t[k] = walk(e)
			}
			return t
		default:
			return node
		}
	}
	walk(v)
	if !rewrote {
		return body, false
	}
	nb, err := json.Marshal(v)
	if err != nil {
		return body, false
	}
	return nb, true
}
