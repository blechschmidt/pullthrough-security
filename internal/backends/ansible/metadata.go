package ansible

import "encoding/json"

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
