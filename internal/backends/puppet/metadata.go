package puppet

import (
	"encoding/json"
	"strings"
)

// The Forge v3 release-metadata document (the JSON returned for
// GET /v3/releases/<owner>-<name>-<version>) carries the release tarball's
// "file_uri", "file_size", "file_md5", and "file_sha256", plus the module
// metadata the proxy does not need. The backend reads this document on a
// release-tarball miss to recover the published digest and verify the fetched
// bytes against it.

// releaseMeta models the fields the proxy needs from a release-metadata
// document. Unknown fields are ignored.
type releaseMeta struct {
	FileURI    string `json:"file_uri"`
	FileSize   int64  `json:"file_size"`
	FileMD5    string `json:"file_md5"`
	FileSHA256 string `json:"file_sha256"`
}

// parseReleaseMeta decodes a release-metadata JSON body. A nil error with a zero
// value is returned for an empty body; a decode error is surfaced so a malformed
// document is treated as "no checksum available" by the caller rather than
// trusted.
func parseReleaseMeta(body []byte) (releaseMeta, error) {
	var rm releaseMeta
	if len(body) == 0 {
		return rm, nil
	}
	if err := json.Unmarshal(body, &rm); err != nil {
		return releaseMeta{}, err
	}
	return rm, nil
}

// checksum returns the strongest usable digest the release metadata declares,
// preferring SHA-256 over the legacy MD5. ok=false when neither field holds a
// well-formed digest.
func (rm releaseMeta) checksum() (expectedChecksum, bool) {
	if h := strings.ToLower(strings.TrimSpace(rm.FileSHA256)); len(h) == sha256HexLen && isHex(h) {
		return expectedChecksum{algo: algoSHA256, hex: h}, true
	}
	if h := strings.ToLower(strings.TrimSpace(rm.FileMD5)); len(h) == md5HexLen && isHex(h) {
		return expectedChecksum{algo: algoMD5, hex: h}, true
	}
	return expectedChecksum{}, false
}

// rewriteMetadata rewrites every absolute upstream URL embedded in a metadata
// document so it routes back through the proxy. It walks the decoded JSON and
// replaces any string value that begins with the upstream origin (e.g.
// "https://forgeapi.puppet.com") with the proxy's PublicBaseURL, preserving the
// path and query. It returns changed=false (and the original bytes) when the
// body does not parse as JSON or contains no such URL, so a non-JSON or link-
// free document is served byte-for-byte. Forge documents use relative URIs
// (e.g. a release "file_uri" of "/v3/files/...") predominantly, so this is
// usually a no-op, but it holds defensively for any absolute self-reference the
// API emits (e.g. paginated "next"/"previous" links).
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
