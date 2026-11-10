package jsr

import (
	"encoding/json"
	"strings"
)

// The JSR version-metadata document (the JSON a registry returns for
// GET /@<scope>/<name>/<version>_meta.json) carries a "manifest" object mapping
// each published file path to its size and content checksum, plus "exports" and
// module-graph fields the proxy does not need. The checksum is a
// Subresource-Integrity-style "sha256-<hex>" string over the file's bytes. The
// backend reads this document on a module-file miss to recover the file's
// declared SHA-256 and verify the fetched bytes against it.

// versionMeta models the fields the proxy needs from a version-metadata
// document. Unknown fields are ignored.
type versionMeta struct {
	Manifest map[string]manifestEntry `json:"manifest"`
}

type manifestEntry struct {
	Size     int64  `json:"size"`
	Checksum string `json:"checksum"`
}

// parseVersionMeta decodes a version-metadata JSON body. A nil error with a zero
// value is returned for an empty body; a decode error is surfaced so a malformed
// document is treated as "no checksum available" by the caller rather than
// trusted.
func parseVersionMeta(body []byte) (versionMeta, error) {
	var vm versionMeta
	if len(body) == 0 {
		return vm, nil
	}
	if err := json.Unmarshal(body, &vm); err != nil {
		return versionMeta{}, err
	}
	return vm, nil
}

// checksumFor returns the lowercase hex SHA-256 the manifest declares for a
// file path (keyed exactly as the manifest keys it, with a leading slash), and
// ok=false when the file is absent or carries no well-formed SHA-256 checksum.
func (vm versionMeta) checksumFor(filePath string) (hex string, ok bool) {
	entry, found := vm.Manifest[filePath]
	if !found {
		return "", false
	}
	return parseSRIChecksum(entry.Checksum)
}

// parseSRIChecksum parses a JSR manifest checksum. JSR records a
// Subresource-Integrity-style "sha256-<hex>" value (a 64-char lowercase hex
// SHA-256, hyphen-separated from the algorithm — not the base64 the SRI spec
// uses for HTML <script integrity>). It returns ok=false for any other algorithm
// or a malformed value so a garbage digest is never treated as a passing check.
func parseSRIChecksum(raw string) (hex string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	// Accept either "sha256-<hex>" (the JSR form) or "sha256:<hex>".
	var sep int
	if i := strings.IndexAny(s, "-:"); i >= 0 {
		sep = i
	} else {
		return "", false
	}
	alg := strings.ToLower(strings.TrimSpace(s[:sep]))
	if alg != "sha256" && alg != "sha-256" {
		return "", false
	}
	h := strings.ToLower(strings.TrimSpace(s[sep+1:]))
	if len(h) != sha256HexLen || !isHex(h) {
		return "", false
	}
	return h, true
}

// rewriteMetadata rewrites every absolute upstream URL embedded in a metadata
// document so it routes back through the proxy. It walks the decoded JSON and
// replaces any string value that begins with the upstream origin (e.g.
// "https://jsr.io") with the proxy's PublicBaseURL, preserving the path and
// query. It returns changed=false (and the original bytes) when the body does
// not parse as JSON or contains no such URL, so a non-JSON or link-free document
// is served byte-for-byte.
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
