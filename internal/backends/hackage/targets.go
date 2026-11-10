package hackage

import (
	"encoding/json"
	"strings"
)

// Hackage's hackage-security (TUF) metadata records, for every package version,
// a "package.json" target-metadata document that pins the sdist tarball's length
// and content hashes. Its shape is a TUF "Targets" role:
//
//	{
//	  "signed": {
//	    "_type": "Targets",
//	    "targets": {
//	      "<repo>/package/<name>-<ver>.tar.gz": {
//	        "hashes": { "md5": "…", "sha256": "…" },
//	        "length": 12345
//	      }
//	    },
//	    "version": 0, "expires": null
//	  },
//	  "signatures": [ … ]
//	}
//
// The proxy fetches this sibling document on an sdist miss and reads the SHA-256
// for the tarball target to verify the fetched bytes against. Only the SHA-256
// is used for security; Hackage records MD5 purely as mirroring metadata.

// tufTargets models just the fields the proxy needs from a package.json.
type tufTargets struct {
	Signed struct {
		Targets map[string]struct {
			Hashes struct {
				SHA256 string `json:"sha256"`
			} `json:"hashes"`
			Length int64 `json:"length"`
		} `json:"targets"`
	} `json:"signed"`
}

// parseTargetSHA256 decodes a package.json TUF target metadata body and returns
// the lowercase hex SHA-256 recorded for the target whose key names the given
// sdist filename (the target keys are repository-relative paths that end in the
// "<name>-<ver>.tar.gz" filename). It returns ok=false for an unparseable body,
// a missing target, or a malformed/absent SHA-256, so a garbage or unavailable
// digest is never treated as a passing check.
func parseTargetSHA256(body []byte, filename string) (hex string, ok bool) {
	if len(body) == 0 {
		return "", false
	}
	var t tufTargets
	if err := json.Unmarshal(body, &t); err != nil {
		return "", false
	}
	for key, target := range t.Signed.Targets {
		if key == filename || strings.HasSuffix(key, "/"+filename) {
			return normalizeSHA256(target.Hashes.SHA256)
		}
	}
	return "", false
}

// normalizeSHA256 returns the lowercase hex form of a 64-char hex SHA-256, or
// ok=false when the value is not a well-formed SHA-256 digest.
func normalizeSHA256(raw string) (hex string, ok bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) != sha256HexLen || !isHex(s) {
		return "", false
	}
	return s, true
}
