package lockfiles

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

// digestSizes are the byte lengths of the hash functions lock files use.
var digestSizes = map[string]int{"md5": 16, "sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

// hexDigest returns a digest from a hex value, or false when the value is not
// hex of the algorithm's length.
func hexDigest(alg, value, of string) (Digest, bool) {
	alg = strings.ToLower(strings.TrimSpace(alg))
	value = strings.ToLower(strings.TrimSpace(value))
	n, ok := digestSizes[alg]
	if !ok || len(value) != 2*n || !isHex(value) {
		return Digest{}, false
	}
	return Digest{Algorithm: alg, Value: value, Of: of}, true
}

// base64Digest returns a digest from a base64 value (standard alphabet, with
// or without padding), converted to hex.
func base64Digest(alg, value, of string) (Digest, bool) {
	alg = strings.ToLower(strings.TrimSpace(alg))
	n, ok := digestSizes[alg]
	if !ok {
		return Digest{}, false
	}
	value = strings.TrimSpace(value)
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(value, "="))
	}
	if err != nil || len(raw) != n {
		return Digest{}, false
	}
	return Digest{Algorithm: alg, Value: hex.EncodeToString(raw), Of: of}, true
}

// sriDigests parses a Subresource Integrity value ("sha512-<base64>
// sha1-<base64>"), as npm, Yarn and pnpm write it. Options ("?foo") and
// unknown algorithms are ignored.
func sriDigests(sri string) []Digest {
	var out []Digest
	for _, part := range strings.Fields(sri) {
		alg, value, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		if i := strings.IndexByte(value, '?'); i >= 0 {
			value = value[:i]
		}
		if d, ok := base64Digest(alg, value, ""); ok {
			out = append(out, d)
		}
	}
	return out
}

// prefixedDigest parses "<alg>:<hex>" or "<alg>=<hex>" ("sha256:9f8e…").
func prefixedDigest(s, of string) (Digest, bool) {
	s = strings.TrimSpace(s)
	i := strings.IndexAny(s, ":=")
	if i <= 0 {
		return Digest{}, false
	}
	return hexDigest(s[:i], s[i+1:], of)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return s != ""
}

// isCommitID reports whether s is a full Git object ID (SHA-1 or SHA-256).
func isCommitID(s string) bool {
	return (len(s) == 40 || len(s) == 64) && isHex(s)
}

// fileNameOf returns the last path segment of a URL or path, unescaped.
func fileNameOf(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	name := raw[strings.LastIndex(raw, "/")+1:]
	if u, err := url.PathUnescape(name); err == nil {
		name = u
	}
	return name
}

// originOf returns "scheme://host" of an http(s) URL, or "".
func originOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// isHTTPURL reports whether s starts like an http(s) URL.
func isHTTPURL(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// gitSource is a dependency fetched from a Git repository.
type gitSource struct {
	repo     string // the repository URL, cleaned
	revision string // the pinned commit, when the reference names one
	ref      string // what the reference names otherwise (a tag, a branch)
}

// parseGitURL splits a VCS reference as npm, Yarn, pip and Cargo write them:
//
//	git+https://github.com/o/r.git#<commit>
//	git+ssh://git@github.com/o/r.git#<commit>
//	https://github.com/o/r.git#commit=<commit>
//	git+https://github.com/o/r?tag=v1#<commit>
//	github:o/r#<ref>
//
// The fragment (or its "commit=" parameter) is the revision when it is a full
// commit ID.
func parseGitURL(raw string) gitSource {
	raw = strings.TrimSpace(raw)
	base, frag, _ := strings.Cut(raw, "#")
	for _, kv := range strings.Split(frag, "&") {
		if v, ok := strings.CutPrefix(kv, "commit="); ok {
			frag = v
		}
	}
	for _, short := range []string{"github:", "gitlab:", "bitbucket:"} {
		if rest, ok := strings.CutPrefix(base, short); ok {
			host := map[string]string{"github:": "github.com", "gitlab:": "gitlab.com", "bitbucket:": "bitbucket.org"}[short]
			base = "https://" + host + "/" + rest
		}
	}
	gs := gitSource{repo: cleanGitRepoURL(base)}
	if isCommitID(frag) {
		gs.revision = strings.ToLower(frag)
	} else {
		gs.ref = frag
	}
	return gs
}

// cleanGitRepoURL removes the "git+" prefix and what cleanURL removes, but
// keeps the user of an ssh URL ("git@"), which is not a secret.
func cleanGitRepoURL(raw string) string {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "git+")
	if strings.HasPrefix(strings.ToLower(raw), "ssh://") {
		rest := raw[len("ssh://"):]
		if at := strings.Index(rest, "@"); at >= 0 && at < strings.IndexAny(rest+"/", "/") {
			user := rest[:at]
			if !strings.Contains(user, ":") && len(user) <= 32 && !strings.HasPrefix(user, linkTokenPrefix) {
				return "ssh://" + user + "@" + cleanURL(rest[at+1:])
			}
		}
	}
	return cleanURL(raw)
}

// npmScopedEscape matches the escaped spellings of a scoped name's slash.
var npmScopedEscape = regexp.MustCompile(`(?i)%2f`)

// npmRegistryBase derives the registry base URL from an npm tarball URL
// ("https://registry.npmjs.org/@types/node/-/node-20.14.10.tgz" →
// "https://registry.npmjs.org"): what comes before "/<name>/-/". ok is false
// for a URL of another shape — a tarball somewhere, not a registry's download
// — whose origin is returned.
func npmRegistryBase(tarball, name string) (base string, ok bool) {
	clean := cleanURL(tarball)
	i := strings.LastIndex(clean, "/-/")
	if i < 0 {
		return originOf(clean), false
	}
	before := clean[:i]
	for _, spelled := range []string{name, strings.Replace(name, "/", "%2f", 1), strings.Replace(name, "/", "%2F", 1)} {
		if spelled != "" && strings.HasSuffix(before, "/"+spelled) {
			return strings.TrimSuffix(before, "/"+spelled), true
		}
	}
	// "%40scope%2fname" and other spellings: unescape the last segments.
	if j := strings.LastIndex(before, "/"); j >= 0 {
		seg := npmScopedEscape.ReplaceAllString(before[j+1:], "/")
		if u, err := url.PathUnescape(seg); err == nil && u == name {
			return before[:j], true
		}
		if k := strings.LastIndex(before[:j], "/"); k >= 0 && strings.HasPrefix(name, "@") {
			if u, err := url.PathUnescape(before[k+1:]); err == nil && u == name {
				return before[:k], true
			}
		}
	}
	return originOf(clean), false
}

// splitNameAt splits "name@rest" at the first "@" that is not the first
// character (which starts a scoped npm name).
func splitNameAt(s string) (name, rest string, ok bool) {
	if len(s) < 2 {
		return "", "", false
	}
	i := strings.IndexByte(s[1:], '@')
	if i < 0 {
		return "", "", false
	}
	return s[:i+1], s[i+2:], true
}

// splitNameAtLast splits "name@version" at the last "@" that is not the first
// character.
func splitNameAtLast(s string) (name, version string, ok bool) {
	i := strings.LastIndexByte(s, '@')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// validPackageName rejects names no ecosystem uses: empty, very long, or
// carrying control characters or whitespace.
func validPackageName(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

// validVersion rejects versions no ecosystem uses.
func validVersion(s string) bool { return validPackageName(s) && len(s) <= 256 }
