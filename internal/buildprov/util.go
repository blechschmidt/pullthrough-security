package buildprov

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// digestBinds assesses whether a parsed in-toto statement binds the artifact's
// content digest. Binding is algorithm-aware: npm provenance binds the tarball's
// sha512 while the proxy's content digest may be a sha256, so when the artifact
// digest's algorithm does not appear in any subject the binding is "not
// checkable" (checked=false) rather than a failure. When the algorithm IS present
// the hex must match (checked=true, ok=match). An empty artifact digest or a
// statement with no subjects is treated as not checkable.
func digestBinds(statement *sigverify.Statement, artDigest string) (checked, ok bool) {
	if statement == nil {
		return false, false
	}
	algo, hex, found := strings.Cut(strings.ToLower(strings.TrimSpace(artDigest)), ":")
	if !found || algo == "" || hex == "" {
		return false, false
	}
	for _, sub := range statement.Subject {
		for a, h := range sub.Digest {
			if strings.EqualFold(a, algo) {
				checked = true
				if strings.EqualFold(h, hex) {
					return true, true
				}
			}
		}
	}
	return checked, false
}

// sameCommit compares two git commit SHAs, tolerating short/abbreviated forms:
// the shorter must be a hex prefix of the longer (case-insensitive). This matches
// how a metadata-claimed short SHA can legitimately equal a full proven SHA.
func sameCommit(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// Require a minimum abbreviation length so a stray short value cannot match
	// arbitrarily.
	short, long := a, b
	if len(long) < len(short) {
		short, long = long, short
	}
	if len(short) < 7 {
		return false
	}
	return strings.HasPrefix(long, short)
}

// sameRepo compares two repository URLs after normalization (scheme, credentials,
// VCS prefixes/suffixes, host case, trailing slash). Both empties never match.
func sameRepo(a, b string) bool {
	na, nb := normalizeRepo(a), normalizeRepo(b)
	return na != "" && na == nb
}

// normalizeRepo reduces a repository URL to a comparable "host/path" form.
func normalizeRepo(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	u = strings.TrimPrefix(u, "git+")
	u = strings.TrimPrefix(u, "ssh://")
	// Drop a trailing "@<ref>" pin past the scheme separator.
	if i := strings.Index(u, "://"); i >= 0 {
		if at := strings.LastIndex(u, "@"); at > i {
			u = u[:at]
		}
	}
	// scp-like git@host:owner/repo.
	if at := strings.Index(u, "@"); at >= 0 && !strings.Contains(u, "://") {
		if colon := strings.Index(u[at:], ":"); colon >= 0 {
			u = u[at+1:]
			u = strings.Replace(u, ":", "/", 1)
		}
	}
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimSuffix(u, "/")
	return strings.ToLower(u)
}

// shortSHA abbreviates a commit SHA to 12 hex characters for messages.
func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
