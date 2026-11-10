package terraform

import (
	"strings"
)

// The module registry protocol's download endpoint
//
//	GET /v1/modules/{namespace}/{name}/{system}/{version}/download
//
// returns 204 No Content with an X-Terraform-Get header naming a go-getter
// source URL for the module's source archive. The proxy resolves that header to
// fetch and cache the archive, and rewrites the header so the client retrieves
// the archive through the proxy. See
// https://developer.hashicorp.com/terraform/internals/module-registry-protocol.

// terraformGet is a parsed X-Terraform-Get value. go-getter encodes the source
// as "[forcePrefix::]<url>[//<subdir>][?<query>]"; the proxy can only cache the
// archive when the underlying transport is plain HTTP(S).
type terraformGet struct {
	// force is the optional go-getter forced-protocol prefix (e.g. "git", "http"),
	// without the "::" separator. Empty when none was present.
	force string
	// url is the underlying source URL with any force prefix, subdir, and query
	// stripped.
	url string
	// subdir is the "//<subdir>" component (without the leading "//"), preserved so
	// the rewritten value extracts the same subtree.
	subdir string
	// query is the "?<query>" component (without the leading "?"), preserved so
	// go-getter applies the same archive/ref hints.
	query string
}

// parseTerraformGet splits an X-Terraform-Get value into its go-getter
// components. An empty input yields ok=false.
func parseTerraformGet(raw string) (terraformGet, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return terraformGet{}, false
	}
	var g terraformGet

	// Forced-protocol prefix: "<prefix>::<rest>". A Windows drive letter
	// ("C:\\...") is not a force prefix, but those never appear in registry
	// responses; the "::" form is unambiguous.
	if i := strings.Index(s, "::"); i >= 0 {
		g.force = strings.ToLower(strings.TrimSpace(s[:i]))
		s = s[i+2:]
	}

	// Query: everything after the first "?".
	if i := strings.IndexByte(s, '?'); i >= 0 {
		g.query = s[i+1:]
		s = s[:i]
	}

	// Subdir: the go-getter "//" separator (distinct from the "://" scheme
	// separator). Search past the scheme.
	if i := subdirIndex(s); i >= 0 {
		g.subdir = s[i+2:]
		s = s[:i]
	}

	g.url = strings.TrimSpace(s)
	if g.url == "" {
		return terraformGet{}, false
	}
	return g, true
}

// subdirIndex returns the index of the go-getter "//" subdir separator in a URL,
// or -1 when there is none. It skips the "://" scheme separator so
// "https://host/p//sub" splits at the second "//".
func subdirIndex(s string) int {
	start := 0
	if i := strings.Index(s, "://"); i >= 0 {
		start = i + 3
	}
	if i := strings.Index(s[start:], "//"); i >= 0 {
		return start + i
	}
	return -1
}

// cacheable reports whether the proxy can fetch and cache the archive itself:
// only plain HTTP(S) sources (no forced non-HTTP transport, an http/https URL)
// are cacheable. git/s3/gcs/etc. getters are passed through to the client.
func (g terraformGet) cacheable() bool {
	switch g.force {
	case "", "http", "https":
	default:
		return false
	}
	lower := strings.ToLower(g.url)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// archiveType infers the go-getter archive hint from the source URL extension,
// returning "" when none is recognized. It lets the rewritten value tell
// go-getter how to unpack the proxy-served archive, which has no file extension.
func (g terraformGet) archiveType() string {
	u := strings.ToLower(g.url)
	switch {
	case strings.HasSuffix(u, ".tar.gz"), strings.HasSuffix(u, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(u, ".tar.bz2"), strings.HasSuffix(u, ".tbz2"):
		return "tar.bz2"
	case strings.HasSuffix(u, ".tar.xz"), strings.HasSuffix(u, ".txz"):
		return "tar.xz"
	case strings.HasSuffix(u, ".zip"):
		return "zip"
	case strings.HasSuffix(u, ".tar"):
		return "tar"
	default:
		return ""
	}
}

// rewrite composes the X-Terraform-Get value pointing the client at archiveURL
// (the proxy's archive endpoint), preserving the subdir and merging the original
// query with an archive-type hint so go-getter unpacks the extension-less
// proxy-served archive correctly.
func (g terraformGet) rewrite(archiveURL string) string {
	out := archiveURL
	if g.subdir != "" {
		out += "//" + g.subdir
	}
	query := g.query
	if !hasQueryKey(query, "archive") {
		if at := g.archiveType(); at != "" {
			if query != "" {
				query += "&"
			}
			query += "archive=" + at
		}
	}
	if query != "" {
		out += "?" + query
	}
	return out
}

// hasQueryKey reports whether the raw query string already sets key.
func hasQueryKey(query, key string) bool {
	for _, kv := range strings.Split(query, "&") {
		if kv == key || strings.HasPrefix(kv, key+"=") {
			return true
		}
	}
	return false
}
