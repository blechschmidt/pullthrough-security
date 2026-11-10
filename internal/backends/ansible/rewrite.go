package ansible

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strings"
)

// Galaxy's API documents and redirects are full of references to the registry
// itself, and a client follows them: ansible-galaxy pages through a versions
// list by "links.next", downloads the tarball a version detail names in
// "download_url", and follows the redirect Galaxy answers for its short
// "/api/v3/collections/..." aliases. Every such reference must come back
// through this backend's mount ("<publicBase>/v1/<name>"); one that does not
// either resolves against the proxy's host root and misses the backend, or
// reaches the upstream directly and skips the content gates and checksum
// verification.
//
// Galaxy writes these references in two shapes, and the client handles each
// differently, so each keeps its shape through the rewrite:
//
//   - A root-relative link ("/api/v3/plugin/.../versions/?limit=100&offset=100"
//     in links.next/first/last, href, versions_url, pulp_href, next_link, ...)
//     stays root-relative and gains the mount's path. It must not become an
//     absolute URL: ansible-core before 2.19 splices a pagination link into the
//     URL it requested, and the v1 role client joins a "next_link" onto the
//     server root, so an absolute value there yields a malformed request.
//   - An absolute URL at the upstream ("https://galaxy.ansible.com/api/...", as
//     in download_url or a v1 "next") becomes absolute at the proxy's public
//     base. ansible-core before 2.19 opens download_url verbatim, so it must stay
//     absolute whenever the proxy knows its public URL; without one it falls
//     back to the root-relative mount path, which newer clients resolve.

// defaultAPIRoot is the path the Galaxy API tree hangs off: "/api/v3/...",
// "/api/v1/...", and "/api/pulp/..." on galaxy.ansible.com, with an Automation
// Hub serving the same API beneath "/api/galaxy/" or "/api/automation-hub/". It
// is what tells a root-relative link apart from a string that merely starts
// with "/" when the upstream URL carries no path of its own.
const defaultAPIRoot = "/api"

// linkRewriter maps references into the upstream Galaxy tree onto the proxy
// mount. It is immutable after construction and safe for concurrent use.
type linkRewriter struct {
	// authority is the upstream host[:port], lower-cased, default port removed.
	authority string
	// basePath is the upstream base path, escaped, with no trailing slash; ""
	// when the upstream URL is a bare origin. The mount exposes exactly the tree
	// beneath it, so it is stripped from every reference that is mapped.
	basePath string
	// linkPrefix is the prefix (ending in "/") a root-relative JSON value must
	// carry to be treated as a link: the upstream base path when there is one,
	// otherwise defaultAPIRoot.
	linkPrefix string
	// publicBase is the client-facing mount with no trailing slash: an absolute
	// URL ("https://proxy.example.com/v1/ansible") when the proxy knows its
	// public URL, otherwise the root-relative "/v1/<name>".
	publicBase string
	// mountPath is the path component of publicBase ("/v1/ansible").
	mountPath string
}

// newLinkRewriter builds the rewriter for an upstream base URL and the
// client-facing mount it is served under.
func newLinkRewriter(base *url.URL, publicBase string) *linkRewriter {
	basePath := strings.TrimRight(base.EscapedPath(), "/")
	linkRoot := basePath
	if linkRoot == "" {
		linkRoot = defaultAPIRoot
	}
	return &linkRewriter{
		authority:  normalizeAuthority(base.Scheme, base.Host),
		basePath:   basePath,
		linkPrefix: linkRoot + "/",
		publicBase: publicBase,
		mountPath:  mountPathOf(publicBase),
	}
}

// mountPathOf returns the path component of a public base: the path of an
// absolute URL, or the base itself when it is already root-relative.
func mountPathOf(publicBase string) string {
	if u, err := url.Parse(publicBase); err == nil && u.Scheme != "" && u.Host != "" {
		return strings.TrimRight(u.EscapedPath(), "/")
	}
	return publicBase
}

// rewriteDocument rewrites every link value in a JSON document so it routes
// back through the mount. Only string values are considered — never object
// keys — and only those rewriteValue recognises as links. It returns
// changed=false and the original bytes when the body is not a single JSON value
// or holds no link, so a non-JSON or link-free document is served byte-for-byte.
// Numbers are carried through as written, so re-encoding cannot round a large
// integer or turn 1.0 into 1.
func (lr *linkRewriter) rewriteDocument(body []byte) (out []byte, changed bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return body, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return body, false // trailing data: not a single JSON document
	}
	doc = lr.rewriteNode(doc, &changed)
	if !changed {
		return body, false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return body, false
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true
}

// rewriteNode walks a decoded JSON value, replacing link strings in place.
func (lr *linkRewriter) rewriteNode(node any, changed *bool) any {
	switch t := node.(type) {
	case string:
		if s, ok := lr.rewriteValue(t); ok && s != t {
			*changed = true
			return s
		}
	case []any:
		for i, e := range t {
			t[i] = lr.rewriteNode(e, changed)
		}
	case map[string]any:
		for k, e := range t {
			t[k] = lr.rewriteNode(e, changed)
		}
	}
	return node
}

// rewriteValue maps one JSON string value onto the mount. It reports ok=false,
// leaving the value untouched, unless the whole value is a link into the
// upstream tree:
//
//   - an absolute http(s) URL at the upstream authority; or
//   - a root-relative path into the API tree (see linkPrefix).
//
// Either way the value must be a well-formed URL reference free of whitespace
// and control characters, as a real link is, and must not carry dot segments.
// So prose that merely starts with "/" or with the upstream's URL, a filesystem
// path, a link to another host, and a look-alike host are all left alone.
//
// An absolute upstream URL outside the upstream base path names a resource the
// mount does not expose, so it has no faithful mapping. It is still moved to
// the public base, path intact, rather than left pointing at the upstream: the
// link then fails at the proxy instead of taking the client around it.
func (lr *linkRewriter) rewriteValue(s string) (string, bool) {
	var prefix, ref string
	absolute := !strings.HasPrefix(s, lr.linkPrefix)
	if absolute {
		authority, rest, ok := cutAuthority(s)
		if !ok || authority != lr.authority {
			return s, false
		}
		prefix, ref = lr.publicBase, rest
	} else {
		prefix, ref = lr.mountPath, s
	}
	if !isCleanRef(s) {
		return s, false
	}
	if _, err := url.Parse(s); err != nil {
		return s, false
	}
	path, suffix := cutPath(ref)
	rel, ok := lr.mountRelative(path)
	if !ok {
		if !absolute || hasDotSegment(path) {
			return s, false
		}
		rel = path
	}
	return prefix + rel + suffix, true
}

// location maps the Location of a redirect the upstream answered for
// requestURL onto the mount, so a redirect the proxy relays instead of
// following still leads the client back through this backend. ok is false when
// the target is not inside the proxied tree — another host, a path outside the
// upstream base, or one whose dot segments could leave it — and such a redirect
// must never be relayed. A relative Location stays relative (the mount's path);
// an absolute one is re-anchored at the public base.
func (lr *linkRewriter) location(requestURL, location string) (string, bool) {
	location = strings.TrimSpace(location)
	if location == "" || !isCleanRef(location) {
		return "", false
	}
	base, err := url.Parse(requestURL)
	if err != nil {
		return "", false
	}
	ref, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	target := base.ResolveReference(ref)
	if target.Opaque != "" || target.User != nil {
		return "", false
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return "", false
	}
	if normalizeAuthority(target.Scheme, target.Host) != lr.authority {
		return "", false
	}
	rel, ok := lr.mountRelative(target.EscapedPath())
	if !ok {
		return "", false
	}
	out := lr.mountPath
	if ref.Scheme != "" || ref.Host != "" {
		out = lr.publicBase
	}
	out += rel
	if target.RawQuery != "" {
		out += "?" + target.RawQuery
	}
	if target.Fragment != "" {
		out += "#" + target.EscapedFragment()
	}
	return out, true
}

// mountRelative maps an upstream path ("" or beginning with "/") to the same
// path relative to the mount by stripping the upstream base path. ok is false
// for a path outside the proxied tree, or one whose dot segments would let a
// client or server normalising it climb out of the mount.
func (lr *linkRewriter) mountRelative(p string) (string, bool) {
	if lr.basePath != "" {
		if p != lr.basePath && !strings.HasPrefix(p, lr.basePath+"/") {
			return "", false
		}
		p = p[len(lr.basePath):]
	}
	if hasDotSegment(p) {
		return "", false
	}
	return p, true
}

// cutAuthority splits an absolute http(s) URL into its normalised authority and
// the remainder (path, query, fragment). ok is false for anything else: a
// relative reference, another scheme, or a URL carrying userinfo.
func cutAuthority(s string) (authority, rest string, ok bool) {
	var scheme string
	switch {
	case hasPrefixFold(s, "https://"):
		scheme = "https"
	case hasPrefixFold(s, "http://"):
		scheme = "http"
	default:
		return "", "", false
	}
	rest = s[len(scheme)+len("://"):]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, rest = rest[:end], rest[end:]
	if authority == "" || strings.Contains(authority, "@") {
		return "", "", false
	}
	return normalizeAuthority(scheme, authority), rest, true
}

// normalizeAuthority lower-cases a host[:port] and drops the scheme's default
// port. The scheme itself is deliberately not part of the result: Galaxy emits
// "http://" self-links from behind its TLS terminator (a v1 "next"), and those
// address the same registry the proxy fetches over the configured scheme.
func normalizeAuthority(scheme, host string) string {
	host = strings.ToLower(host)
	switch strings.ToLower(scheme) {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

// cutPath splits a reference into its path and the "?query#fragment" suffix.
func cutPath(ref string) (path, suffix string) {
	if i := strings.IndexAny(ref, "?#"); i >= 0 {
		return ref[:i], ref[i:]
	}
	return ref, ""
}

// isCleanRef reports whether s could be a URL reference rather than prose: it
// holds no whitespace, control character, or backslash. A real link is
// percent-encoded.
func isCleanRef(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return false
		}
	}
	return true
}

// hasDotSegment reports whether an escaped URL path holds a "." or ".."
// segment once percent-decoded — including one hidden behind an encoded dot or
// an encoded separator — or is not validly escaped at all.
func hasDotSegment(p string) bool {
	dec, err := url.PathUnescape(p)
	if err != nil {
		return true
	}
	for dec != "" {
		seg := dec
		if i := strings.IndexAny(dec, `/\`); i >= 0 {
			seg, dec = dec[:i], dec[i+1:]
		} else {
			dec = ""
		}
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// hasPrefixFold reports whether s begins with prefix, ignoring ASCII case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
