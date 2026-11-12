package intercept

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

// Router maps an intercepted request — the upstream host the client addressed,
// and the path it asked for there — to the configured backend that proxies it.
//
// A rule names a host and, optionally, a path prefix on it:
//
//	registry.npmjs.org             every path on the host
//	deb.debian.org/debian          only /debian and what is below it
//	*.example.com                  every host below example.com
//	*.example.com/packages         /packages on every host below example.com
//
// The path prefix is what an upstream's base URL carries: an upstream
// configured as https://repo1.maven.org/maven2 serves the client's
// /maven2/org/… requests, and the backend expects them as /org/… — the prefix
// is taken off. A request for a path no rule of the host covers is not served
// (/debian-security on a host where only /debian is configured is someone
// else's repository, or nobody's).
//
// Exact host rules take precedence over wildcard rules, and among the rules of
// one host the longest path prefix wins. Hosts are case-insensitive and any
// port is ignored; paths are compared case-sensitively and on segment
// boundaries (/debian does not cover /debian-security).
//
// The zero Router matches nothing. Build one with NewRouter.
type Router struct {
	exact    map[string][]pathRule // host -> rules, longest prefix first
	suffixes []suffixRule          // "*.example.com" rules, longest suffix first
}

type pathRule struct {
	prefix  string // "" (every path) or "/debian" (no trailing slash)
	backend string
}

type suffixRule struct {
	suffix string     // ".example.com" (includes the leading dot)
	rules  []pathRule // longest prefix first
}

// Route is where a Router sends a request.
type Route struct {
	// Backend is the name of the configured upstream that serves the request.
	Backend string
	// Prefix is the path prefix the matching rule names ("" for a host rule).
	// It is taken off the request path before the backend sees it.
	Prefix string
	// Path is the request path with Prefix taken off; it always begins with
	// "/".
	Path string
}

// NewRouter builds a Router from a rule -> backend map. A key is a host
// ("registry.npmjs.org"), a single wildcard ("*.docker.io"), either one
// followed by a path prefix ("deb.debian.org/debian"), or either one written as
// a URL ("https://deb.debian.org/debian", whose scheme is ignored). Entries
// with an empty host or backend are ignored.
func NewRouter(rules map[string]string) *Router {
	r := &Router{exact: make(map[string][]pathRule, len(rules))}
	suffixes := map[string][]pathRule{}
	for key, backend := range rules {
		backend = strings.TrimSpace(backend)
		host, prefix, ok := ParseRule(key)
		if !ok || backend == "" {
			continue
		}
		rule := pathRule{prefix: prefix, backend: backend}
		if strings.HasPrefix(host, "*.") {
			suffixes[host[1:]] = append(suffixes[host[1:]], rule)
			continue
		}
		r.exact[host] = append(r.exact[host], rule)
	}
	for host, list := range r.exact {
		r.exact[host] = sortRules(list)
	}
	for suffix, list := range suffixes {
		r.suffixes = append(r.suffixes, suffixRule{suffix: suffix, rules: sortRules(list)})
	}
	// Longest suffix first so the most specific wildcard wins; ties broken by
	// name so the order does not depend on map iteration.
	sort.Slice(r.suffixes, func(i, j int) bool {
		if len(r.suffixes[i].suffix) != len(r.suffixes[j].suffix) {
			return len(r.suffixes[i].suffix) > len(r.suffixes[j].suffix)
		}
		return r.suffixes[i].suffix < r.suffixes[j].suffix
	})
	return r
}

// sortRules orders a host's rules longest prefix first and drops a duplicate
// prefix (the first backend in name order keeps it, so a conflicting
// configuration resolves the same way on every start).
func sortRules(list []pathRule) []pathRule {
	sort.Slice(list, func(i, j int) bool {
		if len(list[i].prefix) != len(list[j].prefix) {
			return len(list[i].prefix) > len(list[j].prefix)
		}
		if list[i].prefix != list[j].prefix {
			return list[i].prefix < list[j].prefix
		}
		return list[i].backend < list[j].backend
	})
	out := list[:0]
	for i, rule := range list {
		if i > 0 && rule.prefix == list[i-1].prefix {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// ParseRule splits a routing-rule key into its lowercase host (possibly a
// "*.suffix" wildcard) and its path prefix ("" or "/a/b", without a trailing
// slash). ok is false for a key without a host.
func ParseRule(key string) (host, prefix string, ok bool) {
	key = strings.TrimSpace(key)
	if i := strings.Index(key, "://"); i >= 0 {
		key = key[i+3:]
	}
	host, prefix, _ = strings.Cut(key, "/")
	host = strings.ToLower(strings.TrimSpace(host))
	if !strings.HasPrefix(host, "*.") {
		host = normalizeHost(host)
	}
	if host == "" || host == "*." {
		return "", "", false
	}
	// A query or fragment in a URL-shaped key is not part of the prefix.
	if i := strings.IndexAny(prefix, "?#"); i >= 0 {
		prefix = prefix[:i]
	}
	prefix = strings.Trim(prefix, "/")
	if prefix != "" {
		prefix = "/" + prefix
	}
	return host, prefix, true
}

// Intercepts reports whether any rule covers host — whether a connection to it
// is decrypted and served rather than refused or passed through. host may
// carry a port, which is ignored.
func (r *Router) Intercepts(host string) bool {
	if r == nil {
		return false
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	if len(r.exact[h]) > 0 {
		return true
	}
	for _, s := range r.suffixes {
		if strings.HasSuffix(h, s.suffix) {
			return true
		}
	}
	return false
}

// Route returns where a request for path on host goes, or ok=false when no rule
// covers it. path is the request's (decoded) path.
func (r *Router) Route(host, path string) (Route, bool) {
	if r == nil {
		return Route{}, false
	}
	h := normalizeHost(host)
	if h == "" {
		return Route{}, false
	}
	if path == "" {
		path = "/"
	}
	if route, ok := matchRules(r.exact[h], path); ok {
		return route, true
	}
	for _, s := range r.suffixes {
		if !strings.HasSuffix(h, s.suffix) {
			continue
		}
		if route, ok := matchRules(s.rules, path); ok {
			return route, true
		}
	}
	return Route{}, false
}

// matchRules returns the first (longest) rule whose prefix covers path.
func matchRules(rules []pathRule, path string) (Route, bool) {
	for _, rule := range rules {
		rest, ok := cutPathPrefix(path, rule.prefix)
		if ok {
			return Route{Backend: rule.backend, Prefix: rule.prefix, Path: rest}, true
		}
	}
	return Route{}, false
}

// cutPathPrefix takes prefix off path when it covers it on a segment boundary.
// The remainder always begins with "/".
func cutPathPrefix(path, prefix string) (string, bool) {
	if prefix == "" {
		return path, true
	}
	rest, ok := strings.CutPrefix(path, prefix)
	if !ok {
		return "", false
	}
	switch {
	case rest == "":
		return "/", true
	case rest[0] == '/':
		return rest, true
	default:
		return "", false // "/debian-security" is not below "/debian"
	}
}

// Hosts returns the configured rules in sorted order — "host" or "host/path",
// wildcards in their "*.suffix" form — for logging and the observability
// surface.
func (r *Router) Hosts() []string {
	if r == nil {
		return nil
	}
	var out []string
	for h, rules := range r.exact {
		for _, rule := range rules {
			out = append(out, h+rule.prefix)
		}
	}
	for _, s := range r.suffixes {
		for _, rule := range s.rules {
			out = append(out, "*"+s.suffix+rule.prefix)
		}
	}
	sort.Strings(out)
	return out
}

// HostNames returns the distinct exact hostnames the router intercepts, sorted.
// They are the names a network has to send to the proxy — in a DNS zone, a
// hosts file, a redirect rule — for NAT mode; wildcard rules cannot be listed
// and are left out.
func (r *Router) HostNames() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.exact))
	for h := range r.exact {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Len reports the number of configured rules.
func (r *Router) Len() int {
	if r == nil {
		return 0
	}
	n := 0
	for _, rules := range r.exact {
		n += len(rules)
	}
	for _, s := range r.suffixes {
		n += len(s.rules)
	}
	return n
}

// normalizeHost lowercases a host and strips any port and surrounding brackets
// from an IPv6 literal.
func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	// Strip a trailing port if present.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	// A fully qualified name ("pypi.org.") names the same host.
	host = strings.TrimSuffix(host, ".")
	return host
}

// HostOf extracts the lowercase host (no port) from a raw upstream base URL.
// Returns "" when the URL cannot be parsed or has no host. It is a helper for
// callers assembling a Router from upstream configuration.
func HostOf(rawURL string) string {
	u := parseUpstreamURL(rawURL)
	if u == nil {
		return ""
	}
	return normalizeHost(u.Host)
}

// RuleOf returns the routing-rule key for an upstream base URL: its host and,
// when the URL has one, its path ("deb.debian.org/debian"). It returns "" when
// the URL has no host.
func RuleOf(rawURL string) string {
	u := parseUpstreamURL(rawURL)
	if u == nil {
		return ""
	}
	host := normalizeHost(u.Host)
	if host == "" {
		return ""
	}
	return host + strings.TrimRight(u.Path, "/")
}

func parseUpstreamURL(rawURL string) *url.URL {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return u
}

// Rule is one routing rule: requests for Rule ("host" or "host/path") are
// served by the upstream named Upstream.
type Rule struct {
	Rule     string `json:"rule"`
	Upstream string `json:"upstream"`
}

// Rules returns the routing table, sorted by rule.
func (r *Router) Rules() []Rule {
	if r == nil {
		return nil
	}
	var out []Rule
	for h, rules := range r.exact {
		for _, rule := range rules {
			out = append(out, Rule{Rule: h + rule.prefix, Upstream: rule.backend})
		}
	}
	for _, s := range r.suffixes {
		for _, rule := range s.rules {
			out = append(out, Rule{Rule: "*" + s.suffix + rule.prefix, Upstream: rule.backend})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out
}
