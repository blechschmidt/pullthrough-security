package intercept

import (
	"net"
	"net/url"
	"sort"
	"strings"
)

// Router maps an intercepted upstream hostname to the configured backend that
// proxies it. It supports exact host matches and single-label wildcard suffix
// matches ("*.example.com"), with exact matches taking precedence.
//
// The zero Router matches nothing. Build one with NewRouter.
type Router struct {
	exact    map[string]string // host -> backend
	suffixes []suffixRule      // "*.example.com" rules, longest suffix first
}

type suffixRule struct {
	suffix  string // ".example.com" (includes leading dot)
	backend string
}

// NewRouter builds a Router from a host->backend map. Keys may be exact hosts
// ("registry.npmjs.org") or single wildcards ("*.docker.io"). Host keys are
// case-insensitive and any port is ignored. A later-sorted longer suffix wins
// among wildcard rules; exact matches always win over wildcards.
func NewRouter(hosts map[string]string) *Router {
	r := &Router{exact: make(map[string]string, len(hosts))}
	for host, backend := range hosts {
		host = strings.TrimSpace(strings.ToLower(host))
		backend = strings.TrimSpace(backend)
		if host == "" || backend == "" {
			continue
		}
		if strings.HasPrefix(host, "*.") {
			r.suffixes = append(r.suffixes, suffixRule{suffix: host[1:], backend: backend})
			continue
		}
		r.exact[normalizeHost(host)] = backend
	}
	// Longest suffix first so the most specific wildcard wins.
	sort.Slice(r.suffixes, func(i, j int) bool {
		return len(r.suffixes[i].suffix) > len(r.suffixes[j].suffix)
	})
	return r
}

// Lookup returns the backend serving host, or ("", false) when host is not
// configured for interception. host may carry a port, which is ignored.
func (r *Router) Lookup(host string) (string, bool) {
	if r == nil {
		return "", false
	}
	h := normalizeHost(host)
	if h == "" {
		return "", false
	}
	if backend, ok := r.exact[h]; ok {
		return backend, true
	}
	for _, rule := range r.suffixes {
		if strings.HasSuffix(h, rule.suffix) {
			return rule.backend, true
		}
	}
	return "", false
}

// Hosts returns the configured exact hostnames in sorted order, for logging and
// the readiness/observability surface. Wildcard rules are returned in their
// "*.suffix" form.
func (r *Router) Hosts() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.exact)+len(r.suffixes))
	for h := range r.exact {
		out = append(out, h)
	}
	for _, rule := range r.suffixes {
		out = append(out, "*"+rule.suffix)
	}
	sort.Strings(out)
	return out
}

// Len reports the number of configured host rules.
func (r *Router) Len() int {
	if r == nil {
		return 0
	}
	return len(r.exact) + len(r.suffixes)
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
	return host
}

// HostOf extracts the lowercase host (no port) from a raw upstream base URL.
// Returns "" when the URL cannot be parsed or has no host. It is a helper for
// callers assembling a Router from upstream configuration.
func HostOf(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return normalizeHost(u.Host)
}
