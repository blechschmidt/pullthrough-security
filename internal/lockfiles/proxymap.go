package lockfiles

import (
	"net/url"
	"regexp"
	"strings"
)

// Proxy is what the scanner knows about the pull-through proxy itself, so
// that the URLs of a lock file resolved through it can be mapped back to the
// upstreams they stand for. The zero value knows nothing about a deployment
// and still recognises the shapes no other server produces: a personal link
// ("/u/ptl1…/v1/<upstream>/…") and the interception prefix
// ("/_pullthrough/v1/<upstream>/…").
type Proxy struct {
	// PublicURLs are the base URLs clients reach the proxy at: the configured
	// server.publicUrl, and any other name it is known by. Under one of them,
	// the plain mount "/v1/<upstream>/…" is recognised too.
	PublicURLs []string
	// LinkPrefix is the first path segment of personal cache links
	// (userLinks.pathPrefix); empty means the default, "/u".
	LinkPrefix string
	// Upstreams are the proxy's upstreams, by name.
	Upstreams map[string]ProxyUpstream
	// RegistryDefault is the upstream serving container repositories that carry
	// no upstream prefix (server.registry.defaultUpstream).
	RegistryDefault string
}

// ProxyUpstream is one upstream of the proxy.
type ProxyUpstream struct {
	// Type is the upstream type ("npm").
	Type string
	// URL is the upstream's own base URL ("https://registry.npmjs.org").
	URL string
}

// Path shapes of URLs that point at the proxy.
const (
	// interceptPrefix is internal/intercept.RoutePrefix: where TLS interception
	// moves the proxy's links onto the intercepted host.
	interceptPrefix = "/_pullthrough"
	// defaultLinkPrefix is userlinks.DefaultPathPrefix.
	defaultLinkPrefix = "/u"
	// linkTokenPrefix is userlinks.TokenPrefix: every personal link token
	// starts with it.
	linkTokenPrefix = "ptl1"
	// redactedLink stands in for a removed token.
	redactedLink = "<link>"
)

// mapped is where a URL of a lock file points.
type mapped struct {
	// url is the URL without credentials, query, fragment and link token; the
	// proxy's canonical URL when it pointed at the proxy.
	url string
	// upstream names the proxy upstream it pointed at, if it did, and mount
	// is the proxy's token-free URL of that upstream ("…/v1/<upstream>").
	upstream, mount string
	// upstreamURL is that upstream's own URL, when the Proxy knows it.
	upstreamURL string
	// upstreamType is that upstream's type, when the Proxy knows it.
	upstreamType string
}

// linkPrefix returns the personal path prefix in use.
func (p *Proxy) linkPrefix() string {
	if p == nil || strings.Trim(p.LinkPrefix, "/ ") == "" {
		return defaultLinkPrefix
	}
	return "/" + strings.Trim(strings.TrimSpace(p.LinkPrefix), "/")
}

// publicBases returns the configured public URLs, parsed, in configured
// order: the first is the primary (server.publicUrl).
func (p *Proxy) publicBases() []*url.URL {
	if p == nil {
		return nil
	}
	var out []*url.URL
	for _, raw := range p.PublicURLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		u.Path = strings.TrimRight(u.Path, "/")
		u.User, u.RawQuery, u.Fragment, u.RawPath = nil, "", "", ""
		out = append(out, u)
	}
	return out
}

// mapURL maps a URL from a lock file: credentials, query and fragment are
// dropped, a link token removed, and a URL that points at the proxy is mapped
// to the upstream behind it. ok is false for text that is not an absolute
// http(s) URL; it is returned redacted.
func (p *Proxy) mapURL(raw string) (m mapped, ok bool) {
	raw = strings.TrimSpace(raw)
	prefix := p.linkPrefix()
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return mapped{url: redactText(raw, prefix)}, false
	}
	// Paths are matched and rebuilt in their escaped form, so that a URL the
	// mapping does not change keeps its spelling ("@scope%2fname").
	origin := strings.ToLower(u.Scheme) + "://" + u.Host
	escaped := u.EscapedPath()
	plain := origin + escaped

	// Which configured public base, if any, the URL is under.
	host := strings.ToLower(u.Host)
	var basePath string
	underBase := false
	rest := escaped
	for _, b := range p.publicBases() {
		if strings.ToLower(b.Host) != host {
			continue
		}
		bp := b.EscapedPath()
		// The longest base the URL is under wins.
		if (bp == "" || escaped == bp || strings.HasPrefix(escaped, bp+"/")) && (!underBase || len(bp) > len(basePath)) {
			basePath, rest, underBase = bp, strings.TrimPrefix(escaped, bp), true
		}
	}

	// A personal link: "<base>/u/<token>/…". Under a public base the segment
	// after the prefix is a token whatever it looks like (the proxy treats it
	// so); elsewhere only a segment spelled like a token counts, wherever the
	// prefix sits — the part of the path before it is the proxy's base path.
	personal := false
	if underBase {
		if after, found := strings.CutPrefix(rest, prefix+"/"); found {
			_, tail, _ := strings.Cut(after, "/")
			rest, personal = "/"+tail, true
		}
	} else if i := strings.Index(escaped, prefix+"/"+linkTokenPrefix); i >= 0 {
		after := escaped[i+len(prefix)+1:]
		_, tail, _ := strings.Cut(after, "/")
		basePath, rest, personal = escaped[:i], "/"+tail, true
	}

	var name, tail string
	intercepted := false
	switch {
	case strings.HasPrefix(rest, interceptPrefix+"/v1/"):
		name, tail = splitMount(strings.TrimPrefix(rest, interceptPrefix+"/v1/"))
		intercepted = true
	case strings.HasPrefix(rest, "/v1/") && (underBase || personal):
		name, tail = splitMount(strings.TrimPrefix(rest, "/v1/"))
	}
	if name == "" {
		// Not the proxy: keep the URL, without anything spelled like a token.
		return mapped{url: redactText(plain, prefix)}, true
	}

	if intercepted {
		// Interception moved the link onto the host the client talked to. The
		// URL stays as written — it names the host a client fetches from — and
		// the configured upstream is credited only when that host is the
		// upstream's own, or the proxy's: "https://evil.example/_pullthrough/
		// v1/npm/…" is evil.example's, not the npm upstream's.
		mount := origin + basePath + interceptPrefix + "/v1/" + name
		m = mapped{url: redactText(plain, prefix), upstream: name, mount: redactText(mount, prefix)}
		if p != nil {
			if up, known := p.Upstreams[name]; known && (underBase || sameHost(up.URL, host)) {
				m.upstreamURL = redactText(sanitizeURL(up.URL), prefix)
				m.upstreamType = CanonicalType(up.Type)
			}
		}
		return m, true
	}

	// The proxy's canonical, token-free URL for the resource, under the base
	// the URL used.
	mount := strings.TrimRight(origin+basePath, "/") + "/v1/" + name
	m = mapped{url: redactText(mount+tail, prefix), upstream: name, mount: redactText(mount, prefix)}
	// The configured upstreams are this deployment's: they describe a URL
	// under its public URL — not a personal link on a host nobody named, which
	// may be another deployment's.
	if p != nil && underBase {
		if up, known := p.Upstreams[name]; known {
			m.upstreamURL = redactText(sanitizeURL(up.URL), prefix)
			m.upstreamType = CanonicalType(up.Type)
		}
	}
	return m, true
}

// sameHost reports whether rawURL is on host (host[:port], lower case).
func sameHost(rawURL, host string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, host)
}

// splitMount splits "<upstream>/<rest>" into the upstream name and "/<rest>"
// ("" when there is no rest).
func splitMount(s string) (name, tail string) {
	name, rest, found := strings.Cut(s, "/")
	if !validUpstreamName(name) {
		return "", ""
	}
	if found {
		tail = "/" + rest
	}
	return name, tail
}

// validUpstreamName accepts the spelling of an upstream (route) name.
func validUpstreamName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	// A token where an upstream name belongs is a token, not a name.
	return s != "." && s != ".." && !strings.Contains(s, linkTokenPrefix)
}

// sanitizeURL removes credentials, query and fragment from a URL. Text that
// does not parse as a URL is returned as it is, minus anything that looks like
// URL credentials. The user of an ssh URL ("ssh://git@github.com/…") is kept:
// it names an account, it is not a secret.
func sanitizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return stripUserinfo(raw)
	}
	user := u.User
	u.User, u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment = nil, "", false, "", ""
	if user != nil && strings.HasSuffix(strings.ToLower(u.Scheme), "ssh") {
		if _, hasPassword := user.Password(); !hasPassword && sshUserRE.MatchString(user.Username()) &&
			!strings.HasPrefix(user.Username(), linkTokenPrefix) {
			u.User = url.User(user.Username())
		}
	}
	return u.String()
}

// sshUserRE matches the account names ssh URLs use ("git", "org-12345").
var sshUserRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// urlUserinfo matches the userinfo part of a URL ("scheme://user:secret@"):
// everything up to the last "@" of the authority, as net/url reads it — a
// password may itself hold an "@".
var urlUserinfo = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/?#\s"<>]*@`)

// stripUserinfo removes the userinfo of every URL in s, except the bare user
// of an ssh URL ("ssh://git@…"), which names an account and is no secret.
func stripUserinfo(s string) string {
	return urlUserinfo.ReplaceAllStringFunc(s, func(m string) string {
		scheme, userinfo, _ := strings.Cut(m, "://")
		userinfo = strings.TrimSuffix(userinfo, "@")
		if strings.HasSuffix(strings.ToLower(scheme), "ssh") && sshUserRE.MatchString(userinfo) &&
			!strings.HasPrefix(userinfo, linkTokenPrefix) {
			return m
		}
		return scheme + "://"
	})
}

// tokenRun matches a personal link token and anything spelled like the start
// of one.
var tokenRun = regexp.MustCompile(linkTokenPrefix + `[a-z0-9]*`)

// redactText removes credentials from text that may quote a URL: the userinfo
// of a URL, anything spelled like a personal link token, and the path segment
// after the personal prefix in front of a mount ("/u/<anything>/v1/"), which
// is a token whatever it looks like.
func redactText(s, prefix string) string {
	if s == "" {
		return s
	}
	s = stripUserinfo(s)
	s = tokenRun.ReplaceAllString(s, redactedLink)
	if prefix == "" {
		prefix = defaultLinkPrefix
	}
	marker := prefix + "/"
	var b strings.Builder
	for {
		i := strings.Index(s, marker)
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i+len(marker)])
		s = s[i+len(marker):]
		seg, after, found := strings.Cut(s, "/")
		if found && (strings.HasPrefix(after, "v1/") || after == "v1") && seg != redactedLink {
			b.WriteString(redactedLink + "/")
			s = after
		}
	}
	return b.String()
}

// RedactText removes credentials from text that may quote a URL, as the
// scanner does for everything it reports: URL userinfo and personal link
// tokens (with the default link prefix).
func RedactText(s string) string { return redactText(s, defaultLinkPrefix) }

// Redact is RedactText with the proxy's own link prefix. A nil Proxy uses the
// default.
func (p *Proxy) Redact(s string) string { return redactText(s, p.linkPrefix()) }
