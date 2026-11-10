package git

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// Transport identifies how the proxy reaches an upstream Git host.
type Transport int

const (
	// TransportHTTPS reaches the upstream over the smart HTTP(S) protocol.
	TransportHTTPS Transport = iota
	// TransportSSH reaches the upstream over SSH (mirror mode only; requires the
	// git binary and an SSH key).
	TransportSSH
)

// Upstream describes a single configured Git host the proxy mirrors/proxies.
// It is constructed once at startup and is safe for concurrent use.
type Upstream struct {
	// Name is the route identifier; it forms the first path segment of the proxy
	// repo scheme: "/v1/<name>/<owner>/<repo>.git/...".
	Name string
	// Transport is how the proxy reaches the upstream host.
	Transport Transport

	// base is the parsed upstream base for HTTPS transport (e.g.
	// "https://github.com" or "https://ghe.corp/git"). nil for SSH transport.
	base *url.URL
	// sshBase holds the upstream location for SSH transport, e.g.
	// "git@github.com" (host) — repositories are addressed as
	// "<sshUser>@<host>:<repo>". Empty for HTTPS transport.
	sshHost string
	sshUser string

	// creds authenticates HTTPS access to the upstream. The proxy injects its own
	// credentials; it never forwards a client's.
	creds upstream.Credentials
	// client is the shared outbound HTTP client used for pass-through HTTPS
	// proxying. May be nil when only mirror mode (git CLI) is used.
	client *upstream.Client

	// SSH-to-upstream key material (mirror mode). Optional.
	sshKeyFile       string
	sshKnownHosts    string
	sshIgnoreHostKey bool
}

// UpstreamOptions configures a single Git upstream.
type UpstreamOptions struct {
	Name string
	// URL is the upstream base. "https://host[/path]" selects HTTPS transport;
	// "ssh://[user@]host[/path]" or the scp-like "[user@]host:path" selects SSH
	// transport.
	URL string
	// Credentials authenticate HTTPS access (token or username/password). For SSH
	// transport, Username overrides the SSH user parsed from the URL.
	Credentials upstream.Credentials
	// Client is the shared outbound HTTP client for HTTPS pass-through. Required
	// for HTTPS upstreams when pass-through (non-mirror) serving may occur.
	Client *upstream.Client
	// SSHKeyFile is the private key used to authenticate to an SSH upstream
	// (mirror mode). SSHKnownHostsFile pins the upstream host key; when empty and
	// SSHInsecureIgnoreHostKey is false, the system known_hosts is used.
	SSHKeyFile               string
	SSHKnownHostsFile        string
	SSHInsecureIgnoreHostKey bool
}

// NewUpstream validates opts and constructs an Upstream.
func NewUpstream(opts UpstreamOptions) (*Upstream, error) {
	if strings.TrimSpace(opts.Name) == "" {
		return nil, fmt.Errorf("git: upstream name is required")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("git upstream %q: url is required", opts.Name)
	}

	u := &Upstream{
		Name:             opts.Name,
		creds:            opts.Credentials,
		client:           opts.Client,
		sshKeyFile:       opts.SSHKeyFile,
		sshKnownHosts:    opts.SSHKnownHostsFile,
		sshIgnoreHostKey: opts.SSHInsecureIgnoreHostKey,
	}

	raw := strings.TrimSpace(opts.URL)
	switch {
	case strings.HasPrefix(raw, "https://"), strings.HasPrefix(raw, "http://"):
		base, err := url.Parse(strings.TrimRight(raw, "/"))
		if err != nil {
			return nil, fmt.Errorf("git upstream %q: invalid url: %w", opts.Name, err)
		}
		if base.Host == "" {
			return nil, fmt.Errorf("git upstream %q: url has no host", opts.Name)
		}
		u.Transport = TransportHTTPS
		u.base = base
	case strings.HasPrefix(raw, "ssh://"):
		base, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("git upstream %q: invalid ssh url: %w", opts.Name, err)
		}
		if base.Host == "" {
			return nil, fmt.Errorf("git upstream %q: ssh url has no host", opts.Name)
		}
		u.Transport = TransportSSH
		u.sshHost = base.Host
		u.sshUser = userOrDefault(base.User.Username(), opts.Credentials.Username, "git")
		// Preserve any base path (e.g. ssh://git@host/org-prefix) by stashing it in
		// base for repo joining.
		u.base = &url.URL{Path: strings.Trim(base.Path, "/")}
	case scpLike(raw):
		user, host, basePath := parseSCPLike(raw)
		u.Transport = TransportSSH
		u.sshHost = host
		u.sshUser = userOrDefault(user, opts.Credentials.Username, "git")
		u.base = &url.URL{Path: strings.Trim(basePath, "/")}
	default:
		return nil, fmt.Errorf("git upstream %q: unsupported url scheme %q (want http(s):// or ssh:// or user@host:path)", opts.Name, raw)
	}

	return u, nil
}

// sanitizeRepoPath validates and normalizes a client-supplied repository path,
// rejecting traversal and absolute/escape attempts. The result has no leading
// or trailing slash. An empty or root path is rejected.
func sanitizeRepoPath(repoPath string) (string, error) {
	repoPath = strings.TrimSpace(repoPath)
	repoPath = strings.Trim(repoPath, "/")
	if repoPath == "" {
		return "", fmt.Errorf("git: empty repository path")
	}
	// Reject control characters and NUL.
	if strings.ContainsAny(repoPath, "\x00") {
		return "", fmt.Errorf("git: repository path contains a NUL byte")
	}
	// Reject any traversal segment outright. Even though anchoring path.Clean at
	// "/" would prevent escaping the upstream root, a request containing ".." is
	// never legitimate and silently remapping it (e.g. "../x" -> "x") is
	// surprising; treat it as a hard error.
	for _, seg := range strings.Split(repoPath, "/") {
		if seg == ".." {
			return "", fmt.Errorf("git: repository path must not contain '..'")
		}
	}
	cleaned := path.Clean("/" + repoPath)
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "." || cleaned == "" {
		return "", fmt.Errorf("git: repository path resolves to root")
	}
	return cleaned, nil
}

// upstreamHTTPURL builds the absolute upstream smart-HTTP URL for a repository
// endpoint suffix (e.g. "/info/refs" or "/git-upload-pack"). repoPath must
// already be sanitized. It returns an error for non-HTTPS upstreams.
func (u *Upstream) upstreamHTTPURL(repoPath, suffix string, query url.Values) (string, error) {
	if u.Transport != TransportHTTPS {
		return "", fmt.Errorf("git upstream %q: HTTP pass-through requires an http(s) upstream", u.Name)
	}
	out := *u.base
	basePath := strings.TrimRight(u.base.EscapedPath(), "/")
	out.Path = basePath + "/" + repoPath + suffix
	out.RawPath = ""
	if query != nil {
		if enc := query.Encode(); enc != "" {
			out.RawQuery = enc
		}
	}
	return out.String(), nil
}

// upstreamCloneURL builds the URL git uses to clone/fetch the mirror from
// upstream, with embedded credentials for HTTPS token auth. repoPath must be
// sanitized.
func (u *Upstream) upstreamCloneURL(repoPath string) string {
	switch u.Transport {
	case TransportSSH:
		// scp-like syntax: user@host:path
		p := repoPath
		if base := strings.Trim(u.base.Path, "/"); base != "" {
			p = base + "/" + repoPath
		}
		return fmt.Sprintf("%s@%s:%s", u.sshUser, u.sshHost, p)
	default:
		out := *u.base
		basePath := strings.TrimRight(u.base.EscapedPath(), "/")
		out.Path = basePath + "/" + repoPath
		out.RawPath = ""
		// Embed credentials so git's HTTPS transport authenticates. A token is sent
		// as the username (GitHub/GitLab convention: x-access-token / oauth2); basic
		// auth uses username:password.
		switch {
		case u.creds.Token != "":
			out.User = url.UserPassword("x-access-token", u.creds.Token)
		case u.creds.Username != "" || u.creds.Password != "":
			out.User = url.UserPassword(u.creds.Username, u.creds.Password)
		}
		return out.String()
	}
}

// redactedCloneURL returns upstreamCloneURL with any credentials stripped, for
// safe logging.
func (u *Upstream) redactedCloneURL(repoPath string) string {
	if u.Transport == TransportSSH {
		return u.upstreamCloneURL(repoPath)
	}
	out := *u.base
	basePath := strings.TrimRight(u.base.EscapedPath(), "/")
	out.Path = basePath + "/" + repoPath
	out.RawPath = ""
	out.User = nil
	return out.String()
}

func userOrDefault(parsed, override, fallback string) string {
	if override != "" {
		return override
	}
	if parsed != "" {
		return parsed
	}
	return fallback
}

// scpLike reports whether s looks like the scp-style git remote syntax
// "[user@]host:path" (as opposed to a URL with a scheme).
func scpLike(s string) bool {
	if strings.Contains(s, "://") {
		return false
	}
	colon := strings.Index(s, ":")
	if colon < 0 {
		return false
	}
	// A colon before any slash and not part of "host:port/..." with a scheme.
	slash := strings.Index(s, "/")
	if slash >= 0 && slash < colon {
		return false
	}
	return true
}

func parseSCPLike(s string) (user, host, basePath string) {
	if at := strings.Index(s, "@"); at >= 0 {
		user = s[:at]
		s = s[at+1:]
	}
	if colon := strings.Index(s, ":"); colon >= 0 {
		host = s[:colon]
		basePath = s[colon+1:]
	} else {
		host = s
	}
	return user, host, basePath
}
