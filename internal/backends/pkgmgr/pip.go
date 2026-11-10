package pkgmgr

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// pipFilesPrefix is the synthetic path prefix under which PyPI artifacts are
// proxied. Artifact hosts differ from the index host (files.pythonhosted.org vs
// pypi.org) and may vary, so the proxy encodes the artifact's scheme and host in
// the path: "/files/<scheme>/<host>/<original-path>".
const pipFilesPrefix = "/files/"

// NewPyPI builds a pull-through backend for a PyPI-compatible index (the public
// default is https://pypi.org).
//
// Protocol mapping (PEP 503 Simple API, plus PEP 691 JSON):
//   - Simple page: GET /simple/<project>/ returns an HTML (or JSON) listing of
//     distribution files. The file URLs point at a separate artifact host
//     (files.pythonhosted.org). They are rewritten to "/files/<scheme>/<host>/…"
//     so downloads route through the proxy. Simple pages are mutable (new
//     releases appear) and revalidated rather than cached indefinitely.
//   - Artifact:    GET /files/<scheme>/<host>/<path> reconstructs the upstream
//     artifact URL and streams the immutable wheel/sdist, cached aggressively.
//
// Settings:
//
//	"filesUrl"  artifact host base (default https://files.pythonhosted.org)
//	"fileHosts" comma-separated allowlist of artifact hosts the proxy will fetch
//	            (defaults to the host of filesUrl). Hosts outside the allowlist
//	            are refused to prevent the proxy from acting as an open relay.
func NewPyPI(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	filesURL := opts.setting("filesUrl", "https://files.pythonhosted.org")
	filesParsed, err := url.Parse(filesURL)
	if err != nil || filesParsed.Host == "" {
		return nil, fmt.Errorf("pkgmgr %q: invalid filesUrl %q", opts.Name, filesURL)
	}

	allowed := map[string]bool{filesParsed.Host: true}
	if list := opts.setting("fileHosts", ""); list != "" {
		for _, h := range strings.Split(list, ",") {
			if h = strings.TrimSpace(h); h != "" {
				allowed[h] = true
			}
		}
	}

	publicBase := opts.publicBase()
	rules := make([]rewriteRule, 0, len(allowed)*2)
	for host := range allowed {
		for _, scheme := range []string{"https", "http"} {
			rules = append(rules, rewriteRule{
				from: scheme + "://" + host + "/",
				to:   publicBase + pipFilesPrefix + scheme + "/" + host + "/",
			})
		}
	}

	return httpbackend.New(httpbackend.Options{
		Name:          opts.Name,
		BaseURL:       opts.UpstreamURL,
		Client:        opts.Client,
		Credentials:   opts.Credentials,
		Cacheable:     pipCacheable,
		Coordinator:   pipCoordinate,
		Index:         pipIsIndex,
		ForwardAccept: true, // honor PEP 691 content negotiation (HTML vs JSON)
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			return pipArtifactURL(req.Path, allowed)
		},
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			return applyRules(body, rules), nil
		},
	})
}

// pipArtifactURL reconstructs the upstream artifact URL from a
// "/files/<scheme>/<host>/<path>" request path, returning ok=false (so the
// request is not treated as an artifact fetch) when the path is not a files
// route or names a host outside the allowlist.
func pipArtifactURL(path string, allowed map[string]bool) (string, bool) {
	if !strings.HasPrefix(path, pipFilesPrefix) {
		return "", false
	}
	rest := strings.TrimPrefix(path, pipFilesPrefix)
	scheme, afterScheme, ok := strings.Cut(rest, "/")
	if !ok || (scheme != "https" && scheme != "http") {
		return "", false
	}
	host, tail, ok := strings.Cut(afterScheme, "/")
	if !ok || host == "" || !allowed[host] {
		return "", false
	}
	return scheme + "://" + host + "/" + tail, true
}

// pipCacheable caches reconstructed artifacts forever; Simple pages are
// revalidated.
func pipCacheable(req *backends.Request) bool {
	return strings.HasPrefix(req.Path, pipFilesPrefix)
}

// pipIsIndex classifies Simple-API pages (everything that is not a files route)
// as rewritable index documents.
func pipIsIndex(req *backends.Request) bool {
	if req.Method != "" && req.Method != "GET" && req.Method != "HEAD" {
		return false
	}
	return !strings.HasPrefix(req.Path, pipFilesPrefix)
}
