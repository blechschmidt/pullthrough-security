package pkgmgr

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// NewNPM builds a pull-through backend for an npm registry (the public default
// is https://registry.npmjs.org).
//
// Protocol mapping:
//   - Packument:  GET /<pkg> or /<@scope>/<pkg> returns a JSON metadata document
//     listing every version, whose dist.tarball fields are absolute upstream
//     URLs. These are rewritten to point back through the proxy. Packuments are
//     mutable (new versions are published) and therefore revalidated rather than
//     cached indefinitely.
//   - Tarball:    GET /<pkg>/-/<file>.tgz (the "/-/" segment is the npm tarball
//     marker) returns an immutable artifact, cached aggressively.
//
// The packument tarball URLs share the registry's host, so a single literal
// substitution of the upstream base for the proxy base rewrites them all.
func NewNPM(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	upstreamBase := strings.TrimRight(opts.UpstreamURL, "/")
	publicBase := opts.publicBase()
	rules := []rewriteRule{{from: upstreamBase + "/", to: publicBase + "/"}}

	return httpbackend.New(httpbackend.Options{
		Name:          opts.Name,
		BaseURL:       opts.UpstreamURL,
		Client:        opts.Client,
		Credentials:   opts.Credentials,
		Cacheable:     npmCacheable,
		Coordinator:   npmCoordinate,
		Index:         npmIsIndex,
		ForwardAccept: true,
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			return applyRules(body, rules), nil
		},
	})
}

// npmIsTarball reports whether a path addresses an npm tarball. npm tarball URLs
// always contain the "/-/" separator (e.g. "/lodash/-/lodash-4.17.21.tgz",
// "/@scope/pkg/-/pkg-1.0.0.tgz").
func npmIsTarball(path string) bool { return strings.Contains(path, "/-/") }

// npmCacheable caches immutable tarballs forever; packuments are revalidated.
func npmCacheable(req *backends.Request) bool { return npmIsTarball(req.Path) }

// npmIsIndex classifies non-tarball, non-root reads as packument index documents
// to be rewritten.
func npmIsIndex(req *backends.Request) bool {
	if req.Method != "" && req.Method != "GET" && req.Method != "HEAD" {
		return false
	}
	p := strings.TrimSpace(req.Path)
	return p != "" && p != "/" && !npmIsTarball(p)
}
