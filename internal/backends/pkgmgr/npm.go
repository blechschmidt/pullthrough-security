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
		Classify:      npmClassify,
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

// npmArchiveSuffixes are file-name endings a packument or version manifest
// never has. A short path that ends in one is not called a document.
var npmArchiveSuffixes = []string{".tgz", ".tar.gz", ".tar", ".zip", ".gz"}

// npmClassify classifies an npm registry path for the content gates.
//
//   - A tarball, "/<pkg>/-/<file>.tgz" (the path npmCoordinate parses), is the
//     payload.
//   - A packument ("/<pkg>", "/@<scope>/<pkg>") or a version manifest (the same
//     followed by a version or dist-tag) is metadata.
//   - Everything else is left unclassified: the registry's own API under "/-/"
//     ("/-/v1/search", "/-/npm/v1/keys"), and every shape the registry protocol
//     does not define — which is where a registry with a tarball layout of its
//     own serves its tarballs ("/download/@<scope>/<pkg>/<version>/<sha>" on
//     GitHub Packages).
func npmClassify(req *backends.Request) backends.Artifact {
	p := req.Path
	if npmIsTarball(p) {
		if _, ok := npmCoordinate(req); ok && strings.HasSuffix(p, ".tgz") {
			return backends.Payload()
		}
		return backends.Artifact{}
	}
	segs, ok := plainSegments(strings.TrimSuffix(p, "/"))
	if !ok {
		return backends.Artifact{}
	}
	// A name is one segment, or two when scoped; a version or tag may follow.
	name := 1
	if strings.HasPrefix(segs[0], "@") {
		name = 2
	}
	last := segs[len(segs)-1]
	if len(segs) < name || len(segs) > name+1 || last == "-" ||
		hasAnySuffix(strings.ToLower(last), npmArchiveSuffixes) {
		return backends.Artifact{}
	}
	return backends.Metadata()
}
