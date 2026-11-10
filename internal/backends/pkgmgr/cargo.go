package pkgmgr

import (
	"encoding/json"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/backends/httpbackend"
)

// NewCargo builds a pull-through backend for the cargo sparse registry protocol
// (the public default index is https://index.crates.io).
//
// Protocol mapping (RFC 2789 sparse index):
//   - config.json: GET /config.json returns the registry configuration whose
//     "dl" field tells cargo where to download .crate files. It is rewritten to
//     a proxy endpoint so downloads route through the cache.
//   - Index file:  GET /<a>/<b>/<crate> (cargo's fan-out directory layout)
//     returns newline-delimited JSON, one line per published version. These are
//     mutable (versions are appended) and revalidated via ETag rather than
//     cached indefinitely. They contain checksums, not URLs, so they are not
//     rewritten.
//   - Download:    GET /api/v1/crates/<crate>/<version>/download is proxied to
//     the upstream download host (which 302-redirects to the CDN; the redirect
//     is followed transparently) and the immutable .crate is cached.
//
// Settings:
//
//	"downloadUrl" crate download host base (default https://crates.io)
//
// Client configuration points cargo at "sparse+<publicBase>/" (see
// docs/clients.md).
func NewCargo(opts Options) (backends.Backend, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}

	downloadBase := strings.TrimRight(opts.setting("downloadUrl", "https://crates.io"), "/")
	publicBase := opts.publicBase()
	// Point cargo's download URL at the proxy. Without templating markers, cargo
	// appends "/<crate>/<version>/download", which cargoDownloadPrefix matches.
	proxyDL := publicBase + cargoDownloadPrefix

	return httpbackend.New(httpbackend.Options{
		Name:        opts.Name,
		BaseURL:     opts.UpstreamURL,
		Client:      opts.Client,
		Credentials: opts.Credentials,
		Cacheable:   cargoCacheable,
		Coordinator: cargoCoordinate,
		Index:       cargoIsIndex,
		AbsoluteRouter: func(req *backends.Request) (string, bool) {
			if strings.HasPrefix(req.Path, cargoDownloadPrefix) {
				return downloadBase + req.Path, true
			}
			return "", false
		},
		Rewrite: func(body []byte, _ string) ([]byte, error) {
			return rewriteCargoConfig(body, proxyDL), nil
		},
	})
}

// cargoDownloadPrefix is the proxy path under which .crate downloads are served.
// It mirrors crates.io's own download API path so the rewritten "dl" needs no
// templating markers.
const cargoDownloadPrefix = "/api/v1/crates"

// cargoCacheable caches immutable .crate downloads forever; config.json and
// index files are revalidated.
func cargoCacheable(req *backends.Request) bool {
	return strings.HasPrefix(req.Path, cargoDownloadPrefix) &&
		strings.HasSuffix(req.Path, "/download")
}

// cargoIsIndex marks only config.json for rewriting; index files carry no URLs.
func cargoIsIndex(req *backends.Request) bool {
	return req.Path == "/config.json"
}

// rewriteCargoConfig overrides the "dl" field of the sparse-index config.json so
// crate downloads route through the proxy, preserving all other fields. Bodies
// that are not valid JSON objects are returned unchanged.
func rewriteCargoConfig(body []byte, proxyDL string) []byte {
	var cfg map[string]any
	if err := json.Unmarshal(body, &cfg); err != nil {
		return body
	}
	// A literal JSON `null` unmarshals into a nil map (not an error); rewriting it
	// would panic on assignment, so leave a non-object document untouched.
	if cfg == nil {
		return body
	}
	cfg["dl"] = proxyDL
	out, err := json.Marshal(cfg)
	if err != nil {
		return body
	}
	return out
}
