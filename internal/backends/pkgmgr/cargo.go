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
		Classify:    cargoClassify,
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

// cargoClassify classifies a cargo registry path for the content gates.
//
//   - A crate download, "/api/v1/crates/<name>/<version>/download", is the
//     payload. Its URL does not end in the crate's file name, so the
//     classification carries it: "<name>-<version>.crate".
//   - config.json, a sparse-index file and the rest of the registry's web API
//     below "/api/v1/crates" (JSON) are metadata.
//   - Everything else is left unclassified — including an API path that ends in
//     "download" without being the download path above, which an upstream might
//     still answer with a crate.
func cargoClassify(req *backends.Request) backends.Artifact {
	if cargoCacheable(req) {
		if coord, ok := cargoCoordinate(req); ok {
			// The name is offered to the gates as a file name, so it is only built
			// from a name and version that read as such.
			if plainSegment(coord.Name) && plainSegment(coord.Version) {
				return backends.PayloadNamed(coord.Name + "-" + coord.Version + ".crate")
			}
			return backends.Payload()
		}
	}
	if cargoIsIndex(req) {
		return backends.Metadata()
	}
	segs, ok := plainSegments(req.Path)
	if !ok {
		return backends.Artifact{}
	}
	if cargoIsAPIDocument(segs) || cargoIsIndexFile(segs) {
		return backends.Metadata()
	}
	return backends.Artifact{}
}

// cargoIsAPIDocument reports whether segs spell a document of the registry web
// API: "api/v1/crates" itself (search) or a path of up to three elements below
// it ("<name>", "<name>/<version>", "<name>/<version>/dependencies", …) that
// does not end in "download".
func cargoIsAPIDocument(segs []string) bool {
	n := len(segs)
	if n < 3 || n > 6 || segs[0] != "api" || segs[1] != "v1" || segs[2] != "crates" {
		return false
	}
	return !strings.EqualFold(segs[n-1], "download")
}

// cargoIsIndexFile reports whether segs spell a sparse-index file: the crate's
// lowercased name below the directories cargo derives from it (RFC 2789) —
// "1/<n>", "2/<nn>", "3/<n>/<nnn>", and "<nn>/<nn>/<name>" for longer names.
func cargoIsIndexFile(segs []string) bool {
	name := segs[len(segs)-1]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	switch len(name) {
	case 0:
		return false
	case 1:
		return len(segs) == 2 && segs[0] == "1"
	case 2:
		return len(segs) == 2 && segs[0] == "2"
	case 3:
		return len(segs) == 3 && segs[0] == "3" && segs[1] == name[:1]
	default:
		return len(segs) == 3 && segs[0] == name[:2] && segs[1] == name[2:4]
	}
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
