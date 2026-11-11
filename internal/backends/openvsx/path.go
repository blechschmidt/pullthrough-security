package openvsx

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// An OpenVSX registry (the vendor-neutral VS Code extension marketplace,
// open-vsx.org, and API-compatible self-hosted deployments) exposes a small HTTP
// tree of mutable metadata/query documents and the immutable .vsix extension
// archives they describe. The proxy mounts a registry at its route root
// ("<publicBase>/v1/<name>") and honors the Eclipse Open VSX REST layout:
//
//	GET /api/-/query?extensionId=…            query documents           (mutable, live)
//	GET /api/{namespace}                      namespace metadata        (mutable, live)
//	GET /api/{namespace}/{extension}          extension metadata        (mutable, live)
//	GET /api/{namespace}/{extension}/{version}        version metadata  (mutable, live)
//	GET /api/{ns}/{ext}/{targetPlatform}/{version}    version metadata  (mutable, live)
//	GET /api/{ns}/{ext}/…/file/{file}.vsix    extension archive         (immutable, verified)
//	GET /api/{ns}/{ext}/…/file/{file}.sha256  archive checksum sidecar  (immutable, live)
//	GET /vscode/…                             VS Code gallery protocol  (mutable, live)
//
// The metadata and query documents change whenever an extension publishes, so
// they are revalidated live rather than cached; the backend rewrites the
// absolute upstream URLs they embed (files.download, files.sha256, gallery asset
// URLs, …) to the proxy's own public base so a client's archive download routes
// back through the proxy — and therefore through the .vsix content gate — rather
// than directly to the upstream or its CDN.
//
// A .vsix file path pins its {namespace}.{extension}@{version} coordinate, so the
// archive is immutable and content-addressable; on a cache miss the backend
// fetches the sibling .sha256 sidecar, reads the published SHA-256, and verifies
// the fetched bytes against it before they are cached or served (see checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the extension coordinate, which feeds the admission gates
// (nameguard, policy, provenance, installhooks content gate, policyengine) and
// the cacheability decision.

// resourceKind enumerates the classes of resource an OpenVSX registry path can
// address.
type resourceKind int

const (
	// kindMetadata is an /api metadata or query document (namespace/extension/
	// version metadata, /api/-/query, /api/-/search, …). Mutable, served live with
	// its embedded upstream URLs rewritten through the proxy.
	kindMetadata resourceKind = iota
	// kindGallery is a /vscode/... VS Code Marketplace gallery-protocol document.
	// Mutable, served live with embedded upstream URLs rewritten.
	kindGallery
	// kindVsix is a .vsix extension archive under an /api/.../file/ path, pinned by
	// {namespace}.{extension}@{version}. Immutable, cacheable, verified against the
	// sibling .sha256 sidecar.
	kindVsix
	// kindFile is any other file resource under an /api/.../file/ path (the .sha256
	// sidecar, the signature, the manifest, the README, the icon, …). Served live,
	// byte-exact (never rewritten — the .sha256 body must reach a client intact).
	kindFile
)

// vsixExt is the extension a VS Code extension archive carries.
const vsixExt = ".vsix"

// resource is the parsed classification of an inbound OpenVSX registry request.
type resource struct {
	kind resourceKind
	// filename is the final path component for a /file/ resource (the archive or
	// sidecar file); empty otherwise.
	filename string
	// extID is the canonical VS Code extension identifier "{namespace}.{extension}"
	// for a .vsix archive; empty otherwise.
	extID string
	// version is the release version for a .vsix archive; empty otherwise.
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// outside the OpenVSX /api and /vscode trees, so an unrecognized request is
// reported as unsupported rather than blindly proxied. Every path segment is
// checked for emptiness and path traversal because the upstream URL is built
// from these segments.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	switch segs[0] {
	case "api":
		if fi := indexOf(segs, "file"); fi >= 0 {
			// A /file/ resource: the segment after "file" is the filename.
			if fi+1 >= len(segs) {
				return resource{}, false
			}
			filename := segs[fi+1]
			if strings.HasSuffix(filename, vsixExt) && fi >= 4 {
				// segs = [api, ns, ext, (targetPlatform?), version, "file", filename];
				// the version is always the segment immediately before "file".
				return resource{
					kind:     kindVsix,
					filename: filename,
					extID:    segs[1] + "." + segs[2],
					version:  segs[fi-1],
				}, true
			}
			// Any other /file/ resource (the .sha256 sidecar, signature, manifest,
			// readme, icon, …) is proxied live and byte-exact.
			return resource{kind: kindFile, filename: filename}, true
		}
		// Every other /api resource is a mutable metadata/query document.
		return resource{kind: kindMetadata}, true
	case "vscode":
		return resource{kind: kindGallery}, true
	}
	return resource{}, false
}

// indexOf returns the index of the first occurrence of want in segs, or -1.
func indexOf(segs []string, want string) int {
	for i, s := range segs {
		if s == want {
			return i
		}
	}
	return -1
}

// cacheable reports whether the resource may be cached. Only a .vsix archive is
// immutable (its path pins the version); metadata/query/gallery documents are
// mutable and revalidated live, and the small /file/ sidecars are proxied live.
func (r resource) cacheable() bool {
	return r.kind == kindVsix
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A .vsix beneath an /api/.../file/ path is the
// extension an editor installs and runs: a payload.
//
// Nothing else is called metadata, although most of it is. The backend forwards
// the whole /api and /vscode trees rather than a list of known documents, and
// those trees serve the extension itself under other names: the gallery
// protocol's ".../Microsoft.VisualStudio.Services.VSIXPackage" asset is the
// .vsix. A path outside the one archive form classify recognizes therefore says
// nothing about what its bytes are, so everything but the archive is left
// unclassified and a gate judges it from its content.
func (r resource) artifact() backends.Artifact {
	if r.kind == kindVsix {
		return backends.Payload()
	}
	return backends.Artifact{}
}

// verifiableFile reports whether the resource is a .vsix archive the backend
// should verify against the sibling .sha256 sidecar.
func (r resource) verifiableFile() bool {
	return r.kind == kindVsix
}

// rewritable reports whether the resource is a metadata/gallery document whose
// embedded absolute upstream URLs must be rewritten through the proxy. The
// byte-exact /file/ resources (including the .sha256 sidecar) are never rewritten.
func (r resource) rewritable() bool {
	return r.kind == kindMetadata || r.kind == kindGallery
}

// coordinateName returns the extension identifier used to address the artifact
// in the admission gates. Empty for non-archive resources.
func (r resource) coordinateName() string {
	return r.extID
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindMetadata:
		return "metadata"
	case kindGallery:
		return "gallery"
	case kindVsix:
		return "vsix"
	case kindFile:
		return "file"
	default:
		return "other"
	}
}
