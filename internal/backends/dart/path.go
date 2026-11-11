package dart

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The Dart "pub" client speaks the Hosted Pub Repository API (repository-spec
// v2) that pub.dev and self-hosted pub servers implement. A package is
// addressed by its name under "/api/packages/"; the list-versions document
// names, for each release, an absolute "archive_url" (with an "archive_sha256"
// content hash) from which the client downloads a gzipped tar archive:
//
//	GET /api/packages/{package}               list all versions (mutable)
//	GET /api/packages/{package}/advisories    security advisories (mutable)
//	GET /api/archives/{package}-{version}.tar.gz   package archive (immutable, verified)
//
// The archive download path is the proxy's own synthetic endpoint: the backend
// rewrites every "archive_url" in the list-versions document to this
// "/api/archives/..." form under the proxy's public base so that the client's
// archive download flows back through the proxy (where it is cached, verified,
// and gated) rather than directly to the upstream or its blob storage. On a
// request for that endpoint the backend re-reads the list-versions document to
// recover the real upstream archive URL and the "archive_sha256", fetches the
// archive (following redirects to any blob store), and verifies the fetched
// bytes against the content hash before they are cached or served — so a
// tampered or corrupt mirror can neither poison the cache nor reach a client.
//
// A published version's archive is immutable, so the archive endpoint is
// content-addressable and cached indefinitely. The list-versions and advisories
// documents are mutable and are revalidated rather than cached.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a pub path can address.
type resourceKind int

const (
	// kindVersions is the list-all-versions document "/api/packages/{package}"
	// (mutable; archive_url fields are rewritten through the proxy).
	kindVersions resourceKind = iota
	// kindAdvisories is the security-advisories document
	// "/api/packages/{package}/advisories" (mutable, proxied as-is).
	kindAdvisories
	// kindArchive is a package archive "/api/archives/{package}-{version}.tar.gz"
	// (immutable, cached, checksum-verified against the list-versions document).
	kindArchive
)

// archiveExt is the gzipped-tar suffix pub package archives carry.
const archiveExt = ".tar.gz"

// resource is the parsed classification of an inbound pub request path.
type resource struct {
	kind resourceKind
	// name is the package name.
	name string
	// version is the release version for an archive resource.
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that cannot be expressed in the pub layout, so an unrecognized request is
// reported as unsupported rather than blindly proxied.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from these segments, so they must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}
	if segs[0] != "api" {
		return resource{}, false
	}

	switch {
	case len(segs) == 3 && segs[1] == "packages":
		// /api/packages/{package}
		if !validPackageName(segs[2]) {
			return resource{}, false
		}
		return resource{kind: kindVersions, name: segs[2]}, true
	case len(segs) == 4 && segs[1] == "packages" && segs[3] == "advisories":
		// /api/packages/{package}/advisories
		if !validPackageName(segs[2]) {
			return resource{}, false
		}
		return resource{kind: kindAdvisories, name: segs[2]}, true
	case len(segs) == 3 && segs[1] == "archives":
		// /api/archives/{package}-{version}.tar.gz
		name, version, ok := splitArchiveFilename(segs[2])
		if !ok {
			return resource{}, false
		}
		return resource{kind: kindArchive, name: name, version: version}, true
	}
	return resource{}, false
}

// splitArchiveFilename parses a "{package}-{version}.tar.gz" archive filename
// into its package name and version. Pub package names are restricted to
// lowercase letters, digits, and underscores (no hyphens), while a semantic
// version may itself contain hyphens (pre-release identifiers), so the split
// is taken at the first hyphen: everything before it is the package name, and
// everything after it (with the ".tar.gz" suffix removed) is the version.
func splitArchiveFilename(fname string) (name, version string, ok bool) {
	base, found := strings.CutSuffix(fname, archiveExt)
	if !found {
		return "", "", false
	}
	hyphen := strings.IndexByte(base, '-')
	if hyphen <= 0 || hyphen == len(base)-1 {
		return "", "", false
	}
	name = base[:hyphen]
	version = base[hyphen+1:]
	if !validPackageName(name) || version == "" {
		return "", "", false
	}
	return name, version, true
}

// coordinateName returns the package name used to address the artifact in the
// admission gates (nameguard, vulnscan, provenance).
func (r resource) coordinateName() string { return r.name }

// isArchive reports whether the resource is a package-archive download.
func (r resource) isArchive() bool { return r.kind == kindArchive }

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). The archive is what pub unpacks into the package
// cache and builds; the list-versions and advisories documents are JSON a client
// only reads.
//
// An archive is fetched by way of the list-versions document, so that document
// is what Resolved.UpstreamURL names, and its last segment is the package name.
// The classification therefore carries the archive's own file name, for a gate
// that tells a format by its name.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindArchive:
		return backends.PayloadNamed(r.name + "-" + r.version + archiveExt)
	case kindVersions, kindAdvisories:
		return backends.Metadata()
	default:
		return backends.Artifact{}
	}
}

// isVersions reports whether the resource is the list-versions document (whose
// archive_url fields the backend rewrites through the proxy).
func (r resource) isVersions() bool { return r.kind == kindVersions }

// cacheable reports whether the resource may be cached. Only a concrete version
// archive is immutable and cacheable; the list-versions and advisories documents
// are mutable and revalidated live.
func (r resource) cacheable() bool { return r.kind == kindArchive }

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindVersions:
		return "versions"
	case kindAdvisories:
		return "advisories"
	case kindArchive:
		return "archive"
	default:
		return "other"
	}
}

// validPackageName reports whether s is a syntactically valid pub package name:
// a Dart identifier of lowercase letters, digits, and underscores that does not
// start with a digit. Enforced so a malformed name is rejected as unsupported
// rather than concatenated into an upstream URL (and so the first-hyphen split
// of an archive filename is unambiguous).
func validPackageName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
