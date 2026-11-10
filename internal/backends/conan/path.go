package conan

import "strings"

// Conan 2.x speaks the "revisions" REST API that JFrog Artifactory (and thus
// ConanCenter, https://center2.conan.io) and the reference conan_server both
// implement. Every endpoint lives under a "/v2" prefix and addresses a package
// by its full reference — name, version, user, channel — with ConanCenter using
// the placeholder "_" for an absent user/channel (e.g. "zlib/1.2.13/_/_"):
//
//	GET /v2/ping                                            server capability probe
//	GET /v2/users/authenticate | /v2/users/check_credentials   auth
//	GET /v2/conans/search                                   recipe search
//	GET /v2/conans/{n}/{v}/{u}/{c}/latest                   latest recipe revision (mutable)
//	GET /v2/conans/{n}/{v}/{u}/{c}/revisions                recipe revision list (mutable)
//	GET /v2/conans/{n}/{v}/{u}/{c}/search                   package-configuration search
//	GET .../revisions/{rrev}/files                          recipe-revision file list (immutable)
//	GET .../revisions/{rrev}/files/{file}                   recipe file download (immutable)
//	GET .../revisions/{rrev}/search                         package search within a recipe revision
//	GET .../revisions/{rrev}/packages/{pid}/latest          latest package revision (mutable)
//	GET .../revisions/{rrev}/packages/{pid}/revisions       package revision list (mutable)
//	GET .../revisions/{rrev}/packages/{pid}/revisions/{prev}/files        package file list (immutable)
//	GET .../revisions/{rrev}/packages/{pid}/revisions/{prev}/files/{file} package file download (immutable)
//
// A recipe revision (rrev) and a package revision (prev) are themselves content
// hashes of the files they pin, so anything addressed beneath a concrete
// revision is immutable and content-addressable — the proxy caches it
// indefinitely. The mutable discovery endpoints (latest, revision lists, search,
// ping) are revalidated rather than cached.
//
// The recipe content files are conanfile.py, conanmanifest.txt,
// conan_export.tgz, and conan_sources.tgz; the package content files are
// conaninfo.txt, conanmanifest.txt, and conan_package.tgz. conanmanifest.txt
// lists the MD5 digest of every sibling file in the revision — the ecosystem's
// own integrity record — which the backend uses to verify fetched content before
// it is cached or served (see checksum.go / manifest.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Conan v2 path can address.
type resourceKind int

const (
	// kindPing is the GET /v2/ping capability probe (served live).
	kindPing resourceKind = iota
	// kindUsers is an authentication endpoint (authenticate / check_credentials).
	kindUsers
	// kindSearch is a recipe or package search query (mutable, served live).
	kindSearch
	// kindRecipeLatest is the latest-recipe-revision pointer (mutable).
	kindRecipeLatest
	// kindRecipeRevisions is the recipe revision list (mutable).
	kindRecipeRevisions
	// kindRecipeFiles is the file list of a pinned recipe revision (immutable).
	kindRecipeFiles
	// kindRecipeFile is a file download from a pinned recipe revision (immutable,
	// checksum-verified against conanmanifest.txt).
	kindRecipeFile
	// kindPackageLatest is the latest-package-revision pointer (mutable).
	kindPackageLatest
	// kindPackageRevisions is the package revision list (mutable).
	kindPackageRevisions
	// kindPackageFiles is the file list of a pinned package revision (immutable).
	kindPackageFiles
	// kindPackageFile is a file download from a pinned package revision (immutable,
	// checksum-verified against conanmanifest.txt).
	kindPackageFile
)

// manifestFile is the per-revision integrity manifest every recipe and package
// revision carries. It lists "filename: md5" for each sibling file.
const manifestFile = "conanmanifest.txt"

// conaninfoFile records a binary package's resolved settings/options/requires;
// its contents determine the package_id. It is surfaced to the admission gates.
const conaninfoFile = "conaninfo.txt"

// resource is the parsed classification of an inbound Conan v2 request path.
type resource struct {
	kind resourceKind
	// name/version/user/channel form the recipe reference "name/version@user/channel".
	// ConanCenter uses "_" for an absent user and channel.
	name    string
	version string
	user    string
	channel string
	// rrev is the recipe revision (a content hash) when the path pins one.
	rrev string
	// pkgID is the package_id (a hash of the recipe revision + settings/options)
	// for a package-level resource.
	pkgID string
	// prev is the package revision (a content hash) when the path pins one.
	prev string
	// filename is the file path requested beneath a "files/" segment (usually a
	// single flat filename such as "conanfile.py").
	filename string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that cannot be expressed in the Conan v2 layout, so an unrecognized request is
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
	if segs[0] != "v2" {
		return resource{}, false
	}
	rest := segs[1:]
	if len(rest) == 0 {
		return resource{}, false
	}

	switch rest[0] {
	case "ping":
		if len(rest) == 1 {
			return resource{kind: kindPing}, true
		}
		return resource{}, false
	case "users":
		if len(rest) == 2 && (rest[1] == "authenticate" || rest[1] == "check_credentials") {
			return resource{kind: kindUsers}, true
		}
		return resource{}, false
	case "conans":
		return classifyConans(rest[1:])
	default:
		return resource{}, false
	}
}

// classifyConans parses the path segments following "/v2/conans/".
func classifyConans(segs []string) (resource, bool) {
	if len(segs) == 0 {
		return resource{}, false
	}
	// Top-level recipe search: /v2/conans/search.
	if len(segs) == 1 && segs[0] == "search" {
		return resource{kind: kindSearch}, true
	}
	// A reference needs name/version/user/channel.
	if len(segs) < 4 {
		return resource{}, false
	}
	r := resource{
		name:    segs[0],
		version: segs[1],
		user:    segs[2],
		channel: segs[3],
	}
	tail := segs[4:]
	if len(tail) == 0 {
		// Bare reference ("/v2/conans/{n}/{v}/{u}/{c}") is not a defined endpoint.
		return resource{}, false
	}

	switch tail[0] {
	case "latest":
		if len(tail) == 1 {
			r.kind = kindRecipeLatest
			return r, true
		}
	case "search":
		if len(tail) == 1 {
			r.kind = kindSearch
			return r, true
		}
	case "revisions":
		if len(tail) == 1 {
			r.kind = kindRecipeRevisions
			return r, true
		}
		return classifyRecipeRevision(r, tail[1:])
	}
	return resource{}, false
}

// classifyRecipeRevision parses the segments following ".../revisions/" for a
// recipe, where the first element is the recipe revision (rrev).
func classifyRecipeRevision(r resource, segs []string) (resource, bool) {
	r.rrev = segs[0]
	sub := segs[1:]
	if len(sub) == 0 {
		// A bare "/revisions/{rrev}" is used for DELETE, not GET; not proxied.
		return resource{}, false
	}
	switch sub[0] {
	case "files":
		if len(sub) == 1 {
			r.kind = kindRecipeFiles
			return r, true
		}
		r.kind = kindRecipeFile
		r.filename = strings.Join(sub[1:], "/")
		return r, true
	case "search":
		if len(sub) == 1 {
			r.kind = kindSearch
			return r, true
		}
	case "packages":
		return classifyPackage(r, sub[1:])
	}
	return resource{}, false
}

// classifyPackage parses the segments following ".../packages/", where the first
// element is the package_id.
func classifyPackage(r resource, segs []string) (resource, bool) {
	if len(segs) == 0 {
		return resource{}, false
	}
	r.pkgID = segs[0]
	tail := segs[1:]
	if len(tail) == 0 {
		return resource{}, false
	}
	switch tail[0] {
	case "latest":
		if len(tail) == 1 {
			r.kind = kindPackageLatest
			return r, true
		}
	case "revisions":
		if len(tail) == 1 {
			r.kind = kindPackageRevisions
			return r, true
		}
		return classifyPackageRevision(r, tail[1:])
	}
	return resource{}, false
}

// classifyPackageRevision parses the segments following a package's
// ".../revisions/", where the first element is the package revision (prev).
func classifyPackageRevision(r resource, segs []string) (resource, bool) {
	r.prev = segs[0]
	sub := segs[1:]
	if len(sub) == 0 {
		return resource{}, false
	}
	if sub[0] == "files" {
		if len(sub) == 1 {
			r.kind = kindPackageFiles
			return r, true
		}
		r.kind = kindPackageFile
		r.filename = strings.Join(sub[1:], "/")
		return r, true
	}
	return resource{}, false
}

// coordinateName returns the package name used to address the artifact in the
// admission gates (nameguard, vulnscan, provenance). Conan identifies a package
// primarily by its name; the user/channel/version qualify it and are surfaced
// separately via cache metadata.
func (r resource) coordinateName() string {
	return r.name
}

// reference renders the canonical Conan reference "name/version@user/channel",
// collapsing ConanCenter's "_" placeholders to the unqualified "name/version".
func (r resource) reference() string {
	if r.name == "" || r.version == "" {
		return ""
	}
	ref := r.name + "/" + r.version
	if r.user != "" && r.user != "_" {
		ref += "@" + r.user + "/" + r.channel
	}
	return ref
}

// isFile reports whether the resource is a concrete file download (recipe or
// package) addressed beneath a pinned revision.
func (r resource) isFile() bool {
	return r.kind == kindRecipeFile || r.kind == kindPackageFile
}

// verifiableFile reports whether the resource is a content file the backend
// should checksum-verify against its revision's conanmanifest.txt. The manifest
// itself is excluded (it is the source of truth — verifying it against itself is
// meaningless).
func (r resource) verifiableFile() bool {
	return r.isFile() && r.baseFilename() != manifestFile
}

// baseFilename returns the final path component of a requested file.
func (r resource) baseFilename() string {
	if i := strings.LastIndex(r.filename, "/"); i >= 0 {
		return r.filename[i+1:]
	}
	return r.filename
}

// isConanInfo reports whether the requested file is a package's conaninfo.txt.
func (r resource) isConanInfo() bool {
	return r.kind == kindPackageFile && r.baseFilename() == conaninfoFile
}

// cacheable reports whether the resource may be cached. Only resources pinned
// beneath a concrete recipe or package revision are immutable and cacheable; the
// discovery endpoints (latest, revision lists, search, ping, users) are mutable
// and revalidated live.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindRecipeFiles, kindRecipeFile, kindPackageFiles, kindPackageFile:
		return true
	default:
		return false
	}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindPing:
		return "ping"
	case kindUsers:
		return "users"
	case kindSearch:
		return "search"
	case kindRecipeLatest:
		return "recipe-latest"
	case kindRecipeRevisions:
		return "recipe-revisions"
	case kindRecipeFiles:
		return "recipe-files"
	case kindRecipeFile:
		return "recipe-file"
	case kindPackageLatest:
		return "package-latest"
	case kindPackageRevisions:
		return "package-revisions"
	case kindPackageFiles:
		return "package-files"
	case kindPackageFile:
		return "package-file"
	default:
		return "other"
	}
}
