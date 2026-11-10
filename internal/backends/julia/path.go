package julia

import "strings"

// A Julia Pkg Server (https://pkgdocs.julialang.org/dev/protocol/) is a small,
// fully content-addressed HTTP tree. The proxy mounts a server at its route root
// ("<publicBase>/v1/<name>", set as JULIA_PKG_SERVER) and honors the protocol:
//
//	/registries                  map of registry uuids -> current tree hash (mutable)
//	/registry/<uuid>/<hash>       a registry's tarball at <hash>            (immutable)
//	/package/<uuid>/<hash>        a package's source tarball at <hash>      (immutable)
//	/artifact/<hash>              an artifact tarball at <hash>             (immutable)
//
// The <hash> is a git-tree-sha1: the SHA-1 Git tree object hash of the
// decompressed tarball's contents. Because it is part of the URL, a tarball is
// immutable and content-addressable, and the fetched bytes can be verified
// against the hash without any sibling resource (see treehash.go). The
// /registries listing is mutable (it names the current registry tree hash) and
// is revalidated live rather than cached.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and extracts the UUID/tree-hash, which feed the admission gates and the
// cacheability decision. Every path segment is validated because the upstream
// URL is built from these segments.

// resourceKind enumerates the classes of resource a Pkg Server path can address.
type resourceKind int

const (
	// kindRegistries is the /registries listing (uuid -> current tree hash).
	// Mutable, served live, not content-addressed.
	kindRegistries resourceKind = iota
	// kindRegistry is a /registry/<uuid>/<hash> registry tarball. Immutable,
	// cacheable, verified against <hash>.
	kindRegistry
	// kindPackage is a /package/<uuid>/<hash> package source tarball. Immutable,
	// cacheable, verified against <hash>.
	kindPackage
	// kindArtifact is an /artifact/<hash> artifact tarball. Immutable, cacheable,
	// verified against <hash>.
	kindArtifact
)

// gitTreeSHA1HexLen is the hex length of a git-tree-sha1 (a 20-byte SHA-1).
const gitTreeSHA1HexLen = 40

// sha3TreeHexLen is the hex length a future SHA3-256 tree hash would carry. The
// Pkg Server Protocol reserves the option of migrating from SHA-1; such a hash
// is still a valid, immutable content address (so it is cached), but this
// backend can only recompute the SHA-1 Git tree hash, so a SHA3-256 hash is
// served as cacheable-but-unverified rather than refused.
const sha3TreeHexLen = 64

// resource is the parsed classification of an inbound Pkg Server request.
type resource struct {
	kind resourceKind
	// filename is the final path component (the listing name or the tree hash).
	filename string
	// uuid is the registry/package UUID; empty for /registries and /artifact.
	uuid string
	// hash is the git-tree-sha1 content address; empty for /registries. It is the
	// expected hash verifiable tarballs are checked against.
	hash string
	// hashVerifiable reports whether hash is a git-tree-sha1 (SHA-1) the backend
	// can recompute. A reserved-length SHA3-256 hash is cacheable but unverifiable.
	hashVerifiable bool
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Pkg Server Protocol, so an unrecognized request is
// reported as unsupported rather than blindly proxied.
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
	case "registries":
		if len(segs) == 1 {
			return resource{kind: kindRegistries, filename: "registries"}, true
		}
	case "registry":
		// /registry/<uuid>/<hash>
		if len(segs) == 3 && validUUID(segs[1]) {
			if ok, verifiable := validContentHash(segs[2]); ok {
				return resource{kind: kindRegistry, filename: segs[2], uuid: segs[1], hash: segs[2], hashVerifiable: verifiable}, true
			}
		}
	case "package":
		// /package/<uuid>/<hash>
		if len(segs) == 3 && validUUID(segs[1]) {
			if ok, verifiable := validContentHash(segs[2]); ok {
				return resource{kind: kindPackage, filename: segs[2], uuid: segs[1], hash: segs[2], hashVerifiable: verifiable}, true
			}
		}
	case "artifact":
		// /artifact/<hash>
		if len(segs) == 2 {
			if ok, verifiable := validContentHash(segs[1]); ok {
				return resource{kind: kindArtifact, filename: segs[1], hash: segs[1], hashVerifiable: verifiable}, true
			}
		}
	}
	return resource{}, false
}

// validUUID reports whether s is a canonical lowercase hyphenated UUID
// (8-4-4-4-12 hex), the form Julia's registries and packages use. Restricting
// the charset here keeps the route from proxying arbitrary paths and guarantees
// the coordinate fed to the gates is well-formed.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !isLowerHex(c) {
			return false
		}
	}
	return true
}

// validContentHash reports whether s is a valid content-address hash and whether
// the backend can verify it. A 40-char lowercase-hex string is a git-tree-sha1
// (verifiable); a 64-char lowercase-hex string is the reserved SHA3-256 form
// (accepted as a content address, but not verifiable by this backend).
func validContentHash(s string) (ok, verifiable bool) {
	switch len(s) {
	case gitTreeSHA1HexLen:
		if isLowerHexString(s) {
			return true, true
		}
	case sha3TreeHexLen:
		if isLowerHexString(s) {
			return true, false
		}
	}
	return false, false
}

func isLowerHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLowerHex(s[i]) {
			return false
		}
	}
	return true
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// cacheable reports whether the resource may be cached. Only the content-
// addressed tarballs are immutable; the /registries listing is mutable and
// revalidated live.
func (r resource) cacheable() bool {
	return r.kind == kindRegistry || r.kind == kindPackage || r.kind == kindArtifact
}

// verifiable reports whether the backend should recompute and check the tarball
// against the git-tree-sha1 in its URL. True for content-addressed tarballs
// whose hash is a (verifiable) SHA-1 tree hash.
func (r resource) verifiable() bool {
	return r.cacheable() && r.hashVerifiable
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindRegistries:
		return "registries"
	case kindRegistry:
		return "registry"
	case kindPackage:
		return "package"
	case kindArtifact:
		return "artifact"
	default:
		return "other"
	}
}
