package hex

import "strings"

// A Hex repository (the Elixir/Erlang package registry, hex.pm, served from
// repo.hex.pm) is a small static HTTP tree of signed registry resources and the
// immutable release tarballs they describe. The proxy mounts a repository at its
// route root ("<publicBase>/v1/<name>") and honors the registry-v2 layout:
//
//	/names                              all package names (signed protobuf, mutable)
//	/versions                           all packages' versions (signed protobuf, mutable)
//	/packages/<name>                    one package's releases (signed protobuf, mutable)
//	/tarballs/<name>-<version>.tar      a release tarball (immutable, verified)
//
// The three registry resources are gzip-compressed, protobuf-encoded, and wrapped
// in a Signed envelope; they change whenever a package publishes, so they are
// revalidated live rather than cached. A tarball filename pins its
// name-and-version coordinate, so a tarball is immutable and content-addressable;
// on a cache miss the backend fetches the sibling /packages/<name> resource,
// reads the release's outer_checksum (a SHA-256 over the whole tarball), and
// verifies the fetched bytes against it before they are cached or served (see
// registry.go / checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Hex repository path can
// address.
type resourceKind int

const (
	// kindNames is the /names registry resource (all package names). Mutable,
	// served live.
	kindNames resourceKind = iota
	// kindVersions is the /versions registry resource (every package's released
	// versions). Mutable, served live.
	kindVersions
	// kindPackageIndex is the /packages/<name> registry resource (one package's
	// releases, each carrying an outer_checksum). Mutable, served live; also the
	// digest source the backend verifies tarballs against.
	kindPackageIndex
	// kindTarball is a release tarball /tarballs/<name>-<version>.tar, pinned by
	// name and version. Immutable, cacheable, verified against the sibling
	// /packages/<name> resource's outer_checksum.
	kindTarball
)

// tarballExt is the single extension a Hex release tarball carries. The outer
// archive is an uncompressed tar (its contents.tar.gz member is compressed
// inside it).
const tarballExt = ".tar"

// resource is the parsed classification of an inbound Hex repository request.
type resource struct {
	kind resourceKind
	// filename is the final path component (a registry-resource name or the
	// tarball file).
	filename string
	// name/version form the package coordinate. name is set for kindPackageIndex
	// and kindTarball; version only for kindTarball.
	name    string
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Hex repository layout, so an unrecognized request is
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
	case "names":
		if len(segs) == 1 {
			return resource{kind: kindNames, filename: "names"}, true
		}
	case "versions":
		if len(segs) == 1 {
			return resource{kind: kindVersions, filename: "versions"}, true
		}
	case "packages":
		// /packages/<name> — exactly one trailing segment, the package name.
		if len(segs) == 2 && validPackageName(segs[1]) {
			return resource{kind: kindPackageIndex, filename: segs[1], name: segs[1]}, true
		}
	case "tarballs":
		// /tarballs/<name>-<version>.tar — exactly one trailing segment.
		if len(segs) == 2 {
			if name, version, ok := parseTarballFilename(segs[1]); ok {
				return resource{kind: kindTarball, filename: segs[1], name: name, version: version}, true
			}
		}
	}
	return resource{}, false
}

// validPackageName reports whether s is a plausible Hex package name. Hex
// restricts names to lowercase ASCII letters, digits, and underscores; applying
// the rule here keeps the /packages/<name> route from proxying arbitrary paths
// and guarantees the coordinate fed to the gates is well-formed.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_':
		default:
			return false
		}
	}
	return true
}

// parseTarballFilename decodes a Hex tarball filename into its coordinate. A
// tarball is "<name>-<version>.tar". Hex package names may not contain a hyphen,
// so the name is everything before the first hyphen and the version is
// everything between it and the ".tar" extension (which preserves pre-release
// versions such as "1.0.0-rc.1"). The name is validated against Hex's naming
// rule; the version is only checked for non-emptiness and traversal safety.
func parseTarballFilename(name string) (pkg, version string, ok bool) {
	if !strings.HasSuffix(name, tarballExt) {
		return "", "", false
	}
	base := name[:len(name)-len(tarballExt)]
	i := strings.IndexByte(base, '-')
	if i <= 0 || i >= len(base)-1 {
		return "", "", false
	}
	pkg = base[:i]
	version = base[i+1:]
	if !validPackageName(pkg) || version == "" {
		return "", "", false
	}
	// The version is part of the upstream path; reject any residual traversal
	// metacharacters so it cannot escape the tarballs/ directory.
	if strings.ContainsAny(version, "/\\") || version == "." || version == ".." {
		return "", "", false
	}
	return pkg, version, true
}

// cacheable reports whether the resource may be cached. Only tarballs are
// immutable (their filename pins the version); the three registry resources are
// mutable and revalidated live.
func (r resource) cacheable() bool {
	return r.kind == kindTarball
}

// verifiableFile reports whether the resource is a tarball the backend should
// verify against the sibling /packages/<name> resource.
func (r resource) verifiableFile() bool {
	return r.kind == kindTarball
}

// coordinateName returns the package name used to address the artifact in the
// admission gates. Empty for the /names and /versions resources.
func (r resource) coordinateName() string {
	return r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindNames:
		return "names"
	case kindVersions:
		return "versions"
	case kindPackageIndex:
		return "package-index"
	case kindTarball:
		return "tarball"
	default:
		return "other"
	}
}

// isRegistryResource reports whether the resource is one of the signed protobuf
// registry documents (names/versions/packages), as opposed to a tarball.
func (r resource) isRegistryResource() bool {
	return r.kind == kindNames || r.kind == kindVersions || r.kind == kindPackageIndex
}
