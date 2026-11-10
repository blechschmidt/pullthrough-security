package conda

import "strings"

// A Conda channel is a static HTTP tree addressed by subdir (platform) and
// filename. The reference channels (conda.anaconda.org/<channel>, the
// Anaconda/Miniforge defaults) and every self-hosted channel share the same
// layout, which the proxy mounts at its channel root ("<publicBase>/v1/<name>"):
//
//	<channel>/channeldata.json                       channel summary (mutable)
//	<channel>/<subdir>/repodata.json                 per-subdir index (mutable)
//	<channel>/<subdir>/repodata.json.{bz2,zst}       compressed index variants
//	<channel>/<subdir>/current_repodata.json         pruned "latest" index (mutable)
//	<channel>/<subdir>/<name>-<version>-<build>.tar.bz2   package (immutable)
//	<channel>/<subdir>/<name>-<version>-<build>.conda     package v2 (immutable)
//
// The subdir is the platform selector: "noarch" for architecture-independent
// packages, or "<platform>-<arch>" (linux-64, linux-aarch64, osx-64, osx-arm64,
// win-64, ...). A package filename encodes its full coordinate as
// "name-version-build"; neither the version nor the build string contains a
// hyphen, so the coordinate is recovered from the final two hyphen-delimited
// fields.
//
// repodata.json records, for every package in the subdir, a strong SHA-256 (and
// a legacy MD5) digest — the ecosystem's own integrity record. On a cache miss
// the backend fetches the subdir's repodata.json, looks up the requested
// package's SHA-256, and verifies the fetched bytes against it before they are
// cached or served (see repodata.go / checksum.go). A package filename embeds
// its version and build, so a request under a subdir is immutable and
// content-addressable; the repodata/channeldata documents are mutable and
// revalidated rather than cached.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Conda channel path can
// address.
type resourceKind int

const (
	// kindRepodata is a per-subdir index document (repodata.json and its
	// compressed / pruned variants). Mutable, served live.
	kindRepodata resourceKind = iota
	// kindChannelData is the channel-root channeldata.json summary. Mutable.
	kindChannelData
	// kindPackage is a package download (.conda or .tar.bz2) pinned by name,
	// version, and build beneath a subdir. Immutable, cacheable, SHA-256 verified
	// against the subdir's repodata.json.
	kindPackage
)

// repodataFile is the per-subdir index the backend consults to verify a package
// download. The compressed/pruned variants are not used for verification (the
// plain repodata.json is always published alongside them).
const repodataFile = "repodata.json"

// resource is the parsed classification of an inbound Conda channel request.
type resource struct {
	kind resourceKind
	// subdir is the platform selector ("noarch", "linux-64", ...). Empty for the
	// channel-root channeldata.json.
	subdir string
	// filename is the final path component (the index name or the package file).
	filename string
	// name/version/build form the package coordinate for a kindPackage resource.
	name    string
	version string
	build   string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Conda channel layout, so an unrecognized request is
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
	filename := segs[len(segs)-1]

	switch {
	case isCondaPackage(filename):
		// A package lives beneath a subdir: the parent segment must be a valid
		// subdir and the filename must decode to a full coordinate.
		if len(segs) < 2 {
			return resource{}, false
		}
		subdir := segs[len(segs)-2]
		if !isSubdir(subdir) {
			return resource{}, false
		}
		name, version, build, ok := parsePackageFilename(filename)
		if !ok {
			return resource{}, false
		}
		return resource{
			kind:     kindPackage,
			subdir:   subdir,
			filename: filename,
			name:     name,
			version:  version,
			build:    build,
		}, true
	case isRepodata(filename):
		// repodata lives beneath a subdir.
		if len(segs) < 2 {
			return resource{}, false
		}
		subdir := segs[len(segs)-2]
		if !isSubdir(subdir) {
			return resource{}, false
		}
		return resource{kind: kindRepodata, subdir: subdir, filename: filename}, true
	case filename == "channeldata.json":
		return resource{kind: kindChannelData, filename: filename}, true
	default:
		return resource{}, false
	}
}

// isCondaPackage reports whether a filename is a Conda package archive.
func isCondaPackage(name string) bool {
	return strings.HasSuffix(name, ".conda") || strings.HasSuffix(name, ".tar.bz2")
}

// isRepodata reports whether a filename is a per-subdir index document the proxy
// serves live (the plain JSON index plus the compressed and pruned variants).
func isRepodata(name string) bool {
	switch name {
	case "repodata.json", "repodata.json.bz2", "repodata.json.zst",
		"current_repodata.json", "current_repodata.json.bz2", "current_repodata.json.zst",
		"repodata_from_packages.json", "repodata_from_packages.json.bz2":
		return true
	default:
		return false
	}
}

// isSubdir reports whether s is a Conda subdir selector: "noarch" or one of the
// "<platform>-<arch>" forms the ecosystem defines. Restricting to the known
// platform prefixes keeps an arbitrary directory name from being mistaken for a
// package subdir.
func isSubdir(s string) bool {
	if s == "noarch" {
		return true
	}
	i := strings.IndexByte(s, '-')
	if i <= 0 || i >= len(s)-1 {
		return false
	}
	switch s[:i] {
	case "linux", "osx", "win", "freebsd", "zos", "emscripten", "wasi":
		return true
	default:
		return false
	}
}

// parsePackageFilename decodes a Conda package filename into its coordinate. A
// package is "name-version-build" followed by the archive extension; neither the
// version nor the build string contains a hyphen, so the coordinate is the final
// two hyphen-delimited fields and everything before them is the name.
func parsePackageFilename(name string) (pkg, version, build string, ok bool) {
	base := name
	switch {
	case strings.HasSuffix(base, ".tar.bz2"):
		base = base[:len(base)-len(".tar.bz2")]
	case strings.HasSuffix(base, ".conda"):
		base = base[:len(base)-len(".conda")]
	default:
		return "", "", "", false
	}
	j := strings.LastIndexByte(base, '-')
	if j <= 0 {
		return "", "", "", false
	}
	i := strings.LastIndexByte(base[:j], '-')
	if i <= 0 {
		return "", "", "", false
	}
	pkg = base[:i]
	version = base[i+1 : j]
	build = base[j+1:]
	if pkg == "" || version == "" || build == "" {
		return "", "", "", false
	}
	return pkg, version, build, true
}

// cacheable reports whether the resource may be cached. Only package downloads
// are immutable (their filename pins the version and build); the repodata and
// channeldata documents are mutable and revalidated live.
func (r resource) cacheable() bool {
	return r.kind == kindPackage
}

// verifiableFile reports whether the resource is a package the backend should
// verify against the subdir's repodata.json.
func (r resource) verifiableFile() bool {
	return r.kind == kindPackage
}

// coordinateName returns the package name used to address the artifact in the
// admission gates. Empty for index documents.
func (r resource) coordinateName() string {
	return r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindRepodata:
		return "repodata"
	case kindChannelData:
		return "channeldata"
	case kindPackage:
		return "package"
	default:
		return "other"
	}
}
