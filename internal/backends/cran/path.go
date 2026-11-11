package cran

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A CRAN (R) repository is a static HTTP tree of per-area PACKAGES indices and
// the package tarballs they describe. The canonical CRAN mirror and every
// CRAN-compatible repository (Posit Package Manager, Bioconductor, a local
// miniCRAN) share the same layout, which the proxy mounts at its repository root
// ("<publicBase>/v1/<name>"):
//
//	src/contrib/PACKAGES                               source index (mutable)
//	src/contrib/PACKAGES.gz                            compressed index
//	src/contrib/<pkg>_<version>.tar.gz                 source package (immutable)
//	src/contrib/Archive/<pkg>/<pkg>_<version>.tar.gz   archived source package
//	bin/windows/contrib/<rver>/PACKAGES                Windows binary index
//	bin/windows/contrib/<rver>/<pkg>_<version>.zip     Windows binary package
//	bin/macosx/<arch>/contrib/<rver>/PACKAGES          macOS binary index
//	bin/macosx/<arch>/contrib/<rver>/<pkg>_<version>.tgz  macOS binary package
//
// The PACKAGES index is a DCF (Debian-control) file: one stanza per package
// carrying at least Package, Version, and an MD5sum field — the ecosystem's own
// integrity record. On a cache miss the backend fetches the sibling PACKAGES
// index, looks up the requested package's MD5sum, and verifies the fetched
// tarball against it before it is cached or served (see packages.go /
// checksum.go). A package filename encodes its name and version, so a tarball is
// immutable and content-addressable; the PACKAGES indices are mutable and
// revalidated rather than cached.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a CRAN repository path can
// address.
type resourceKind int

const (
	// kindIndex is a PACKAGES index document (PACKAGES, PACKAGES.gz, PACKAGES.rds).
	// Mutable, served live.
	kindIndex resourceKind = iota
	// kindPackage is a package tarball (.tar.gz source, or a .zip / .tgz binary)
	// pinned by name and version. Immutable, cacheable, verified against the
	// sibling PACKAGES index's MD5sum.
	kindPackage
)

// packagesFile is the plain DCF index the backend consults to verify a package
// download. The compressed / serialized variants (.gz, .rds) are not used for
// verification (the plain PACKAGES is always published alongside them).
const packagesFile = "PACKAGES"

// resource is the parsed classification of an inbound CRAN repository request.
type resource struct {
	kind resourceKind
	// filename is the final path component (the index name or the package file).
	filename string
	// name/version form the package coordinate for a kindPackage resource.
	name    string
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the CRAN repository layout, so an unrecognized request is
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

	if isIndex(filename) {
		return resource{kind: kindIndex, filename: filename}, true
	}
	if name, version, ok := parsePackageFilename(filename); ok {
		return resource{kind: kindPackage, filename: filename, name: name, version: version}, true
	}
	return resource{}, false
}

// isIndex reports whether a filename is a PACKAGES index document (the plain DCF
// file plus its compressed and R-serialized variants).
func isIndex(name string) bool {
	switch name {
	case "PACKAGES", "PACKAGES.gz", "PACKAGES.rds", "PACKAGES.bz2", "PACKAGES.xz":
		return true
	default:
		return false
	}
}

// parsePackageFilename decodes a CRAN package filename into its coordinate. A
// package is "<name>_<version>" followed by the archive extension. R package
// names may not contain an underscore, so the name is everything before the
// first underscore and the version is everything between it and the extension.
func parsePackageFilename(name string) (pkg, version string, ok bool) {
	base := name
	switch {
	case strings.HasSuffix(base, ".tar.gz"):
		base = base[:len(base)-len(".tar.gz")]
	case strings.HasSuffix(base, ".tgz"):
		base = base[:len(base)-len(".tgz")]
	case strings.HasSuffix(base, ".zip"):
		base = base[:len(base)-len(".zip")]
	default:
		return "", "", false
	}
	i := strings.IndexByte(base, '_')
	if i <= 0 || i >= len(base)-1 {
		return "", "", false
	}
	pkg = base[:i]
	version = base[i+1:]
	if pkg == "" || version == "" {
		return "", "", false
	}
	return pkg, version, true
}

// cacheable reports whether the resource may be cached. Only package tarballs
// are immutable (their filename pins the version); the PACKAGES indices are
// mutable and revalidated live.
func (r resource) cacheable() bool {
	return r.kind == kindPackage
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A package — a source tarball R builds and installs,
// or a prebuilt Windows or macOS binary — is the payload. A PACKAGES index, in
// any of its encodings, is what a client reads to see which versions exist; it
// is recognized by its exact file name.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindPackage:
		return backends.Payload()
	case kindIndex:
		return backends.Metadata()
	default:
		return backends.Artifact{}
	}
}

// verifiableFile reports whether the resource is a package the backend should
// verify against the sibling PACKAGES index.
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
	case kindIndex:
		return "index"
	case kindPackage:
		return "package"
	default:
		return "other"
	}
}
