package hackage

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A Hackage repository is a static HTTP tree of the incremental package index,
// TUF security metadata, per-package .cabal descriptions, and the immutable
// source-distribution (sdist) tarballs. The proxy mounts a repository at its
// route root ("<publicBase>/v1/<name>") and honors the Hackage layout:
//
//	/01-index.tar.gz                              incremental package index (mutable)
//	/01-index.tar                                 uncompressed index         (mutable)
//	/root.json /snapshot.json /timestamp.json …   TUF security metadata      (mutable)
//	/package/<name>-<ver>                          package landing (metadata) (mutable)
//	/package/<name>-<ver>/<name>.cabal             package description        (mutable)
//	/package/<name>-<ver>/package.json             TUF target metadata        (mutable)
//	/package/<name>-<ver>/<name>-<ver>.tar.gz      sdist tarball              (immutable, verified)
//	/package/<name>-<ver>.tar.gz                   sdist tarball (short form) (immutable, verified)
//
// Only the sdist tarball is immutable and content-addressable; everything else
// is revalidated live. On an sdist miss the backend fetches the sibling
// package.json TUF target metadata, reads the tarball's SHA-256, and verifies
// the fetched bytes against it before they are cached or served (see
// targets.go / checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Hackage repository path can
// address.
type resourceKind int

const (
	// kindIndex is the incremental package index (01-index.tar[.gz]). Mutable,
	// served live.
	kindIndex resourceKind = iota
	// kindTUFMetadata is a TUF security document (root/snapshot/timestamp/
	// mirrors.json). Mutable, served live.
	kindTUFMetadata
	// kindTargetMetadata is a per-package TUF target metadata document
	// (package.json), the digest source the backend verifies sdists against.
	// Mutable, served live.
	kindTargetMetadata
	// kindCabal is a package's .cabal description. Mutable, served live.
	kindCabal
	// kindPackagePage is a package landing path (/package/<name>[-<ver>]).
	// Mutable, served live.
	kindPackagePage
	// kindSdist is a source-distribution tarball, pinned by name and version.
	// Immutable, cacheable, verified against the sibling package.json.
	kindSdist
)

// sdistExt is the extension a Hackage sdist tarball carries.
const sdistExt = ".tar.gz"

// tufMetadataFiles is the set of top-level TUF security documents.
var tufMetadataFiles = map[string]bool{
	"root.json":      true,
	"snapshot.json":  true,
	"timestamp.json": true,
	"mirrors.json":   true,
}

// resource is the parsed classification of an inbound Hackage repository
// request.
type resource struct {
	kind resourceKind
	// filename is the final path component (an index/metadata name or the sdist
	// file).
	filename string
	// name/version form the package coordinate. name is set for cabal/target/
	// page/sdist; version is set when the path pins one.
	name    string
	version string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the Hackage repository layout, so an unrecognized request is
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

	// Top-level index and TUF metadata.
	if len(segs) == 1 {
		switch {
		case segs[0] == "01-index.tar.gz" || segs[0] == "01-index.tar":
			return resource{kind: kindIndex, filename: segs[0]}, true
		case tufMetadataFiles[segs[0]]:
			return resource{kind: kindTUFMetadata, filename: segs[0]}, true
		}
		return resource{}, false
	}

	if segs[0] != "package" {
		return resource{}, false
	}

	switch len(segs) {
	case 2:
		// /package/<name>-<ver>.tar.gz (short sdist form) or /package/<pkgid> (page).
		if strings.HasSuffix(segs[1], sdistExt) {
			pkgid := strings.TrimSuffix(segs[1], sdistExt)
			if name, version, ok := parsePkgID(pkgid); ok {
				return resource{kind: kindSdist, filename: segs[1], name: name, version: version}, true
			}
			return resource{}, false
		}
		// A package landing path: either "<name>-<ver>" or a bare "<name>".
		if name, version, ok := parsePkgID(segs[1]); ok {
			return resource{kind: kindPackagePage, filename: segs[1], name: name, version: version}, true
		}
		if validPackageName(segs[1]) {
			return resource{kind: kindPackagePage, filename: segs[1], name: segs[1]}, true
		}
		return resource{}, false
	case 3:
		// /package/<name>-<ver>/<file>
		dir := segs[1]
		file := segs[2]
		name, version, ok := parsePkgID(dir)
		if !ok {
			return resource{}, false
		}
		switch {
		case file == dir+sdistExt:
			return resource{kind: kindSdist, filename: file, name: name, version: version}, true
		case file == "package.json":
			return resource{kind: kindTargetMetadata, filename: file, name: name, version: version}, true
		case strings.HasSuffix(file, ".cabal") && validCabalFilename(file, name):
			return resource{kind: kindCabal, filename: file, name: name, version: version}, true
		}
		return resource{}, false
	}
	return resource{}, false
}

// parsePkgID splits a Hackage package identifier "<name>-<version>" into its
// name and version. A Hackage name may itself contain hyphens (e.g.
// "aeson-pretty"), while a PVP version is a dot-separated run of decimal
// components (e.g. "0.8.10"); the version is therefore the suffix after the
// right-most hyphen whose tail is a valid version. It returns ok=false when no
// such split yields a valid name and version.
func parsePkgID(pkgid string) (name, version string, ok bool) {
	for i := len(pkgid) - 1; i > 0; i-- {
		if pkgid[i] != '-' {
			continue
		}
		cand := pkgid[i+1:]
		if !validVersion(cand) {
			// A hyphen inside the name region; keep scanning leftwards only while
			// the tail could still be a version. Once the tail stops being a valid
			// version we can stop — versions do not contain hyphens.
			break
		}
		n := pkgid[:i]
		if validPackageName(n) {
			return n, cand, true
		}
	}
	return "", "", false
}

// validPackageName reports whether s is a plausible Hackage package name.
// Hackage names are composed of alphanumeric ASCII characters and hyphens (case
// is significant, e.g. "HUnit"); each hyphen-separated component must contain a
// letter so a name is never confused with a version. Applying the rule here
// keeps the /package route from proxying arbitrary paths and guarantees the
// coordinate fed to the gates is well-formed.
func validPackageName(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasLetter = true
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return hasLetter
}

// validVersion reports whether s is a plausible PVP version: a non-empty,
// dot-separated run of decimal components, e.g. "2", "1.0", "0.8.10".
func validVersion(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// validCabalFilename reports whether file is the expected "<name>.cabal" for a
// package (cabal serves the description under the package's own name).
func validCabalFilename(file, name string) bool {
	return file == name+".cabal"
}

// cacheable reports whether the resource may be cached. Only sdist tarballs are
// immutable (their filename pins the version); everything else is revalidated
// live.
func (r resource) cacheable() bool { return r.kind == kindSdist }

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). The sdist tarball — in either spelling of its path —
// is the source cabal unpacks and builds: the payload. Everything else the
// layout names is a document a client reads to decide what to fetch: the
// package index (an archive, but one that holds only .cabal descriptions and
// TUF target metadata), the TUF security documents, a package's target
// metadata, its .cabal description and its landing page.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindSdist:
		return backends.Payload()
	case kindIndex:
		// 01-index.tar(.gz) is a tar of every package's .cabal file: an index that
		// is an archive, fetched by cabal at this one fixed path.
		return backends.MetadataArchive()
	case kindTUFMetadata, kindTargetMetadata, kindCabal, kindPackagePage:
		return backends.Metadata()
	default:
		return backends.Artifact{}
	}
}

// verifiableFile reports whether the resource is an sdist the backend should
// verify against the sibling package.json TUF target metadata.
func (r resource) verifiableFile() bool { return r.kind == kindSdist }

// coordinateName returns the package name used to address the artifact in the
// admission gates. Empty for the index and TUF-root metadata.
func (r resource) coordinateName() string { return r.name }

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindIndex:
		return "index"
	case kindTUFMetadata:
		return "tuf-metadata"
	case kindTargetMetadata:
		return "target-metadata"
	case kindCabal:
		return "cabal"
	case kindPackagePage:
		return "package-page"
	case kindSdist:
		return "sdist"
	default:
		return "other"
	}
}
