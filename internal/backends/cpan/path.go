package cpan

import (
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A CPAN mirror (and every CPAN-compatible mirror — a local minicpan, an
// Artifactory CPAN repository, the MetaCPAN-fronted www.cpan.org CDN) is a
// static HTTP tree with two load-bearing areas, which the proxy mounts at its
// repository root ("<publicBase>/v1/<name>"):
//
//	modules/02packages.details.txt.gz          master package index (module -> dist path)
//	modules/03modlist.data.gz                  module registration list
//	modules/01mailrc.txt.gz                    author (PAUSE id) list
//	authors/id/<A>/<AB>/<AUTHOR>/CHECKSUMS     per-author-directory integrity record
//	authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Ver>.tar.gz   distribution tarball (immutable)
//	authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Ver>.meta     distribution metadata
//	authors/id/<A>/<AB>/<AUTHOR>/<Dist>-<Ver>.readme   distribution readme
//
// The author directory is sharded by PAUSE id: "E/ET/ETHER" is the first
// letter, the first two letters, and the full upper-cased PAUSE id. Every such
// directory publishes a CHECKSUMS file — a PGP-clearsigned Perl data structure
// mapping each file in the directory to its SHA-256 (and legacy MD5) digest and
// size. That CHECKSUMS file is the ecosystem's own integrity record: on a cache
// miss the backend fetches the sibling CHECKSUMS, looks up the requested
// distribution's SHA-256, and verifies the fetched tarball against it — streaming,
// so a mismatch aborts the cache write and the client stream without buffering
// the archive (see checksums.go / verify.go). A distribution filename encodes its
// name and version, so a tarball is immutable and content-addressable; the module
// indices and the CHECKSUMS file itself are mutable and revalidated live.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource kinds
// and derives the distribution coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a CPAN mirror path can address.
type resourceKind int

const (
	// kindIndex is a mutable discovery document served live: a modules/ index, a
	// per-author CHECKSUMS file, or a distribution's sidecar .meta/.readme. None
	// are cached immutably (CHECKSUMS and the module indices are regenerated, and
	// the sidecars are small and revalidated with their distribution).
	kindIndex resourceKind = iota
	// kindDistribution is a distribution archive (.tar.gz / .tgz / .zip / .tar.bz2
	// / .tar.xz) pinned by name and version in the author tree. Immutable,
	// cacheable, and verified against the sibling CHECKSUMS file's SHA-256.
	kindDistribution
)

// checksumsFile is the per-author-directory integrity record the backend
// consults to verify a distribution download.
const checksumsFile = "CHECKSUMS"

// distExtensions are the archive suffixes a CPAN distribution tarball can carry.
// Ordered longest-first so a filename is matched against the most specific suffix.
var distExtensions = []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"}

// resource is the parsed classification of an inbound CPAN mirror request.
type resource struct {
	kind resourceKind
	// filename is the final path component (the index/CHECKSUMS name or the
	// distribution file).
	filename string
	// name/version form the distribution coordinate for a kindDistribution
	// resource. version may be empty for a nonstandard filename that still carries
	// a recognized archive extension; verification keys on the filename, not the
	// coordinate, so such a file is still verified against CHECKSUMS.
	name    string
	version string
	// masterIndex marks a file that sits directly in the modules/ directory
	// ("modules/<file>"), where a mirror keeps its master indices.
	masterIndex bool
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the CPAN mirror layout, so an unrecognized request is reported
// as unsupported rather than blindly proxied. Only paths under the "authors/" and
// "modules/" areas are accepted.
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
	top := segs[0]
	if top != "authors" && top != "modules" {
		return resource{}, false
	}
	filename := segs[len(segs)-1]

	// A distribution archive in the author tree is the only cacheable, verifiable
	// resource. Everything else (module indices, CHECKSUMS, sidecar .meta/.readme)
	// is a live index document.
	if top == "authors" && filename != checksumsFile {
		if name, version, ok := parseDistFilename(filename); ok {
			return resource{kind: kindDistribution, filename: filename, name: name, version: version}, true
		}
	}
	return resource{kind: kindIndex, filename: filename, masterIndex: top == "modules" && len(segs) == 2}, true
}

// parseDistFilename decodes a CPAN distribution filename into its coordinate. A
// distribution is "<Name>-<Version>" followed by an archive extension, where the
// name itself may contain hyphens (e.g. "Acme-CPANAuthors-Canadian-0.0108.tar.gz"
// is name "Acme-CPANAuthors-Canadian", version "0.0108"). The version boundary is
// the last hyphen whose following character begins a version token — a digit, or a
// leading "v" before a digit (e.g. "Foo-v1.2.3.tar.gz"). It returns ok=false when
// the filename carries no recognized archive extension.
func parseDistFilename(name string) (dist, version string, ok bool) {
	base, hasExt := trimDistExtension(name)
	if !hasExt {
		return "", "", false
	}
	i := versionBoundary(base)
	if i <= 0 || i >= len(base)-1 {
		// A recognized archive with no parseable version boundary (e.g.
		// "Foo-Bar.tar.gz"): still a distribution, verified by filename, but with no
		// coordinate the gates can key on.
		return "", "", true
	}
	return base[:i], base[i+1:], true
}

// trimDistExtension strips a recognized distribution archive extension from name,
// returning the stem and whether an extension was found.
func trimDistExtension(name string) (stem string, ok bool) {
	for _, ext := range distExtensions {
		if strings.HasSuffix(name, ext) {
			return name[:len(name)-len(ext)], true
		}
	}
	return name, false
}

// versionBoundary returns the index of the hyphen that separates the distribution
// name from its version in base (the filename with its archive extension removed),
// or -1 if none is found. It scans from the right for the last hyphen followed by a
// version token.
func versionBoundary(base string) int {
	for i := len(base) - 1; i > 0; i-- {
		if base[i] != '-' {
			continue
		}
		if startsVersionToken(base[i+1:]) {
			return i
		}
	}
	return -1
}

// startsVersionToken reports whether s begins a CPAN version token: a digit, or a
// leading "v" immediately followed by a digit.
func startsVersionToken(s string) bool {
	if s == "" {
		return false
	}
	if isDigit(s[0]) {
		return true
	}
	if (s[0] == 'v' || s[0] == 'V') && len(s) > 1 && isDigit(s[1]) {
		return true
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// cacheable reports whether the resource may be cached. Only distribution
// archives are immutable (their filename pins the version); the module indices,
// CHECKSUMS, and sidecar documents are mutable and revalidated live.
func (r resource) cacheable() bool {
	return r.kind == kindDistribution
}

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A distribution archive is what a CPAN client
// unpacks, builds and installs, running its Makefile.PL or Build.PL: the
// payload.
//
// kindIndex is not one class. classify gives it to every accepted path that is
// not a recognized distribution in the author tree, so of those only the ones
// the mirror layout positively identifies as documents are called metadata:
//
//   - a CHECKSUMS file, and a distribution's .meta and .readme sidecars, by
//     name, wherever they are served from;
//   - a file directly in modules/, where a mirror keeps its master indices
//     (02packages.details.txt.gz, 03modlist.data.gz, 06perms.txt.gz).
//
// Everything else is left unclassified, for a gate to judge from the bytes:
//
//   - any other file in the author tree. An author directory holds whatever
//     its owner uploaded, including archives in a format distExtensions does
//     not list (.tar, .tar.Z, a gzipped single module);
//   - anything deeper under modules/. The by-module/, by-category/ and
//     by-authors/ trees there are views of the author directories and serve
//     the very same distribution archives, which classify recognizes only
//     under authors/.
//
// A name parseDistFilename accepts is never called metadata, whatever
// directory it is in.
func (r resource) artifact() backends.Artifact {
	if r.kind == kindDistribution {
		return backends.Payload()
	}
	if _, _, isDist := parseDistFilename(r.filename); isDist {
		return backends.Artifact{}
	}
	if r.masterIndex || r.filename == checksumsFile ||
		strings.HasSuffix(r.filename, ".meta") || strings.HasSuffix(r.filename, ".readme") {
		return backends.Metadata()
	}
	return backends.Artifact{}
}

// verifiableFile reports whether the resource is a distribution the backend
// should verify against the sibling CHECKSUMS file.
func (r resource) verifiableFile() bool {
	return r.kind == kindDistribution
}

// coordinateName returns the distribution name used to address the artifact in
// the admission gates. Empty for index documents and for distributions whose
// filename did not parse into a coordinate.
func (r resource) coordinateName() string {
	return r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindIndex:
		return "index"
	case kindDistribution:
		return "distribution"
	default:
		return "other"
	}
}
