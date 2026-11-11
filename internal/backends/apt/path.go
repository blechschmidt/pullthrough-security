package apt

import (
	"path"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// A Debian/Ubuntu APT repository (the "dists" layout served by deb.debian.org,
// archive.ubuntu.com, and any reprepro/aptly/Artifactory mirror) addresses four
// families of resource off the repository root (the route prefix "/v1/<name>" is
// stripped before classification):
//
//	Release index (the signed trust anchor, mutable, revalidated, parsed):
//	  GET /dists/<suite>/InRelease         inline-clearsigned Release
//	  GET /dists/<suite>/Release           Release document
//	  GET /dists/<suite>/Release.gpg       detached PGP signature over Release
//
//	Package indices (mutable, revalidated; SHA-256-verified against Release and
//	parsed to recover the per-.deb SHA-256 digests):
//	  GET /dists/<suite>/<comp>/binary-<arch>/Packages[.gz|.xz|.bz2]
//
//	Other index metadata (mutable, served live, not verified/parsed):
//	  GET /dists/<suite>/<comp>/source/Sources[.gz]
//	  GET /dists/<suite>/<comp>/i18n/Translation-*
//	  GET /dists/<suite>/<comp>/Contents-*  and by-hash/ variants
//
//	Pool artifacts (immutable, cached, SHA-256-verified against the digest the
//	parsed Packages index declared):
//	  GET /pool/<comp>/<l>/<src>/<pkg>_<ver>_<arch>.deb (also .udeb/.ddeb)
//
// Classification derives the coordinate (package name + version) from the .deb
// basename so it can feed nameguard, the vulnerability/license/signature gates,
// provenance, and the risk engine; it records the suite-relative locator of a
// Packages index so the backend can recover its expected digest from Release; and
// it decides cacheability (only the immutable pool artifacts are cached).

// resourceKind enumerates the classes of resource an APT repository path can
// address.
type resourceKind int

const (
	// kindDeb is a binary package in the pool: immutable, cached, and verified
	// against the SHA-256 the Packages index declared.
	kindDeb resourceKind = iota
	// kindInRelease is the inline-clearsigned Release document: the trust anchor,
	// revalidated live, GPG-verified when a trusted keyring is configured.
	kindInRelease
	// kindRelease is the (unsigned-body) Release document, accompanied by a
	// detached Release.gpg signature.
	kindRelease
	// kindReleaseSig is the detached Release.gpg signature, served as-is.
	kindReleaseSig
	// kindPackages is a binary Packages index (optionally compressed): mutable,
	// SHA-256-verified against Release, and parsed to recover per-.deb digests.
	kindPackages
	// kindMeta is any other index document under dists/ (Sources, Contents,
	// Translation, by-hash): mutable, served live, neither verified nor parsed.
	kindMeta
	// kindOther is any path outside the recognized layout (served live, uncached).
	kindOther
)

// resource is the parsed classification of an inbound APT request path.
type resource struct {
	kind resourceKind
	// suite is the distribution suite segment (e.g. "bookworm"), for Release-anchored
	// resources. Empty otherwise.
	suite string
	// distRelPath is the locator of a Packages index relative to its
	// "/dists/<suite>/" root (e.g. "main/binary-amd64/Packages.gz"); it is the key
	// under which Release publishes the index's SHA-256. Set for kindPackages.
	distRelPath string
	// poolPath is the repository-root-relative path of a .deb (e.g.
	// "pool/main/f/foo/foo_1.0_amd64.deb"); it matches the Filename field of the
	// Packages stanza that declares the digest. Set for kindDeb.
	poolPath string
	// name and version are the parsed package coordinate, for kindDeb.
	name    string
	version string
	// index marks a kindMeta path as a document the repository format itself
	// names (see indexDocument). kindMeta is everything else under
	// "dists/<suite>/", and real archives keep more than index documents there.
	index bool
	// iconSet marks the one index document that is a tar archive: an AppStream
	// icon set (see iconSetDocument).
	iconSet bool
}

// debExts are the binary-package extensions APT serves out of the pool.
var debExts = []string{".deb", ".udeb", ".ddeb"}

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that cannot be
// expressed in the APT repository layout or that contain a traversal segment.
func classify(p string) (resource, bool) {
	clean := strings.Trim(p, "/")
	if clean == "" {
		return resource{}, false
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		// Reject empty segments and any path traversal; the upstream URL is built
		// from the cleaned path, so every segment must be inert.
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	last := segs[len(segs)-1]

	// Pool artifacts: a binary package anywhere under the layout (canonically
	// /pool/...). Classified by extension so udeb/ddeb are covered.
	if ext, ok := debExtension(last); ok {
		name, version := splitDebFilename(last, ext)
		return resource{
			kind:     kindDeb,
			poolPath: clean,
			name:     name,
			version:  version,
		}, true
	}

	// Everything else of interest lives under dists/<suite>/.
	if segs[0] == "dists" && len(segs) >= 2 {
		suite := segs[1]
		switch {
		case len(segs) == 3 && last == "InRelease":
			return resource{kind: kindInRelease, suite: suite}, true
		case len(segs) == 3 && last == "Release":
			return resource{kind: kindRelease, suite: suite}, true
		case len(segs) == 3 && last == "Release.gpg":
			return resource{kind: kindReleaseSig, suite: suite}, true
		}
		if isPackagesIndex(last) {
			return resource{
				kind:        kindPackages,
				suite:       suite,
				distRelPath: strings.Join(segs[2:], "/"),
			}, true
		}
		// Any other dists/ document (Sources, Contents-*, Translation-*, by-hash/...).
		return resource{kind: kindMeta, suite: suite, index: indexDocument(segs[2:]), iconSet: iconSetDocument(segs[2:])}, true
	}

	return resource{kind: kindOther}, true
}

// debExtension reports the binary-package extension of a filename, if any.
func debExtension(filename string) (string, bool) {
	for _, ext := range debExts {
		if strings.HasSuffix(filename, ext) {
			return ext, true
		}
	}
	return "", false
}

// isPackagesIndex reports whether a filename is a binary Packages index in any of
// the compression encodings APT publishes (plain, gzip, xz, bzip2, lz4).
func isPackagesIndex(filename string) bool {
	switch filename {
	case "Packages", "Packages.gz", "Packages.xz", "Packages.bz2", "Packages.lz4":
		return true
	default:
		return false
	}
}

// indexCompressions are the encodings a repository publishes an index file in.
var indexCompressions = []string{".gz", ".bz2", ".xz", ".lzma", ".lz4", ".zst"}

// indexDocument reports whether rel — a path below "dists/<suite>/" that
// classify gives no kind of its own — is a document the repository format
// defines: something APT reads to learn what the repository offers.
//
// It exists because "dists/<suite>/" is not an index-only tree. Archives keep
// content there that a machine boots, unpacks or runs: Debian and Ubuntu publish
// their installer images under "<comp>/installer-<arch>/", and Ubuntu its
// release upgrader ("<comp>/dist-upgrader-all/current/<suite>.tar.gz", which
// do-release-upgrade unpacks and executes) and signed boot loaders
// ("<comp>/signed/", "<comp>/uefi/"). So a path counts as an index document only
// when its name is one the format assigns, never because of where it sits:
//
//	InRelease, Release, Release.gpg   the copies kept per component and architecture
//	Packages, Sources                 package indices
//	Contents-<arch>                   file lists
//	i18n/Translation-<lang>           package descriptions (and the legacy i18n/Index)
//	dep11/Components-<arch>.yml       the AppStream catalogue,
//	dep11/CID-Index-<arch>.json       its component index
//	dep11/icons-<size>.tar            and its icon sets (archives, of images a client displays)
//	cnf/Commands-<arch>               the command-not-found index
//
// each plain or in one of indexCompressions; the diffs of such an index
// ("<index>.diff/Index" and the patches beside it); and an index file addressed
// by its digest ("by-hash/<Hash>/<hex digest>").
func indexDocument(rel []string) bool {
	n := len(rel)
	if n == 0 {
		return false
	}
	name, dir, parent := rel[n-1], "", ""
	if n >= 2 {
		dir = rel[n-2]
	}
	if n >= 3 {
		parent = rel[n-3]
	}
	switch {
	case parent == "by-hash":
		return byHashName(dir, name)
	case strings.HasSuffix(dir, ".diff"):
		return indexName(parent, strings.TrimSuffix(dir, ".diff"))
	case name == "InRelease", name == "Release", name == "Release.gpg":
		return true
	}
	for _, ext := range indexCompressions {
		if stem, ok := strings.CutSuffix(name, ext); ok {
			return indexName(dir, stem)
		}
	}
	return indexName(dir, name)
}

// indexName reports whether name (uncompressed) is an index file of the
// repository format, given the directory it is published in.
func indexName(dir, name string) bool {
	if name == "Packages" || name == "Sources" || tokenAfter(name, "Contents-") {
		return true
	}
	switch dir {
	case "i18n":
		return name == "Index" || tokenAfter(name, "Translation-")
	case "dep11":
		for _, f := range []struct{ prefix, suffix string }{
			{"Components-", ".yml"}, {"CID-Index-", ".json"}, {"icons-", ".tar"},
		} {
			if stem, ok := strings.CutSuffix(name, f.suffix); ok && tokenAfter(stem, f.prefix) {
				return true
			}
		}
	case "cnf":
		return tokenAfter(name, "Commands-")
	}
	return false
}

// tokenAfter reports whether name is prefix followed by a single token — an
// architecture, a language code, an icon size — none of which contains a dot.
func tokenAfter(name, prefix string) bool {
	token, ok := strings.CutPrefix(name, prefix)
	return ok && token != "" && !strings.Contains(token, ".")
}

// byHashName reports whether hash/digest names an index file by its digest: one
// of the hash fields a Release file declares, followed by a hex digest of that
// hash's length.
func byHashName(hash, digest string) bool {
	var hexLen int
	switch hash {
	case "MD5Sum":
		hexLen = 32
	case "SHA1":
		hexLen = 40
	case "SHA256":
		hexLen = sha256HexLen
	case "SHA512":
		hexLen = 128
	default:
		return false
	}
	return len(digest) == hexLen && isHex(digest)
}

// splitDebFilename derives the package name and version from a .deb basename of
// the canonical form "<name>_<version>_<arch>.deb". It is a coordinate hint only
// (the SHA-256 verification is keyed off the full pool path, which is
// unambiguous), so a non-canonical name simply yields an empty version.
func splitDebFilename(filename, ext string) (name, version string) {
	base := strings.TrimSuffix(path.Base(filename), ext)
	// "<name>_<version>_<arch>"
	first := strings.IndexByte(base, '_')
	if first < 0 {
		return base, ""
	}
	name = base[:first]
	rest := base[first+1:]
	if second := strings.IndexByte(rest, '_'); second >= 0 {
		version = rest[:second]
	} else {
		version = rest
	}
	return name, version
}

// coordinateName returns the package name as the coordinate for the admission
// gates (only meaningful for pool artifacts).
func (r resource) coordinateName() string { return r.name }

// verifiableArtifact reports whether the resource is a .deb whose content the
// backend should checksum-verify against the Packages-declared digest.
func (r resource) verifiableArtifact() bool { return r.kind == kindDeb }

// cacheable reports whether the resource may be cached. Only the immutable pool
// artifacts are cached; every dists/ index is mutable and revalidated live.
func (r resource) cacheable() bool { return r.kind == kindDeb }

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass). A binary package is what dpkg unpacks and whose
// maintainer scripts it runs: the payload. The Release documents, their
// signature and the indices are what APT reads to decide what to fetch.
//
// Everything else is left unclassified, for a gate to judge from the bytes: a
// path outside the layout (kindOther) — which is where a source package's .dsc
// and tarballs are served from — and a path under "dists/<suite>/" that the
// repository format does not name (kindMeta without index). The latter is not
// called metadata, because archives keep installable content there as well; see
// indexDocument.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindDeb:
		return backends.Payload()
	case kindInRelease, kindRelease, kindReleaseSig, kindPackages:
		return backends.Metadata()
	case kindMeta:
		switch {
		case r.index && r.iconSet:
			// An AppStream icon set is a tarball of images: an index that is an
			// archive.
			return backends.MetadataArchive()
		case r.index:
			return backends.Metadata()
		}
	}
	return backends.Artifact{}
}

// iconSetDocument reports whether rel — a path below "dists/<suite>/" — is an
// AppStream icon set ("dep11/icons-<size>.tar", plain or compressed): the one
// index document of the format that is a tar archive.
func iconSetDocument(rel []string) bool {
	n := len(rel)
	if n < 2 || rel[n-2] != "dep11" {
		return false
	}
	name := rel[n-1]
	for _, ext := range indexCompressions {
		if stem, ok := strings.CutSuffix(name, ext); ok {
			name = stem
			break
		}
	}
	stem, ok := strings.CutSuffix(name, ".tar")
	return ok && tokenAfter(stem, "icons-")
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindDeb:
		return "deb"
	case kindInRelease:
		return "inrelease"
	case kindRelease:
		return "release"
	case kindReleaseSig:
		return "release-sig"
	case kindPackages:
		return "packages"
	case kindMeta:
		return "meta"
	default:
		return "other"
	}
}
