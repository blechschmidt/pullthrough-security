package yum

import (
	"path"
	"strings"
)

// An RPM/YUM/DNF repository (the layout served by Fedora, RHEL/CentOS, openSUSE,
// Amazon Linux, and any createrepo_c/Artifactory/Nexus mirror) addresses three
// families of resource off the repository root (the route prefix "/v1/<name>" is
// stripped before classification):
//
//	Repository metadata index (the trust anchor, mutable, revalidated, parsed):
//	  GET /repodata/repomd.xml              the metadata manifest
//	  GET /repodata/repomd.xml.asc          detached PGP signature over repomd.xml
//	  GET /repodata/repomd.xml.key          repository signing public key
//
//	Repository metadata files (mutable, revalidated; checksum-verified against
//	repomd.xml; primary.xml is parsed to recover per-.rpm digests):
//	  GET /repodata/<hash>-primary.xml.gz   the package list + digests
//	  GET /repodata/<hash>-filelists.xml.gz, -other.xml.gz, ...
//
//	Packages (immutable, cached, checksum-verified against the digest primary.xml
//	declared):
//	  GET /Packages/<name>-<ver>-<rel>.<arch>.rpm  (also served flat at the root)
//
// Classification derives the coordinate (package name + version) from the .rpm
// basename so it can feed nameguard, the vulnerability/license/signature gates,
// provenance, and the risk engine; it records the repo-root-relative locator so
// the backend can match it against repomd/primary entries; and it decides
// cacheability (only the immutable .rpm packages are cached).

// resourceKind enumerates the classes of resource a YUM repository path can
// address.
type resourceKind int

const (
	// kindRpm is a package: immutable, cached, and verified against the digest
	// primary.xml declared.
	kindRpm resourceKind = iota
	// kindRepomd is repodata/repomd.xml: the trust anchor, revalidated live and
	// GPG-verified when a trusted keyring is configured.
	kindRepomd
	// kindRepomdSig is the detached repomd.xml.asc signature or the .key file,
	// served as-is.
	kindRepomdSig
	// kindRepodata is any other repodata/ metadata file (primary/filelists/other):
	// mutable, verified against repomd.xml, and (for primary) parsed.
	kindRepodata
	// kindOther is any path outside the recognized layout (served live, uncached).
	kindOther
)

// resource is the parsed classification of an inbound YUM request path.
type resource struct {
	kind resourceKind
	// rpmPath is the repository-root-relative path of an .rpm (e.g.
	// "Packages/foo-1.0-1.x86_64.rpm"); it matches the location href of the
	// primary.xml entry that declares the digest. Set for kindRpm.
	rpmPath string
	// repodataPath is the repository-root-relative path of a repodata file (e.g.
	// "repodata/abc-primary.xml.gz"); it matches the location href in repomd.xml.
	// Set for kindRepodata.
	repodataPath string
	// name and version are the parsed package coordinate, for kindRpm.
	name    string
	version string
}

const (
	repomdPath = "repodata/repomd.xml"
	rpmExt     = ".rpm"
)

// classify parses an inbound path (route prefix already stripped, leading slash
// retained) into a resource. It returns ok=false for paths that contain a
// traversal segment; any other path is classified (unknown shapes become
// kindOther and are served live).
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

	// Package: any .rpm artifact, wherever it is served.
	if strings.HasSuffix(last, rpmExt) {
		name, version := splitRPMFilename(last)
		return resource{kind: kindRpm, rpmPath: clean, name: name, version: version}, true
	}

	// Repository metadata lives under repodata/.
	if segs[0] == "repodata" {
		switch {
		case clean == repomdPath:
			return resource{kind: kindRepomd}, true
		case last == "repomd.xml.asc" || last == "repomd.xml.key":
			return resource{kind: kindRepomdSig}, true
		default:
			return resource{kind: kindRepodata, repodataPath: clean}, true
		}
	}

	return resource{kind: kindOther}, true
}

// splitRPMFilename derives the package name and version from an RPM basename of
// the canonical NEVRA form "<name>-<version>-<release>.<arch>.rpm". RPM names may
// contain hyphens, so the split takes the version and release as the last two
// hyphen-separated tokens of the name-version-release portion (after stripping
// the ".<arch>.rpm" suffix). It is a coordinate hint only — the SHA-256
// verification is keyed off the full repo-relative path — so a non-canonical name
// simply yields an empty version.
func splitRPMFilename(filename string) (name, version string) {
	base := strings.TrimSuffix(path.Base(filename), rpmExt)
	// Strip the trailing ".<arch>".
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	// base is now "name-version-release"; release is after the last '-', version
	// before it, name is the remainder.
	relDash := strings.LastIndexByte(base, '-')
	if relDash <= 0 {
		return base, ""
	}
	verDash := strings.LastIndexByte(base[:relDash], '-')
	if verDash <= 0 {
		return base[:relDash], ""
	}
	name = base[:verDash]
	version = base[verDash+1 : relDash]
	return name, version
}

// coordinateName returns the package name as the coordinate for the admission
// gates (only meaningful for .rpm artifacts).
func (r resource) coordinateName() string { return r.name }

// verifiableArtifact reports whether the resource is an .rpm whose content the
// backend should checksum-verify against the primary-declared digest.
func (r resource) verifiableArtifact() bool { return r.kind == kindRpm }

// cacheable reports whether the resource may be cached. Only the immutable .rpm
// packages are cached; every repodata document is mutable and revalidated live.
func (r resource) cacheable() bool { return r.kind == kindRpm }

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindRpm:
		return "rpm"
	case kindRepomd:
		return "repomd"
	case kindRepomdSig:
		return "repomd-sig"
	case kindRepodata:
		return "repodata"
	default:
		return "other"
	}
}
