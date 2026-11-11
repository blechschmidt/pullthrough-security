package swift

import (
	"regexp"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// The Swift Package Registry speaks a small REST API (SE-0292 / the reference
// "Swift Package Registry Service" specification) that addresses a package by a
// scope and a name and, for a concrete release, by a semantic version. Every
// endpoint lives directly beneath the registry base (there is no "/v1" style
// prefix on the wire — the proxy mounts the registry under its own
// "/v1/<name>/" route, which the gateway strips before classify sees the path):
//
//	GET /{scope}/{name}                       list package releases (mutable)
//	GET /{scope}/{name}/{version}             fetch release metadata (immutable)
//	GET /{scope}/{name}/{version}/Package.swift   fetch package manifest (immutable)
//	GET /{scope}/{name}/{version}.zip         download source archive (immutable, verified)
//	GET /identifiers?url={url}                look up package identifiers by SCM URL (mutable)
//
// A published release is immutable: its metadata, manifest, and source archive
// never change for a given {scope}/{name}/{version}, so anything addressed
// beneath a concrete version is content-addressable and cached indefinitely.
// The release list and the identifier lookup are mutable discovery endpoints and
// are revalidated rather than cached.
//
// The source archive's integrity is guaranteed by a SHA-256 "checksum" the
// release metadata records for its "source-archive" resource (and echoed in the
// download's "Digest: sha-256=..." header). On a cache miss the backend fetches
// the release metadata, reads that checksum, and verifies the fetched archive
// against it before the bytes are cached or served (see checksum.go /
// metadata.go) — so a tampered or corrupt mirror can neither poison the cache
// nor reach a client.
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a Swift registry path can
// address.
type resourceKind int

const (
	// kindReleases is the list-releases endpoint "/{scope}/{name}" (mutable).
	kindReleases resourceKind = iota
	// kindRelease is a release metadata document "/{scope}/{name}/{version}"
	// (immutable, cached).
	kindRelease
	// kindManifest is a package manifest "/{scope}/{name}/{version}/Package.swift"
	// (or a tools-version-specific "Package@swift-X.Y.swift"); immutable, cached.
	kindManifest
	// kindArchive is a source archive "/{scope}/{name}/{version}.zip" (immutable,
	// cached, checksum-verified against the release metadata).
	kindArchive
	// kindIdentifiers is the "/identifiers?url=" SCM-URL lookup (mutable).
	kindIdentifiers
)

// archiveExt is the source-archive suffix the registry serves beneath a version.
const archiveExt = ".zip"

// manifestFile is the canonical package manifest filename.
const manifestFile = "Package.swift"

// resource is the parsed classification of an inbound Swift registry path.
type resource struct {
	kind resourceKind
	// scope and name form the package identity "scope.name".
	scope string
	name  string
	// version is the release version when the path pins one.
	version string
	// manifestName is the requested manifest filename (Package.swift or a
	// Package@swift-X.Y.swift variant) for a manifest resource.
	manifestName string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that cannot be expressed in the Swift registry layout, so an unrecognized
// request is reported as unsupported rather than blindly proxied.
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

	// Identifier lookup: a single "identifiers" segment (the ?url= query carries
	// the lookup target and is preserved separately).
	if len(segs) == 1 && segs[0] == "identifiers" {
		return resource{kind: kindIdentifiers}, true
	}

	// Every other endpoint is addressed beneath a scope and a name.
	if len(segs) < 2 {
		return resource{}, false
	}
	r := resource{scope: segs[0], name: segs[1]}
	if !validScope(r.scope) || !validName(r.name) {
		return resource{}, false
	}
	rest := segs[2:]

	switch len(rest) {
	case 0:
		// /{scope}/{name} → release list.
		r.kind = kindReleases
		return r, true
	case 1:
		// /{scope}/{name}/{version}      → release metadata
		// /{scope}/{name}/{version}.zip  → source archive
		if v, ok := strings.CutSuffix(rest[0], archiveExt); ok {
			if v == "" {
				return resource{}, false
			}
			r.kind = kindArchive
			r.version = v
			return r, true
		}
		r.kind = kindRelease
		r.version = rest[0]
		return r, true
	case 2:
		// /{scope}/{name}/{version}/Package.swift (or Package@swift-X.Y.swift).
		if isManifestFile(rest[1]) {
			r.kind = kindManifest
			r.version = rest[0]
			r.manifestName = rest[1]
			return r, true
		}
	}
	return resource{}, false
}

// isManifestFile reports whether a filename is a Swift package manifest — the
// canonical Package.swift or a tools-version-specific Package@swift-X.Y.swift
// variant the registry advertises for version-specific manifests.
func isManifestFile(name string) bool {
	if name == manifestFile {
		return true
	}
	return strings.HasPrefix(name, "Package@swift-") && strings.HasSuffix(name, ".swift")
}

// coordinateName returns the package identity "scope.name" used to address the
// artifact in the admission gates (nameguard, vulnscan, provenance). The Swift
// registry identifies a package by the reverse-DNS-style "scope.name" pair.
func (r resource) coordinateName() string {
	if r.scope == "" || r.name == "" {
		return ""
	}
	return r.scope + "." + r.name
}

// isArchive reports whether the resource is a source-archive download.
func (r resource) isArchive() bool { return r.kind == kindArchive }

// artifact classifies the resource for the content gates (see
// backends.ArtifactClass).
//
// The source archive is what SwiftPM unpacks and builds. A package manifest is a
// payload as well, although it is a single small file: Package.swift is a Swift
// program, and SwiftPM compiles and runs it during dependency resolution, before
// it downloads the archive. The release list and the identifier lookup are JSON
// documents a client only reads.
//
// So is the release-metadata document, but only where the path really names
// one. classify takes every third segment that does not end in ".zip" for a
// version, so "1.1.1.ZIP" and "1.1.1.zip;a=b" arrive here as releases, and a
// registry that matches paths without regard to case, or one that strips
// ";name=value" path parameters, can answer them with the archive. Only a
// segment that is positively a version is called metadata (see
// isReleaseVersion); any other is left unclassified, and a gate judges the
// response from its content.
func (r resource) artifact() backends.Artifact {
	switch r.kind {
	case kindArchive:
		return backends.Payload()
	case kindManifest:
		// Package.swift is one Swift source file, compiled and run by SwiftPM.
		return backends.PayloadFile()
	case kindReleases, kindIdentifiers:
		return backends.Metadata()
	case kindRelease:
		if isReleaseVersion(r.version) {
			return backends.Metadata()
		}
	}
	return backends.Artifact{}
}

// semverPattern matches a semantic version: three numeric components, then
// optional pre-release and build identifiers. It is the only form a release
// version takes in the registry protocol.
var semverPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

// isReleaseVersion reports whether the {version} segment of a release-metadata
// path is positively a version: a semantic version, optionally followed by the
// ".json" extension the protocol lets a client append. A pre-release identifier
// may itself spell "zip" ("1.0.0-rc.ZIP" is a well-formed version), so a segment
// that ends in the archive suffix in any letter case is not accepted either.
func isReleaseVersion(segment string) bool {
	version := strings.TrimSuffix(segment, ".json")
	if strings.HasSuffix(strings.ToLower(version), archiveExt) {
		return false
	}
	return semverPattern.MatchString(version)
}

// cacheable reports whether the resource may be cached. Only resources pinned
// beneath a concrete release version are immutable and cacheable; the release
// list and the identifier lookup are mutable discovery endpoints and are
// revalidated live.
func (r resource) cacheable() bool {
	switch r.kind {
	case kindRelease, kindManifest, kindArchive:
		return true
	default:
		return false
	}
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindReleases:
		return "releases"
	case kindRelease:
		return "release"
	case kindManifest:
		return "manifest"
	case kindArchive:
		return "archive"
	case kindIdentifiers:
		return "identifiers"
	default:
		return "other"
	}
}

// validScope reports whether s is a syntactically valid package scope:
// alphanumerics and single interior hyphens, at most 39 characters. Enforced so
// a malformed scope is rejected as unsupported rather than concatenated into an
// upstream URL.
func validScope(s string) bool {
	if s == "" || len(s) > 39 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-':
			// A hyphen may not lead, trail, or repeat.
			if i == 0 || i == len(s)-1 || s[i-1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validName reports whether s is a syntactically valid package name:
// alphanumerics and single interior hyphens or underscores, at most 100
// characters.
func validName(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_':
			if i == 0 || i == len(s)-1 {
				return false
			}
			if prev := s[i-1]; prev == '-' || prev == '_' {
				return false
			}
		default:
			return false
		}
	}
	return true
}
