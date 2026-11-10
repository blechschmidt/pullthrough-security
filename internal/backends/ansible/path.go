package ansible

import "strings"

// Ansible Galaxy (galaxy.ansible.com) exposes a v3 REST API. A collection is
// addressed by a namespace and a name (its fully-qualified name is
// "namespace.name"), and published collection artifacts are distributed as
// content-addressable ".tar.gz" tarballs. The proxy mounts the registry at its
// route root ("<publicBase>/v1/<name>") and honors the Galaxy v3 layout:
//
//	GET  /api/v3/plugin/ansible/content/<repo>/collections/index/<ns>/<name>/
//	GET  /api/v3/plugin/ansible/content/<repo>/collections/index/<ns>/<name>/versions/
//	GET  /api/v3/plugin/ansible/content/<repo>/collections/index/<ns>/<name>/versions/<version>/
//	GET  /api/v3/plugin/ansible/content/<repo>/collections/artifacts/<ns>-<name>-<version>.tar.gz
//	GET  /api/v3/collections/<ns>/<name>/...                      (short alias; Galaxy redirects it to the index path)
//	GET  /api/v1/roles/...                                        (legacy role metadata)
//
// The index/versions/version-detail documents are metadata: they are served
// live (revalidated per request, never cached) with every link they carry into
// the registry — the root-relative pagination and cross-reference links as well
// as absolute upstream URLs, notably a version detail's "download_url" —
// rewritten onto the proxy's mount (see rewrite.go). A collection artifact
// tarball pins its namespace/name/version in its filename, so it is immutable
// and content-addressable; on a cache miss the backend fetches the sibling
// version-detail document, reads the artifact's published SHA-256, and verifies
// the fetched bytes against it before they are cached or served (see
// metadata.go / checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into a resource kind and
// derives the collection coordinate, which feeds the admission gates (nameguard,
// policy, provenance, vulnscan, license, policyengine) and the cacheability
// decision.

// resourceKind enumerates the classes of resource a Galaxy path can address.
type resourceKind int

const (
	// kindMetadata is any Galaxy API document (collection index, versions list,
	// version detail, role metadata, search). Served live and URL-rewritten; the
	// version-detail document is additionally the digest source the backend
	// verifies collection artifacts against.
	kindMetadata resourceKind = iota
	// kindArtifact is a published collection artifact tarball
	// (<ns>-<name>-<version>.tar.gz under a ".../collections/artifacts/" path).
	// Immutable, cacheable, verified against the sibling version-detail SHA-256.
	kindArtifact
)

// artifactSuffix is the suffix of a published collection artifact tarball.
const artifactSuffix = ".tar.gz"

// resource is the parsed classification of an inbound Galaxy request.
type resource struct {
	kind resourceKind
	// namespace and name form the collection coordinate. Set for kindArtifact
	// (parsed from the filename) and, best-effort, for an index metadata path.
	namespace string
	name      string
	// version is the collection version. Set for kindArtifact and, best-effort,
	// for a version-detail metadata path.
	version string
	// indexBase is the upstream path (leading slash, no trailing slash) ending in
	// ".../collections", from which the sibling version-detail document URL is
	// built for an artifact digest lookup. Set for kindArtifact.
	indexBase string
}

// classify parses an inbound path into a resource. A path that does not fit the
// Galaxy layout is still treated as live metadata (fail-open passthrough with
// URL rewriting), mirroring how the registry serves many ancillary endpoints; a
// malformed path (empty segment or traversal) is rejected. Only a well-formed
// collection-artifact path is classified as a cacheable, verified artifact.
func classify(path string) (resource, bool) {
	clean := strings.Trim(path, "/")
	if clean == "" {
		return resource{kind: kindMetadata}, true
	}
	segs := strings.Split(clean, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return resource{}, false
		}
	}

	// A collection artifact lives at ".../collections/artifacts/<file>.tar.gz".
	if i := artifactsIndex(segs); i >= 0 {
		file := segs[len(segs)-1]
		ns, name, version, ok := parseArtifactFile(file)
		if !ok {
			// A file under artifacts/ we cannot decompose is served live rather than
			// cached unverified.
			return resource{kind: kindMetadata}, true
		}
		indexBase := "/" + strings.Join(segs[:i+1], "/") // ".../collections"
		return resource{
			kind:      kindArtifact,
			namespace: ns,
			name:      name,
			version:   version,
			indexBase: indexBase,
		}, true
	}

	// Best-effort coordinate extraction from a collection index path:
	// ".../collections/index/<ns>/<name>[/versions[/<version>]]".
	res := resource{kind: kindMetadata}
	if j := indexSegment(segs); j >= 0 && len(segs) > j+2 {
		res.namespace = segs[j+1]
		res.name = segs[j+2]
		if len(segs) > j+4 && segs[j+3] == "versions" {
			res.version = segs[j+4]
		}
	}
	return res, true
}

// artifactsIndex returns the index i of the "collections" segment in a
// ".../collections/artifacts/<file>" path (so segs[i]=="collections",
// segs[i+1]=="artifacts", and the file is the final segment with a .tar.gz
// suffix), or -1 when the path is not a collection-artifact path.
func artifactsIndex(segs []string) int {
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] == "collections" && segs[i+1] == "artifacts" && i+2 == len(segs)-1 {
			if strings.HasSuffix(segs[i+2], artifactSuffix) {
				return i
			}
		}
	}
	return -1
}

// indexSegment returns the index of a "collections"/"index" pair's "index"
// segment, or -1.
func indexSegment(segs []string) int {
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "collections" && segs[i+1] == "index" {
			return i + 1
		}
	}
	return -1
}

// parseArtifactFile decomposes a collection artifact filename
// "<namespace>-<name>-<version>.tar.gz" into its parts. Ansible restricts
// namespace and name to lowercase ASCII letters, digits, and underscores (never
// a hyphen), so splitting on the first two hyphens is unambiguous even when the
// semver version carries a prerelease hyphen (e.g. "1.0.0-rc1").
func parseArtifactFile(file string) (namespace, name, version string, ok bool) {
	base := strings.TrimSuffix(file, artifactSuffix)
	if base == file {
		return "", "", "", false
	}
	parts := strings.SplitN(base, "-", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	namespace, name, version = parts[0], parts[1], parts[2]
	if !validIdent(namespace) || !validIdent(name) || !validVersion(version) {
		return "", "", "", false
	}
	return namespace, name, version, true
}

// validIdent reports whether s is a plausible Ansible namespace or collection
// name: lowercase ASCII letters, digits, and underscores, non-empty.
func validIdent(s string) bool {
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

// validVersion reports whether s is a plausible semver version. It permits the
// characters a semver version uses (alphanumerics, '.', '+', '-') and rejects
// path metacharacters so the version cannot escape its directory.
func validVersion(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.' || c == '+' || c == '-':
		default:
			return false
		}
	}
	return s != "." && s != ".."
}

// cacheable reports whether the resource may be cached. Only a collection
// artifact is immutable (its filename pins the version); metadata is served
// live and rewritten.
func (r resource) cacheable() bool { return r.kind == kindArtifact }

// coordinateName returns the fully-qualified collection name ("namespace.name")
// used to address the artifact in the admission gates, or "" when the namespace
// and name are not known.
func (r resource) coordinateName() string {
	if r.namespace == "" || r.name == "" {
		return ""
	}
	return r.namespace + "." + r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindArtifact:
		return "collection-artifact"
	default:
		return "metadata"
	}
}
