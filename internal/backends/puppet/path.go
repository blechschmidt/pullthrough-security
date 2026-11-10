package puppet

import "strings"

// Puppet Forge (forgeapi.puppet.com) exposes a v3 REST API. A module is
// addressed by an owner (the publishing user) and a module name; its canonical
// slug is "owner-name", and a specific release adds a semver version
// ("owner-name-version"). Release tarballs are distributed as ".tar.gz" files
// addressed by that release slug. The proxy mounts the API at its route root
// ("<publicBase>/v1/<name>") and honors the Forge v3 layout:
//
//	GET  /v3/modules/<owner>-<name>                      module metadata (incl. releases)
//	GET  /v3/releases/<owner>-<name>-<version>           release metadata (incl. file_md5/file_sha256/file_uri)
//	GET  /v3/files/<owner>-<name>-<version>.tar.gz       release tarball
//	GET  /v3/modules | /v3/releases | /v3/users ...      search/listing metadata
//
// The module/release/listing documents are metadata: they are served live
// (revalidated per request, never cached) with every absolute upstream URL they
// embed rewritten through the proxy. A release tarball pins its
// owner/name/version in its filename, so it is immutable and content-
// addressable; on a cache miss the backend fetches the sibling release-metadata
// document, reads the release's published file_sha256 (preferred) or file_md5,
// and verifies the fetched bytes against it before they are cached or served
// (see metadata.go / checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into a resource kind and
// derives the module coordinate, which feeds the admission gates (nameguard,
// policy, provenance, vulnscan, license, policyengine) and the cacheability
// decision.

// resourceKind enumerates the classes of resource a Forge path can address.
type resourceKind int

const (
	// kindMetadata is any Forge API document (module, release, listing/search).
	// Served live and URL-rewritten; the release-metadata document is additionally
	// the digest source the backend verifies release tarballs against.
	kindMetadata resourceKind = iota
	// kindArtifact is a release tarball (<owner>-<name>-<version>.tar.gz under
	// "/v3/files/"). Immutable, cacheable, verified against the sibling release
	// metadata's file_sha256/file_md5.
	kindArtifact
)

// artifactSuffix is the suffix of a release tarball.
const artifactSuffix = ".tar.gz"

// resource is the parsed classification of an inbound Forge request.
type resource struct {
	kind resourceKind
	// owner and name form the module coordinate. Set for kindArtifact (parsed
	// from the filename) and, best-effort, for a module/release metadata path.
	owner string
	name  string
	// version is the module version. Set for kindArtifact and, best-effort, for a
	// release-metadata path.
	version string
	// basePrefix is the upstream path prefix (leading slash, no trailing slash)
	// that precedes "/v3" in the request, so the sibling release-metadata URL is
	// built correctly when the API is served under a sub-path. Set for
	// kindArtifact.
	basePrefix string
}

// classify parses an inbound path into a resource. A path that does not fit the
// Forge layout is still treated as live metadata (fail-open passthrough with URL
// rewriting), mirroring how the API serves many ancillary endpoints; a malformed
// path (empty segment or traversal) is rejected. Only a well-formed release-file
// path is classified as a cacheable, verified artifact.
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

	// A release tarball lives at "<prefix>/v3/files/<file>.tar.gz".
	if i := filesIndex(segs); i >= 0 {
		file := segs[len(segs)-1]
		owner, name, version, ok := parseReleaseFile(file)
		if !ok {
			// A file under files/ we cannot decompose is served live rather than
			// cached unverified.
			return resource{kind: kindMetadata}, true
		}
		basePrefix := ""
		if i > 0 {
			basePrefix = "/" + strings.Join(segs[:i], "/")
		}
		return resource{
			kind:       kindArtifact,
			owner:      owner,
			name:       name,
			version:    version,
			basePrefix: basePrefix,
		}, true
	}

	// Best-effort coordinate extraction from a module or release metadata path:
	// "<prefix>/v3/modules/<owner>-<name>" or "<prefix>/v3/releases/<slug>".
	res := resource{kind: kindMetadata}
	if v := v3Index(segs); v >= 0 && len(segs) == v+3 {
		switch segs[v+1] {
		case "modules":
			if owner, name, ok := parseModuleSlug(segs[v+2]); ok {
				res.owner, res.name = owner, name
			}
		case "releases":
			if owner, name, version, ok := parseReleaseSlug(segs[v+2]); ok {
				res.owner, res.name, res.version = owner, name, version
			}
		}
	}
	return res, true
}

// filesIndex returns the index i of the "v3" segment in a
// "<prefix>/v3/files/<file>" path (so segs[i]=="v3", segs[i+1]=="files", and the
// file is the final segment with a .tar.gz suffix), or -1 when the path is not a
// release-file path.
func filesIndex(segs []string) int {
	for i := 0; i+2 < len(segs); i++ {
		if segs[i] == "v3" && segs[i+1] == "files" && i+2 == len(segs)-1 {
			if strings.HasSuffix(segs[i+2], artifactSuffix) {
				return i
			}
		}
	}
	return -1
}

// v3Index returns the index of a "v3" segment, or -1.
func v3Index(segs []string) int {
	for i := range segs {
		if segs[i] == "v3" {
			return i
		}
	}
	return -1
}

// parseReleaseFile decomposes a release tarball filename
// "<owner>-<name>-<version>.tar.gz" into its parts.
func parseReleaseFile(file string) (owner, name, version string, ok bool) {
	base := strings.TrimSuffix(file, artifactSuffix)
	if base == file {
		return "", "", "", false
	}
	return parseReleaseSlug(base)
}

// parseReleaseSlug decomposes a release slug "<owner>-<name>-<version>".
// Puppet restricts the owner to lowercase ASCII letters and digits and the
// module name to a lowercase letter followed by letters/digits/underscores
// (never a hyphen), so splitting on the first two hyphens is unambiguous even
// when the semver version carries a prerelease hyphen (e.g. "1.0.0-rc1").
func parseReleaseSlug(slug string) (owner, name, version string, ok bool) {
	parts := strings.SplitN(slug, "-", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	owner, name, version = parts[0], parts[1], parts[2]
	if !validOwner(owner) || !validName(name) || !validVersion(version) {
		return "", "", "", false
	}
	return owner, name, version, true
}

// parseModuleSlug decomposes a module slug "<owner>-<name>".
func parseModuleSlug(slug string) (owner, name string, ok bool) {
	parts := strings.SplitN(slug, "-", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	owner, name = parts[0], parts[1]
	if !validOwner(owner) || !validName(name) {
		return "", "", false
	}
	return owner, name, true
}

// validOwner reports whether s is a plausible Forge owner (username): lowercase
// ASCII letters and digits, non-empty.
func validOwner(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// validName reports whether s is a plausible Forge module name: a lowercase
// letter followed by lowercase letters, digits, and underscores.
func validName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
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

// cacheable reports whether the resource may be cached. Only a release tarball
// is immutable (its filename pins the version); metadata is served live and
// rewritten.
func (r resource) cacheable() bool { return r.kind == kindArtifact }

// coordinateName returns the canonical module slug ("owner-name") used to
// address the artifact in the admission gates, or "" when the owner and name
// are not known.
func (r resource) coordinateName() string {
	if r.owner == "" || r.name == "" {
		return ""
	}
	return r.owner + "-" + r.name
}

// releaseSlug returns the release slug "owner-name-version", or "" when any
// component is missing.
func (r resource) releaseSlug() string {
	if r.owner == "" || r.name == "" || r.version == "" {
		return ""
	}
	return r.owner + "-" + r.name + "-" + r.version
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindArtifact:
		return "release-tarball"
	default:
		return "metadata"
	}
}
