package jsr

import "strings"

// A JSR package is addressed by a scope ("@<scope>") and a name, together with a
// semver version. The proxy mounts the registry at its route root
// ("<publicBase>/v1/<name>") and honors the JSR static-tree layout:
//
//	/@<scope>/<name>/meta.json             package metadata (mutable)
//	/@<scope>/<name>/<version>_meta.json   version metadata, incl. the publish manifest (immutable)
//	/@<scope>/<name>/<version>/<path...>   a module file in a published version (immutable)
//
// The two metadata documents change (meta.json) or are revalidated per request,
// so they are not cached; their served bytes have absolute upstream URLs
// rewritten through the proxy. A module-file path pins its
// scope/name/version/path coordinate, so it is immutable and content-
// addressable; on a cache miss the backend fetches the sibling
// <version>_meta.json, reads the file's SHA-256 from the "manifest" map, and
// verifies the fetched bytes against it before they are cached or served (see
// manifest.go / checksum.go).
//
// This file classifies an inbound path (with the "/v1/<name>" route prefix
// already stripped, retaining its leading slash) into one of these resource
// kinds and derives the package coordinate, which feeds the admission gates
// (nameguard, policy, provenance, vulnscan, license, policyengine) and the
// cacheability decision.

// resourceKind enumerates the classes of resource a JSR registry path can
// address.
type resourceKind int

const (
	// kindPackageMeta is the /@<scope>/<name>/meta.json document (all versions).
	// Mutable, served live, URL-rewritten.
	kindPackageMeta resourceKind = iota
	// kindVersionMeta is the /@<scope>/<name>/<version>_meta.json document (one
	// version's manifest/exports). Immutable but served live, URL-rewritten; also
	// the digest source the backend verifies module files against.
	kindVersionMeta
	// kindModuleFile is a module file /@<scope>/<name>/<version>/<path>, pinned by
	// scope, name, version, and path. Immutable, cacheable, verified against the
	// sibling <version>_meta.json manifest.
	kindModuleFile
)

// versionMetaSuffix is the suffix that identifies a version-metadata document.
const versionMetaSuffix = "_meta.json"

// resource is the parsed classification of an inbound JSR registry request.
type resource struct {
	kind resourceKind
	// scope and name form the package coordinate (without the leading "@" on the
	// scope).
	scope string
	name  string
	// version is set for kindVersionMeta and kindModuleFile.
	version string
	// filePath is the module file's path within the version (for kindModuleFile),
	// with a leading slash so it matches the version manifest's keys.
	filePath string
}

// classify parses an inbound path into a resource. It returns ok=false for paths
// that do not fit the JSR registry layout, so an unrecognized request is
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

	// Every JSR path begins with a scope segment "@<scope>" followed by the name.
	if len(segs) < 3 || !strings.HasPrefix(segs[0], "@") {
		return resource{}, false
	}
	scope := segs[0][1:]
	name := segs[1]
	if !validScope(scope) || !validName(name) {
		return resource{}, false
	}

	// /@<scope>/<name>/<tail...>
	switch {
	case len(segs) == 3 && segs[2] == "meta.json":
		return resource{kind: kindPackageMeta, scope: scope, name: name}, true
	case len(segs) == 3 && strings.HasSuffix(segs[2], versionMetaSuffix):
		version := strings.TrimSuffix(segs[2], versionMetaSuffix)
		if !validVersion(version) {
			return resource{}, false
		}
		return resource{kind: kindVersionMeta, scope: scope, name: name, version: version}, true
	case len(segs) >= 4:
		// /@<scope>/<name>/<version>/<path...> — a module file.
		version := segs[2]
		if !validVersion(version) {
			return resource{}, false
		}
		filePath := "/" + strings.Join(segs[3:], "/")
		return resource{kind: kindModuleFile, scope: scope, name: name, version: version, filePath: filePath}, true
	}
	return resource{}, false
}

// validScope reports whether s is a plausible JSR scope (the part after "@").
// JSR restricts scopes to lowercase ASCII letters, digits, and hyphens.
func validScope(s string) bool { return isLowerAlnumHyphen(s) }

// validName reports whether s is a plausible JSR package name. JSR restricts
// names to lowercase ASCII letters, digits, and hyphens.
func validName(s string) bool { return isLowerAlnumHyphen(s) }

func isLowerAlnumHyphen(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// validVersion reports whether s is a plausible JSR (semver) version. It permits
// the characters a semver version uses (alphanumerics, '.', '+', '-') and
// rejects path metacharacters so the version cannot escape its directory.
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

// cacheable reports whether the resource may be cached. Only module files are
// immutable (their path pins the version); the two metadata documents are served
// live and rewritten.
func (r resource) cacheable() bool { return r.kind == kindModuleFile }

// coordinateName returns the package name used to address the artifact in the
// admission gates — the JSR-native "@scope/name".
func (r resource) coordinateName() string {
	return "@" + r.scope + "/" + r.name
}

// kindLabel returns a stable diagnostic label for a resource kind.
func (r resource) kindLabel() string {
	switch r.kind {
	case kindPackageMeta:
		return "package-meta"
	case kindVersionMeta:
		return "version-meta"
	case kindModuleFile:
		return "module-file"
	default:
		return "other"
	}
}
