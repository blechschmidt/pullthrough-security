package ansible

import "strings"

// This file exports what the full mirror (internal/fullmirror, Task 191) needs
// to hold the collection artifacts it fetches to this backend: which
// collection names and versions the backend reads, and how it reads a request
// path back. The mirror takes an artifact's path from repos/locate
// (".../collections/artifacts/<ns>-<name>-<version>.tar.gz") and asks for it
// only when the backend caches the path as that collection's version — the
// coordinate the admission gates see and the version whose version-detail
// SHA-256 verifies the download.

// ValidCollection reports whether fqcn is a collection name
// ("namespace.name") the backend parses: a namespace and a name of lower-case
// letters, digits and "_".
func ValidCollection(fqcn string) bool {
	ns, name, ok := strings.Cut(fqcn, ".")
	return ok && validIdent(ns) && validIdent(name)
}

// ValidRelease reports whether version of collection names an artifact the
// backend caches under exactly that collection and version.
func ValidRelease(collection, version string) bool {
	ns, name, ok := strings.Cut(collection, ".")
	if !ok || !validIdent(ns) || !validIdent(name) || !validVersion(version) {
		return false
	}
	c, v, ok := ArtifactPathCoordinate("/api/v3/plugin/ansible/content/published/collections/artifacts/" + ns + "-" + name + "-" + version + artifactSuffix)
	return ok && c == collection && v == version
}

// ArtifactPathCoordinate reports the collection ("namespace.name") and
// version the backend attributes a request path to (the route prefix
// stripped, the path decoded) when it caches the path as a collection
// artifact; ok is false for every other path, which the backend serves live.
func ArtifactPathCoordinate(path string) (collection, version string, ok bool) {
	res, ok := classify(path)
	if !ok || res.kind != kindArtifact || !res.cacheable() {
		return "", "", false
	}
	return res.coordinateName(), res.version, true
}
