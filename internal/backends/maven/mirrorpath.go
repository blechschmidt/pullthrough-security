package maven

import "strings"

// This file exports the path builder the full-mirror feed adapter (Task 191)
// lists a repository's files with. The adapter reads coordinates from the
// repository's Maven Indexer index and must name exactly the paths a build
// tool requests, and the backend caches, for them.

// ArtifactPath returns the request path of one file of a release:
//
//	/<groupId, dots as slashes>/<artifactId>/<version>/<artifactId>-<version>[-<classifier>].<extension>
//
// ok is false unless every part is written in the characters Maven
// coordinates are made of (letters, digits, ".", "_", "-" and "+"; see
// plainPath) and the backend reads the path back (classify) as a cacheable
// artifact of that groupId, artifactId and version: not a checksum or
// signature sidecar, not a maven-metadata.xml document, not a snapshot that
// is revalidated on every request.
func ArtifactPath(groupID, artifactID, version, classifier, extension string) (string, bool) {
	for _, part := range []string{groupID, artifactID, version, extension} {
		if part == "" || strings.Contains(part, "/") || !plainPath(part) {
			return "", false
		}
	}
	if classifier != "" && (strings.Contains(classifier, "/") || !plainPath(classifier)) {
		return "", false
	}
	file := artifactID + "-" + version
	if classifier != "" {
		file += "-" + classifier
	}
	file += "." + extension
	p := "/" + strings.ReplaceAll(groupID, ".", "/") + "/" + artifactID + "/" + version + "/" + file
	r, ok := classify(p)
	if !ok || r.kind != kindArtifact || r.groupID != groupID || r.artifactID != artifactID || r.version != version || !r.cacheable() {
		return "", false
	}
	// The characters are plain: the path is its own escaped form.
	return p, true
}
