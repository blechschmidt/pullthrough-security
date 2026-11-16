package puppet

// This file exports what the full mirror (internal/fullmirror, Task 191) needs
// to hold the release tarballs it fetches to this backend: which module slugs
// and versions the backend reads, and how it reads a request path back. The
// mirror takes a release's path from repos/locate
// ("/v3/files/<owner>-<name>-<version>.tar.gz") and asks for it only when the
// backend caches the path as that module's release — the coordinate the
// admission gates see and the release whose file_sha256 verifies the
// download.

// ValidModule reports whether slug is a module slug ("owner-name") the backend
// parses: an owner of lower-case letters and digits, a name of lower-case
// letters, digits and "_" that starts with a letter. The Forge also lists
// owners spelt with upper-case letters ("Slashbunny-phpfpm"); the backend
// forwards their tarballs uncached and unverified, so the mirror leaves them
// out.
func ValidModule(slug string) bool {
	_, _, ok := parseModuleSlug(slug)
	return ok
}

// ValidRelease reports whether version of module names a release tarball the
// backend caches under exactly that module and version.
func ValidRelease(module, version string) bool {
	if !ValidModule(module) || !validVersion(version) {
		return false
	}
	m, v, ok := ReleaseFileCoordinate("/v3/files/" + module + "-" + version + artifactSuffix)
	return ok && m == module && v == version
}

// ReleaseFileCoordinate reports the module slug and version the backend
// attributes a request path to (the route prefix stripped, the path decoded)
// when it caches the path as a release tarball; ok is false for every other
// path, which the backend serves live.
func ReleaseFileCoordinate(path string) (module, version string, ok bool) {
	res, ok := classify(path)
	if !ok || res.kind != kindArtifact || !res.cacheable() {
		return "", "", false
	}
	return res.coordinateName(), res.version, true
}
