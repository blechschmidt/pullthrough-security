package dart

// This file exports what the full mirror (internal/fullmirror, Task 191) needs
// to hold the archives it fetches to this backend: which package names the
// backend serves, and how it reads an archive path back. The mirror takes an
// archive's path from the archive_url the backend rewrote into the
// list-versions document ("/api/archives/<package>-<version>.tar.gz") and asks
// for it only when the backend caches the path as that package's version —
// the coordinate the admission gates see and the version whose
// archive_sha256 verifies the download.

// ValidPackageName reports whether s is a package name the backend serves: a
// Dart identifier of lower-case letters, digits and "_" that does not start
// with a digit, at most 64 bytes. pub.dev still lists a dozen legacy names
// spelt with upper-case letters ("Autolinker"); the backend serves none of
// them.
func ValidPackageName(s string) bool { return validPackageName(s) }

// ArchivePathCoordinate reports the package and version the backend
// attributes a request path to (the route prefix stripped, the path decoded)
// when it caches the path as a package archive; ok is false for every other
// path.
func ArchivePathCoordinate(path string) (name, version string, ok bool) {
	res, ok := classify(path)
	if !ok || !res.isArchive() || !res.cacheable() {
		return "", "", false
	}
	return res.name, res.version, true
}
