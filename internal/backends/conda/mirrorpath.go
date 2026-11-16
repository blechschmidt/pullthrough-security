package conda

import (
	"net/url"
	"strings"
)

// This file exports what the full mirror's feed adapter (internal/fullmirror,
// Task 191) needs to name the packages this backend serves: a subdir's
// repodata lists each package by its file name, and the backend serves it at
// "/<subdir>/<filename>" beneath the channel (path.go).

// PackagePath returns the path, relative to the backend's mount, of a package
// file a subdir's repodata lists, with the coordinate the backend derives from
// that path (the name and version the admission gates see). ok is false for a
// file the backend does not serve as a package: a subdir that is not a conda
// subdir, or a file name that is not "<name>-<version>-<build>" with a package
// suffix (.conda, .tar.bz2), or that holds a character no channel file name
// does.
func PackagePath(subdir, filename string) (path, name, version string, ok bool) {
	if !plainSegment(subdir) || !plainSegment(filename) {
		return "", "", "", false
	}
	res, ok := classify("/" + subdir + "/" + filename)
	if !ok || res.kind != kindPackage || res.subdir != subdir || res.filename != filename {
		return "", "", "", false
	}
	return "/" + url.PathEscape(subdir) + "/" + url.PathEscape(filename), res.name, res.version, true
}

// IsSubdir reports whether s names a subdir the backend serves packages from:
// "noarch" or "<platform>-<arch>" for a platform conda knows.
func IsSubdir(s string) bool { return plainSegment(s) && isSubdir(s) }

// plainSegment reports whether s can be one segment of a channel path: not
// empty, not a dot segment, without a separator, an escape or a control
// character.
func plainSegment(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c == 0x7f || strings.IndexByte(`/\%?#`, c) >= 0 {
			return false
		}
	}
	return true
}
