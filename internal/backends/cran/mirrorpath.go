package cran

import (
	"net/url"
	"strings"
)

// This file exports what the full mirror's feed adapter (internal/fullmirror,
// Task 191) needs to name the source packages this backend serves.

// SourcePackagePath returns the path, relative to the backend's mount, of the
// source tarball of a package version a src/contrib PACKAGES index lists:
// "/src/contrib/<name>_<version>.tar.gz", or, for a stanza whose Path field
// names a subdirectory (CRAN lists its recommended packages a second time
// under "<R version>/Recommended"), "/src/contrib/<dir>/<name>_<version>.tar.gz",
// where R's download.packages fetches it. ok is false when the backend would
// not serve that path as this package version — the file name does not parse
// back to name and version (path.go) — or dir is not a relative directory.
func SourcePackagePath(dir, name, version string) (string, bool) {
	file := name + "_" + version + ".tar.gz"
	if !plainSegment(name) || !plainSegment(version) || !plainSegment(file) {
		return "", false
	}
	raw, escaped := "/src/contrib/", "/src/contrib/"
	if dir = strings.Trim(dir, "/"); dir != "" {
		for _, seg := range strings.Split(dir, "/") {
			if !plainSegment(seg) {
				return "", false
			}
			raw += seg + "/"
			escaped += url.PathEscape(seg) + "/"
		}
	}
	res, ok := classify(raw + file)
	if !ok || res.kind != kindPackage || res.name != name || res.version != version || res.filename != file {
		return "", false
	}
	return escaped + url.PathEscape(file), true
}

// plainSegment reports whether s can be one segment of a repository path: not
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
