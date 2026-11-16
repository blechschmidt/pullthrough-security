package openvsx

import (
	"regexp"
	"strings"
)

// This file exports the backend's archive path for the full-mirror feed
// adapter (internal/fullmirror, Task 191), which lists every version a
// registry document names without reading one document per version, and
// checks the archive URLs the registry writes against what the backend
// serves.

// Universal is the target platform of an archive built for every platform.
const Universal = "universal"

// targetPlatforms are the target platforms openvsx-server publishes
// extensions for (TargetPlatform.TARGET_PLATFORM_NAMES).
var targetPlatforms = []string{
	"win32-x64", "win32-ia32", "win32-arm64",
	"linux-x64", "linux-arm64", "linux-armhf",
	"alpine-x64", "alpine-arm64",
	"darwin-x64", "darwin-arm64",
	"web", Universal,
}

// TargetPlatforms returns the target platforms openvsx-server knows.
func TargetPlatforms() []string { return append([]string(nil), targetPlatforms...) }

// IsTargetPlatform reports whether s is a target platform openvsx-server
// knows.
func IsTargetPlatform(s string) bool {
	for _, p := range targetPlatforms {
		if s == p {
			return true
		}
	}
	return false
}

// maxNameLen is openvsx-server's bound on a namespace or extension name.
const maxNameLen = 255

// ValidName reports whether s is a namespace or extension name as
// openvsx-server accepts one: [\w\-\+\$~]+ (\w is ASCII), at most 255
// characters. None of these characters needs escaping in a path segment, and
// none is the "." that joins a namespace and a name into an extension's
// identifier.
func ValidName(s string) bool {
	if s == "" || len(s) > maxNameLen || s == "-" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '+' || c == '$' || c == '~':
		default:
			return false
		}
	}
	return true
}

// versionPattern is openvsx-server's VERSION_PATH_PARAM_REGEX (SemVer 2.0):
// the versions its file endpoint serves.
var versionPattern = regexp.MustCompile(`^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)` +
	`(?:-(?:(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?` +
	`(?:\+(?:[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

// ValidVersion reports whether s is a version the registry's file endpoint
// serves: SemVer 2.0, as openvsx-server matches the path parameter, at most
// 255 characters.
func ValidVersion(s string) bool { return len(s) <= maxNameLen && versionPattern.MatchString(s) }

// VsixPath is the path of an extension version's archive on the registry's
// file endpoint, under the name openvsx-server stores every archive with
// (NamingUtil.toFileFormat; a migration renamed the archives published before
// the pattern):
//
//	/api/{namespace}/{extension}/{version}/file/{namespace}.{extension}-{version}.vsix
//	/api/{namespace}/{extension}/{platform}/{version}/file/{namespace}.{extension}-{version}@{platform}.vsix
//
// the first for the universal archive, the second for a target platform's. ok
// is false for a name, version or platform the registry does not have, and
// for a path the backend would not classify as that version's archive (a
// namespace or extension named "file" is read as the file marker).
func VsixPath(namespace, extension, targetPlatform, version string) (string, bool) {
	if !ValidName(namespace) || !ValidName(extension) || !ValidVersion(version) || !IsTargetPlatform(targetPlatform) {
		return "", false
	}
	file := namespace + "." + extension + "-" + version
	p := "/api/" + namespace + "/" + extension + "/"
	if targetPlatform != Universal {
		file += "@" + targetPlatform
		p += targetPlatform + "/"
	}
	file += vsixExt
	p += version + "/file/" + file
	res, ok := classify(p)
	if !ok || res.kind != kindVsix || res.extID != namespace+"."+extension || res.version != version || res.filename != file {
		return "", false
	}
	return p, true
}

// VsixCoordinate reads the extension ("{namespace}.{extension}") and version
// a request path names as an archive, as the backend classifies it; ok is
// false for a path the backend does not serve as an archive.
func VsixCoordinate(path string) (extension, version string, ok bool) {
	res, ok := classify(path)
	if !ok || res.kind != kindVsix || strings.Count(res.extID, ".") != 1 {
		return "", "", false
	}
	return res.extID, res.version, true
}
