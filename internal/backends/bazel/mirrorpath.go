package bazel

import (
	"net/url"
	"strings"
)

// This file exports the backend's own request paths for the full-mirror feed
// adapter (internal/fullmirror, Task 190), which lists a module version's
// files and must name them exactly as Bazel requests them through the proxy.
// Every builder holds the path it builds to classify: a path it returns is
// one this backend serves as the resource the builder names, for the module
// and version it was given, and ok is false for a name, version or file the
// registry layout cannot carry. Each segment is percent-escaped, so the
// path decodes to what classify accepted.

// MetadataPath is a module's metadata.json, "/modules/<name>/metadata.json"
// (its version list; mutable, served live).
func MetadataPath(name string) (string, bool) {
	return built([]string{"modules", name, "metadata.json"}, func(r resource) bool {
		return r.kind == kindMetadata && r.name == name
	})
}

// ModuleFilePath is a module version's MODULE.bazel (cacheable).
func ModuleFilePath(name, version string) (string, bool) {
	return built([]string{"modules", name, version, "MODULE.bazel"}, func(r resource) bool {
		return r.kind == kindModuleBazel && r.name == name && r.version == version
	})
}

// SourcePath is a module version's source.json (rewritten, served live).
func SourcePath(name, version string) (string, bool) {
	return built([]string{"modules", name, version, sourceFile}, func(r resource) bool {
		return r.kind == kindSource && r.name == name && r.version == version
	})
}

// PatchPath is a patch file a version's source.json lists under "patches",
// "/modules/<name>/<version>/patches/<file>" (cacheable).
func PatchPath(name, version, file string) (string, bool) {
	return built([]string{"modules", name, version, "patches", file}, func(r resource) bool {
		return r.kind == kindPatch && r.name == name && r.version == version && r.filename == file
	})
}

// OverlayPath is a file a version's source.json lists under "overlay" (rel
// is its path in the source tree, "/"-separated),
// "/modules/<name>/<version>/overlay/<rel>" (cacheable).
func OverlayPath(name, version, rel string) (string, bool) {
	segs := append([]string{"modules", name, version, "overlay"}, strings.Split(rel, "/")...)
	return built(segs, func(r resource) bool {
		return r.kind == kindOverlay && r.name == name && r.version == version && r.filename == rel
	})
}

// built joins segs into a path, checks it with classify and check, and
// returns it escaped segment by segment.
func built(segs []string, check func(resource) bool) (string, bool) {
	for _, s := range segs {
		if s == "" || strings.ContainsAny(s, "/\\") {
			return "", false
		}
	}
	res, ok := classify("/" + strings.Join(segs, "/"))
	if !ok || !check(res) {
		return "", false
	}
	esc := make([]string, len(segs))
	for i, s := range segs {
		esc[i] = url.PathEscape(s)
	}
	return "/" + strings.Join(esc, "/"), true
}
