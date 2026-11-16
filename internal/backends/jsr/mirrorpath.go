package jsr

import (
	"net/url"
	"strings"
)

// This file exports the path builders the full-mirror feed adapter (Task 191)
// lists a JSR package's documents and module files with: it must name exactly
// the paths a runtime requests, and the backend caches, for them.

// PackageMetaPath returns the path of a package's metadata document,
// "/@<scope>/<name>/meta.json"; ok is false unless the backend reads it back
// as that package's metadata document.
func PackageMetaPath(scope, name string) (string, bool) {
	p := "/@" + scope + "/" + name + "/meta.json"
	r, ok := classify(p)
	if !ok || r.kind != kindPackageMeta || r.scope != scope || r.name != name {
		return "", false
	}
	return p, true
}

// VersionMetaPath returns the path of a version's metadata document (the one
// that carries the version's manifest), "/@<scope>/<name>/<version>_meta.json";
// ok is false unless the backend reads it back as that version's document.
func VersionMetaPath(scope, name, version string) (string, bool) {
	p := "/@" + scope + "/" + name + "/" + version + versionMetaSuffix
	r, ok := classify(p)
	if !ok || r.kind != kindVersionMeta || r.scope != scope || r.name != name || r.version != version {
		return "", false
	}
	return p, true
}

// ModuleFilePath returns the request path of a module file of a version,
// "/@<scope>/<name>/<version><file>" — file being the path the version's
// manifest keys it by ("/mod.ts") — with each segment of file escaped for a
// request. ok is false unless the backend reads the path back as a cacheable
// module file of that scope, name and version, at exactly that file path (the
// key it verifies the bytes against): an empty or dot segment, or a control
// character, is refused.
func ModuleFilePath(scope, name, version, file string) (string, bool) {
	if len(file) < 2 || file[0] != '/' {
		return "", false
	}
	for i := 0; i < len(file); i++ {
		if c := file[i]; c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	segs := strings.Split(file[1:], "/")
	esc := make([]string, len(segs))
	for i, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", false
		}
		esc[i] = url.PathEscape(s)
	}
	r, ok := classify("/@" + scope + "/" + name + "/" + version + file)
	if !ok || r.kind != kindModuleFile || r.scope != scope || r.name != name || r.version != version || r.filePath != file || !r.cacheable() {
		return "", false
	}
	return "/@" + scope + "/" + name + "/" + version + "/" + strings.Join(esc, "/"), true
}
