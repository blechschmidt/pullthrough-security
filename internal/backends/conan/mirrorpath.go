package conan

import (
	"net/url"
	"strings"
)

// This file exports the backend's own request paths for the full-mirror feed
// adapter (internal/fullmirror, Task 190), which reads a recipe's revisions
// and file lists through the proxy and must name the files exactly as a
// Conan client requests them. The references are ConanCenter's: a name and a
// version, no user and no channel ("_/_"). Every builder holds the path it
// builds to classify: a path it returns is one this backend serves as the
// resource the builder names, for the reference, revisions and file it was
// given; ok is false for anything the layout cannot carry (an empty segment,
// a "/" inside one — a nested file name included). Each segment is
// percent-escaped, so the path decodes to what classify accepted.

// noUserChannel is ConanCenter's placeholder for an absent user and channel.
const noUserChannel = "_"

// RecipeSearchPath is the remote's recipe search ("?q=<pattern>" is appended
// by the caller): served live.
func RecipeSearchPath() string { return "/v2/conans/search" }

// RecipeLatestPath is a reference's latest recipe revision (mutable, live).
func RecipeLatestPath(name, version string) (string, bool) {
	return builtRef(name, version, []string{"latest"}, func(r resource) bool { return r.kind == kindRecipeLatest })
}

// RecipeFilesPath is the file list of a recipe revision (immutable, cacheable).
func RecipeFilesPath(name, version, rrev string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "files"}, func(r resource) bool {
		return r.kind == kindRecipeFiles && r.rrev == rrev
	})
}

// RecipeFilePath is one file of a recipe revision (immutable, cacheable).
func RecipeFilePath(name, version, rrev, file string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "files", file}, func(r resource) bool {
		return r.kind == kindRecipeFile && r.rrev == rrev && r.filename == file
	})
}

// PackageSearchPath is the binary-package search of a recipe revision: every
// package ID with its settings and options (live).
func PackageSearchPath(name, version, rrev string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "search"}, func(r resource) bool {
		return r.kind == kindSearch && r.rrev == rrev
	})
}

// PackageLatestPath is a binary package's latest package revision (mutable,
// live).
func PackageLatestPath(name, version, rrev, pkgID string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "packages", pkgID, "latest"}, func(r resource) bool {
		return r.kind == kindPackageLatest && r.rrev == rrev && r.pkgID == pkgID
	})
}

// PackageFilesPath is the file list of a package revision (immutable,
// cacheable).
func PackageFilesPath(name, version, rrev, pkgID, prev string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "packages", pkgID, "revisions", prev, "files"}, func(r resource) bool {
		return r.kind == kindPackageFiles && r.rrev == rrev && r.pkgID == pkgID && r.prev == prev
	})
}

// PackageFilePath is one file of a package revision (immutable, cacheable).
func PackageFilePath(name, version, rrev, pkgID, prev, file string) (string, bool) {
	return builtRef(name, version, []string{"revisions", rrev, "packages", pkgID, "revisions", prev, "files", file}, func(r resource) bool {
		return r.kind == kindPackageFile && r.rrev == rrev && r.pkgID == pkgID && r.prev == prev && r.filename == file
	})
}

// builtRef builds "/v2/conans/<name>/<version>/_/_/<tail…>", checks it with
// classify (the reference, then check), and returns it escaped segment by
// segment.
func builtRef(name, version string, tail []string, check func(resource) bool) (string, bool) {
	segs := append([]string{"v2", "conans", name, version, noUserChannel, noUserChannel}, tail...)
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
			return "", false
		}
	}
	res, ok := classify("/" + strings.Join(segs, "/"))
	if !ok || res.name != name || res.version != version || res.user != noUserChannel || res.channel != noUserChannel || !check(res) {
		return "", false
	}
	esc := make([]string, len(segs))
	for i, s := range segs {
		esc[i] = url.PathEscape(s)
	}
	return "/" + strings.Join(esc, "/"), true
}
