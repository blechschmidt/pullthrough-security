package pkgmgr

import (
	"net/url"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
)

// This file derives the logical package coordinate (name + version) of an
// artifact request for each ecosystem. The coordinate is attached to the
// resolved request (via httpbackend.Coordinator) so the admission-policy layer
// (Task 9) can identify the artifact for allowlist/denylist matching and
// package-to-commit provenance lookup. Extraction is best-effort: it runs only on
// the artifact paths each backend already classifies as immutable downloads, and
// returns ok=false for anything it cannot confidently parse, in which case the
// artifact is served with no coordinate (policy then sees an unidentified
// artifact rather than a wrong one).

// npmCoordinate parses an npm tarball path of the form
// "/<name>/-/<file>-<version>.tgz" or "/@scope/<name>/-/...". The package name is
// everything before the "/-/" marker; the version is the tarball filename with
// the package short-name prefix and ".tgz" suffix stripped.
func npmCoordinate(req *backends.Request) (backends.Coordinate, bool) {
	p := strings.TrimPrefix(req.Path, "/")
	name, file, ok := strings.Cut(p, "/-/")
	if !ok || name == "" || file == "" {
		return backends.Coordinate{}, false
	}
	name, _ = url.PathUnescape(name)
	version := strings.TrimSuffix(file, ".tgz")
	short := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		short = name[i+1:]
	}
	if pfx := short + "-"; strings.HasPrefix(version, pfx) {
		version = version[len(pfx):]
	}
	return backends.Coordinate{Name: name, Version: version}, true
}

// goCoordinate parses a Go module proxy path of the form
// "/<module>/@v/<version>.<ext>". The module path is the (case-escaped) name; the
// version is the filename without its extension. Module/version case-escaping
// ("!u" for an uppercase rune) is left intact: it is the canonical proxy form and
// matches what provenance metadata records.
func goCoordinate(req *backends.Request) (backends.Coordinate, bool) {
	module, after, ok := strings.Cut(req.Path, "/@v/")
	if !ok {
		return backends.Coordinate{}, false
	}
	module = strings.TrimPrefix(module, "/")
	var version string
	switch {
	case strings.HasSuffix(after, ".zip"):
		version = strings.TrimSuffix(after, ".zip")
	case strings.HasSuffix(after, ".info"):
		version = strings.TrimSuffix(after, ".info")
	case strings.HasSuffix(after, ".mod"):
		version = strings.TrimSuffix(after, ".mod")
	default:
		return backends.Coordinate{}, false
	}
	if module == "" || version == "" {
		return backends.Coordinate{}, false
	}
	return backends.Coordinate{Name: module, Version: version}, true
}

// cargoCoordinate parses a crate download path of the form
// "/api/v1/crates/<name>/<version>/download".
func cargoCoordinate(req *backends.Request) (backends.Coordinate, bool) {
	rest := strings.TrimPrefix(req.Path, cargoDownloadPrefix+"/")
	rest = strings.TrimSuffix(rest, "/download")
	name, version, ok := strings.Cut(rest, "/")
	if !ok || name == "" || version == "" || strings.Contains(version, "/") {
		return backends.Coordinate{}, false
	}
	return backends.Coordinate{Name: name, Version: version}, true
}

// nugetCoordinate parses a flat-container package path of the form
// "/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg". NuGet ids are
// case-insensitive; the flat container uses the lowercased id, which is what is
// returned.
func nugetCoordinate(req *backends.Request) (backends.Coordinate, bool) {
	p := strings.ToLower(req.Path)
	if !strings.HasSuffix(p, ".nupkg") {
		return backends.Coordinate{}, false
	}
	segs := strings.Split(strings.Trim(req.Path, "/"), "/")
	// .../<id>/<version>/<file>.nupkg
	if len(segs) < 3 {
		return backends.Coordinate{}, false
	}
	version := segs[len(segs)-2]
	id := segs[len(segs)-3]
	if id == "" || version == "" {
		return backends.Coordinate{}, false
	}
	return backends.Coordinate{Name: strings.ToLower(id), Version: version}, true
}

// pipCoordinate parses the wheel/sdist filename out of a reconstructed PyPI
// artifact path ("/files/<scheme>/<host>/.../<file>") and derives the project
// name and version. Wheels follow PEP 427 ("<name>-<version>-<pytag>...whl");
// sdists are "<name>-<version>.tar.gz" (or .zip). The project name is normalized
// (PEP 503: lowercase, runs of [-_.] collapsed to "-") so it matches how
// provenance resolvers key PyPI projects.
func pipCoordinate(req *backends.Request) (backends.Coordinate, bool) {
	if !strings.HasPrefix(req.Path, pipFilesPrefix) {
		return backends.Coordinate{}, false
	}
	file := req.Path
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	if file, err := url.PathUnescape(file); err == nil {
		return pipNameVersion(file)
	}
	return pipNameVersion(file)
}

// pipNameVersion extracts (normalized name, version) from a distribution
// filename.
func pipNameVersion(file string) (backends.Coordinate, bool) {
	switch {
	case strings.HasSuffix(file, ".whl"):
		// name-version-pytag-abitag-platformtag.whl
		base := strings.TrimSuffix(file, ".whl")
		parts := strings.Split(base, "-")
		if len(parts) < 2 {
			return backends.Coordinate{}, false
		}
		name, version := normalizePyPI(parts[0]), parts[1]
		if name == "" || version == "" {
			return backends.Coordinate{}, false
		}
		return backends.Coordinate{Name: name, Version: version}, true
	case strings.HasSuffix(file, ".tar.gz") || strings.HasSuffix(file, ".zip") ||
		strings.HasSuffix(file, ".tar.bz2"):
		base := file
		for _, ext := range []string{".tar.gz", ".tar.bz2", ".zip"} {
			base = strings.TrimSuffix(base, ext)
		}
		// sdists are "<name>-<version>"; the version starts at the last "-" that is
		// followed by a digit, which separates a (possibly hyphenated) name.
		i := strings.LastIndex(base, "-")
		if i <= 0 || i+1 >= len(base) {
			return backends.Coordinate{}, false
		}
		name, version := normalizePyPI(base[:i]), base[i+1:]
		if name == "" || version == "" {
			return backends.Coordinate{}, false
		}
		return backends.Coordinate{Name: name, Version: version}, true
	default:
		return backends.Coordinate{}, false
	}
}

// normalizePyPI applies PEP 503 normalization to a project name.
func normalizePyPI(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return strings.Trim(b.String(), "-")
}
