package rubygems

// This file exports what the full mirror (internal/fullmirror, Task 190) needs
// to hold the gem paths it fetches to this backend: how the backend reads a
// request path. The mirror takes a gem's path from repos/locate
// ("/gems/<name>-<version>.gem") and asks for it only when the backend reads
// the path back as that gem and version — the coordinate the admission gates
// see and the version whose /info checksum verifies the download.

// GemPathCoordinate reports the gem name and version token (with any platform
// suffix) the backend attributes a request path to, as Resolve reads it (the
// route prefix stripped, the path decoded); ok is false for a path that is not
// a .gem download.
//
// The split is the backend's (splitNameVersion): the first "-" followed by a
// digit ends the name. A gem whose name contains such a "-" ("3scale-3scale_ws_api")
// is therefore read as another gem ("3scale", version "3scale_ws_api-0.1").
func GemPathCoordinate(path string) (name, version string, ok bool) {
	res, ok := classify(path)
	if !ok || res.kind != kindGem {
		return "", "", false
	}
	return res.name, res.version, true
}
