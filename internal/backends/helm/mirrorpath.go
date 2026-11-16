package helm

import "strings"

// This file exports what the full mirror's feed adapter (internal/fullmirror,
// Task 191) needs to name the archives this backend serves: the path the
// rewritten repository index hands a client for an entry's archive, so that
// the mirror fetches exactly what a client pulling the chart is served.

// ArchivePath returns the path, relative to the backend's mount, that the
// rewritten repository index hands a client for the archive an index entry
// lists at location: the index-resolved link rewrite.go mints for it
// ("/-/<chart>/<version>/<file>", classified by path.go), whose file segment
// archiveFile derives from the location. chart is the key the entry is listed
// under in `entries` and version the entry's `version`; Helm downloads the
// first of an entry's urls.
//
// ok is false where the rewrite hands out no archive link: for an empty
// location (left as it is) and for a chart or version a path segment cannot
// carry (the entry gets the unaddressable link, which serves nothing).
func ArchivePath(chart, version, location string) (string, bool) {
	chart, version, location = strings.TrimSpace(chart), strings.TrimSpace(version), strings.TrimSpace(location)
	if location == "" || !addressable(chart) || !addressable(version) {
		return "", false
	}
	link := linker{}.archive(chart, version, archiveFile(location, chart, version))
	if !quotable(link) {
		return "", false
	}
	return "/" + link, true
}
