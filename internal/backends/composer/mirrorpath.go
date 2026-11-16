package composer

import "time"

// This file exports what the full mirror (internal/fullmirror, Task 190) needs
// to name the dist archives this backend serves without building a URL of its
// own: the dist locator from the backend's own builder, the package-name and
// dev-version rules the backend routes by, and the release time each version's
// metadata states. The full mirror reads a package's v2 metadata through the
// proxy, as a client does, and asks for exactly the dist paths the rewritten
// metadata hands a client.

// DistPath returns the path, relative to the backend's mount, at which the
// backend serves a version's dist archive —
// "/dist/<vendor>/<package>/<version>/<reference>.<type>", the locator every
// rewritten "dist.url" names (see distPath) — or ok=false when the dist cannot
// be addressed through the proxy.
func DistPath(vendor, pkg, version, reference, distType string) (string, bool) {
	return distPath(vendor, pkg, version, reference, distType)
}

// SplitPackageName splits a "vendor/package" name into its two halves, with
// ok=false for any name the backend does not route (see validNamePart).
func SplitPackageName(name string) (vendor, pkg string, ok bool) {
	return splitPackageName(name)
}

// IsDevVersion reports whether a version is a development (branch) version by
// Composer's rule — a "dev-" prefix or a "-dev" suffix: it lives in the
// package's "~dev" metadata document and moves to a new reference over time.
func IsDevVersion(version string) bool { return isDevVersion(version) }

// ReleaseTimes returns the release time ("time") each version of the named
// package states in a v2 metadata document, keyed by version as the metadata
// spells it. The minified delta encoding is expanded exactly as ParseMetadata
// expands it, so a version that inherits its time from the previous one has
// it. Versions without a time that parses are absent; a version listed twice
// keeps its first time. It is an error if the body is not a JSON object or
// exceeds the backend's size bound.
func ReleaseTimes(data []byte, name string) (map[string]time.Time, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	list, ok := parseVersionList(doc.packages[name])
	if !ok {
		return out, nil
	}
	objects := list.objects()
	if doc.minified {
		objects = expandMinified(objects)
	}
	for _, obj := range objects {
		version, ok := exactString(obj["version"])
		if !ok || version == "" {
			continue
		}
		raw, ok := exactString(obj["time"])
		if !ok {
			continue
		}
		t, ok := parseReleaseTime(raw)
		if !ok {
			continue
		}
		if _, dup := out[version]; !dup {
			out[version] = t
		}
	}
	return out, nil
}

// parseReleaseTime reads a version's "time": ISO 8601 with an offset, as
// Packagist writes it ("2024-09-11T13:17:53+00:00"), or the space-separated
// UTC form older Satis builds write.
func parseReleaseTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
