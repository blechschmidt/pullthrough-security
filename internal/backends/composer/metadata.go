package composer

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Composer/Packagist exposes package data through two document families the proxy
// must understand:
//
//   - packages.json — the repository root. It advertises the templated URLs a
//     client expands to reach per-package metadata ("metadata-url", typically
//     "/p2/%package%.json") and, historically, provider listings. The proxy
//     serves it live (it is mutable) but parses it to validate structure.
//
//   - /p2/<vendor>/<package>.json — the Composer v2 metadata layout: the list of
//     published versions for one package, each carrying its dist archive
//     coordinates (type, URL, source reference, and SHA-1 shasum), requirements,
//     and license. The proxy serves it live but parses it to recover the dist
//     shasum used to verify a fetched archive, and to surface license metadata to
//     the license-compliance gate.
//
// The v2 layout is usually "minified" ("minified":"composer/2.0"): within a
// package's version array, the first object is complete and each subsequent
// object carries only the keys that changed from the previous one, with the
// sentinel value "__unset" meaning "remove this key". ParseMetadata expands that
// delta encoding back into independent, fully-populated version objects.

// maxMetadataBytes bounds how much of a Composer metadata document the backend
// parses. Per-package v2 files are at most a few hundred KiB even for packages
// with a long release history; the root packages.json is small.
const maxMetadataBytes = 16 << 20 // 16 MiB

// Dist describes a version's distributable archive.
type Dist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
	Shasum    string `json:"shasum"`
}

// Version is one fully-expanded entry of a package's v2 metadata array.
type Version struct {
	Name    string
	Version string
	Dist    Dist
	// License lists the SPDX license identifiers declared for the version
	// (Composer's "license" is an array of strings).
	License []string
}

// Metadata is the parsed form of a /p2/<vendor>/<package>.json document.
type Metadata struct {
	// Minified is the value of the document's "minified" field (e.g.
	// "composer/2.0"), or "" when the document was already expanded.
	Minified string
	// Packages maps a package name ("vendor/package") to its expanded versions.
	Packages map[string][]Version
}

// rawMetadata mirrors the v2 document envelope for decoding. Each version object
// is kept as a raw map so the minified delta encoding can be expanded before the
// typed fields are extracted.
type rawMetadata struct {
	Minified string                                  `json:"minified"`
	Packages map[string][]map[string]json.RawMessage `json:"packages"`
}

// ParseMetadata decodes a /p2/<vendor>/<package>.json document, expanding the
// Composer v2 minified delta encoding when present. It is an error if the body is
// not valid JSON or exceeds the size bound; an empty or package-less document
// parses to an empty Metadata so callers can serve it without special-casing.
func ParseMetadata(data []byte) (*Metadata, error) {
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("composer: metadata document exceeds %d bytes", maxMetadataBytes)
	}
	var raw rawMetadata
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("composer: parsing package metadata: %w", err)
	}
	md := &Metadata{
		Minified: strings.TrimSpace(raw.Minified),
		Packages: make(map[string][]Version, len(raw.Packages)),
	}
	minified := strings.EqualFold(md.Minified, "composer/2.0")
	for name, rawVersions := range raw.Packages {
		expanded := rawVersions
		if minified {
			expanded = expandMinified(rawVersions)
		}
		versions := make([]Version, 0, len(expanded))
		for _, obj := range expanded {
			versions = append(versions, extractVersion(obj))
		}
		md.Packages[name] = versions
	}
	return md, nil
}

// expandMinified reverses Composer's MetadataMinifier delta encoding: the first
// object is complete, and each subsequent object carries only the keys that
// differ from the cumulative previous object, with the value "__unset" removing a
// key. It returns a slice of independent, fully-populated objects.
func expandMinified(in []map[string]json.RawMessage) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(in))
	// expanded accumulates the running state across versions.
	expanded := map[string]json.RawMessage{}
	for _, delta := range in {
		for key, val := range delta {
			if isUnset(val) {
				delete(expanded, key)
				continue
			}
			expanded[key] = val
		}
		// Snapshot a copy so later deltas do not mutate already-emitted objects.
		snapshot := make(map[string]json.RawMessage, len(expanded))
		for k, v := range expanded {
			snapshot[k] = v
		}
		out = append(out, snapshot)
	}
	return out
}

// isUnset reports whether a raw JSON value is the Composer "__unset" sentinel
// string.
func isUnset(val json.RawMessage) bool {
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return false
	}
	return s == "__unset"
}

// extractVersion pulls the typed fields the backend cares about out of an
// expanded version object. Unknown/absent fields are left zero; a malformed sub-
// field (e.g. a non-object "dist") is tolerated and simply yields a zero value.
func extractVersion(obj map[string]json.RawMessage) Version {
	var v Version
	v.Name = jsonString(obj["name"])
	v.Version = jsonString(obj["version"])
	if d, ok := obj["dist"]; ok {
		_ = json.Unmarshal(d, &v.Dist)
	}
	if l, ok := obj["license"]; ok {
		v.License = jsonStringSlice(l)
	}
	return v
}

// jsonString decodes a raw JSON value as a trimmed string, returning "" on any
// error or for a non-string value.
func jsonString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// jsonStringSlice decodes a raw JSON value as a string array, tolerating a bare
// string (which Composer also accepts for "license").
func jsonStringSlice(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	if s := jsonString(raw); s != "" {
		return []string{s}
	}
	return nil
}

// FindByReference returns the version whose dist reference matches the given
// reference, searching all packages in the document. It returns ok=false when no
// version carries that reference.
func (m *Metadata) FindByReference(reference string) (Version, bool) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Version{}, false
	}
	for _, versions := range m.Packages {
		for _, v := range versions {
			if v.Dist.Reference == reference {
				return v, true
			}
		}
	}
	return Version{}, false
}

// Checksum returns the parsed SHA-1 dist checksum of a version, and whether it
// carries a usable one.
func (v Version) Checksum() (expectedChecksum, bool) {
	shasum := strings.ToLower(strings.TrimSpace(v.Dist.Shasum))
	if len(shasum) == distShasumHexLen && isHex(shasum) {
		return expectedChecksum{hex: shasum}, true
	}
	return expectedChecksum{}, false
}

// rawRoot mirrors the packages.json root envelope for structural validation.
type rawRoot struct {
	MetadataURL  string          `json:"metadata-url"`
	ProvidersURL string          `json:"providers-url"`
	SearchURL    string          `json:"search"`
	ListURL      string          `json:"list"`
	Packages     json.RawMessage `json:"packages"`
}

// Root is the parsed form of a packages.json repository root.
type Root struct {
	MetadataURL  string
	ProvidersURL string
	SearchURL    string
	ListURL      string
}

// ParseRoot decodes and structurally validates a packages.json document. It is
// used to confirm the proxied root is well-formed and to surface the advertised
// metadata-url template; the proxy serves the document live regardless.
func ParseRoot(data []byte) (*Root, error) {
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("composer: packages.json exceeds %d bytes", maxMetadataBytes)
	}
	var raw rawRoot
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("composer: parsing packages.json: %w", err)
	}
	return &Root{
		MetadataURL:  strings.TrimSpace(raw.MetadataURL),
		ProvidersURL: strings.TrimSpace(raw.ProvidersURL),
		SearchURL:    strings.TrimSpace(raw.SearchURL),
		ListURL:      strings.TrimSpace(raw.ListURL),
	}, nil
}
