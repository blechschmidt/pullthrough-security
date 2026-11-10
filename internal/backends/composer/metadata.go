package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Composer/Packagist exposes package data through two document families the proxy
// must understand:
//
//   - packages.json — the repository root. It advertises the templated URLs a
//     client expands to reach per-package metadata ("metadata-url", typically
//     "/p2/%package%.json") and, historically, provider listings. The proxy
//     serves it live (it is mutable), rewritten so every lookup it advertises
//     comes back through the proxy (see rewrite.go).
//
//   - /p2/<vendor>/<package>.json — the Composer v2 metadata layout: the list of
//     published versions for one package, each carrying its dist archive
//     coordinates (type, URL, source reference, and SHA-1 shasum), requirements,
//     and license. The proxy serves it live with every dist URL rewritten to its
//     own dist endpoint, and re-reads it on a dist request to recover the real
//     download URL and the shasum used to verify the fetched archive, and to
//     surface license metadata to the license-compliance gate.
//
// The v2 layout is usually "minified" ("minified":"composer/2.0"): within a
// package's version array, the first object is complete and each subsequent
// object carries only the keys that changed from the previous one, with the
// sentinel value "__unset" meaning "remove this key". ParseMetadata expands that
// delta encoding back into independent, fully-populated version objects.
//
// Everything here reads a document the way a Composer client does — exact,
// case-sensitive keys; string-typed values only; the exact "composer/2.0" marker;
// a version collection that may be a JSON array or a JSON object — because the
// proxy rewrites what the client will read and later resolves what the client
// asks for. If the two disagreed about which version an entry describes or which
// URL it declares, a dist could be served under the wrong coordinate.

// maxMetadataBytes bounds how much of a Composer metadata document the backend
// parses. Per-package v2 files are at most a few hundred KiB even for packages
// with a long release history; the root packages.json is small.
const maxMetadataBytes = 16 << 20 // 16 MiB

// minifiedFormat is the "minified" marker value that announces the delta
// encoding. Composer compares it for strict equality, and so does the proxy.
const minifiedFormat = "composer/2.0"

// unsetSentinel is the value that removes an inherited key in the minified
// delta encoding.
const unsetSentinel = "__unset"

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

// document is the decoded envelope of a v2 metadata document: its top-level
// object (kept raw so unknown keys such as "security-advisories" survive a
// rewrite byte-for-byte), whether its version lists are delta-encoded, and the
// raw per-package version collections.
type document struct {
	top      map[string]json.RawMessage
	minified bool
	// packages maps a package name to its raw version collection. It is nil when
	// the document has no usable "packages" object.
	packages map[string]json.RawMessage
}

// parseDocument decodes the envelope of a v2 metadata document. It is an error
// if the body is not a JSON object or exceeds the size bound.
func parseDocument(data []byte) (*document, error) {
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("composer: metadata document exceeds %d bytes", maxMetadataBytes)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("composer: parsing package metadata: %w", err)
	}
	if top == nil {
		return nil, errors.New("composer: package metadata is not a JSON object")
	}
	doc := &document{top: top}
	if marker, ok := exactString(top["minified"]); ok {
		doc.minified = marker == minifiedFormat
	}
	// "packages" is an object keyed by package name. PHP encodes an empty map as
	// "[]", so a value that is not an object simply means "no packages".
	if raw, ok := top["packages"]; ok {
		var packages map[string]json.RawMessage
		if err := json.Unmarshal(raw, &packages); err == nil {
			doc.packages = packages
		}
	}
	return doc, nil
}

// versionList is one package's version collection in document order. A Composer
// client walks it with a PHP foreach, which iterates a JSON array and a JSON
// object alike, so both shapes are accepted. keys is nil for an array and holds
// the object's keys otherwise, so the collection can be re-encoded in the shape
// it arrived in.
type versionList struct {
	keys  []string
	items []json.RawMessage
}

// parseVersionList decodes a package's raw version collection. ok=false means the
// value is neither an array nor an object, i.e. nothing a client could iterate.
func parseVersionList(raw json.RawMessage) (*versionList, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false
	}
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, false
		}
		return &versionList{items: items}, true
	case '{':
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if _, err := dec.Token(); err != nil { // consume '{'
			return nil, false
		}
		list := &versionList{keys: []string{}}
		seen := map[string]int{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return nil, false
			}
			key, isKey := tok.(string)
			if !isKey {
				return nil, false
			}
			var item json.RawMessage
			if err := dec.Decode(&item); err != nil {
				return nil, false
			}
			// A repeated key keeps its first position and takes the last value,
			// exactly as a PHP array built by json_decode does.
			if i, dup := seen[key]; dup {
				list.items[i] = item
				continue
			}
			seen[key] = len(list.keys)
			list.keys = append(list.keys, key)
			list.items = append(list.items, item)
		}
		return list, true
	default:
		return nil, false
	}
}

// marshal re-encodes the collection in its original shape.
func (l *versionList) marshal() (json.RawMessage, error) {
	if l.keys == nil {
		return encodeArray(l.items), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range l.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(&buf, key); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		writeRawValue(&buf, l.items[i])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// objects decodes the collection's elements into raw key/value maps, skipping any
// element that is not a JSON object (a client cannot load such an element either).
func (l *versionList) objects() []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(l.items))
	for _, item := range l.items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil || obj == nil {
			continue
		}
		out = append(out, obj)
	}
	return out
}

// ParseMetadata decodes a /p2/<vendor>/<package>.json document, expanding the
// Composer v2 minified delta encoding when present. It is an error if the body is
// not a JSON object or exceeds the size bound; an empty or package-less document
// parses to an empty Metadata so callers can serve it without special-casing.
func ParseMetadata(data []byte) (*Metadata, error) {
	doc, err := parseDocument(data)
	if err != nil {
		return nil, err
	}
	md := &Metadata{Packages: make(map[string][]Version, len(doc.packages))}
	if marker, ok := exactString(doc.top["minified"]); ok {
		md.Minified = strings.TrimSpace(marker)
	}
	for name, raw := range doc.packages {
		list, ok := parseVersionList(raw)
		if !ok {
			continue
		}
		expanded := list.objects()
		if doc.minified {
			expanded = expandMinified(expanded)
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
	s, ok := exactString(val)
	return ok && s == unsetSentinel
}

// extractVersion pulls the typed fields the backend cares about out of an
// expanded version object. Unknown/absent fields are left zero; a malformed sub-
// field (e.g. a non-object "dist") is tolerated and simply yields a zero value.
func extractVersion(obj map[string]json.RawMessage) Version {
	var v Version
	v.Name = jsonString(obj["name"])
	v.Version, _ = exactString(obj["version"])
	if d, ok := parseDist(obj["dist"]); ok {
		v.Dist = d
	}
	if l, ok := obj["license"]; ok {
		v.License = jsonStringSlice(l)
	}
	return v
}

// parseDist decodes a version's "dist" value. ok=false means the value is not a
// dist a Composer client could download: it is not an object, lacks a string
// "type" or "url" (Composer requires both), or carries a non-string reference.
func parseDist(raw json.RawMessage) (Dist, bool) {
	if len(raw) == 0 {
		return Dist{}, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return Dist{}, false
	}
	return distFromObject(obj)
}

// distFromObject reads the dist fields out of a decoded dist object (see
// parseDist for the acceptance rules).
func distFromObject(obj map[string]json.RawMessage) (Dist, bool) {
	var (
		d  Dist
		ok bool
	)
	if d.Type, ok = exactString(obj["type"]); !ok || d.Type == "" {
		return Dist{}, false
	}
	if d.URL, ok = exactString(obj["url"]); !ok || d.URL == "" {
		return Dist{}, false
	}
	if d.Reference, ok = optionalString(obj["reference"]); !ok {
		return Dist{}, false
	}
	// A shasum that is not a string cannot be a digest; it is treated as absent.
	d.Shasum, _ = optionalString(obj["shasum"])
	return d, true
}

// exactString decodes a raw JSON value that is a string, without trimming or
// otherwise normalizing it. ok=false for an absent value or any other JSON type
// (including null).
func exactString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// optionalString decodes a raw JSON value that may legitimately be missing: an
// absent or null value yields ("", true), a string yields its exact value, and
// any other JSON type yields ok=false.
func optionalString(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", true
	}
	return exactString(raw)
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

// marshalJSON encodes a value the proxy itself produces (a URL, a key, a small
// structure) as compact JSON without HTML-escaping.
func marshalJSON(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// encodeObject assembles a JSON object from raw member values, with its keys in
// sorted order. The values are written exactly as given: they came out of a
// successful decode, so they are valid JSON, and copying them verbatim keeps
// everything a rewrite does not touch byte-identical (and spares re-scanning a
// large document once per nesting level).
func encodeObject(obj map[string]json.RawMessage) (json.RawMessage, error) {
	keys := make([]string, 0, len(obj))
	size := 2
	for k, v := range obj {
		keys = append(keys, k)
		size += len(k) + len(v) + 4
	}
	sort.Strings(keys)
	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeJSONString(buf, k); err != nil {
			return nil, err
		}
		buf.WriteByte(':')
		writeRawValue(buf, obj[k])
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// encodeArray assembles a JSON array from raw element values, written exactly as
// given (see encodeObject).
func encodeArray(items []json.RawMessage) json.RawMessage {
	size := 2
	for _, item := range items {
		size += len(item) + 1
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	buf.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeRawValue(buf, item)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

// writeRawValue writes a raw JSON value, substituting null for an empty one so
// the output is well-formed whatever it is handed.
func writeRawValue(buf *bytes.Buffer, raw json.RawMessage) {
	if len(bytes.TrimSpace(raw)) == 0 {
		buf.WriteString("null")
		return
	}
	buf.Write(raw)
}

// writeJSONString writes s as a JSON string. Plain keys — which is all a
// metadata document has — are quoted directly; anything needing an escape goes
// through the encoder.
func writeJSONString(buf *bytes.Buffer, s string) error {
	plain := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			plain = false
			break
		}
	}
	if plain {
		buf.WriteByte('"')
		buf.WriteString(s)
		buf.WriteByte('"')
		return nil
	}
	enc, err := marshalJSON(s)
	if err != nil {
		return err
	}
	buf.Write(enc)
	return nil
}

// FindDist returns the entry of the named package that has exactly the given
// version, dist reference token (see referenceToken) and dist type. All three
// must match the same entry: a dist request names a version for the admission
// gates and a reference for content addressing, and the pair is only honored when
// the upstream metadata lists it — so a request cannot borrow an allowed
// version's name to fetch another version's archive, nor fetch a reference the
// upstream never published for that version.
func (m *Metadata) FindDist(name, version, token, distType string) (Version, bool) {
	if m == nil || version == "" || token == "" {
		return Version{}, false
	}
	for _, v := range m.Packages[name] {
		if v.Version == version && v.Dist.URL != "" && v.Dist.Type == distType && referenceToken(v.Dist.Reference) == token {
			return v, true
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

// ParseRoot decodes and structurally validates a packages.json document,
// surfacing the lookup templates it advertises.
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
