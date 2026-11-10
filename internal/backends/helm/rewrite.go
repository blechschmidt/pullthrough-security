package helm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// A chart repository's index.yaml tells the client where each chart archive
// lives (`entries.<chart>[].urls`). Real repositories publish absolute URLs
// there, frequently on another host than the index itself (a GitHub Pages index
// listing GitHub release assets is the common case). Served as-is, such an index
// sends the client straight to the upstream for the archive: past the cache,
// past the digest verification, past every admission gate. So the backend
// rewrites the index before serving it: every chart URL is replaced by an
// index-resolved URL under this backend's mount (see path.go), and the archive
// is fetched — from wherever the index says — by the proxy.
//
// The rewrite has to be sound: a URL the client can see but the rewriter missed
// is a hole. Three decisions follow from that.
//
// Structure comes from the YAML parser, not from pattern matching. What counts
// as an entry's `urls` is decided by a full parse of the document; the rewriter
// never guesses from the text.
//
// Keys are matched the way Helm matches them. Helm decodes the index through
// encoding/json (directly for a JSON index, via a YAML-to-JSON conversion
// otherwise), which matches object keys to struct fields case-insensitively
// under Unicode simple folding. `URLS:` and `urlſ:` are therefore `urls` to a
// Helm client (verified against helm v3.16), and so they are here; a repeated
// key is honored at every occurrence.
//
// Anything that could smuggle a URL past a structural walk is refused. YAML can
// introduce an entry's `urls` without spelling it at the place it applies: an
// alias (`urls: *u`, or `*k: [...]` as the key), a merge key (`<<: {urls: ...}`),
// a tagged key (`!!binary dXJscw==:` is base64 for "urls"). Helm's parser honors
// every one of these (again verified against the real client). No tool that
// generates an index emits them, so rather than emulate them the rewriter
// refuses the document: an index it cannot fully account for is not served.
//
// Only the URL scalars change. The parser reports where each one starts; the
// rewriter replaces exactly those bytes and copies every other byte of the
// document through untouched, so descriptions, annotations, ordering, comments
// and formatting — and any field this backend has never heard of — reach the
// client as the repository published them. Each replacement is checked against
// the source text first (the bytes at the reported position must spell the value
// the parser decoded), so a position that does not line up fails the rewrite
// instead of corrupting the document or leaving a URL behind.

// indexDocument is a scanned index.yaml: its chart entries in document order,
// with the source position of every chart URL.
type indexDocument struct {
	apiVersion string
	// hasEntries reports that the document carries an `entries` mapping (an
	// empty one counts; a missing or null one does not).
	hasEntries bool
	entries    []indexEntry
}

// indexEntry is one chart version as the index declares it.
type indexEntry struct {
	// chart is the key the entry is listed under in `entries`: the name a client
	// asks for (`helm pull <repo>/<chart>`) and the one the backend addresses the
	// entry by. name is the entry's own `name` field, normally identical.
	chart      string
	name       string
	version    string
	digest     string
	appVersion string
	deprecated bool
	urls       []urlScalar
}

// urlScalar is one element of an entry's `urls` sequence.
type urlScalar struct {
	// value is the scalar as the parser decoded it.
	value string
	// line and column locate the scalar's first character in the source
	// (1-based; the column counts characters, not bytes).
	line, column int
	style        yaml.Style
}

// location returns the URL the scalar declares, or "" when it declares none.
func (u urlScalar) location() string { return strings.TrimSpace(u.value) }

const (
	yamlNullTag  = "!!null"
	yamlMergeTag = "!!merge"
)

// scanIndexSource scans an upstream index and returns, with the scanned
// document, the bytes its positions refer to — the bytes to rewrite and serve.
//
// Those are the upstream's own bytes whenever the scanner accepts them. The one
// exception is a JSON index that is valid JSON but not valid YAML. A Helm client
// reads a JSON index with a JSON parser, and JSON allows spellings YAML does not:
// an escaped solidus ("https:\/\/…", PHP's default), a surrogate pair for a
// character outside the BMP ("\ud83d\ude80", Python's default), a raw DEL.
// Helm loads such an index; the YAML scanner cannot. Rather than refuse a
// repository every Helm client can use, the document is re-encoded as canonical
// JSON — the same value, in a spelling both parsers read identically — and that
// is what gets scanned, rewritten and served.
func scanIndexSource(data []byte) (*indexDocument, []byte, error) {
	doc, err := scanIndex(data)
	if err == nil {
		return doc, data, nil
	}
	canonical, ok := canonicalJSONIndex(data)
	if !ok {
		return nil, nil, err
	}
	doc, cerr := scanIndex(canonical)
	if cerr != nil {
		// Still not acceptable in canonical form: report the original complaint,
		// which describes the document the upstream actually published.
		return nil, nil, err
	}
	return doc, canonical, nil
}

// canonicalJSONIndex re-encodes a JSON document so that a YAML parser reads it
// exactly as a JSON parser does. It reports ok=false when data is not a single
// JSON object (a YAML index, or malformed JSON).
func canonicalJSONIndex(data []byte) ([]byte, bool) {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber() // carry numbers through as written
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false // trailing content: not a single JSON document
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, false
	}
	// encoding/json writes DEL (0x7f) raw, which YAML forbids unescaped. It can
	// only occur inside a string, so escaping every occurrence is exact.
	out := bytes.ReplaceAll(buf.Bytes(), []byte{0x7f}, []byte("\\u007f"))
	return out, true
}

// scanIndex parses an index.yaml document and walks the part of it that
// determines where charts are downloaded from, refusing any construct that
// could make a client see a chart URL the walk does not (see the file comment).
func scanIndex(data []byte) (*indexDocument, error) {
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("helm: index.yaml exceeds %d bytes", maxIndexBytes)
	}
	// The parser transcodes UTF-16 input, after which its positions no longer
	// index the bytes we hold. Nothing publishes a UTF-16 index.
	if bytes.HasPrefix(data, []byte{0xFF, 0xFE}) || bytes.HasPrefix(data, []byte{0xFE, 0xFF}) {
		return nil, errors.New("helm: index.yaml is not UTF-8")
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("helm: index.yaml is empty")
		}
		return nil, fmt.Errorf("helm: parsing index.yaml: %w", err)
	}
	// A client reads the first document of the stream. Insisting that nothing
	// but empty documents follows (a stray trailing "---" is harmless) removes
	// any room for disagreement about which document that is.
	for {
		var trailing yaml.Node
		err := dec.Decode(&trailing)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !emptyDocument(&trailing) {
			return nil, errors.New("helm: index.yaml holds more than one YAML document")
		}
	}

	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return nil, errors.New("helm: index.yaml is not a YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("helm: index.yaml is %s, not a mapping", describeNode(root))
	}

	out := &indexDocument{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		if err := checkKey(key); err != nil {
			return nil, err
		}
		switch {
		case strings.EqualFold(key.Value, "entries"):
			if err := out.scanEntries(val); err != nil {
				return nil, err
			}
		case strings.EqualFold(key.Value, "apiVersion"):
			out.apiVersion = scalarText(val)
		}
	}
	return out, nil
}

// scanEntries walks the `entries` mapping: chart name -> list of versions.
func (d *indexDocument) scanEntries(entries *yaml.Node) error {
	if isNull(entries) {
		return nil
	}
	if entries.Kind != yaml.MappingNode {
		return fmt.Errorf("helm: index.yaml line %d: entries is %s, not a mapping", entries.Line, describeNode(entries))
	}
	d.hasEntries = true
	for i := 0; i+1 < len(entries.Content); i += 2 {
		key, versions := entries.Content[i], entries.Content[i+1]
		if err := checkKey(key); err != nil {
			return err
		}
		if isNull(versions) {
			continue
		}
		if versions.Kind != yaml.SequenceNode {
			return fmt.Errorf("helm: index.yaml line %d: the versions of chart %q are %s, not a list",
				versions.Line, key.Value, describeNode(versions))
		}
		chart := strings.TrimSpace(key.Value)
		for _, item := range versions.Content {
			if isNull(item) {
				continue
			}
			if item.Kind != yaml.MappingNode {
				return fmt.Errorf("helm: index.yaml line %d: a version of chart %q is %s, not a mapping",
					item.Line, key.Value, describeNode(item))
			}
			entry, err := scanEntry(chart, item)
			if err != nil {
				return err
			}
			d.entries = append(d.entries, entry)
		}
	}
	return nil
}

// scanEntry reads one chart version. A field that is repeated (which a JSON
// index may do) takes its last value, as it does for a client; every `urls`
// occurrence contributes its URLs, so each of them is rewritten whichever one a
// given client ends up honoring.
func scanEntry(chart string, m *yaml.Node) (indexEntry, error) {
	e := indexEntry{chart: chart}
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		if err := checkKey(key); err != nil {
			return e, err
		}
		switch {
		case strings.EqualFold(key.Value, "urls"):
			if isNull(val) {
				continue
			}
			if val.Kind != yaml.SequenceNode {
				return e, fmt.Errorf("helm: index.yaml line %d: urls of chart %q is %s, not a list",
					val.Line, chart, describeNode(val))
			}
			for _, u := range val.Content {
				// A tag can change what the scalar means to a client (`!!binary`
				// is decoded) and an anchor lets it be referenced from elsewhere;
				// neither occurs in a generated index.
				if u.Kind != yaml.ScalarNode || u.Style&yaml.TaggedStyle != 0 || u.Anchor != "" {
					return e, fmt.Errorf("helm: index.yaml line %d: a url of chart %q is %s, not a plain string",
						u.Line, chart, describeNode(u))
				}
				e.urls = append(e.urls, urlScalar{value: u.Value, line: u.Line, column: u.Column, style: u.Style})
			}
		case strings.EqualFold(key.Value, "name"):
			e.name = scalarText(val)
		case strings.EqualFold(key.Value, "version"):
			e.version = scalarText(val)
		case strings.EqualFold(key.Value, "digest"):
			e.digest = scalarText(val)
		case strings.EqualFold(key.Value, "appVersion"):
			e.appVersion = scalarText(val)
		case strings.EqualFold(key.Value, "deprecated"):
			e.deprecated = strings.EqualFold(scalarText(val), "true")
		}
	}
	return e, nil
}

// checkKey accepts a mapping key only when it is spelled out where it applies:
// a scalar, without an explicit tag, that is not a merge key. Every other form
// can introduce a field (an entry's `urls`, or a whole entry) under a name the
// walk would not recognize.
//
// A merge key is recognized by its TEXT, not by how this parser tagged it. The
// two parsers disagree about what makes "<<" a merge: Helm's (yaml.v2) merges
// whenever the scalar is implicit, and a scalar carrying the non-specific tag
// "!" is implicit even when quoted — so `! "<<": {urls: [...]}` merges for a
// Helm client. yaml.v3, which reads the document here, drops that tag and
// reports an ordinary quoted string key. Judging by the tag alone let such a key
// through, and with it a chart URL the rewrite never saw (verified against helm
// v3.16). Refusing every key that spells "<<" costs nothing: an index where it
// is NOT a merge is rejected by Helm anyway (unknown field "<<").
func checkKey(k *yaml.Node) error {
	switch {
	case k.Kind != yaml.ScalarNode:
		return fmt.Errorf("helm: index.yaml line %d: a mapping key is %s, not a plain string", k.Line, describeNode(k))
	case k.Style&yaml.TaggedStyle != 0:
		return fmt.Errorf("helm: index.yaml line %d: mapping key %q carries an explicit tag (%s)", k.Line, k.Value, k.Tag)
	case k.Tag == yamlMergeTag, strings.TrimSpace(k.Value) == "<<":
		return fmt.Errorf("helm: index.yaml line %d: merge keys (<<) are not supported", k.Line)
	}
	return nil
}

// isNull reports whether n is a null scalar (an absent value).
func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == yamlNullTag
}

// emptyDocument reports whether a parsed document holds nothing at all.
func emptyDocument(doc *yaml.Node) bool {
	if doc.Kind != yaml.DocumentNode {
		return false
	}
	return len(doc.Content) == 0 ||
		(len(doc.Content) == 1 && isNull(doc.Content[0]) && doc.Content[0].Value == "" && doc.Content[0].Anchor == "")
}

// scalarText returns the trimmed text of an untagged scalar field, and "" for
// anything else (null, a collection, an alias, a tagged value). The fields read
// through it only label an entry; one the backend cannot read leaves the entry
// without a usable name or version, which makes it unaddressable rather than
// mislabeled.
func scalarText(n *yaml.Node) string {
	if n.Kind != yaml.ScalarNode || n.Style&yaml.TaggedStyle != 0 || n.Tag == yamlNullTag {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

// describeNode names a node's shape for an error message.
func describeNode(n *yaml.Node) string {
	switch n.Kind {
	case yaml.AliasNode:
		return "an alias"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		switch {
		case n.Style&yaml.TaggedStyle != 0:
			return "a tagged scalar (" + n.Tag + ")"
		case n.Anchor != "":
			return "an anchored scalar"
		case n.Tag == yamlNullTag:
			return "null"
		}
		return "a scalar"
	}
	return "an unexpected node"
}

// index builds the lookup form of the document. Entries without a version
// cannot be addressed as an artifact and are dropped; a digest that is not a
// well-formed SHA-256 is treated as absent.
func (d *indexDocument) index() *Index {
	idx := &Index{APIVersion: d.apiVersion, Entries: make(map[string][]ChartVersion)}
	for _, e := range d.entries {
		if e.version == "" {
			continue
		}
		cv := ChartVersion{
			Name:       firstNonEmpty(e.name, e.chart),
			Version:    e.version,
			URLs:       make([]string, 0, len(e.urls)),
			AppVersion: e.appVersion,
			Deprecated: e.deprecated,
		}
		for _, u := range e.urls {
			if loc := u.location(); loc != "" {
				cv.URLs = append(cv.URLs, loc)
			}
		}
		if hex, ok := normalizeDigest(e.digest); ok {
			cv.Digest = hex
		}
		idx.Entries[e.chart] = append(idx.Entries[e.chart], cv)
	}
	return idx
}

// linker mints the URLs a rewritten index hands to clients.
type linker struct {
	// base prefixes every link. It is the backend's absolute public base URL
	// with a trailing slash, or "" to emit references relative to the repository
	// URL — which every Helm client resolves against the URL it was given for
	// the repository, so they lead back to this mount with no configuration.
	base string
}

// archive returns the index-resolved URL of one of an entry's archives.
func (l linker) archive(chart, version, file string) string {
	return l.base + indexedPrefix + "/" + url.PathEscape(chart) + "/" + url.PathEscape(version) + "/" + url.PathEscape(file)
}

// unaddressable returns the URL substituted for the archives of an entry whose
// chart name or version cannot be carried in a URL path (empty, a dot segment,
// containing a path separator, ...). It leads to this mount but names nothing,
// so such an entry cannot be downloaded at all — rather than being downloaded
// from the upstream directly. Helm itself rejects these entries.
func (l linker) unaddressable() string {
	return l.base + indexedPrefix + "/unaddressable-entry"
}

// rewrite returns data with every chart URL replaced by a link under this
// backend's mount. A URL scalar that is empty names no location (a client
// resolves it to the repository itself) and is left alone; every other one is
// replaced, whatever it holds. When nothing needs replacing data is returned
// as-is.
func (d *indexDocument) rewrite(data []byte, links linker) ([]byte, error) {
	type patch struct {
		start, end int
		text       string
	}
	var (
		patches []patch
		cursor  = newSourceCursor(data)
		prevEnd int
		grow    int
	)
	for i := range d.entries {
		e := &d.entries[i]
		usable := addressable(e.chart) && addressable(e.version)
		for _, u := range e.urls {
			loc := u.location()
			if loc == "" {
				continue
			}
			start, ok := cursor.seek(u.line, u.column)
			if !ok {
				return nil, fmt.Errorf("helm: index.yaml line %d: cannot locate a url of chart %q in the source", u.line, e.chart)
			}
			end, ok := scalarEnd(data, start, u)
			if !ok || start < prevEnd {
				return nil, fmt.Errorf("helm: index.yaml line %d: a url of chart %q is not a single-line string", u.line, e.chart)
			}
			link := links.unaddressable()
			if usable {
				link = links.archive(e.chart, e.version, archiveFile(loc, e.chart, e.version))
			}
			if !quotable(link) {
				return nil, fmt.Errorf("helm: cannot express the proxied url of chart %q %q", e.chart, e.version)
			}
			patches = append(patches, patch{start: start, end: end, text: link})
			grow += len(link) + 2 - (end - start)
			prevEnd = end
		}
	}
	if len(patches) == 0 {
		return data, nil
	}

	out := make([]byte, 0, len(data)+grow)
	pos := 0
	for _, p := range patches {
		out = append(out, data[pos:p.start]...)
		// A double-quoted scalar is valid wherever the original scalar stood, in
		// block and flow context alike, and is equally a JSON string — so the
		// same replacement serves a YAML and a JSON index.
		out = append(out, '"')
		out = append(out, p.text...)
		out = append(out, '"')
		pos = p.end
	}
	return append(out, data[pos:]...), nil
}

// quotable reports whether s can stand between double quotes unescaped in both
// YAML and JSON: printable ASCII without a quote or a backslash. Links are built
// from a validated base and percent-encoded segments, so this always holds; it
// is checked so that a violation can never yield a malformed document.
func quotable(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return s != ""
}

// scalarEnd returns the offset just past the URL scalar starting at off, having
// confirmed that the source text there spells the value the parser decoded. It
// reports false for a scalar it cannot delimit with certainty: one that spans
// lines, a block scalar, or text that does not match the decoded value (which
// means off does not point where the parser said the scalar is).
func scalarEnd(data []byte, off int, u urlScalar) (int, bool) {
	switch {
	case u.style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		return 0, false
	case u.style&yaml.DoubleQuotedStyle != 0:
		return quotedEnd(data, off, '"', u.value)
	case u.style&yaml.SingleQuotedStyle != 0:
		return quotedEnd(data, off, '\'', u.value)
	}
	// A plain scalar has no escapes: confined to one line, its source text is
	// its value, byte for byte. (Folded across lines the two differ, since the
	// value holds a space where the source holds a line break.)
	end := off + len(u.value)
	if u.value == "" || end > len(data) || string(data[off:end]) != u.value || hasLineBreak(data[off:end]) {
		return 0, false
	}
	return end, true
}

// quotedEnd delimits a quoted scalar opening at off with the quote q. The
// closing quote is found by the scalar grammar itself — in double quotes a
// backslash escapes the next character, in single quotes a doubled quote is a
// literal one — and the enclosed text must decode to want.
func quotedEnd(data []byte, off int, q byte, want string) (int, bool) {
	if off >= len(data) || data[off] != q {
		return 0, false
	}
	escaped := false
	for i := off + 1; i < len(data); i++ {
		switch c := data[i]; {
		case c == '\\' && q == '"':
			escaped = true
			i++
		case c == q && q == '\'' && i+1 < len(data) && data[i+1] == q:
			escaped = true
			i++
		case c == q:
			inner := data[off+1 : i]
			if hasLineBreak(inner) || !decodesTo(data[off:i+1], inner, q, escaped, want) {
				return 0, false
			}
			return i + 1, true
		}
	}
	return 0, false
}

// decodesTo reports whether a quoted scalar decodes to want. Without escapes
// the enclosed text is the value; with them the scalar is decoded by the YAML
// parser itself, so the comparison uses the very rules that produced want.
func decodesTo(quoted, inner []byte, q byte, escaped bool, want string) bool {
	if !escaped {
		return string(inner) == want
	}
	if q == '\'' {
		return strings.ReplaceAll(string(inner), "''", "'") == want
	}
	var got string
	return yaml.Unmarshal(quoted, &got) == nil && got == want
}

// lineBreakWidth returns the byte length of the YAML line break starting at
// data[i], or 0 when there is none. YAML's line breaks are CR LF (one break),
// CR, LF, NEL (U+0085), LS (U+2028) and PS (U+2029); the parser counts lines by
// exactly these, so the cursor must too.
func lineBreakWidth(data []byte, i int) int {
	switch data[i] {
	case '\n':
		return 1
	case '\r':
		if i+1 < len(data) && data[i+1] == '\n' {
			return 2
		}
		return 1
	case 0xC2:
		if i+1 < len(data) && data[i+1] == 0x85 {
			return 2
		}
	case 0xE2:
		if i+2 < len(data) && data[i+1] == 0x80 && (data[i+2] == 0xA8 || data[i+2] == 0xA9) {
			return 3
		}
	}
	return 0
}

// hasLineBreak reports whether b contains a YAML line break.
func hasLineBreak(b []byte) bool {
	for i := range b {
		if lineBreakWidth(b, i) > 0 {
			return true
		}
	}
	return false
}

// sourceCursor converts the parser's (line, column) positions into byte offsets
// of the source. It only moves forward — positions are requested in document
// order — so converting every URL of a document costs one pass over it, however
// long its lines are (a JSON index is commonly a single line).
type sourceCursor struct {
	data []byte
	line int // 1-based line the cursor is on
	col  int // 1-based character column of the cursor
	off  int // byte offset of the cursor
}

func newSourceCursor(data []byte) *sourceCursor {
	c := &sourceCursor{data: data, line: 1, col: 1}
	// The parser consumes a leading byte-order mark before it starts counting.
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		c.off = 3
	}
	return c
}

// seek advances to the given position and returns its byte offset. It reports
// false when the position lies behind the cursor or outside the source; the
// cursor is not usable after that.
func (c *sourceCursor) seek(line, col int) (int, bool) {
	if line < c.line || (line == c.line && col < c.col) {
		return 0, false
	}
	data, off := c.data, c.off
	for c.line < line {
		// Skip to just past the next line break. Only four byte values can begin
		// one, so the common case is a plain byte scan.
		for {
			if off >= len(data) {
				return 0, false
			}
			if b := data[off]; b == '\n' || b == '\r' || b == 0xC2 || b == 0xE2 {
				if w := lineBreakWidth(data, off); w > 0 {
					off += w
					break
				}
			}
			off++
		}
		c.line++
		c.col = 1
	}
	for c.col < col {
		if off >= len(data) {
			return 0, false
		}
		size := 1
		if b := data[off]; b == '\n' || b == '\r' {
			return 0, false
		} else if b >= utf8.RuneSelf {
			if lineBreakWidth(data, off) > 0 {
				return 0, false
			}
			_, size = utf8.DecodeRune(data[off:])
		}
		off += size
		c.col++
	}
	c.off = off
	return off, true
}

// archiveFile derives the final path segment of the index-resolved URL for one
// of an entry's listed locations. Helm saves a pulled chart under the basename
// of the URL it downloaded, so the basename of the upstream location is kept
// whenever it can be: a client sees the filename it would have seen going
// direct. A location with no usable basename — or one that is not an HTTP(S) or
// relative URL at all — falls back to the conventional "<chart>-<version>.tgz".
//
// The result selects, among an entry's locations, the one a request means, so
// it must be a pure function of its arguments; it is always addressable and
// never ends in ".prov" (which would read as a provenance request).
func archiveFile(location, chart, version string) string {
	canonical := chart + "-" + version + chartExt
	if !addressable(canonical) {
		// Only reachable when the two together exceed the segment bound.
		canonical = "chart" + chartExt
	}
	rest := location
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	// Drop a scheme and authority so the host is never mistaken for a filename.
	hasAuthority := false
	if i := strings.Index(rest, "://"); i > 0 && isScheme(rest[:i]) {
		if s := strings.ToLower(rest[:i]); s != "http" && s != "https" {
			return canonical
		}
		rest, hasAuthority = rest[i+3:], true
	} else if strings.HasPrefix(rest, "//") {
		rest, hasAuthority = rest[2:], true
	}
	if hasAuthority {
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			return canonical
		}
		rest = rest[i:]
	}
	base, err := url.PathUnescape(rest[strings.LastIndexByte(rest, '/')+1:])
	if err != nil || !addressable(base) || strings.HasSuffix(base, provExt) {
		return canonical
	}
	return base
}

// isScheme reports whether s is a syntactically valid URL scheme.
func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return s != ""
}
