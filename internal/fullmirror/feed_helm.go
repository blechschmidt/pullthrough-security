package fullmirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/pullthrough-security/internal/backends/helm"
)

// helm follows a classic chart repository's index (Task 191).
//
// A chart repository publishes one document, index.yaml, listing every chart
// version with its archive URLs and digest; Helm has no central registry, so
// the feed covers the one repository the upstream fronts. Changes reads the
// index conditionally (If-None-Match / If-Modified-Since with the validators
// of the copy read last: an unchanged index costs a 304) and diffs it against
// the stored copy, one record per chart version: a version added or changed
// (republished with another digest, or moved to another URL) is reported as
// chart@version, a chart or a version gone as deleted. Bootstrap lists every
// chart of the index. Redirects are followed (Bitnami's index lives on
// repo.broadcom.com); the upstream's credentials go only to its own origin.
//
// Releases comes from the stored copy: each version with one artifact, the
// path the backend's rewritten index hands a client for the version's first
// URL — the one Helm downloads — "/-/<chart>/<version>/<file>"
// (helm.ArchivePath), which the backend serves by looking the entry up in its
// own copy of the index. A version's `created` is not kept (no Published):
// `helm repo index` without --merge stamps every entry anew, and every
// version would be reported again at each publication. Provenance files
// (.prov) are not mirrored: the index does not say which charts have one.
//
// A version is reported once it has been listed for the settle period (feed
// option "settle", default 15m; see feed_firstseen.go): the backend serves an
// archive only once its own copy of the index lists it, and a CDN (GitHub
// Pages caches an index for 10 minutes) may still hand it an older index —
// the archive would be answered 404, which the engine does not retry. The
// period counts from the poll that first saw the version (on a first read,
// from its `created`, or from the index's Last-Modified for a version created
// less than a day before it).
//
// Indexes are large (Bitnami's is 27.6 MB) and parsing one with yaml.v3 holds
// a node tree ten times its size, so the index is read as a stream by a
// reader of the block-style YAML chart repositories publish (`helm repo
// index`, chart-releaser, ChartMuseum, Artifactory): it keeps one line and one
// entry in memory and reads only entries.<chart>[].{version, digest, created,
// urls}. It is a strict subset of YAML — anything it cannot vouch for reading
// exactly as yaml.v3 does (flow collections, anchors, aliases, tags, several
// documents, a JSON index, a tab where a space is expected, a value spanning
// lines where one is read) fails it; an index of at most 8 MiB is then read
// whole by the backend's own parser (helm.ParseIndex) and yaml.v3, a larger one
// is refused. Like the backend, it refuses merge keys, and an entry whose chart
// key, version or URL the rewrite cannot address is not mirrored.
//
// The upstream's index is "<url>/index.yaml" for any upstream (ChartMuseum,
// Artifactory, Nexus, GitLab and Harbor serve one); the feed option "url"
// names another copy of it (a document, or a repository whose index.yaml is
// read). An upstream serving charts from an OCI registry (setting oci: true)
// has no index and cannot be followed.

// Bounds of the helm feed.
const (
	// helmMaxIndex bounds the index, compressed and not: the backend refuses
	// a larger one (helm maxIndexBytes), so nothing in it could be served.
	helmMaxIndex = 128 << 20
	// helmWholeMax is the size up to which an index the streaming reader
	// does not handle is read whole.
	helmWholeMax = 8 << 20
	// helmMaxLine bounds one line of an index.
	helmMaxLine = 1 << 20
	// helmMaxDepth bounds the nesting of an index.
	helmMaxDepth = 64
	// helmMaxCharts bounds the charts of one index.
	helmMaxCharts = 500_000
	// helmDefaultSettle is how long a version is listed before it is
	// reported: GitHub Pages, where most chart repositories live, caches an
	// index for 10 minutes.
	helmDefaultSettle = 15 * time.Minute
	// helmFirstSeenFile keeps when the feed first saw each version.
	helmFirstSeenFile = "helm-firstseen.bin"
)

type helmFeed struct {
	*indexFeed
	src *helmSource
}

func newHelmFeed(env Env) (Feed, error) {
	opts, err := parseOptions(env, "url", "settle")
	if err != nil {
		return nil, err
	}
	k, err := newKit(env)
	if err != nil {
		return nil, err
	}
	settle, err := gitSettleOption(opts, helmDefaultSettle)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(env.Settings["oci"]), "true") {
		return nil, fmt.Errorf("upstream %s serves Helm charts from an OCI registry (setting oci), which publishes no index.yaml to follow: it cannot be mirrored as a whole (see docs/full-mirroring.md#helm)", k.upstream.Redacted())
	}
	index := join(k.upstream, "index.yaml")
	if raw := opts["url"]; raw != "" {
		u, err := parseBaseURL("the feed option url", raw)
		if err != nil {
			return nil, err
		}
		index = join(u, "index.yaml")
		if p := strings.ToLower(u.Path); strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".json") {
			index = u.String()
		}
	}
	src := &helmSource{k: k, files: files{dir: env.Dir}, index: index, wholeMax: helmWholeMax, settle: settle, now: time.Now}
	return &helmFeed{indexFeed: newIndexFeed("helm", env, src), src: src}, nil
}

func init() { Register("helm", newHelmFeed) }

// Releases lists a chart's versions from the stored copy of the index, in
// SemVer order (versions that do not parse first), each with the archive a
// client downloads.
func (f *helmFeed) Releases(_ context.Context, name string) ([]Release, error) {
	recs, err := f.lookup(name)
	if err != nil {
		return nil, err
	}
	rels := snapReleases(recs)
	// internal/versions has no Helm scheme (orderReleases would keep the
	// copy's order, which is by version string).
	sort.SliceStable(rels, func(i, j int) bool { return helmCompareVersions(rels[i].Version, rels[j].Version) < 0 })
	return rels, nil
}

// helmSource reads a repository's index.
type helmSource struct {
	k     kit
	files files
	// index is the index document's URL.
	index string
	// wholeMax is the size up to which an index the streaming reader does
	// not handle is read whole (helmWholeMax; lowered by tests).
	wholeMax int
	// settle is how long a version is listed before it is reported.
	settle time.Duration
	// now is this host's clock.
	now func() time.Time
}

// helmState is what the next read of the index is conditioned on.
type helmState struct {
	URL string `json:"url"`
	httpValidators
	// Pending is when (Unix seconds, this host's clock) the earliest version
	// held back settles: the index is then read even if unchanged.
	Pending int64 `json:"pending,omitempty"`
}

func (s *helmSource) readIndex(ctx context.Context, prev json.RawMessage, old *snapHeader, b *snapBuilder) (indexRead, error) {
	var st helmState
	if prev != nil && json.Unmarshal(prev, &st) != nil {
		st = helmState{}
	}
	local := s.now()
	hdr := http.Header{}
	if old != nil && st.URL == s.index && (st.Pending == 0 || local.Unix() < st.Pending) {
		st.httpValidators.set(hdr)
	}
	resp, body, err := s.k.getStream(ctx, s.index, hdr, helmMaxIndex)
	if errors.Is(err, errNotModified) {
		if len(hdr) == 0 {
			return indexRead{}, fmt.Errorf("%s answered an unconditional request with 304", s.index)
		}
		return indexRead{Unchanged: true}, nil
	}
	if err != nil {
		return indexRead{}, err
	}
	defer body.Close()
	content, release, err := openContent(body, s.index, helmMaxIndex)
	if err != nil {
		return indexRead{}, err
	}
	defer release()
	table := firstSeenOpen(s.files, helmFirstSeenFile, s.index, s.settle, resp, local)
	generated, err := s.read(content, func(e helmEntry) { helmAdd(b, table, e) })
	if err != nil {
		return indexRead{}, err
	}
	if err := table.save(); err != nil {
		return indexRead{}, err
	}
	state, _ := json.Marshal(helmState{URL: s.index, httpValidators: validatorsOf(resp), Pending: table.due(local)})
	rd := indexRead{State: state}
	if generated != "" && len(generated) <= 64 && cleanName(generated) {
		rd.Head = generated
		if t, err := time.Parse(time.RFC3339Nano, generated); err == nil {
			rd.HeadTime = t.UTC()
		}
	}
	return rd, nil
}

// read reads the index, calling add with each chart version, and returns its
// `generated` stamp: as a stream, or — an index of at most wholeMax bytes the
// streaming reader does not handle — whole.
func (s *helmSource) read(content io.Reader, add func(helmEntry)) (string, error) {
	head, err := io.ReadAll(io.LimitReader(content, int64(s.wholeMax)+1))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", s.index, err)
	}
	var unsupported *helmUnsupportedError
	if len(head) <= s.wholeMax {
		var entries []helmEntry
		generated, err := helmScanIndex(bytes.NewReader(head), func(e helmEntry) error {
			entries = append(entries, e)
			return nil
		})
		if errors.As(err, &unsupported) {
			entries, generated, err = helmReadIndexWhole(head)
			if err != nil {
				return "", Permanent(fmt.Errorf("%s is not an index the proxy's helm backend serves: %w", s.index, err))
			}
		} else if err != nil {
			return "", fmt.Errorf("%s: %w", s.index, err)
		}
		for _, e := range entries {
			add(e)
		}
		return generated, nil
	}
	generated, err := helmScanIndex(io.MultiReader(bytes.NewReader(head), content), func(e helmEntry) error {
		add(e)
		return nil
	})
	if errors.As(err, &unsupported) {
		return "", Permanent(fmt.Errorf("%s: the index is larger than %d MiB and uses YAML the streaming reader does not handle (%v); see docs/full-mirroring.md#helm", s.index, s.wholeMax>>20, unsupported))
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", s.index, err)
	}
	return generated, nil
}

// helmAdd adds a chart version's record — its archive at the path the backend
// rewrites its first URL to — once it has been listed for the settle period.
// An entry the rewrite cannot address is left out.
func helmAdd(b *snapBuilder, table *firstSeenTable, e helmEntry) {
	p, ok := helm.ArchivePath(e.Chart, e.Version, e.URL)
	if !ok {
		return
	}
	rec := snapRecord{Name: e.Chart, Version: e.Version, Path: p, Digest: helmDigest(e.Digest)}
	if !rec.valid() {
		return
	}
	var created int64
	if t, err := time.Parse(time.RFC3339Nano, e.Created); err == nil && t.Unix() > 0 {
		created = t.Unix()
	}
	if table.admit(&rec, created) {
		b.Add(rec)
	}
}

// helmDigest is what a record keeps of an entry's digest: enough of it to see
// the archive republished.
func helmDigest(d string) string {
	d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "sha256:"))
	if len(d) > 16 {
		d = d[:16]
	}
	if !snapValidString(d, 256) {
		return ""
	}
	return d
}

// helmEntry is what the feed reads of one chart version.
type helmEntry struct {
	// Chart is the key the version is listed under in `entries` (trimmed):
	// the name the backend addresses it by.
	Chart string `json:"chart"`
	// Version, Digest and Created are the entry's fields, trimmed ("" when
	// absent or null).
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
	Created string `json:"created,omitempty"`
	// URL is the first non-empty element of the entry's urls.
	URL string `json:"url,omitempty"`
}

// helmField identifies the entry fields the feed reads, matched the way the
// backend (and a Helm client) matches keys: case-insensitively.
func helmField(key string) int {
	for i, f := range [...]string{"version", "digest", "created", "urls"} {
		if strings.EqualFold(key, f) {
			return i
		}
	}
	return -1
}

const (
	helmFieldVersion = iota
	helmFieldDigest
	helmFieldCreated
	helmFieldURLs
)

// --- the streaming reader ------------------------------------------------------

// helmUnsupportedError is what the streaming reader reports for anything it
// does not handle: a construct outside its subset of YAML, or a syntax error.
type helmUnsupportedError struct {
	line int
	what string
}

func (e *helmUnsupportedError) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.what) }

func helmUnsupported(line int, format string, args ...any) error {
	return &helmUnsupportedError{line: line, what: fmt.Sprintf(format, args...)}
}

// errHelmNoEntries reports an index without an entries map.
var errHelmNoEntries = errors.New("the index has no entries map")

// helmLine is one line of an index: its text without the line break, and the
// spaces it is indented by.
type helmLine struct {
	text   []byte // after the indentation
	indent int
	num    int
}

func (l *helmLine) blank() bool   { return len(l.text) == 0 }
func (l *helmLine) comment() bool { return len(l.text) > 0 && l.text[0] == '#' }

// helmLineReader yields an index's lines, checked as yaml.v3's reader checks
// its input — valid UTF-8 of the characters YAML allows — and refusing the
// line breaks it would see where this reader does not (a lone CR, NEL, LS,
// PS).
type helmLineReader struct {
	br     *bufio.Reader
	long   []byte // a line longer than br's buffer, assembled
	num    int
	peeked *helmLine
	eof    bool
	err    error
}

func newHelmLineReader(r io.Reader) *helmLineReader {
	return &helmLineReader{br: bufio.NewReaderSize(r, 64<<10)}
}

// readLine reads the next line with its line break: a slice of the reader's
// buffer, or of long for a line longer than the buffer.
func (r *helmLineReader) readLine() ([]byte, error) {
	r.long = r.long[:0]
	for {
		frag, err := r.br.ReadSlice('\n')
		if err == bufio.ErrBufferFull || len(r.long) > 0 {
			if len(r.long)+len(frag) > helmMaxLine+2 {
				return nil, helmUnsupported(r.num+1, "a line longer than %d bytes", helmMaxLine)
			}
			r.long = append(r.long, frag...)
			if err == bufio.ErrBufferFull {
				continue
			}
			frag = r.long
		}
		return frag, err
	}
}

// peek returns the next line without consuming it (nil at the end).
func (r *helmLineReader) peek() (*helmLine, error) {
	if r.peeked != nil || r.err != nil || r.eof {
		return r.peeked, r.err
	}
	raw, err := r.readLine()
	var unsupported *helmUnsupportedError
	switch {
	case errors.As(err, &unsupported):
		r.err = err
		return nil, err
	case err == io.EOF:
		if len(raw) == 0 {
			r.eof = true
			return nil, nil
		}
	case err != nil:
		r.err = err
		return nil, err
	}
	r.num++
	raw = bytes.TrimSuffix(raw, []byte{'\n'})
	raw = bytes.TrimSuffix(raw, []byte{'\r'})
	if r.num == 1 {
		raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	}
	if err := helmCheckLine(raw, r.num); err != nil {
		r.err = err
		return nil, err
	}
	indent := 0
	for indent < len(raw) && raw[indent] == ' ' {
		indent++
	}
	r.peeked = &helmLine{text: append([]byte(nil), raw[indent:]...), indent: indent, num: r.num}
	return r.peeked, nil
}

// next consumes the line peek returned.
func (r *helmLineReader) next() { r.peeked = nil }

// helmCheckLine refuses a line holding a character yaml.v3 refuses, or one it
// reads as a line break.
func helmCheckLine(b []byte, num int) error {
	for i := 0; i < len(b); {
		c := b[i]
		if c >= 0x20 && c < 0x7f || c == '\t' {
			i++
			continue
		}
		if c < 0x80 {
			return helmUnsupported(num, "control character %#x", c)
		}
		r, size := utf8.DecodeRune(b[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			return helmUnsupported(num, "invalid UTF-8")
		case r == 0x85 || r == 0x2028 || r == 0x2029:
			return helmUnsupported(num, "a line break other than LF")
		case r == 0xFEFF:
			return helmUnsupported(num, "a byte-order mark inside the document")
		case r < 0xA0, r >= 0xD800 && r < 0xE000, r == 0xFFFE, r == 0xFFFF:
			return helmUnsupported(num, "character %U", r)
		}
		i += size
	}
	return nil
}

// helmParser reads an index from a helmLineReader.
type helmParser struct {
	r          *helmLineReader
	emit       func(helmEntry) error
	depth      int
	charts     map[string]struct{}
	sawEntries bool
	hasEntries bool
	generated  string
}

// helmScanIndex reads an index as a stream, calling emit for every chart
// version that has a version, in document order, and returns the index's
// `generated` stamp. A construct the reader does not handle is a
// *helmUnsupportedError.
func helmScanIndex(r io.Reader, emit func(helmEntry) error) (string, error) {
	p := &helmParser{r: newHelmLineReader(r), emit: emit, charts: map[string]struct{}{}}
	if err := p.document(); err != nil {
		return "", err
	}
	if !p.hasEntries {
		return "", Permanent(errHelmNoEntries)
	}
	return p.generated, nil
}

// peekContent skips blank and comment lines and returns the next line.
func (p *helmParser) peekContent() (*helmLine, error) {
	for {
		l, err := p.r.peek()
		if err != nil || l == nil {
			return nil, err
		}
		if !l.blank() && !l.comment() {
			if l.text[0] == '\t' {
				return nil, helmUnsupported(l.num, "a tab where indentation is expected")
			}
			return l, nil
		}
		p.r.next()
	}
}

// helmDocMarker reports a document marker ("---" or "...") at the start of a
// line.
func helmDocMarker(l *helmLine) bool {
	t := l.text
	return l.indent == 0 && len(t) >= 3 && (string(t[:3]) == "---" || string(t[:3]) == "...") && (len(t) == 3 || t[3] == ' ' || t[3] == '\t')
}

// helmEntryLine reports a block sequence entry ("-" then a blank or the end).
func helmEntryLine(t []byte) bool {
	return len(t) > 0 && t[0] == '-' && (len(t) == 1 || t[1] == ' ' || t[1] == '\t')
}

// document reads the document: one block mapping at the top, nothing but
// empty documents after it.
func (p *helmParser) document() error {
	l, err := p.peekContent()
	if err != nil {
		return err
	}
	if l == nil {
		return helmUnsupported(p.r.num, "an empty document")
	}
	if l.indent == 0 && l.text[0] == '%' {
		return helmUnsupported(l.num, "a directive")
	}
	if helmDocMarker(l) {
		if string(l.text[:3]) == "..." || !helmTrailer(l.text[3:]) {
			return helmUnsupported(l.num, "content on the document's first line")
		}
		p.r.next()
		if l, err = p.peekContent(); err != nil {
			return err
		}
		if l == nil {
			return helmUnsupported(p.r.num, "an empty document")
		}
	}
	if l.indent != 0 {
		return helmUnsupported(l.num, "an indented top level")
	}
	if err := p.mapping(0, nil, p.topKey); err != nil {
		return err
	}
	for {
		l, err := p.peekContent()
		if err != nil {
			return err
		}
		if l == nil {
			return nil
		}
		if !helmDocMarker(l) || !helmTrailer(l.text[3:]) {
			return helmUnsupported(l.num, "content after the document")
		}
		p.r.next()
	}
}

// helmKind is the shape of a value the parser consumed.
type helmKind int

const (
	helmNull       helmKind = iota
	helmScalar              // a scalar on one line
	helmLongScalar          // a scalar over several lines, or a block scalar
	helmMap                 // a block mapping, or {}
	helmSeq                 // a block sequence, or []
)

// helmNested handles the collections a value holds; a nil handler skips
// them.
type helmNested struct {
	// mapping reads a block mapping whose keys are at col; first is its
	// first key line when it starts on a sequence entry's line.
	mapping func(col int, first *helmLine) error
	// sequence reads a block sequence whose dashes are at col.
	sequence func(col int) error
}

func (p *helmParser) enter(line int) error {
	p.depth++
	if p.depth > helmMaxDepth {
		return helmUnsupported(line, "nesting deeper than %d levels", helmMaxDepth)
	}
	return nil
}

// mapping reads a block mapping whose keys are at col, calling onKey with
// each key and the rest of its line; onKey consumes the value. first is the
// mapping's first key line when it was already consumed (a mapping on a
// sequence entry's line).
func (p *helmParser) mapping(col int, first *helmLine, onKey func(col int, key string, rest []byte, line int) error) error {
	line := p.r.num
	if first != nil {
		line = first.num
	}
	if err := p.enter(line); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	l := first
	for {
		if l == nil {
			next, err := p.peekContent()
			if err != nil {
				return err
			}
			if next == nil || next.indent < col || helmDocMarker(next) {
				return nil
			}
			if next.indent > col {
				return helmUnsupported(next.num, "unexpected indentation")
			}
			p.r.next()
			l = next
		}
		if helmEntryLine(l.text) {
			return helmUnsupported(l.num, "a sequence entry where a mapping key belongs")
		}
		key, rest, ok, err := helmSplitKey(l.text, l.num)
		if err != nil {
			return err
		}
		if !ok {
			return helmUnsupported(l.num, "no mapping key")
		}
		if err := onKey(col, key, rest, l.num); err != nil {
			return err
		}
		l = nil
	}
}

// sequence reads a block sequence whose dashes are at col, calling onEntry
// with what follows each dash; onEntry consumes the entry.
func (p *helmParser) sequence(col int, onEntry func(rest []byte, l *helmLine) error) error {
	if err := p.enter(p.r.num); err != nil {
		return err
	}
	defer func() { p.depth-- }()
	for {
		l, err := p.peekContent()
		if err != nil {
			return err
		}
		if l == nil || l.indent < col || helmDocMarker(l) {
			return nil
		}
		if l.indent > col {
			return helmUnsupported(l.num, "unexpected indentation")
		}
		if !helmEntryLine(l.text) {
			return nil
		}
		p.r.next()
		if err := onEntry(l.text[1:], l); err != nil {
			return err
		}
	}
}

func (p *helmParser) mapOrSkip(col int, first *helmLine, h helmNested) error {
	if h.mapping != nil {
		return h.mapping(col, first)
	}
	return p.mapping(col, first, p.skipKey)
}

func (p *helmParser) seqOrSkip(col int, h helmNested) error {
	if h.sequence != nil {
		return h.sequence(col)
	}
	return p.sequence(col, func(rest []byte, l *helmLine) error {
		_, _, err := p.entry(col, rest, l, helmNested{})
		return err
	})
}

// skipKey consumes a mapping value the feed does not read.
func (p *helmParser) skipKey(col int, _ string, rest []byte, line int) error {
	_, _, err := p.value(col, rest, line, true, helmNested{})
	return err
}

// value consumes the value of a mapping key at column n (keyValue) or of a
// sequence entry whose dash is at column n, whose first line holds inline
// (what follows the key's colon, or the dash). It returns the value's shape
// and, for a scalar on one line, its text (decoded; untrimmed).
func (p *helmParser) value(n int, inline []byte, line int, keyValue bool, h helmNested) (helmKind, string, error) {
	rest := bytes.TrimLeft(inline, " ")
	if len(rest) > 0 && rest[0] == '\t' {
		return 0, "", helmUnsupported(line, "a tab before a value")
	}
	if len(rest) == 0 || rest[0] == '#' {
		return p.nested(n, keyValue, h)
	}
	switch c := rest[0]; c {
	case '|', '>':
		return helmLongScalar, "", p.blockScalar(n, rest, line)
	case '"', '\'':
		text, end, closed, err := helmQuoted(rest, line)
		if err != nil {
			return 0, "", err
		}
		if closed {
			if !helmTrailer(rest[end:]) {
				return 0, "", helmUnsupported(line, "text after a quoted scalar")
			}
			return helmScalar, text, nil
		}
		return helmLongScalar, "", p.quotedLines(n, c)
	case '[', '{':
		closing := byte(']')
		kind := helmSeq
		if c == '{' {
			closing, kind = '}', helmMap
		}
		if len(rest) < 2 || rest[1] != closing || !helmTrailer(rest[2:]) {
			return 0, "", helmUnsupported(line, "a flow collection")
		}
		return kind, "", nil
	case '&', '*', '!':
		return 0, "", helmUnsupported(line, "an anchor, alias or tag")
	case '%', '@', '`', ',', ']', '}':
		return 0, "", helmUnsupported(line, "%q cannot start a scalar", c)
	case '-', '?', ':':
		if len(rest) == 1 || rest[1] == ' ' || rest[1] == '\t' {
			return 0, "", helmUnsupported(line, "an indicator where a value belongs")
		}
	}
	text, ok := helmPlainLine(rest)
	if !ok {
		return 0, "", helmUnsupported(line, "a plain scalar holding ': ', a trailing ':' or a tab")
	}
	multi, err := p.plainContinues(n, helmHasComment(rest))
	if err != nil {
		return 0, "", err
	}
	if multi {
		return helmLongScalar, "", nil
	}
	switch text {
	case "", "~", "null", "Null", "NULL":
		// Null; its text is what the backend reads where it reads the
		// node's text (an element of urls).
		return helmNull, text, nil
	}
	return helmScalar, text, nil
}

// nested consumes a value that starts on the line after its key or dash: a
// block mapping or sequence more indented than n, a sequence at n itself for
// a mapping key's value, or nothing (null).
func (p *helmParser) nested(n int, keyValue bool, h helmNested) (helmKind, string, error) {
	l, err := p.peekContent()
	if err != nil || l == nil || helmDocMarker(l) {
		return helmNull, "", err
	}
	switch {
	case l.indent > n && helmEntryLine(l.text):
		return helmSeq, "", p.seqOrSkip(l.indent, h)
	case l.indent > n:
		return helmMap, "", p.mapOrSkip(l.indent, nil, h)
	case l.indent == n && keyValue && helmEntryLine(l.text):
		return helmSeq, "", p.seqOrSkip(n, h)
	}
	return helmNull, "", nil
}

// entry consumes a sequence entry whose dash is at col: rest is what follows
// the dash. A mapping may start on the dash's line.
func (p *helmParser) entry(col int, rest []byte, l *helmLine, h helmNested) (helmKind, string, error) {
	sp := 0
	for sp < len(rest) && rest[sp] == ' ' {
		sp++
	}
	inline := rest[sp:]
	if len(inline) > 0 && inline[0] != '#' && inline[0] != '\t' {
		if helmEntryLine(inline) {
			return 0, "", helmUnsupported(l.num, "a sequence inside a sequence entry")
		}
		_, _, isKey, err := helmSplitKey(inline, l.num)
		if err != nil {
			return 0, "", err
		}
		if isKey {
			first := &helmLine{text: inline, indent: col + 1 + sp, num: l.num}
			return helmMap, "", p.mapOrSkip(first.indent, first, h)
		}
	}
	return p.value(col, rest, l.num, false, h)
}

// blockScalar consumes a literal or folded block scalar of a value at column n
// whose header is on the current line, applying yaml.v3's indentation rules.
func (p *helmParser) blockScalar(n int, header []byte, line int) error {
	// At most one chomping indicator and one indentation indicator, in
	// either order.
	i, increment, chomping := 1, 0, false
	for i < len(header) {
		if c := header[i]; (c == '+' || c == '-') && !chomping {
			chomping = true
		} else if c >= '1' && c <= '9' && increment == 0 {
			increment = int(c - '0')
		} else {
			break
		}
		i++
	}
	if !helmTrailer(header[i:]) && !(len(header) > i && header[i] == '#') {
		return helmUnsupported(line, "text after a block scalar's header")
	}
	indent := 0
	if increment > 0 {
		indent = n + increment
	}
	lead := 0
	for {
		l, err := p.r.peek()
		if err != nil || l == nil {
			return err
		}
		if l.blank() {
			lead = max(lead, l.indent)
			p.r.next()
			continue
		}
		if l.text[0] == '\t' && (indent == 0 || l.indent < indent) {
			return helmUnsupported(l.num, "a tab in a block scalar's indentation")
		}
		if indent == 0 {
			if lead > l.indent {
				return helmUnsupported(l.num, "blank lines more indented than a block scalar's first line")
			}
			indent = max(l.indent, n+1)
		}
		break
	}
	for {
		l, err := p.r.peek()
		if err != nil || l == nil {
			return err
		}
		if l.blank() {
			p.r.next()
			continue
		}
		if l.indent < indent {
			if l.text[0] == '\t' {
				return helmUnsupported(l.num, "a tab in a block scalar's indentation")
			}
			return nil
		}
		p.r.next()
	}
}

// quotedLines consumes the lines of a quoted scalar (quote q) of a value at
// column n that does not close on its first line.
func (p *helmParser) quotedLines(n int, q byte) error {
	for {
		l, err := p.r.peek()
		if err != nil {
			return err
		}
		if l == nil {
			return helmUnsupported(p.r.num, "a quoted scalar that does not end")
		}
		if helmDocMarker(l) || (!l.blank() && l.indent <= n) {
			return helmUnsupported(l.num, "a quoted scalar's line not indented beyond its key")
		}
		p.r.next()
		end, closed, err := helmQuoteEnd(l.text, 0, q, l.num)
		if err != nil {
			return err
		}
		if closed {
			if !helmTrailer(l.text[end:]) {
				return helmUnsupported(l.num, "text after a quoted scalar")
			}
			return nil
		}
	}
}

// plainContinues consumes the lines that continue a plain scalar of a value
// at column n: the lines indented beyond n, up to a comment. ended says the
// scalar's first line ended in a comment.
func (p *helmParser) plainContinues(n int, ended bool) (bool, error) {
	multi := false
	for {
		l, err := p.r.peek()
		if err != nil {
			return false, err
		}
		if l == nil {
			return multi, nil
		}
		if l.blank() {
			p.r.next()
			continue
		}
		if l.indent <= n || helmDocMarker(l) {
			return multi, nil
		}
		if l.text[0] == '\t' {
			return false, helmUnsupported(l.num, "a tab in a plain scalar's indentation")
		}
		if l.comment() {
			ended = true
			p.r.next()
			continue
		}
		if ended {
			return false, helmUnsupported(l.num, "a line indented beyond its key after a comment")
		}
		if _, ok := helmPlainLine(l.text); !ok {
			return false, helmUnsupported(l.num, "a plain scalar holding ': ', a trailing ':' or a tab")
		}
		ended = helmHasComment(l.text)
		multi = true
		p.r.next()
	}
}

// helmPlainLine reads a plain scalar's text on one line: up to a comment,
// without trailing spaces. ok is false for text a plain scalar cannot hold in
// block context (": " or a trailing ':') or a tab.
func helmPlainLine(t []byte) (string, bool) {
	end := len(t)
	for i := 0; i < len(t) && end == len(t); i++ {
		switch t[i] {
		case '\t':
			return "", false
		case '#':
			if i > 0 && t[i-1] == ' ' {
				end = i
			}
		case ':':
			if i+1 == len(t) || t[i+1] == ' ' {
				return "", false
			}
		}
	}
	return string(bytes.TrimRight(t[:end], " ")), true
}

// helmHasComment reports whether a plain scalar's line ends in a comment.
func helmHasComment(t []byte) bool {
	for i := 1; i < len(t); i++ {
		if t[i] == '#' && t[i-1] == ' ' {
			return true
		}
	}
	return false
}

// helmTrailer reports whether what follows a value on its line is nothing,
// spaces, or spaces and a comment.
func helmTrailer(t []byte) bool {
	rest := bytes.TrimLeft(t, " ")
	return len(rest) == 0 || (rest[0] == '#' && len(rest) < len(t))
}

// helmSplitKey splits a mapping entry's line into its key (decoded) and what
// follows the colon. ok is false for a line that holds no key; an error
// reports a key the reader does not handle (a complex, empty or merge key, a
// tab, a key too long for yaml.v3).
func helmSplitKey(t []byte, line int) (key string, rest []byte, ok bool, err error) {
	if len(t) == 0 {
		return "", nil, false, nil
	}
	switch c := t[0]; {
	case c == '"' || c == '\'':
		val, end, closed, qerr := helmQuoted(t, line)
		if qerr != nil || !closed {
			return "", nil, false, nil
		}
		j := end
		for j < len(t) && t[j] == ' ' {
			j++
		}
		if j == len(t) || t[j] != ':' || (j+1 < len(t) && t[j+1] != ' ' && t[j+1] != '\t') {
			return "", nil, false, nil
		}
		if j > 1000 {
			return "", nil, false, helmUnsupported(line, "a key longer than yaml.v3 reads")
		}
		if strings.TrimSpace(val) == "<<" {
			return "", nil, false, helmUnsupported(line, "a merge key")
		}
		return val, t[j+1:], true, nil
	case (c == '?' || c == ':') && (len(t) == 1 || t[1] == ' ' || t[1] == '\t'):
		return "", nil, false, helmUnsupported(line, "a complex or empty key")
	case strings.IndexByte("&*!|>%@`[]{},#-", c) >= 0 && (c != '-' || len(t) == 1 || t[1] == ' ' || t[1] == '\t'):
		return "", nil, false, nil
	}
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '\t':
			return "", nil, false, helmUnsupported(line, "a tab in a mapping key's line")
		case '#':
			if t[i-1] == ' ' {
				return "", nil, false, nil
			}
		case ':':
			if i+1 < len(t) && t[i+1] != ' ' && t[i+1] != '\t' {
				continue
			}
			if i > 1000 {
				return "", nil, false, helmUnsupported(line, "a key longer than yaml.v3 reads")
			}
			key = string(bytes.TrimRight(t[:i], " "))
			if key == "<<" {
				return "", nil, false, helmUnsupported(line, "a merge key")
			}
			return key, t[i+1:], true, nil
		}
	}
	return "", nil, false, nil
}

// helmQuoted reads a quoted scalar starting at t[0]: its decoded text and the
// offset past its closing quote when it closes on this line. An escape yaml.v3
// refuses is an error.
func helmQuoted(t []byte, line int) (text string, end int, closed bool, err error) {
	q := t[0]
	end, closed, err = helmQuoteEnd(t, 1, q, line)
	if err != nil || !closed {
		return "", 0, closed, err
	}
	inner := t[1 : end-1]
	if q == '\'' {
		return strings.ReplaceAll(string(inner), "''", "'"), end, true, nil
	}
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if inner[i] != '\\' {
			b.WriteByte(inner[i])
			continue
		}
		i++
		r, n := helmEscape(inner[i:])
		b.WriteString(r)
		i += n - 1
	}
	return b.String(), end, true, nil
}

// helmQuoteEnd scans a quoted scalar's text from t[from] for its closing
// quote q, checking double-quoted escapes as yaml.v3 does. It returns the
// offset past the closing quote, or closed false at the line's end.
func helmQuoteEnd(t []byte, from int, q byte, line int) (int, bool, error) {
	for i := from; i < len(t); i++ {
		switch c := t[i]; {
		case c == q && q == '\'':
			if i+1 < len(t) && t[i+1] == '\'' {
				i++
				continue
			}
			return i + 1, true, nil
		case c == q:
			return i + 1, true, nil
		case c == '\\' && q == '"':
			if i+1 == len(t) {
				return 0, false, nil // an escaped line break
			}
			if _, n := helmEscape(t[i+1:]); n == 0 {
				return 0, false, helmUnsupported(line, "an escape yaml.v3 refuses")
			} else {
				i += n
			}
		}
	}
	return 0, false, nil
}

// helmEscapes are the one-character escapes of a double-quoted scalar.
var helmEscapes = map[byte]string{'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n", 'v': "\v", 'f': "\f",
	'r': "\r", 'e': "\x1b", ' ': " ", '"': "\"", '\'': "'", '\\': "\\", 'N': "\u0085", '_': "\u00a0", 'L': "\u2028", 'P': "\u2029"}

// helmEscape decodes the double-quoted escape at the start of t (after its
// backslash): the text it stands for and its length; n is 0 for an escape
// yaml.v3 refuses.
func helmEscape(t []byte) (string, int) {
	if len(t) == 0 {
		return "", 0
	}
	if s, ok := helmEscapes[t[0]]; ok {
		return s, 1
	}
	digits := 0
	switch t[0] {
	case 'x':
		digits = 2
	case 'u':
		digits = 4
	case 'U':
		digits = 8
	}
	if digits == 0 || len(t) < 1+digits {
		return "", 0
	}
	v, err := strconv.ParseUint(string(t[1:1+digits]), 16, 32)
	if err != nil || v >= 0xD800 && v <= 0xDFFF || v > 0x10FFFF || strings.ContainsAny(string(t[1:1+digits]), "+-") {
		return "", 0
	}
	return string(rune(v)), 1 + digits
}

// topKey reads a key of the document's top-level mapping.
func (p *helmParser) topKey(col int, key string, rest []byte, line int) error {
	switch {
	case strings.EqualFold(key, "entries"):
		if p.sawEntries {
			return helmUnsupported(line, "a second entries key")
		}
		p.sawEntries = true
		kind, _, err := p.value(col, rest, line, true, helmNested{mapping: p.entries})
		switch {
		case err != nil:
			return err
		case kind == helmMap:
			p.hasEntries = true
		case kind != helmNull:
			return helmUnsupported(line, "entries is not a mapping")
		}
		return nil
	case strings.EqualFold(key, "generated"):
		kind, text, err := p.value(col, rest, line, true, helmNested{})
		if err == nil && kind == helmScalar {
			p.generated = strings.TrimSpace(text)
		}
		return err
	}
	return p.skipKey(col, key, rest, line)
}

// entries reads the entries mapping: each chart's list of versions.
func (p *helmParser) entries(col int, first *helmLine) error {
	return p.mapping(col, first, func(col int, key string, rest []byte, line int) error {
		chart := strings.TrimSpace(key)
		if _, dup := p.charts[chart]; dup {
			return helmUnsupported(line, "chart %q listed twice", truncate(chart, 60))
		}
		if len(p.charts) >= helmMaxCharts {
			return Permanent(fmt.Errorf("the index lists more than %d charts", helmMaxCharts))
		}
		p.charts[chart] = struct{}{}
		kind, _, err := p.value(col, rest, line, true, helmNested{sequence: func(scol int) error { return p.versions(scol, chart) }})
		if err == nil && kind != helmSeq && kind != helmNull {
			return helmUnsupported(line, "the versions of chart %q are not a list", truncate(chart, 60))
		}
		return err
	})
}

// versions reads a chart's list of versions.
func (p *helmParser) versions(col int, chart string) error {
	return p.sequence(col, func(rest []byte, l *helmLine) error {
		kind, _, err := p.entry(col, rest, l, helmNested{mapping: func(mcol int, first *helmLine) error { return p.chartVersion(mcol, first, chart) }})
		if err == nil && kind != helmMap && kind != helmNull {
			return helmUnsupported(l.num, "a version of chart %q is not a mapping", truncate(chart, 60))
		}
		return err
	})
}

// chartVersion reads one version's mapping and emits it.
func (p *helmParser) chartVersion(col int, first *helmLine, chart string) error {
	e := helmEntry{Chart: chart}
	var seen [4]bool
	err := p.mapping(col, first, func(col int, key string, rest []byte, line int) error {
		f := helmField(key)
		if f < 0 {
			return p.skipKey(col, key, rest, line)
		}
		if seen[f] {
			return helmUnsupported(line, "a repeated %s field", key)
		}
		seen[f] = true
		if f == helmFieldURLs {
			kind, _, err := p.value(col, rest, line, true, helmNested{sequence: func(scol int) error { return p.urls(scol, &e.URL) }})
			if err == nil && kind != helmSeq && kind != helmNull {
				return helmUnsupported(line, "urls is not a list")
			}
			return err
		}
		kind, text, err := p.value(col, rest, line, true, helmNested{})
		switch {
		case err != nil:
			return err
		case kind == helmScalar:
			text = strings.TrimSpace(text)
		case kind == helmNull:
			text = ""
		default:
			return helmUnsupported(line, "%s is not a string on one line", key)
		}
		switch f {
		case helmFieldVersion:
			e.Version = text
		case helmFieldDigest:
			e.Digest = text
		case helmFieldCreated:
			e.Created = text
		}
		return nil
	})
	if err != nil || e.Version == "" {
		return err
	}
	return p.emit(e)
}

// urls reads a version's urls, keeping the first that is not empty — as the
// backend does, by the element's text: a null written "~" or "null" is that
// text to it (and to yaml.v3), and the backend rewrites it to a link.
func (p *helmParser) urls(col int, out *string) error {
	return p.sequence(col, func(rest []byte, l *helmLine) error {
		kind, text, err := p.entry(col, rest, l, helmNested{})
		switch {
		case err != nil:
			return err
		case kind == helmScalar, kind == helmNull:
			if u := strings.TrimSpace(text); u != "" && *out == "" {
				*out = u
			}
		default:
			return helmUnsupported(l.num, "a url is not a string on one line")
		}
		return nil
	})
}

// --- reading an index whole ------------------------------------------------------

// helmReadIndexWhole reads an index as the backend reads every index: the
// backend's own parser (helm.ParseIndex) decides whether it is one the proxy
// serves — keys matched as a Helm client matches them, the constructs that
// could hide a chart URL from the rewrite refused — and yaml.v3 reads what
// the feed keeps of each version. A repeated key the feed reads is refused,
// as the streaming reader refuses it. It is the fallback for an index of at
// most helmWholeMax bytes the streaming reader does not handle, and the
// reference the streaming reader is fuzzed against.
func helmReadIndexWhole(data []byte) ([]helmEntry, string, error) {
	if len(data) > helmMaxIndex {
		return nil, "", fmt.Errorf("the index is larger than %d bytes", helmMaxIndex)
	}
	if _, err := helm.ParseIndex(data); err != nil {
		return nil, "", err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		// A JSON index YAML cannot read (an escaped solidus, a surrogate
		// pair) is read, as by the backend, in its canonical JSON form.
		canon, ok := helmCanonicalJSON(data)
		if !ok {
			return nil, "", err
		}
		doc = yaml.Node{}
		if err := yaml.Unmarshal(canon, &doc); err != nil {
			return nil, "", err
		}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, "", errors.New("the index is not a mapping")
	}
	root := doc.Content[0]
	var out []helmEntry
	generated, sawEntries := "", false
	for i := 0; i+1 < len(root.Content); i += 2 {
		k, v := root.Content[i], root.Content[i+1]
		switch {
		case strings.EqualFold(k.Value, "entries"):
			if sawEntries {
				return nil, "", errors.New("a second entries key")
			}
			sawEntries = true
			entries, err := helmWholeEntries(v)
			if err != nil {
				return nil, "", err
			}
			out = append(out, entries...)
		case strings.EqualFold(k.Value, "generated"):
			generated = helmScalarText(v)
		}
	}
	return out, generated, nil
}

// helmWholeEntries reads the entries mapping of a parsed index (whose shape
// helm.ParseIndex has checked).
func helmWholeEntries(v *yaml.Node) ([]helmEntry, error) {
	if helmIsNull(v) {
		return nil, nil
	}
	var out []helmEntry
	charts := map[string]bool{}
	for j := 0; j+1 < len(v.Content); j += 2 {
		chart := strings.TrimSpace(v.Content[j].Value)
		if charts[chart] {
			return nil, fmt.Errorf("chart %q listed twice", truncate(chart, 60))
		}
		charts[chart] = true
		for _, item := range v.Content[j+1].Content {
			if helmIsNull(item) {
				continue
			}
			e := helmEntry{Chart: chart}
			var seen [4]bool
			for m := 0; m+1 < len(item.Content); m += 2 {
				fk, fv := item.Content[m], item.Content[m+1]
				f := helmField(fk.Value)
				if f < 0 {
					continue
				}
				if seen[f] {
					return nil, fmt.Errorf("a repeated %s field in chart %q", fk.Value, truncate(chart, 60))
				}
				seen[f] = true
				switch f {
				case helmFieldURLs:
					for _, u := range fv.Content {
						if loc := strings.TrimSpace(u.Value); loc != "" && e.URL == "" {
							e.URL = loc
						}
					}
				case helmFieldVersion:
					e.Version = helmScalarText(fv)
				case helmFieldDigest:
					e.Digest = helmScalarText(fv)
				case helmFieldCreated:
					e.Created = helmScalarText(fv)
				}
			}
			if e.Version != "" {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// helmIsNull reports a null scalar.
func helmIsNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

// helmScalarText is a field's text as the backend reads it: an untagged
// scalar's, trimmed; "" for anything else.
func helmScalarText(n *yaml.Node) string {
	if n.Kind != yaml.ScalarNode || n.Style&yaml.TaggedStyle != 0 || n.Tag == "!!null" {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

// helmCanonicalJSON re-encodes a JSON index the way the backend does before
// reading it (helm scanIndexSource): the same value, spelt so that a YAML
// parser reads it as a JSON parser does.
func helmCanonicalJSON(data []byte) ([]byte, bool) {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, false
	}
	return bytes.ReplaceAll(buf.Bytes(), []byte{0x7f}, []byte(`\u007f`)), true
}

// --- version order ----------------------------------------------------------------

// helmVersion is a chart version as Helm reads one (Masterminds/semver: a
// leading "v", a missing minor or patch allowed).
type helmVersion struct {
	major, minor, patch uint64
	pre                 []string
}

// helmParseVersion reads a chart version; ok is false for one that is not
// SemVer.
func helmParseVersion(s string) (helmVersion, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !helmIdents(s[i+1:]) {
			return helmVersion{}, false
		}
		s = s[:i]
	}
	var v helmVersion
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if !helmIdents(s[i+1:]) {
			return helmVersion{}, false
		}
		v.pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return helmVersion{}, false
	}
	nums := [3]uint64{}
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return helmVersion{}, false
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return helmVersion{}, false
		}
		nums[i] = n
	}
	v.major, v.minor, v.patch = nums[0], nums[1], nums[2]
	return v, true
}

// helmIdents reports dot-separated SemVer identifiers.
func helmIdents(s string) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" || strings.Trim(id, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") != "" {
			return false
		}
	}
	return true
}

// helmCompareVersions orders chart versions by SemVer precedence; versions
// that do not parse sort first, and equal precedence falls back to the text,
// so that the order is total.
func helmCompareVersions(a, b string) int {
	va, okA := helmParseVersion(a)
	vb, okB := helmParseVersion(b)
	switch {
	case !okA && !okB:
		return strings.Compare(a, b)
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for _, c := range [...][2]uint64{{va.major, vb.major}, {va.minor, vb.minor}, {va.patch, vb.patch}} {
		if c[0] != c[1] {
			if c[0] < c[1] {
				return -1
			}
			return 1
		}
	}
	if c := helmComparePre(va.pre, vb.pre); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// helmComparePre orders pre-release identifiers (SemVer 2.0 §11).
func helmComparePre(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		nx, ny := strings.Trim(x, "0123456789") == "", strings.Trim(y, "0123456789") == ""
		switch {
		case nx && ny:
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
		case nx:
			return -1
		case ny:
			return 1
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
