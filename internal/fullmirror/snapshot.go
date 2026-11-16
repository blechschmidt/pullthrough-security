package fullmirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sort"
	"strconv"
	"unicode/utf8"
)

// This file keeps stored copies of a complete index (Task 191): what the
// adapters of the registries that publish one — APT's Packages, CRAN's
// PACKAGES, conda's repodata, a Helm repository's index.yaml, Hex's /versions —
// diff each new copy against, and answer Releases from. A copy holds one
// record per file the index lists (or per version, or per package, when the
// files are found elsewhere), and is built so that
//
//   - building one takes bounded memory however large the index: records are
//     sorted in runs that spill to the adapter's directory, then merged;
//   - diffing two is a merge of two sorted streams;
//   - looking a package up reads one block of a few KB; and
//   - a copy is named by the SHA-256 of its records, which a cursor names and
//     every full read checks: the same index read twice is the same copy, and
//     a copy that does not match its name is never trusted.
//
// The file ("index-<sha256>.snap") is the magic line, the header's length (8
// bytes, big-endian), the header (JSON: the digest, the counts, and the index
// of the blocks) and the blocks: gzip members of record lines. Records are
// sorted by their canonical JSON encoding, byte for byte — which keeps the
// records of one package together (its name is the first field, and a JSON
// string followed by its closing quote is a prefix of no other), and those of
// one version within it. Blocks end only where a package's records end.

// Names and bounds of the stored copies.
const (
	snapPrefix  = "index-"
	snapSuffix  = ".snap"
	snapCurrent = "index-current.json"
	snapMagic   = "PTSNAP1\n"
	snapFormat  = "pullthrough-index-copy/1"
	// snapBlockTarget is the uncompressed size a block is cut at, once the
	// package being written ends.
	snapBlockTarget = 64 << 10
	// snapRunLimit is how many bytes of records are sorted in memory before
	// they spill to a run file.
	snapRunLimit = 16 << 20
	// snapMaxHeader bounds the header (it holds the block index).
	snapMaxHeader = 64 << 20
	// snapMaxLine bounds one record's line.
	snapMaxLine = 64 << 10
	// snapMaxRecords bounds a copy.
	snapMaxRecords = 50_000_000
	// snapMaxGroup bounds the records of one package (a conda package with
	// every build of every version has a few thousand).
	snapMaxGroup = 200_000
	// snapMaxBlock bounds one block, which holds at least one package.
	snapMaxBlock = 128 << 20
)

// snapRecord is one record of a stored index: a file of a version of a
// package, or a version without its files, or a package as a whole.
type snapRecord struct {
	// Name is the package's name as the registry spells it.
	Name string `json:"n"`
	// Version is the version the record is about; empty for a record about
	// the package as a whole (a time stamp the index states per package).
	Version string `json:"v,omitempty"`
	// Path is the file's path on the upstream's mount ("/pool/…"); empty when
	// Releases finds the version's files elsewhere.
	Path string `json:"p,omitempty"`
	// Index names the part of the index the record came from (APT's
	// "trixie/main/binary-amd64", conda's "noarch"): what the adapter copies
	// into the next copy when that part did not change. Empty for an index of
	// one part.
	Index string `json:"i,omitempty"`
	// Size is the file's size in bytes, when the index states it.
	Size int64 `json:"s,omitempty"`
	// Time is when the file, version or package was published or last
	// changed, in Unix seconds, when the index states it.
	Time int64 `json:"t,omitempty"`
	// Digest is the index's digest of the file or the entry (any short
	// string): a file republished under the same path is a change.
	Digest string `json:"d,omitempty"`
	// Yanked marks a version the registry withdrew but still lists.
	Yanked bool `json:"y,omitempty"`
}

// snapValidString reports whether s fits a record field: valid UTF-8 without
// control characters, at most max bytes.
func snapValidString(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// valid reports whether the record can be stored: a name the engine can carry,
// fields without control characters, a path the engine may request.
func (r *snapRecord) valid() bool {
	switch {
	case !cleanName(r.Name) || !snapValidString(r.Name, 1024):
		return false
	case !snapValidString(r.Version, 1024), !snapValidString(r.Index, 256), !snapValidString(r.Digest, 256):
		return false
	case r.Path != "" && !validArtifactPath(r.Path):
		return false
	case r.Size < 0 || r.Time < 0:
		return false
	}
	return true
}

// appendLine appends the record's canonical JSON encoding (fields in a fixed
// order, empty ones left out).
func (r *snapRecord) appendLine(b []byte) []byte {
	b = append(b, `{"n":`...)
	b = snapAppendString(b, r.Name)
	if r.Version != "" {
		b = append(b, `,"v":`...)
		b = snapAppendString(b, r.Version)
	}
	if r.Path != "" {
		b = append(b, `,"p":`...)
		b = snapAppendString(b, r.Path)
	}
	if r.Index != "" {
		b = append(b, `,"i":`...)
		b = snapAppendString(b, r.Index)
	}
	if r.Size != 0 {
		b = append(b, `,"s":`...)
		b = strconv.AppendInt(b, r.Size, 10)
	}
	if r.Time != 0 {
		b = append(b, `,"t":`...)
		b = strconv.AppendInt(b, r.Time, 10)
	}
	if r.Digest != "" {
		b = append(b, `,"d":`...)
		b = snapAppendString(b, r.Digest)
	}
	if r.Yanked {
		b = append(b, `,"y":true`...)
	}
	return append(b, '}')
}

// snapAppendString appends s as a JSON string. Record strings hold no control
// characters (valid), so only the quote and the backslash are escaped.
func snapAppendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			b = append(b, '\\', c)
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// snapNameKey is the key a package sorts by in a copy: its name as the JSON
// string its records start with.
func snapNameKey(name string) []byte { return snapAppendString(nil, name) }

// snapKeyName decodes a package key for a message.
func snapKeyName(key []byte) string {
	var s string
	if json.Unmarshal(key, &s) != nil {
		s = string(key)
	}
	return truncate(s, 80)
}

// snapLineKey returns the JSON string a record line starts with (`{"n":"…"`):
// its package's key.
func snapLineKey(line []byte) ([]byte, bool) {
	const lead = `{"n":"`
	if !bytes.HasPrefix(line, []byte(lead)) {
		return nil, false
	}
	for i := len(lead); i < len(line); i++ {
		switch line[i] {
		case '\\':
			i++
		case '"':
			return line[len(lead)-1 : i+1], true
		}
	}
	return nil, false
}

// snapDecodeLine reads a record line, checking that it is a record the
// builder could have written — valid, and in its canonical encoding, so that
// the name a line sorts by is the name it holds.
func snapDecodeLine(line []byte) (snapRecord, bool) {
	var r snapRecord
	if err := json.Unmarshal(line, &r); err != nil || !r.valid() {
		return snapRecord{}, false
	}
	var buf [512]byte
	if !bytes.Equal(r.appendLine(buf[:0]), line) {
		return snapRecord{}, false
	}
	return r, true
}

// snapHeader is a stored copy's header.
type snapHeader struct {
	Format string `json:"format"`
	// Kind is the adapter's type: a copy of another adapter is not read.
	Kind string `json:"kind"`
	// Digest is the SHA-256 of the record lines, each with its newline: the
	// copy's name.
	Digest  string      `json:"digest"`
	Names   int         `json:"names"`
	Records int         `json:"records"`
	Blocks  []snapBlock `json:"blocks"`

	// Set when the header is read.
	keys      [][]byte
	dataStart int64
	size      int64
}

// snapBlock is one block of a copy.
type snapBlock struct {
	// First is the name of the block's first package.
	First string `json:"k"`
	// Off and Len locate the block's gzip member, Off counted from the end
	// of the header.
	Off int64 `json:"o"`
	Len int64 `json:"l"`
	// Records is how many records the block holds.
	Records int `json:"r"`
}

// snapName is a copy's file name.
func snapName(digest string) string { return snapPrefix + digest + snapSuffix }

// snapIsDigest reports whether s is a lower-case hex SHA-256.
func snapIsDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// errSnapInvalid marks a stored copy that does not read back: missing,
// damaged, or not the copy its name says.
var errSnapInvalid = errors.New("the stored copy of the index does not read")

func snapInvalid(digest string, err error) error {
	return fmt.Errorf("%w %s: %v", errSnapInvalid, truncate(digest, 12), err)
}

// --- building a copy ---------------------------------------------------------

// snapBuilder collects the records of a new copy.
type snapBuilder struct {
	f       files
	kind    string
	lines   []string
	size    int
	runs    []string
	added   int
	dropped int
	scratch []byte
	failed  error
	// limit is the bytes of lines held before a run spills (snapRunLimit;
	// lowered by tests).
	limit int
}

// newSnapBuilder starts a copy for an adapter of type kind in the files' dir.
func (f files) newSnapBuilder(kind string) *snapBuilder {
	return &snapBuilder{f: f, kind: kind, limit: snapRunLimit}
}

// Add adds a record. A record that cannot be stored (an invalid name, a path
// the engine may not request) is dropped and counted; Add reports whether the
// record was kept.
func (b *snapBuilder) Add(r snapRecord) bool {
	if b.failed != nil {
		return false
	}
	if !r.valid() {
		b.dropped++
		return false
	}
	if b.added >= snapMaxRecords {
		b.failed = Permanent(fmt.Errorf("the index lists more than %d records", snapMaxRecords))
		return false
	}
	b.scratch = r.appendLine(b.scratch[:0])
	if len(b.scratch) > snapMaxLine {
		b.dropped++
		return false
	}
	line := string(b.scratch)
	b.lines = append(b.lines, line)
	b.size += len(line) + 16
	b.added++
	if b.size >= b.limit {
		if err := b.spill(); err != nil {
			b.failed = err
		}
	}
	return true
}

// Dropped is how many records Add refused.
func (b *snapBuilder) Dropped() int { return b.dropped }

// Added is how many records Add kept.
func (b *snapBuilder) Added() int { return b.added }

// CopyFrom adds the records of a stored copy that keep accepts: the records of
// the parts of an index that did not change since that copy was made.
func (b *snapBuilder) CopyFrom(old *snapHeader, keep func(*snapRecord) bool) error {
	r, err := b.f.openSnapshot(old, true)
	if err != nil {
		return err
	}
	defer r.Close()
	for r.Next() {
		if rec := r.Record(); keep(&rec) {
			b.Add(rec)
		}
	}
	return r.Err()
}

// sortUnique sorts lines and removes duplicates.
func sortUnique(lines []string) []string {
	sort.Strings(lines)
	out := lines[:0]
	for i, l := range lines {
		if i == 0 || l != out[len(out)-1] {
			out = append(out, l)
		}
	}
	return out
}

// spill writes the lines held, sorted, to a run file.
func (b *snapBuilder) spill() error {
	if b.f.dir == "" {
		return errValidationOnly
	}
	b.lines = sortUnique(b.lines)
	fh, err := os.CreateTemp(b.f.dir, "."+snapPrefix+"run-*.tmp")
	if err != nil {
		return err
	}
	b.runs = append(b.runs, fh.Name())
	bw := bufio.NewWriterSize(fh, 256<<10)
	zw, _ := gzip.NewWriterLevel(bw, gzip.BestSpeed)
	lw := bufio.NewWriterSize(zw, 64<<10)
	for _, l := range b.lines {
		lw.WriteString(l)
		lw.WriteByte('\n')
	}
	err = errors.Join(lw.Flush(), zw.Close(), bw.Flush(), fh.Close())
	b.lines, b.size = nil, 0
	return err
}

// Abort discards the copy being built.
func (b *snapBuilder) Abort() {
	for _, r := range b.runs {
		os.Remove(r)
	}
	b.runs, b.lines = nil, nil
}

// lineSource yields sorted, unique lines.
type lineSource interface {
	next() bool
	line() []byte
	err() error
}

type sliceLines struct {
	lines []string
	i     int
	cur   []byte
}

func (s *sliceLines) next() bool {
	if s.i >= len(s.lines) {
		return false
	}
	s.cur = append(s.cur[:0], s.lines[s.i]...)
	s.i++
	return true
}
func (s *sliceLines) line() []byte { return s.cur }
func (s *sliceLines) err() error   { return nil }

// runReader reads one run file.
type runReader struct {
	fh  *os.File
	zr  *gzip.Reader
	br  *bufio.Reader
	cur []byte
	e   error
}

func openRun(path string) (*runReader, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bufio.NewReaderSize(fh, 256<<10))
	if err != nil {
		fh.Close()
		return nil, err
	}
	return &runReader{fh: fh, zr: zr, br: bufio.NewReaderSize(zr, snapMaxLine+1)}, nil
}

func (r *runReader) next() bool {
	if r.e != nil {
		return false
	}
	line, err := r.br.ReadSlice('\n')
	if err != nil {
		if err != io.EOF || len(line) > 0 {
			r.e = fmt.Errorf("reading a run of the copy being built: %w", err)
		}
		return false
	}
	r.cur = append(r.cur[:0], line[:len(line)-1]...)
	return true
}

func (r *runReader) close() {
	r.zr.Close()
	r.fh.Close()
}

// mergeLines merges sorted runs, dropping duplicates.
type mergeLines struct {
	h    runHeap
	all  []*runReader
	cur  []byte
	e    error
	init bool
}

type runHeap []*runReader

func (h runHeap) Len() int            { return len(h) }
func (h runHeap) Less(i, j int) bool  { return bytes.Compare(h[i].cur, h[j].cur) < 0 }
func (h runHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *runHeap) Push(x interface{}) { *h = append(*h, x.(*runReader)) }
func (h *runHeap) Pop() interface{} {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func newMergeLines(paths []string) (*mergeLines, error) {
	m := &mergeLines{}
	for _, p := range paths {
		r, err := openRun(p)
		if err != nil {
			m.close()
			return nil, err
		}
		m.all = append(m.all, r)
	}
	return m, nil
}

func (m *mergeLines) next() bool {
	if m.e != nil {
		return false
	}
	if !m.init {
		m.init = true
		for _, r := range m.all {
			if r.next() {
				m.h = append(m.h, r)
			} else if r.e != nil {
				m.e = r.e
				return false
			}
		}
		heap.Init(&m.h)
	}
	for m.h.Len() > 0 {
		top := m.h[0]
		line := append([]byte(nil), top.cur...)
		if top.next() {
			heap.Fix(&m.h, 0)
		} else {
			if top.e != nil {
				m.e = top.e
				return false
			}
			heap.Pop(&m.h)
		}
		if m.cur != nil && bytes.Equal(line, m.cur) {
			continue
		}
		m.cur = line
		return true
	}
	return false
}

func (m *mergeLines) line() []byte { return m.cur }
func (m *mergeLines) err() error   { return m.e }
func (m *mergeLines) close() {
	for _, r := range m.all {
		r.close()
	}
}

// countingWriter counts what passes through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Finish sorts and stores the copy and returns its header. The copy is named
// by its digest; a copy of the same records replaces an identical file.
func (b *snapBuilder) Finish() (*snapHeader, error) {
	defer b.Abort()
	if b.failed != nil {
		return nil, b.failed
	}
	if b.f.dir == "" {
		return nil, errValidationOnly
	}
	var src lineSource
	if len(b.runs) == 0 {
		b.lines = sortUnique(b.lines)
		src = &sliceLines{lines: b.lines}
	} else {
		if len(b.lines) > 0 {
			if err := b.spill(); err != nil {
				return nil, err
			}
		}
		m, err := newMergeLines(b.runs)
		if err != nil {
			return nil, err
		}
		defer m.close()
		src = m
	}

	data, err := os.CreateTemp(b.f.dir, "."+snapPrefix+"data-*.tmp")
	if err != nil {
		return nil, err
	}
	defer func() {
		data.Close()
		os.Remove(data.Name())
	}()
	bw := bufio.NewWriterSize(data, 256<<10)
	cw := &countingWriter{w: bw}
	zw, _ := gzip.NewWriterLevel(cw, gzip.DefaultCompression)
	h := sha256.New()
	hdr := &snapHeader{Format: snapFormat, Kind: b.kind, Blocks: []snapBlock{}}
	var block bytes.Buffer
	var curKey []byte
	first, blockRecords, group := "", 0, 0
	flush := func() error {
		if block.Len() == 0 {
			return nil
		}
		off := cw.n
		zw.Reset(cw)
		if _, err := zw.Write(block.Bytes()); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		hdr.Blocks = append(hdr.Blocks, snapBlock{First: first, Off: off, Len: cw.n - off, Records: blockRecords})
		block.Reset()
		blockRecords = 0
		return nil
	}
	for src.next() {
		line := src.line()
		key, ok := snapLineKey(line)
		if !ok {
			return nil, fmt.Errorf("fullmirror: a record line of the copy being built has no name: %.80q", line)
		}
		if !bytes.Equal(key, curKey) {
			if block.Len() >= snapBlockTarget {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			curKey = append(curKey[:0], key...)
			group = 0
			hdr.Names++
			if block.Len() == 0 {
				if err := json.Unmarshal(key, &first); err != nil {
					return nil, fmt.Errorf("fullmirror: a record's name does not decode: %w", err)
				}
			}
		}
		group++
		if group > snapMaxGroup {
			return nil, Permanent(fmt.Errorf("the index lists more than %d files for package %s", snapMaxGroup, snapKeyName(curKey)))
		}
		block.Write(line)
		block.WriteByte('\n')
		if block.Len() > snapMaxBlock {
			return nil, Permanent(fmt.Errorf("the index lists more than %d bytes of records for package %s", snapMaxBlock, snapKeyName(curKey)))
		}
		h.Write(line)
		h.Write([]byte{'\n'})
		hdr.Records++
		blockRecords++
	}
	if err := src.err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	hdr.Digest = hex.EncodeToString(h.Sum(nil))
	head, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	if len(head) > snapMaxHeader {
		return nil, Permanent(fmt.Errorf("the index is too large to keep a copy of (%d blocks)", len(hdr.Blocks)))
	}
	err = b.f.write(snapName(hdr.Digest), func(w io.Writer) error {
		var pre [len(snapMagic) + 8]byte
		copy(pre[:], snapMagic)
		binary.BigEndian.PutUint64(pre[len(snapMagic):], uint64(len(head)))
		if _, err := w.Write(pre[:]); err != nil {
			return err
		}
		if _, err := w.Write(head); err != nil {
			return err
		}
		if _, err := data.Seek(0, io.SeekStart); err != nil {
			return err
		}
		_, err := io.Copy(w, data)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Read the header back as every reader does: the copy is usable only
	// once it reads.
	return b.f.readSnapHeader(hdr.Digest, b.kind)
}

// --- reading a copy ----------------------------------------------------------

// readSnapHeader reads and checks the header of the stored copy named by
// digest, of an adapter of type kind.
func (f files) readSnapHeader(digest, kind string) (*snapHeader, error) {
	if f.dir == "" {
		return nil, errValidationOnly
	}
	if !snapIsDigest(digest) {
		return nil, snapInvalid(digest, errors.New("not the digest of a stored copy"))
	}
	fh, err := os.Open(f.path(snapName(digest)))
	if err != nil {
		return nil, snapInvalid(digest, err)
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, snapInvalid(digest, err)
	}
	var pre [len(snapMagic) + 8]byte
	if _, err := io.ReadFull(fh, pre[:]); err != nil || string(pre[:len(snapMagic)]) != snapMagic {
		return nil, snapInvalid(digest, fmt.Errorf("not a stored copy (%v)", err))
	}
	n := binary.BigEndian.Uint64(pre[len(snapMagic):])
	if n == 0 || n > snapMaxHeader || int64(n) > st.Size()-int64(len(pre)) {
		return nil, snapInvalid(digest, fmt.Errorf("a header of %d bytes", n))
	}
	head := make([]byte, n)
	if _, err := io.ReadFull(fh, head); err != nil {
		return nil, snapInvalid(digest, err)
	}
	var hdr snapHeader
	if err := json.Unmarshal(head, &hdr); err != nil {
		return nil, snapInvalid(digest, err)
	}
	hdr.dataStart = int64(len(pre)) + int64(n)
	hdr.size = st.Size()
	if err := hdr.check(digest, kind); err != nil {
		return nil, snapInvalid(digest, err)
	}
	return &hdr, nil
}

// check validates a header against the copy's name and the file's size.
func (h *snapHeader) check(digest, kind string) error {
	switch {
	case h.Format != snapFormat:
		return fmt.Errorf("format %q", truncate(h.Format, 40))
	case h.Kind != kind:
		return fmt.Errorf("a copy of the %q adapter, not %q", truncate(h.Kind, 40), kind)
	case h.Digest != digest:
		return errors.New("its header names another digest")
	case h.Records < 0 || h.Records > snapMaxRecords || h.Names < 0 || h.Names > h.Records:
		return fmt.Errorf("%d records of %d packages", h.Records, h.Names)
	case (h.Records == 0) != (len(h.Blocks) == 0) || len(h.Blocks) > h.Names:
		return fmt.Errorf("%d blocks for %d packages", len(h.Blocks), h.Names)
	}
	h.keys = make([][]byte, len(h.Blocks))
	var off int64
	records := 0
	for i, b := range h.Blocks {
		if !cleanName(b.First) || !snapValidString(b.First, 1024) || b.Off != off || b.Len <= 0 || b.Records <= 0 {
			return fmt.Errorf("block %d is not where the previous one ends", i)
		}
		h.keys[i] = snapNameKey(b.First)
		if i > 0 && bytes.Compare(h.keys[i-1], h.keys[i]) >= 0 {
			return fmt.Errorf("block %d is out of order", i)
		}
		off += b.Len
		records += b.Records
		if off < 0 || records > h.Records {
			return fmt.Errorf("block %d overflows", i)
		}
	}
	if h.dataStart+off != h.size {
		return fmt.Errorf("the blocks end at %d, the file at %d", h.dataStart+off, h.size)
	}
	if records != h.Records {
		return fmt.Errorf("the blocks hold %d records, the header says %d", records, h.Records)
	}
	return nil
}

// snapReader walks a stored copy's records in order. It checks them as it
// reads — in order, each a record the builder could have written — and, for
// a reader opened at the start, the count and the digest once the last record
// has been read: a caller acts on what it read only once Next has returned
// false and Err is nil.
type snapReader struct {
	hdr    *snapHeader
	fh     *os.File
	zr     *gzip.Reader
	br     *bufio.Reader
	h      hash.Hash
	cur    []byte
	rec    snapRecord
	n      int
	err    error
	done   bool
	digest string
}

// openSnapshot opens a copy for reading from its first record; with check, the
// count and digest are verified at the end.
func (f files) openSnapshot(hdr *snapHeader, check bool) (*snapReader, error) {
	return f.openSnapshotAt(hdr, 0, check)
}

// openSnapshotAt opens a copy for reading from block i.
func (f files) openSnapshotAt(hdr *snapHeader, i int, check bool) (*snapReader, error) {
	r := &snapReader{hdr: hdr, digest: hdr.Digest}
	if i >= len(hdr.Blocks) {
		r.done = true
		if check && (i != 0 || hdr.Records != 0 || hex.EncodeToString(sha256.New().Sum(nil)) != hdr.Digest) {
			return nil, snapInvalid(hdr.Digest, errors.New("an empty copy that does not match its digest"))
		}
		return r, nil
	}
	fh, err := os.Open(f.path(snapName(hdr.Digest)))
	if err != nil {
		return nil, snapInvalid(hdr.Digest, err)
	}
	start := hdr.dataStart + hdr.Blocks[i].Off
	zr, err := gzip.NewReader(bufio.NewReaderSize(io.NewSectionReader(fh, start, hdr.size-start), 256<<10))
	if err != nil {
		fh.Close()
		return nil, snapInvalid(hdr.Digest, err)
	}
	r.fh, r.zr = fh, zr
	r.br = bufio.NewReaderSize(zr, snapMaxLine+1)
	if check && i == 0 {
		r.h = sha256.New()
	}
	return r, nil
}

func (r *snapReader) fail(err error) bool {
	r.err = snapInvalid(r.digest, err)
	r.done = true
	return false
}

// Next advances to the next record.
func (r *snapReader) Next() bool {
	if r.done || r.err != nil {
		return false
	}
	line, err := r.br.ReadSlice('\n')
	if err != nil {
		if err == io.EOF && len(line) == 0 {
			r.done = true
			if r.h != nil {
				switch {
				case r.n != r.hdr.Records:
					return r.fail(fmt.Errorf("%d records, the header says %d", r.n, r.hdr.Records))
				case hex.EncodeToString(r.h.Sum(nil)) != r.digest:
					return r.fail(errors.New("its records do not match its digest"))
				}
			}
			return false
		}
		return r.fail(fmt.Errorf("record %d: %v", r.n+1, err))
	}
	line = line[:len(line)-1]
	if r.n > 0 && bytes.Compare(line, r.cur) <= 0 {
		return r.fail(fmt.Errorf("record %d is out of order", r.n+1))
	}
	rec, ok := snapDecodeLine(line)
	if !ok {
		return r.fail(fmt.Errorf("record %d is not a record", r.n+1))
	}
	if r.h != nil {
		r.h.Write(line)
		r.h.Write([]byte{'\n'})
	}
	r.cur = append(r.cur[:0], line...)
	r.rec = rec
	r.n++
	return true
}

// Record is the current record; Line its encoding (valid until Next).
func (r *snapReader) Record() snapRecord { return r.rec }
func (r *snapReader) Line() []byte       { return r.cur }

// Err reports a copy that did not read back.
func (r *snapReader) Err() error { return r.err }

// Close releases the file.
func (r *snapReader) Close() {
	if r.zr != nil {
		r.zr.Close()
	}
	if r.fh != nil {
		r.fh.Close()
	}
}

// blockFor returns the block that holds key's records, if any could: the
// last block starting at or before key.
func (h *snapHeader) blockFor(key []byte) int {
	return sort.Search(len(h.keys), func(i int) bool { return bytes.Compare(h.keys[i], key) > 0 }) - 1
}

// snapLookup returns a package's records from a copy (nil when it has none),
// reading the one block that holds them.
func (f files) snapLookup(hdr *snapHeader, name string) ([]snapRecord, error) {
	key := snapNameKey(name)
	i := hdr.blockFor(key)
	if i < 0 {
		return nil, nil
	}
	b := hdr.Blocks[i]
	fh, err := os.Open(f.path(snapName(hdr.Digest)))
	if err != nil {
		return nil, snapInvalid(hdr.Digest, err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(io.NewSectionReader(fh, hdr.dataStart+b.Off, b.Len))
	if err != nil {
		return nil, snapInvalid(hdr.Digest, err)
	}
	defer zr.Close()
	zr.Multistream(false)
	br := bufio.NewReaderSize(zr, snapMaxLine+1)
	var out []snapRecord
	var prev []byte
	for n := 0; ; n++ {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if err == io.EOF && len(line) == 0 {
				if n != b.Records {
					return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d holds %d records, the header says %d", i, n, b.Records))
				}
				return out, nil
			}
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d: %v", i, err))
		}
		line = line[:len(line)-1]
		k, ok := snapLineKey(line)
		switch {
		case !ok:
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d: a line without a name", i))
		case n == 0 && !bytes.Equal(k, hdr.keys[i]):
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d does not start with %q", i, truncate(b.First, 60)))
		case n > 0 && bytes.Compare(line, prev) <= 0:
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d is out of order", i))
		}
		prev = append(prev[:0], line...)
		switch c := bytes.Compare(k, key); {
		case c < 0:
			continue
		case c > 0:
			return out, nil
		}
		rec, ok := snapDecodeLine(line)
		if !ok {
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("block %d: a line that is not a record", i))
		}
		if len(out) >= snapMaxGroup {
			return nil, snapInvalid(hdr.Digest, fmt.Errorf("more than %d records for %s", snapMaxGroup, truncate(name, 60)))
		}
		out = append(out, rec)
	}
}

// snapListNames lists up to max package names of a copy that sort after
// after ("" lists from the first), and whether more follow.
func (f files) snapListNames(hdr *snapHeader, after string, max int) ([]string, bool, error) {
	start := 0
	var afterKey []byte
	if after != "" {
		afterKey = snapNameKey(after)
		if start = hdr.blockFor(afterKey); start < 0 {
			start = 0
		}
	}
	r, err := f.openSnapshotAt(hdr, start, false)
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	var names []string
	var last []byte
	for r.Next() {
		k, _ := snapLineKey(r.Line())
		if afterKey != nil && bytes.Compare(k, afterKey) <= 0 {
			continue
		}
		if last != nil && bytes.Equal(k, last) {
			continue
		}
		if len(names) == max {
			return names, true, nil
		}
		last = append(last[:0], k...)
		names = append(names, r.Record().Name)
	}
	return names, false, r.Err()
}

// --- diffing two copies --------------------------------------------------------

// snapGroups reads a copy one package at a time.
type snapGroups struct {
	r     *snapReader
	held  bool
	key   []byte
	name  string
	lines [][]byte
	recs  []snapRecord
	err   error
}

func newSnapGroups(r *snapReader) *snapGroups {
	g := &snapGroups{r: r}
	g.held = r.Next()
	return g
}

// next reads the next package's records.
func (g *snapGroups) next() bool {
	if !g.held {
		g.err = g.r.Err()
		return false
	}
	k, _ := snapLineKey(g.r.Line())
	g.key = append(g.key[:0], k...)
	g.name = g.r.Record().Name
	g.lines, g.recs = g.lines[:0], g.recs[:0]
	for g.held {
		k, _ := snapLineKey(g.r.Line())
		if !bytes.Equal(k, g.key) {
			break
		}
		if len(g.lines) >= snapMaxGroup {
			g.err = snapInvalid(g.r.digest, fmt.Errorf("more than %d records for %s", snapMaxGroup, truncate(g.name, 60)))
			return false
		}
		g.lines = append(g.lines, append([]byte(nil), g.r.Line()...))
		g.recs = append(g.recs, g.r.Record())
		g.held = g.r.Next()
	}
	return true
}

// snapDiff walks two copies in order and calls emit for every difference —
// a new package (by name), a package gone (deleted), and within a package
// present in both: a change to its package-level records (by name: the whole
// package is looked at again), or else each version added or changed (by
// name and version) and each version gone (deleted). emit returns false to
// stop the walk.
func snapDiff(old, cur *snapReader, emit func(Coordinate) bool) error {
	a, b := newSnapGroups(old), newSnapGroups(cur)
	okA, okB := a.next(), b.next()
	for okA || okB {
		var c int
		switch {
		case !okB:
			c = -1
		case !okA:
			c = 1
		default:
			c = bytes.Compare(a.key, b.key)
		}
		switch {
		case c < 0:
			if !emit(Coordinate{Name: a.name, Deleted: true}) {
				return nil
			}
			okA = a.next()
		case c > 0:
			if !emit(Coordinate{Name: b.name}) {
				return nil
			}
			okB = b.next()
		default:
			if !snapDiffPackage(a, b, emit) {
				return nil
			}
			okA, okB = a.next(), b.next()
		}
	}
	if a.err != nil {
		return a.err
	}
	return b.err
}

// snapDiffPackage compares one package's records in two copies.
func snapDiffPackage(a, b *snapGroups, emit func(Coordinate) bool) bool {
	if snapSameLines(a.lines, b.lines) {
		return true
	}
	pa, va, orderA := snapByVersion(a)
	pb, vb, orderB := snapByVersion(b)
	if pa != pb {
		return emit(Coordinate{Name: b.name})
	}
	for _, v := range orderB {
		if old, ok := va[v]; !ok || old != vb[v] {
			if !emit(Coordinate{Name: b.name, Version: v}) {
				return false
			}
		}
	}
	for _, v := range orderA {
		if _, ok := vb[v]; !ok {
			if !emit(Coordinate{Name: a.name, Version: v, Deleted: true}) {
				return false
			}
		}
	}
	return true
}

// snapByVersion splits a package's record lines into its package-level lines
// (joined) and each version's (joined, by version), with the versions in the
// order they first appear.
func snapByVersion(g *snapGroups) (string, map[string]string, []string) {
	var pkg bytes.Buffer
	byVersion := map[string]*bytes.Buffer{}
	var order []string
	for i, rec := range g.recs {
		if rec.Version == "" {
			pkg.Write(g.lines[i])
			pkg.WriteByte('\n')
			continue
		}
		buf, ok := byVersion[rec.Version]
		if !ok {
			buf = &bytes.Buffer{}
			byVersion[rec.Version] = buf
			order = append(order, rec.Version)
		}
		buf.Write(g.lines[i])
		buf.WriteByte('\n')
	}
	out := make(map[string]string, len(byVersion))
	for v, buf := range byVersion {
		out[v] = buf.String()
	}
	return pkg.String(), out, order
}

func snapSameLines(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// snapReleases groups a package's records into releases: one per version,
// whose files are the records with a path (each path once). Published is the
// earliest time the records state; a version any record marks yanked is
// yanked. Package-level records are left out.
func snapReleases(recs []snapRecord) []Release {
	var out []Release
	idx := map[string]int{}
	seen := map[string]bool{}
	for _, r := range recs {
		if r.Version == "" {
			continue
		}
		i, ok := idx[r.Version]
		if !ok {
			i = len(out)
			idx[r.Version] = i
			out = append(out, Release{Version: r.Version})
		}
		rel := &out[i]
		if r.Yanked {
			rel.Yanked = true
		}
		if r.Time > 0 {
			if t := unixTime(r.Time); rel.Published.IsZero() || t.Before(rel.Published) {
				rel.Published = t
			}
		}
		if r.Path != "" && !seen[r.Version+"\x00"+r.Path] {
			seen[r.Version+"\x00"+r.Path] = true
			rel.Artifacts = append(rel.Artifacts, Artifact{Path: r.Path, Size: r.Size})
		}
	}
	return out
}
