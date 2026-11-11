package llmpkgscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// File is one member of an unpacked package, held in memory.
type File struct {
	// Path is the member's sanitized, root-relative path: always relative, never
	// containing "..", with control and invisible characters removed. It is the
	// only key a tool can address the file by.
	Path string
	// Size is the member's declared size in the archive.
	Size int64
	// Data is the retained content, text only. Binary members keep no content:
	// the model cannot read them, so holding megabytes of them would only cost
	// memory.
	Data []byte
	// Binary reports a non-text member; Kind describes what it looks like.
	Binary bool
	Kind   string
	// Truncated reports that Data is only a prefix of the member.
	Truncated bool
	// Unretained reports a text member whose content was dropped because the
	// scan's memory budget was spent.
	Unretained bool
	// Lines is the number of lines in Data.
	Lines int
	// Score ranks the file for the prompt (higher = shown first); Role says why.
	Score int
	Role  string
	// Signals are fixed-vocabulary hints from a deterministic pass over the
	// content ("exec", "decode", ...). They steer attention; they are not findings.
	Signals []string

	lineStarts []int // byte offset of each line start in Data
}

// Link is a symbolic or hard link member. It is recorded, never followed.
type Link struct {
	Path   string
	Target string
	Hard   bool
	// Escapes reports a target that is absolute or climbs out of the package
	// root — the shape of a link-based extraction attack.
	Escapes bool
}

// Tree is the bounded, read-only, in-memory image of an unpacked artifact. It
// is built once and never modified afterwards, so it may be shared by
// concurrent readers.
type Tree struct {
	// Files is sorted by path; index addresses the same files by path.
	Files []*File
	index map[string]*File
	Links []Link

	// Format is the container format the unpacker detected.
	Format string
	// Digest is the sha256 (hex) of the artifact bytes the tree was built from,
	// computed over the very stream that was unpacked.
	Digest string
	// ArtifactBytes is the size of that stream.
	ArtifactBytes int64
	// UnpackedBytes is the decompressed size the unpacker produced.
	UnpackedBytes int64
	// RetainedBytes is the content held in memory.
	RetainedBytes int64

	// Notes states, in plain sentences, everything about the package this tree
	// does NOT show: members beyond a limit, cut files, an unpack that stopped
	// early. They are shown to the model verbatim so a truncated view is never
	// mistaken for the whole package.
	Notes []string
	// Anomalies are structural oddities of the archive itself that are evidence in
	// their own right: path-traversal names, escaping links, a decompression bomb.
	Anomalies []string
	// StrongAnomalies counts the anomalies that have no innocent explanation — a
	// member name or link that reaches outside the package root, a decompression
	// bomb. An archive built to attack whatever extracts it is not cleared by a
	// model finding its file contents unremarkable.
	StrongAnomalies int
}

// Truncated reports whether the tree is an incomplete view of the package.
func (t *Tree) Truncated() bool { return len(t.Notes) > 0 }

// Lookup resolves a path to a file. The path is normalized the same way member
// names were, so "./a/b", "/a/b" and "a/b" address the same file, and anything
// that is not a key of the tree — including every "../" escape — resolves to
// nothing. There is no filesystem behind this lookup.
func (t *Tree) Lookup(p string) (*File, bool) {
	clean, _ := safePath(p)
	f, ok := t.index[clean]
	return f, ok
}

// Errors from building a tree. Each maps to an unscanned reason code.
var (
	errOversized   = errors.New("llmpkgscan: artifact exceeds the size limit")
	errUnsupported = errors.New("llmpkgscan: artifact is not a supported archive")
	errEmpty       = errors.New("llmpkgscan: archive contains no files")
	errUnpackLimit = errors.New("llmpkgscan: archive could not be unpacked within the limits")
	// errNotArchive: the stream carries no archive or compression signature at
	// all. Whether that is a problem depends on what the resource claims to be
	// (see claimsArchive), which the caller knows and this function does not.
	errNotArchive = errors.New("llmpkgscan: resource is not an archive")
)

// Bounds on what one tree records beyond file content.
const (
	maxLinks       = 200
	maxAnomalies   = 40
	maxPathBytes   = 512
	signalScanCap  = 256 << 10 // bytes of each file the signal pass reads
	sniffBytes     = 8 << 10   // bytes examined to tell text from binary
	maxDuplicateID = 99
)

// buildTree unpacks an artifact stream into a Tree. It hashes the stream as it
// unpacks it — the digest it reports is therefore the digest of exactly the
// bytes that were examined, not of a second read that could have raced a cache
// refill.
func buildTree(ctx context.Context, r io.Reader, lim Limits) (*Tree, error) {
	hasher := sha256.New()
	src := &countReader{r: io.TeeReader(r, hasher)}

	t := &Tree{index: make(map[string]*File)}
	var (
		tooDeep    int
		cut        int
		unretained int
		duplicates = make(map[string]int)
	)
	retainedCap := retainedTextCap
	if lim.MaxUnpackedBytes > 0 && lim.MaxUnpackedBytes < retainedCap {
		retainedCap = lim.MaxUnpackedBytes
	}

	visit := func(e contentscan.ArchiveEntry) bool {
		p, unsafe := safePath(e.Name)
		if unsafe {
			t.strongAnomaly("member name escapes the package root or is not a plain relative path: %s", quoteUntrusted(e.Name, 160))
		}
		if lim.MaxDepth > 0 && strings.Count(p, "/")+1 > lim.MaxDepth {
			tooDeep++
			return true
		}
		// Two members with one name: an extractor keeps one of them and which one
		// depends on the extractor, so both are kept here, under distinct keys.
		if _, dup := t.index[p]; dup {
			duplicates[p]++
			if n := duplicates[p]; n <= maxDuplicateID {
				if n == 1 {
					t.anomaly("archive contains more than one member named %s", quoteUntrusted(p, 160))
				}
				p = fmt.Sprintf("%s [duplicate member %d]", p, n)
			} else {
				return true
			}
		}

		f := &File{Path: p, Size: e.Size, Truncated: e.Truncated}
		if f.Size < int64(len(e.Data)) {
			f.Size = int64(len(e.Data))
		}
		text, isText := decodeText(e.Data)
		if !isText {
			f.Binary = true
			f.Kind = sniffBinary(e.Data)
		} else {
			f.Kind = "text"
			if t.RetainedBytes+int64(len(text)) > retainedCap {
				f.Unretained = true
				unretained++
			} else {
				// Copy to an exactly-sized slice: the walker's read buffer may carry
				// up to twice the capacity, which would silently double the memory
				// the retention cap is meant to bound.
				f.Data = append(make([]byte, 0, len(text)), text...)
				t.RetainedBytes += int64(len(text))
				f.indexLines()
			}
		}
		if e.Truncated {
			cut++
		}
		t.Files = append(t.Files, f)
		t.index[p] = f
		return true
	}

	onLink := func(l contentscan.ArchiveLink) {
		p, unsafe := safePath(l.Name)
		link := Link{Path: p, Target: l.Target, Hard: l.Hard, Escapes: unsafe || linkEscapes(p, l.Target)}
		if link.Escapes {
			kind := "symbolic link"
			if l.Hard {
				kind = "hard link"
			}
			t.strongAnomaly("%s %s points outside the package root: -> %s", kind, quoteUntrusted(l.Name, 120), quoteUntrusted(l.Target, 120))
		}
		if len(t.Links) < maxLinks {
			t.Links = append(t.Links, link)
		}
	}

	stats, werr := contentscan.WalkArchive(ctx, src, contentscan.ArchiveLimits{
		MaxArchiveBytes:     lim.MaxArtifactBytes,
		MaxUnpackedBytes:    lim.MaxUnpackedBytes,
		MaxFileBytes:        lim.MaxFileBytes,
		MaxFiles:            lim.MaxFiles,
		MaxCompressionRatio: lim.MaxCompressionRatio,
	}, visit, onLink)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if werr != nil && !archiveMagic(src.head) {
		// Nothing could be unpacked and the stream does not even start like an
		// archive: a metadata document, not a package. There is no verdict to file
		// under a digest, so the rest of the stream is not read.
		return nil, errNotArchive
	}

	// Finish hashing: the unpacker stops at the end of the archive, which is not
	// necessarily the end of the stream. One byte past the limit is enough to
	// know the artifact is oversized.
	if remaining := lim.MaxArtifactBytes + 1 - src.n; remaining > 0 {
		if _, err := io.Copy(io.Discard, io.LimitReader(src, remaining)); err != nil {
			return nil, fmt.Errorf("llmpkgscan: reading artifact: %w", err)
		}
	}
	if src.n > lim.MaxArtifactBytes {
		return nil, errOversized
	}
	if werr != nil {
		return nil, fmt.Errorf("%w: %v", errUnsupported, werr)
	}

	t.Format = stats.Format
	t.Digest = hex.EncodeToString(hasher.Sum(nil))
	t.ArtifactBytes = src.n
	t.UnpackedBytes = stats.UnpackedBytes

	for _, reason := range stats.Incomplete {
		switch reason {
		case contentscan.IncompleteFiles:
			t.note("The archive has more members than the limit of %d. Members beyond that limit were NOT unpacked: they are invisible to this review and no tool can reach them.", lim.MaxFiles)
		case contentscan.IncompleteUnpackedBytes:
			t.note("Unpacking stopped after %d decompressed bytes (the limit). Whatever the archive holds beyond that point was NOT unpacked and is invisible to this review.", lim.MaxUnpackedBytes)
		case contentscan.IncompleteRatio:
			t.note("Unpacking stopped because the archive decompresses more than %g-fold. Whatever it holds beyond that point was NOT unpacked and is invisible to this review.", lim.MaxCompressionRatio)
			t.strongAnomaly("the archive decompresses more than %g-fold — the profile of a decompression bomb", lim.MaxCompressionRatio)
		case contentscan.IncompleteZipDirectory:
			t.note("The zip directory declares far more members than the limit of %d, so the archive was NOT unpacked.", lim.MaxFiles)
			t.strongAnomaly("the zip directory declares an implausible number of members")
		case contentscan.IncompleteArchiveBytes:
			// Unreachable once the size check above passed; kept so a new walker
			// reason can never be silently dropped.
			t.note("The artifact is larger than the scanner reads; its tail was NOT examined.")
		case contentscan.IncompleteFileBytes:
			// Reported with the count below.
		default:
			t.note("Unpacking stopped early (%s); part of the archive was NOT examined.", reason)
		}
	}
	if cut > 0 {
		t.note("%d file(s) are larger than the per-file limit of %d bytes. Only the first %d bytes of each are available; the rest of those files is invisible to this review.", cut, lim.MaxFileBytes, lim.MaxFileBytes)
	}
	if tooDeep > 0 {
		t.note("%d member(s) nested deeper than %d directories were NOT unpacked and are invisible to this review.", tooDeep, lim.MaxDepth)
		t.anomaly("%d member(s) are nested deeper than %d directories", tooDeep, lim.MaxDepth)
	}
	if unretained > 0 {
		t.note("The content of %d text file(s) was not kept because the scan's memory budget was spent. They appear in the listing but cannot be read.", unretained)
	}
	if stats.Links > len(t.Links) {
		t.note("The archive has %d link members; only the first %d are listed.", stats.Links, len(t.Links))
	}

	if len(t.Files) == 0 {
		if !stats.Complete() || tooDeep > 0 {
			return nil, errUnpackLimit
		}
		return nil, errEmpty
	}

	sort.Slice(t.Files, func(i, j int) bool { return t.Files[i].Path < t.Files[j].Path })
	rankFiles(t)
	return t, nil
}

func (t *Tree) note(format string, args ...any) {
	t.Notes = append(t.Notes, fmt.Sprintf(format, args...))
}

func (t *Tree) anomaly(format string, args ...any) {
	if len(t.Anomalies) < maxAnomalies {
		t.Anomalies = append(t.Anomalies, fmt.Sprintf(format, args...))
	}
}

// strongAnomaly records an anomaly with no innocent explanation. It is counted
// even when the list of rendered anomalies is already full.
func (t *Tree) strongAnomaly(format string, args ...any) {
	t.StrongAnomalies++
	t.anomaly(format, args...)
}

// headBytes is how much of the start of a stream is kept for archiveMagic: one
// tar block, which carries the "ustar" signature at offset 257.
const headBytes = 512

// countReader counts the bytes read through it and keeps the first headBytes.
type countReader struct {
	r    io.Reader
	n    int64
	head []byte
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if room := headBytes - len(c.head); room > 0 && n > 0 {
		c.head = append(c.head, p[:min(n, room)]...)
	}
	c.n += int64(n)
	return n, err
}

// archiveMagic reports whether a stream starts with the signature of an archive
// or compression container — whether or not this scanner can unpack it.
//
// It separates two things an unpack failure can mean. A resource that starts
// like an archive but could not be unpacked (a compression the scanner lacks, a
// corrupt or deliberately malformed container) is a package that went
// unexamined, and is reported as such. A resource with no such signature is a
// metadata document that happens to share a package's coordinate — a wheel's
// METADATA sidecar, a .nuspec, a gemspec — and is none of this gate's business.
func archiveMagic(head []byte) bool {
	at := func(off int, sig string) bool {
		return len(head) >= off+len(sig) && string(head[off:off+len(sig)]) == sig
	}
	switch {
	case at(0, "\x1f\x8b"), // gzip
		at(0, "PK\x03\x04"), at(0, "PK\x05\x06"), at(0, "PK\x07\x08"), // zip
		at(0, "BZh"),                         // bzip2
		at(0, "\xfd7zXZ\x00"),                // xz
		at(0, "\x28\xb5\x2f\xfd"),            // zstd
		at(0, "\x04\x22\x4d\x18"),            // lz4
		at(0, "LZIP"),                        // lzip
		at(0, "\x5d\x00\x00"),                // lzma (alone)
		at(0, "7z\xbc\xaf\x27\x1c"),          // 7-zip
		at(0, "Rar!\x1a\x07"),                // rar
		at(0, "\x1f\x9d"), at(0, "\x1f\xa0"), // compress, lzh
		at(0, "!<arch>\n"),                                // ar (a .deb)
		at(0, "\xed\xab\xee\xdb"),                         // rpm
		at(0, "070701"), at(0, "070702"), at(0, "070707"), // cpio
		at(0, "xar!"),    // xar
		at(0, "MSCF"),    // cabinet
		at(257, "ustar"): // tar
		return true
	}
	// A zstd skippable frame (magic 0x184D2A50..5F, little-endian): a zstd stream
	// may legally begin with one.
	return len(head) >= 4 && head[0]&0xf0 == 0x50 && head[1] == 0x2a && head[2] == 0x4d && head[3] == 0x18
}

// archiveSuffixes are the file-name endings under which package managers accept
// an installable archive. A resource carrying one claims to be a package.
var archiveSuffixes = []string{
	".tgz", ".tar.gz", ".tar", ".taz", ".tar.z", ".tbz", ".tbz2", ".tar.bz2",
	".txz", ".tar.xz", ".tlz", ".tar.lz", ".tar.lzma", ".tzst", ".tar.zst",
	".tbr", ".tar.br", ".zip", ".whl", ".egg", ".gem", ".crate", ".nupkg",
	".snupkg", ".jar", ".war", ".ear", ".aar", ".phar", ".vsix", ".conda",
	".apk", ".deb", ".rpm", ".7z", ".rar", ".cab", ".gz", ".bz2", ".xz", ".zst",
}

// claimsArchive reports whether a file name presents the resource as an
// installable archive.
func claimsArchive(filename string) bool {
	name := strings.ToLower(filename)
	for _, suf := range archiveSuffixes {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	return false
}

// safePath turns an archive member name into the root-relative key the tree
// stores the file under. It never returns an absolute path or one containing
// "..": separators are unified, "." and empty segments dropped, ".." segments
// and any root or drive prefix removed, control and invisible characters
// replaced. unsafe reports that the name was not already a plain relative path
// — it tried to be absolute or to climb out of the root — which the caller
// records as an anomaly. The result is at most maxPathBytes long.
func safePath(name string) (clean string, unsafe bool) {
	s := strings.ReplaceAll(name, `\`, "/")
	// A Windows drive prefix ("C:/...") is an absolute path on the systems that
	// honor it.
	if len(s) >= 2 && s[1] == ':' && isASCIILetter(s[0]) {
		unsafe = true
		s = s[2:]
	}
	if strings.HasPrefix(s, "/") {
		unsafe = true
	}
	segs := strings.Split(s, "/")
	out := segs[:0]
	for _, seg := range segs {
		switch seg {
		case "", ".":
			continue
		case "..":
			unsafe = true
			continue
		}
		out = append(out, scrubSegment(seg))
	}
	clean = strings.Join(out, "/")
	if clean == "" {
		clean = "_unnamed"
	}
	if len(clean) > maxPathBytes {
		// Keep both ends and make the middle unambiguous, so two long names that
		// differ only in the elided part still get distinct keys.
		sum := sha256.Sum256([]byte(clean))
		keep := (maxPathBytes - 20) / 2
		clean = truncateUTF8(clean, keep) + "~" + hex.EncodeToString(sum[:6]) + "~" + tailUTF8(clean, keep)
	}
	return clean, unsafe
}

// scrubSegment makes one path segment printable: invalid UTF-8, control
// characters and invisible/bidirectional formatting characters — which can make
// a name render as something other than what it is — become '?'.
func scrubSegment(seg string) string {
	clean := true
	for _, r := range seg {
		if r == utf8.RuneError || isControlRune(r) || isInvisibleRune(r) {
			clean = false
			break
		}
	}
	if clean && utf8.ValidString(seg) {
		return seg
	}
	var b strings.Builder
	for _, r := range seg {
		if r == utf8.RuneError || isControlRune(r) || isInvisibleRune(r) {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// isInvisibleRune reports zero-width and bidirectional-control characters: the
// ones used to hide text or to make source render differently from how it
// executes ("Trojan Source").
func isInvisibleRune(r rune) bool {
	switch {
	case r == 0x00AD, r == 0xFEFF, r == 0x061C, r == 0x180E:
		return true
	case r >= 0x200B && r <= 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2060 && r <= 0x2069:
		return true
	}
	return false
}

// truncateUTF8 returns at most n bytes of s without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// tailUTF8 returns at most the last n bytes of s without splitting a rune.
func tailUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// linkEscapes reports whether a link at p with the given target resolves
// outside the package root.
func linkEscapes(p, target string) bool {
	tgt := strings.ReplaceAll(target, `\`, "/")
	if tgt == "" {
		return false
	}
	if strings.HasPrefix(tgt, "/") || (len(tgt) >= 2 && tgt[1] == ':' && isASCIILetter(tgt[0])) {
		return true
	}
	resolved := path.Clean(path.Join(path.Dir(p), tgt))
	return resolved == ".." || strings.HasPrefix(resolved, "../")
}

// decodeText decides whether a member is text and returns its UTF-8 form.
// UTF-16 with a byte-order mark is decoded rather than dismissed as binary:
// PowerShell install scripts are routinely saved that way, and a script the
// model cannot read is a script that was never reviewed.
func decodeText(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		return data, true
	}
	if len(data) >= 2 {
		switch {
		case data[0] == 0xFF && data[1] == 0xFE:
			return decodeUTF16(data[2:], binary.LittleEndian), true
		case data[0] == 0xFE && data[1] == 0xFF:
			return decodeUTF16(data[2:], binary.BigEndian), true
		}
	}
	sample := data
	if len(sample) > sniffBytes {
		sample = sample[:sniffBytes]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return nil, false
	}
	// Text has few control characters and is (mostly) valid UTF-8. A sample cut
	// mid-rune must not be counted as invalid, hence the slack at its end.
	var control, invalid int
	for i := 0; i < len(sample); {
		c := sample[i]
		if c < utf8.RuneSelf {
			if c < 0x20 && c != '\n' && c != '\r' && c != '\t' && c != '\f' && c != 0x1b {
				control++
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(sample[i:])
		if r == utf8.RuneError && size == 1 && i < len(sample)-utf8.UTFMax {
			invalid++
		}
		i += size
	}
	if control*20 > len(sample) || invalid*10 > len(sample) {
		return nil, false
	}
	// Strip a UTF-8 byte-order mark so line 1 starts with the file's content.
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}), true
}

func decodeUTF16(data []byte, order binary.ByteOrder) []byte {
	units := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		units = append(units, order.Uint16(data[i:]))
	}
	return []byte(string(utf16.Decode(units)))
}

// binaryMagic names common binary formats by their leading bytes. It is a
// description for the model, not a security classification.
var binaryMagic = []struct {
	magic []byte
	name  string
}{
	{[]byte{0x7f, 'E', 'L', 'F'}, "ELF executable or shared object"},
	{[]byte{'M', 'Z'}, "Windows PE executable or DLL"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, "Mach-O binary"},
	{[]byte{0xCE, 0xFA, 0xED, 0xFE}, "Mach-O binary"},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, "Java class file or Mach-O universal binary"},
	{[]byte{0x00, 'a', 's', 'm'}, "WebAssembly module"},
	{[]byte{0x1f, 0x8b}, "gzip-compressed data"},
	{[]byte{'B', 'Z', 'h'}, "bzip2-compressed data"},
	{[]byte{0xFD, '7', 'z', 'X', 'Z', 0x00}, "xz-compressed data"},
	{[]byte{0x28, 0xB5, 0x2F, 0xFD}, "zstd-compressed data"},
	{[]byte{'P', 'K', 0x03, 0x04}, "zip archive (also jar, wheel, nupkg)"},
	{[]byte{'7', 'z', 0xBC, 0xAF}, "7-zip archive"},
	{[]byte{0x89, 'P', 'N', 'G'}, "PNG image"},
	{[]byte{0xFF, 0xD8, 0xFF}, "JPEG image"},
	{[]byte{'G', 'I', 'F', '8'}, "GIF image"},
	{[]byte{'%', 'P', 'D', 'F'}, "PDF document"},
	{[]byte{'S', 'Q', 'L', 'i', 't', 'e'}, "SQLite database"},
	{[]byte{'w', 'O', 'F', 'F'}, "web font"},
	{[]byte{0x00, 0x01, 0x00, 0x00}, "TrueType font"},
	{[]byte{'!', '<', 'a', 'r', 'c', 'h', '>'}, "ar archive (static library or .deb)"},
}

func sniffBinary(data []byte) string {
	for _, m := range binaryMagic {
		if bytes.HasPrefix(data, m.magic) {
			return m.name
		}
	}
	// A CPython bytecode file: a 2-byte version magic followed by "\r\n".
	if len(data) >= 4 && data[2] == '\r' && data[3] == '\n' {
		return "Python bytecode (.pyc)"
	}
	return "binary data"
}

// indexLines records where each line of Data starts.
func (f *File) indexLines() {
	f.lineStarts = f.lineStarts[:0]
	if len(f.Data) == 0 {
		f.Lines = 0
		return
	}
	f.lineStarts = append(f.lineStarts, 0)
	for i, c := range f.Data {
		if c == '\n' && i+1 < len(f.Data) {
			f.lineStarts = append(f.lineStarts, i+1)
		}
	}
	f.Lines = len(f.lineStarts)
}

// line returns the 1-based line n without its terminator.
func (f *File) line(n int) []byte {
	if n < 1 || n > len(f.lineStarts) {
		return nil
	}
	start := f.lineStarts[n-1]
	end := len(f.Data)
	if n < len(f.lineStarts) {
		end = f.lineStarts[n]
	}
	return bytes.TrimRight(f.Data[start:end], "\r\n")
}

// lineAt returns the 1-based line number containing byte offset off.
func (f *File) lineAt(off int) int {
	i := sort.Search(len(f.lineStarts), func(i int) bool { return f.lineStarts[i] > off })
	if i == 0 {
		return 1
	}
	return i
}

// Readable reports whether the file has content a tool can show.
func (f *File) Readable() bool { return !f.Binary && !f.Unretained }

// describe renders the file's kind for listings.
func (f *File) describe() string {
	switch {
	case f.Binary:
		return "binary: " + f.Kind
	case f.Unretained:
		return "text (content not retained)"
	case f.Truncated:
		return fmt.Sprintf("text, %d lines (only the first %d bytes kept)", f.Lines, len(f.Data))
	default:
		return fmt.Sprintf("text, %d lines", f.Lines)
	}
}
