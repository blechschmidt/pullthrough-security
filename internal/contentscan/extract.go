package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// errUnrecognizedArchive signals the artifact is not an archive format the gate
// understands; the caller treats it as a clean, not-inspected result (fail open).
var errUnrecognizedArchive = errors.New("contentscan: unrecognized archive format")

// canonEco normalizes an ecosystem alias to a canonical key.
func canonEco(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "pypi", "python", "pip":
		return "pip"
	case "gem", "gems", "ruby", "rubygems":
		return "rubygems"
	case "crates", "crate", "rust", "cargo":
		return "cargo"
	case "node", "nodejs", "npm":
		return "npm"
	case "composer", "packagist", "php":
		return "composer"
	case "nuget", "dotnet", ".net":
		return "nuget"
	default:
		return strings.ToLower(strings.TrimSpace(eco))
	}
}

// expectsBinaries reports whether the artifact is a binary distribution whose
// payload legitimately contains compiled objects (a Python wheel, a NuGet
// package, a conda package, a JAR). For such artifacts the embedded-binary and
// high-entropy-blob heuristics are suppressed — the bytes are expected — while
// the secret / obfuscated-JS / dynamic-exec heuristics still apply.
func expectsBinaries(art Artifact) bool {
	name := strings.ToLower(art.Filename)
	mt := strings.ToLower(art.MediaType)
	switch {
	case strings.HasSuffix(name, ".whl") || strings.Contains(mt, "wheel"):
		return true
	case strings.HasSuffix(name, ".nupkg"):
		return true
	case strings.HasSuffix(name, ".conda"):
		return true
	case strings.HasSuffix(name, ".jar") || strings.HasSuffix(name, ".war") || strings.HasSuffix(name, ".aar"):
		return true
	}
	switch canonEco(art.Ecosystem) {
	case "nuget", "homebrew":
		// A Homebrew bottle is a precompiled binary tarball, so compiled objects in
		// its payload are expected; the secret / obfuscated-JS / dynamic-exec
		// heuristics still apply.
		return true
	default:
		return false
	}
}

// walkedFile is one regular file read out of an archive.
type walkedFile struct {
	name string
	data []byte
	// size is the entry's declared (uncompressed) size; data holds at most the
	// per-file cap of it.
	size int64
	// truncated reports that data is a prefix of the entry (the per-file cap or a
	// walk limit cut it short).
	truncated bool
	// mode holds the member's Unix permission bits, including set-uid (04000),
	// set-gid (02000) and sticky (01000), when the container records them; zero
	// otherwise.
	mode uint32
	// synthetic reports an entry the walker composed from the container's own
	// metadata (an RPM header's scriptlets) rather than read out as a member.
	synthetic bool
}

// walkedLink is a non-regular entry that names another path: a symbolic or hard
// link. The walker never follows or materializes one — it has no filesystem to
// do so on — but a link is reported because a link that points outside the
// archive root is a classic extraction attack and therefore a signal in itself.
type walkedLink struct {
	name   string
	target string
	hard   bool
}

// visitor receives each extracted file. It returns false to stop the walk early
// (e.g. the finding budget is exhausted).
type visitor func(wf walkedFile) bool

// Reasons a walk stopped before the whole archive was examined.
const (
	stopArchiveBytes  = "max-archive-bytes"  // the compressed artifact exceeded the input cap
	stopFiles         = "max-files"          // the entry-count guard tripped
	stopUnpackedBytes = "max-unpacked-bytes" // the decompressed-byte cap tripped
	stopRatio         = "compression-ratio"  // the decompression-ratio guard tripped (bomb)
	stopZipDirectory  = "zip-directory"      // the zip central directory declares too many entries
	stopFileBytes     = "max-file-bytes"     // at least one entry was cut at the per-file cap
	// stopNestedFormat: a part of the artifact that the installer unpacks (an
	// RPM's payload, a .deb's data archive, a nested archive) is in a format or
	// compression the walker cannot open, so its members were not examined.
	stopNestedFormat = "unsupported-nested-format"
	// stopMalformed: the container's structure broke off part-way (a truncated or
	// corrupt member table); what precedes the break was examined.
	stopMalformed = "malformed-container"
	// stopSecondReading: the artifact also ends like a zip archive — so a zip
	// reader would open it and see other members than the format at its head
	// holds — and that reading could not be examined (the artifact is too large
	// to keep for a second pass and no random access to it was given).
	stopSecondReading = "unexamined-second-reading"
)

// errWalkLimit aborts the decompressed stream once a walk limit trips. It never
// escapes the walker: the limit is reported through walkStats, not as an error.
var errWalkLimit = errors.New("contentscan: archive walk limit reached")

// ratioFloor is the decompressed size below which the compression-ratio guard
// does not apply: tiny, highly-repetitive archives legitimately compress
// thousands-fold, and a bomb is only a bomb once it is big.
const ratioFloor = 4 << 20

// zipDirectorySlack is the number of central-directory records tolerated beyond
// four times the file cap before a zip is refused unparsed. Directory records
// include directories and other non-file entries, hence the multiple.
const zipDirectorySlack = 4096

// Nesting bounds.
const (
	// maxCompressionLayers bounds compression inside compression (a ".tar.gz.xz"):
	// nobody ships more than two, and an unbounded chain is a recursion bomb.
	maxCompressionLayers = 3
	// nestedZipCap bounds a zip found inside another archive. A zip's directory
	// is at its end, so a nested one has to be buffered to be opened.
	nestedZipCap = 16 << 20
	// peekBytes is how much of a stream is examined to recognize its format: one
	// tar block.
	peekBytes = 512
	// secondReadingCap bounds the copy of a streamed artifact that is kept so it
	// can be read a second time, as a zip from its end. A larger artifact gets
	// that second look only through random access.
	secondReadingCap = 16 << 20
)

// Prefixes under which the members of a second reading are reported: the same
// file, opened as a different archive format than the one its first bytes name.
const (
	zipReadingPrefix = "_same-file-read-as-zip!/"
	tarReadingPrefix = "_same-file-read-as-tar!/"
)

// walkStats is what a walk learned about the archive.
type walkStats struct {
	// format is the detected container: "tar.gz", "zip", "deb", "rpm", "nar.xz", …
	format string
	// files counts the regular files handed to the visitor.
	files int
	// links and others count the non-regular entries seen (never materialized).
	links  int
	others int
	// compressed is the number of artifact bytes consumed; unpacked is the number
	// of decompressed bytes produced (read or skipped).
	compressed int64
	unpacked   int64
	// reasons lists why the walk is incomplete, in the order the limits tripped.
	// Empty means the whole archive was examined.
	reasons []string
	// prefix is the number of bytes in front of the first member of a zip that
	// does not start at the beginning of the file (zero for an ordinary one).
	prefix int64
	// second names a second reading of the same file: "zip" when a file whose
	// head is another format is also a zip from its end, "tar" when a zip's first
	// bytes are also a valid tar header. Empty for an ordinary artifact.
	second string
}

// truncated reports whether any limit cut the walk short.
func (s *walkStats) truncated() bool { return len(s.reasons) > 0 }

func (s *walkStats) addReason(r string) {
	for _, have := range s.reasons {
		if have == r {
			return
		}
	}
	s.reasons = append(s.reasons, r)
}

// walkOptions selects the walker behaviour a caller opts into. The zero value
// is the content-analysis gate's own: archives only, and no archive opened
// inside another except where the package format itself nests one.
type walkOptions struct {
	// name is the artifact's file name. It names the single file inside a
	// compressed stream that is not an archive ("install.sh.gz" -> "install.sh").
	name string
	// singleFile accepts content that is not an archive — compressed or not —
	// and walks it as the one file it is. Without it such content is not an
	// archive (errUnrecognizedArchive).
	singleFile bool
	// nested is how many levels of archive-inside-archive are opened beyond the
	// ones a package format defines (a gem's data.tar.gz, a .deb's control and
	// data archives, an RPM's payload). Zero opens none: a nested archive is then
	// one opaque member.
	nested int
	// at, when non-nil, gives random access to the artifact (size bytes long). A
	// zip is then read through it — directory first, members on demand — instead
	// of being buffered whole from the stream, which is what lets a zip larger
	// than the input cap be inventoried at all.
	at   io.ReaderAt
	size int64
	// reread, when non-nil, also gives random access to the artifact (size bytes
	// long), but only for a second reading: the artifact is walked from the
	// stream, and looked at again through reread only if it turns out to be a zip
	// from its end as well.
	reread io.ReaderAt
}

// walker carries the state of one archive walk, shared across nested archives
// so every bound is a bound on the whole artifact rather than on each layer.
type walker struct {
	ctx    context.Context
	b      budget
	opts   walkOptions
	visit  visitor
	onLink func(walkedLink)
	in     *countingReader
	// random counts the bytes read through walkOptions.at, which bypass in.
	random *countingReaderAt
	stats  walkStats
	// entries counts every archive member seen (files, directories, links) against
	// the entry-count guard, so an archive of a million empty directories is cut
	// off as surely as one of a million files.
	entries int
	stopped bool // the visitor asked to stop
	limited bool // a hard limit tripped; nothing further may be read
	// generic counts the archives currently being walked that are nested in the
	// artifact without being part of its format: an archive that merely sits
	// inside the package, as opposed to the package's own inner archive.
	generic int
}

// walkArchive detects the artifact's archive format from its leading bytes and
// walks every regular file, invoking visit for each (bounded per the budget).
// It returns whether the walk hit a size/entry bound (truncated) and a non-nil
// error only for an unrecognized or unreadable archive, which the caller treats
// as fail-open. The whole walk is bounded by ctx (the scan timeout).
func walkArchive(ctx context.Context, r io.Reader, b budget, visit visitor) (truncated bool, err error) {
	stats, err := walkArchiveStats(ctx, r, b, visit, nil)
	return stats.truncated(), err
}

// walkArchiveStats is walkArchive returning the full walk statistics and
// reporting link entries to onLink (which may be nil).
func walkArchiveStats(ctx context.Context, r io.Reader, b budget, visit visitor, onLink func(walkedLink)) (walkStats, error) {
	return walkArtifactStats(ctx, r, b, walkOptions{}, visit, onLink)
}

// walkArtifactStats is walkArchiveStats with the caller's walk options.
func walkArtifactStats(ctx context.Context, r io.Reader, b budget, opts walkOptions, visit visitor, onLink func(walkedLink)) (walkStats, error) {
	w := &walker{ctx: ctx, b: b, opts: opts, visit: visit, onLink: onLink}
	w.in = &countingReader{r: io.LimitReader(r, b.maxArchiveBytes+1), max: b.maxArchiveBytes}
	err := w.walkTop()
	return w.finish(), err
}

// walkTop recognizes the artifact's outermost container and walks it.
//
// A file can be more than one archive. Which one a tool sees depends on where it
// looks: a tar, gzip, ar, cpio or RPM reader starts at the first byte, a zip
// reader at the last — a zip's directory is at its end, and every zip reader in
// use accepts whatever precedes the first member. So a file that begins as a
// tarball and ends as a zip is a tarball to npm and a wheel to pip, and a walker
// that trusted the first bytes alone would show a reviewer the one reading while
// the installer unpacks the other. The first bytes pick the primary reading; the
// file is then also read the other way (zipReading, tarReading), and what that
// yields is reported next to it.
func (w *walker) walkTop() error {
	rec := &streamRecorder{keep: w.opts.at == nil && w.opts.reread == nil}
	w.in.rec = rec
	br := bufio.NewReaderSize(w.in, 4*peekBytes)
	head, _ := br.Peek(peekBytes)
	kind := sniffContainer(head)
	if kind == containerZip || kind == containerNone {
		// These hold the whole artifact themselves; nothing needs recording.
		w.in.rec = nil
	}
	var err error
	switch {
	case kind.compression():
		err = w.walkTopCompressed(kind, br)
	case kind == containerZip:
		w.stats.format = "zip"
		return w.walkTopZip(br, looksLikeTarBlock(head) && !allZero(head))
	case kind == containerTar:
		w.stats.format = "tar"
		err = w.walkTar(w.guard(br), "", 0)
	case kind == containerAr:
		w.stats.format = "ar"
		err = w.walkAr(w.guard(br), "", 0)
	case kind == containerRPM:
		w.stats.format = "rpm"
		err = w.walkRPM(br, "", 0)
	case kind == containerCpio:
		w.stats.format = "cpio"
		err = w.walkCpio(w.guard(br), "", 0, nil)
	case kind == containerNAR:
		w.stats.format = "nar"
		err = w.walkNAR(w.guard(br), "", 0)
	default:
		return w.walkOpaque(br)
	}
	return w.zipReading(br, rec, err)
}

// walkTopCompressed walks an artifact whose outermost layer is a compression.
func (w *walker) walkTopCompressed(kind container, br *bufio.Reader) error {
	dr, closer, err := w.decompressor(kind, br)
	if err != nil {
		return err
	}
	defer closer()
	single := stripCompressionSuffix(path.Base(strings.ReplaceAll(w.opts.name, `\`, "/")))
	if single == "" || single == "." || single == "/" {
		single = "content"
	}
	return w.inflated(dr, kind.suffix(), "", single, 0, 1, true)
}

// walkTopZip walks an artifact that starts as a zip. alsoTar reports that its
// first block is a valid tar header as well: the file is then also walked as
// the tar an extractor starting at the first byte would see.
func (w *walker) walkTopZip(br *bufio.Reader, alsoTar bool) error {
	if w.opts.at != nil {
		err := w.walkZipAt("")
		if alsoTar && err == nil && !w.done() && w.random != nil {
			w.tarReading(io.NewSectionReader(w.random, 0, w.opts.size))
		}
		return err
	}
	data, ok, err := w.readZip(br, 0)
	if err != nil || !ok {
		return err
	}
	if err := w.walkZipBytes(data, "", 0); err != nil {
		return err
	}
	if alsoTar && !w.done() {
		w.tarReading(bytes.NewReader(data))
	}
	return nil
}

// tarReading walks, as a tar, a file whose primary reading is a zip. A zip
// whose first 512 bytes carry a valid tar checksum did not come about by
// accident: the two readings are there to be different.
func (w *walker) tarReading(r io.Reader) {
	w.stats.second = "tar"
	w.generic++
	defer func() { w.generic-- }()
	_ = w.walkTar(w.guard(r), tarReadingPrefix, 0)
}

// zipReading looks at an artifact whose head is not a zip the way a zip reader
// does — from its end — once the primary walk is over. primaryErr is that
// walk's result, and is what zipReading returns unless the file turns out to be
// a zip and nothing else.
//
//   - No zip directory at the end: nothing to add.
//   - A zip, and the primary reading found members: both readings stand. The
//     zip's members are reported under zipReadingPrefix.
//   - A zip, and the primary reading found nothing (the head merely looked like
//     another format: zero padding reads as an empty tar) or failed: the file is
//     a zip behind a prefix, and is reported as one.
//   - A zip directory, but no way to re-read the file (it outgrew the copy kept
//     for this and there is no random access): the reason is recorded, so the
//     view is never mistaken for the whole of what an installer may unpack.
func (w *walker) zipReading(br *bufio.Reader, rec *streamRecorder, primaryErr error) error {
	defer func() { w.in.rec = nil }()
	if w.done() {
		return primaryErr
	}
	// A zip reader looks at the end of the file: read what the primary walk left
	// unread (the input reader records it as it passes).
	if _, err := io.Copy(io.Discard, br); err != nil || w.ctx.Err() != nil {
		return primaryErr
	}

	at, size := w.opts.at, w.opts.size
	if at == nil && w.opts.reread != nil && w.opts.size == w.in.n {
		at = w.opts.reread
	}
	var tail []byte
	switch {
	case at != nil:
		n := int64(maxZipTrailer)
		if n > size {
			n = size
		}
		tail = make([]byte, n)
		if _, err := at.ReadAt(tail, size-n); err != nil && err != io.EOF {
			return primaryErr
		}
	case w.b.maxArchiveBytes > 0 && w.in.n > w.b.maxArchiveBytes:
		// The end of the artifact was never read; the input-cap reason says so.
		return primaryErr
	default:
		size = w.in.n
		tail = rec.end()
	}
	if !plausibleZipEnd(tail, size) {
		return primaryErr
	}

	var (
		zr     *zip.Reader
		zerr   error
		random *countingReaderAt
	)
	switch {
	case at != nil:
		random = &countingReaderAt{ra: at, limit: -1}
		if w.b.maxFiles > 0 {
			random.limit = int64(4*w.b.maxFiles+zipDirectorySlack)*zipDirectoryEntryBytes + 256<<10
		}
		zr, zerr = zip.NewReader(random, size)
		if random.exceeded {
			w.stats.addReason(stopZipDirectory)
			return primaryErr
		}
	case rec.keep && int64(len(rec.whole)) == size:
		if w.b.maxFiles > 0 && bytes.Count(rec.whole, zipDirectorySignature) > 4*w.b.maxFiles+zipDirectorySlack {
			w.stats.addReason(stopZipDirectory)
			return primaryErr
		}
		zr, zerr = zip.NewReader(bytes.NewReader(rec.whole), size)
	default:
		w.stats.second = "zip"
		w.stats.addReason(stopSecondReading)
		return primaryErr
	}
	if (zerr != nil && !errors.Is(zerr, zip.ErrInsecurePath)) || zr == nil || len(zr.File) == 0 {
		return primaryErr // the end-of-directory signature was a coincidence
	}
	if w.b.maxFiles > 0 && len(zr.File) > 4*w.b.maxFiles+zipDirectorySlack {
		w.stats.addReason(stopZipDirectory)
		return primaryErr
	}
	if random != nil {
		random.limit = -1 // the directory is read; members are bounded by the walk's own limits
		w.random = random
	}

	if primaryErr != nil || w.entries == 0 {
		// Nothing came of the reading the head suggested: this is a zip behind a
		// prefix, like the ones walkOpaque finds.
		w.stats.format = "zip"
		if rec.keep && int64(len(rec.whole)) == size {
			// The prefix ends where the first member's local header begins.
			if first := bytes.Index(rec.whole, []byte("PK\x03\x04")); first > 0 {
				w.stats.prefix = int64(first)
				w.emitPrefix(rec.whole[:first])
			}
		} else if first := firstZipMember(zr); first > 0 {
			w.stats.prefix = first
		}
		w.walkZipFiles(zr, "", 0)
		return nil
	}
	w.stats.second = "zip"
	w.generic++
	w.walkZipFiles(zr, zipReadingPrefix, 0)
	w.generic--
	return primaryErr
}

// firstZipMember is where the first member of an opened zip begins, as nearly
// as the directory tells: the lowest data offset, less the fixed part of a local
// header and the member's name. It is zero for a zip without a prefix.
func firstZipMember(zr *zip.Reader) int64 {
	first := int64(-1)
	for _, f := range zr.File {
		off, err := f.DataOffset()
		if err != nil {
			continue
		}
		if off -= 30 + int64(len(f.Name)); off < 0 {
			off = 0
		}
		if first < 0 || off < first {
			first = off
		}
	}
	if first < 0 {
		return 0
	}
	return first
}

// plausibleZipEnd reports whether tail — the last bytes of a file size bytes
// long — holds a zip end-of-central-directory record that could describe a
// directory inside that file. It is a cheap filter in front of the zip reader,
// and what decides whether a file that cannot be re-read is reported as one a
// zip reader would open: the four signature bytes alone turn up by chance in
// compressed data; a record whose fields also fit the file does not.
func plausibleZipEnd(tail []byte, size int64) bool {
	const recordLen = 22
	sig := []byte("PK\x05\x06")
	for end := len(tail); ; {
		i := bytes.LastIndex(tail[:end], sig)
		if i < 0 {
			return false
		}
		end = i + len(sig) - 1
		if len(tail)-i < recordLen {
			continue
		}
		rec := tail[i : i+recordLen]
		le16 := func(off int) int64 { return int64(rec[off]) | int64(rec[off+1])<<8 }
		le32 := func(off int) int64 {
			return int64(rec[off]) | int64(rec[off+1])<<8 | int64(rec[off+2])<<16 | int64(rec[off+3])<<24
		}
		disk, cdDisk, onDisk, entries := le16(4), le16(6), le16(8), le16(10)
		cdSize, cdOffset, comment := le32(12), le32(16), le16(20)
		pos := size - int64(len(tail)) + int64(i) // where the record sits in the file
		if int64(i)+recordLen+comment > int64(len(tail)) {
			continue // the comment would run past the end of the file
		}
		if cdSize == 0xffffffff || cdOffset == 0xffffffff || entries == 0xffff {
			// Zip64: the real values are in the zip64 record just before this one.
			if pos >= 20+56 {
				return true
			}
			continue
		}
		if disk != 0 || cdDisk != 0 || onDisk != entries || entries == 0 {
			continue
		}
		if cdSize < 46*entries || cdOffset+cdSize > pos {
			continue
		}
		return true
	}
}

// allZero reports whether b holds only zero bytes.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// streamRecorder remembers what a second look at a streamed artifact needs: its
// last maxZipTrailer bytes, where a zip's directory ends, and — as long as the
// artifact is no larger than secondReadingCap — every byte of it.
type streamRecorder struct {
	tail  []byte
	whole []byte
	// keep reports that whole still holds the entire stream.
	keep bool
}

// Write records p. It never fails.
func (s *streamRecorder) Write(p []byte) (int, error) {
	if s.keep {
		if len(s.whole)+len(p) > secondReadingCap {
			s.keep, s.whole = false, nil
		} else {
			s.whole = append(s.whole, p...)
		}
	}
	if len(p) >= maxZipTrailer {
		s.tail = append(s.tail[:0], p[len(p)-maxZipTrailer:]...)
		return len(p), nil
	}
	s.tail = append(s.tail, p...)
	if len(s.tail) > 2*maxZipTrailer {
		n := copy(s.tail, s.tail[len(s.tail)-maxZipTrailer:])
		s.tail = s.tail[:n]
	}
	return len(p), nil
}

// end returns the last bytes of the stream, at most maxZipTrailer of them.
func (s *streamRecorder) end() []byte {
	if len(s.tail) > maxZipTrailer {
		return s.tail[len(s.tail)-maxZipTrailer:]
	}
	return s.tail
}

// maxZipTrailer is how far from the end of a file a zip's end-of-directory
// record can start: the 22-byte record plus the longest possible comment.
const maxZipTrailer = 22 + 65535

// prefixName is the name under which the bytes in front of a prefixed zip's
// first member are reported.
const prefixName = "_data-before-the-archive"

// walkOpaque handles an artifact that starts like no container.
//
// It may still be one. A zip is located from its end, and every zip reader in
// use — Python's zipfile (pip), the JVM's, .NET's, unzip — accepts arbitrary
// bytes in front of the first member: that is how self-extracting archives,
// Python zipapps and executable jars are built. An installer therefore unpacks
// a wheel or a jar with a few bytes of prefix as readily as a clean one, and a
// walker that looked only at the first bytes would call the same file "not an
// archive". So content that does not start like a container is checked for a
// zip directory at its end, and walked as the zip it is; what precedes the
// first member — a launcher stub, as a rule — is reported as a file of its own.
//
// Anything else is one file, if the caller accepts single files, and otherwise
// not an archive.
func (w *walker) walkOpaque(br *bufio.Reader) error {
	if w.opts.at != nil {
		// Random access: the directory can be looked for without buffering.
		if w.walkPrefixedZipAt() {
			return nil
		}
		if !w.opts.singleFile {
			return errUnrecognizedArchive
		}
		data, hitCap, err := readBounded(br, w.b.maxFileBytes)
		if err != nil || len(data) == 0 {
			return err
		}
		if !w.countEntry() {
			return nil
		}
		w.stats.format = "file"
		size := w.opts.size
		if size < int64(len(data)) {
			size = int64(len(data))
		}
		w.emit(walkedFile{name: w.singleName(), data: data, size: size, truncated: hitCap || size > int64(len(data))})
		return nil
	}

	// The whole artifact is needed to look at its end; it is bounded by the
	// input cap, like a zip.
	data, err := io.ReadAll(br)
	if err != nil {
		return err
	}
	whole := w.b.maxArchiveBytes <= 0 || int64(len(data)) <= w.b.maxArchiveBytes
	if whole {
		if zr, prefix, ok := w.prefixedZip(data); ok {
			w.stats.format = "zip"
			w.stats.prefix = int64(prefix)
			w.emitPrefix(data[:prefix])
			w.walkZipFiles(zr, "", 0)
			return nil
		}
	}
	if !w.opts.singleFile {
		return errUnrecognizedArchive
	}
	if len(data) == 0 || !w.countEntry() {
		return nil
	}
	w.stats.format = "file"
	kept := data
	if w.b.maxFileBytes > 0 && int64(len(kept)) > w.b.maxFileBytes {
		kept = kept[:w.b.maxFileBytes]
	} else if w.b.maxFileBytes <= 0 {
		kept = nil
	}
	w.emit(walkedFile{name: w.singleName(), data: kept, size: int64(len(data)), truncated: len(kept) < len(data)})
	return nil
}

// singleName is the name a single-file artifact is reported under.
func (w *walker) singleName() string {
	name := path.Base(strings.ReplaceAll(w.opts.name, `\`, "/"))
	if name == "" || name == "." || name == "/" {
		return "content"
	}
	return name
}

// emitPrefix reports the bytes in front of a prefixed zip's first member.
func (w *walker) emitPrefix(prefix []byte) {
	if len(prefix) == 0 || !w.countEntry() {
		return
	}
	kept := prefix
	if w.b.maxFileBytes > 0 && int64(len(kept)) > w.b.maxFileBytes {
		kept = kept[:w.b.maxFileBytes]
	}
	w.emit(walkedFile{name: prefixName, data: kept, size: int64(len(prefix)), truncated: len(kept) < len(prefix), synthetic: true})
}

// prefixedZip reports whether data, which does not start like a zip, is one
// behind a prefix, and returns the opened archive and the length of the prefix.
func (w *walker) prefixedZip(data []byte) (*zip.Reader, int, bool) {
	tail := data
	if len(tail) > maxZipTrailer {
		tail = tail[len(tail)-maxZipTrailer:]
	}
	if !bytes.Contains(tail, []byte("PK\x05\x06")) {
		return nil, 0, false
	}
	if w.b.maxFiles > 0 && bytes.Count(data, zipDirectorySignature) > 4*w.b.maxFiles+zipDirectorySlack {
		return nil, 0, false
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || zr == nil || len(zr.File) == 0 {
		return nil, 0, false
	}
	// The prefix ends where the first member's local header begins.
	prefix := bytes.Index(data, []byte("PK\x03\x04"))
	if prefix < 0 {
		prefix = 0
	}
	return zr, prefix, true
}

// walkPrefixedZipAt is prefixedZip through random access: it reports whether
// the artifact was walked as a zip.
func (w *walker) walkPrefixedZipAt() bool {
	random := &countingReaderAt{ra: w.opts.at, limit: -1}
	if w.b.maxFiles > 0 {
		random.limit = int64(4*w.b.maxFiles+zipDirectorySlack)*zipDirectoryEntryBytes + 256<<10
	}
	zr, err := zip.NewReader(random, w.opts.size)
	if random.exceeded || (err != nil && !errors.Is(err, zip.ErrInsecurePath)) || zr == nil || len(zr.File) == 0 {
		return false
	}
	if w.b.maxFiles > 0 && len(zr.File) > 4*w.b.maxFiles+zipDirectorySlack {
		return false
	}
	random.limit = -1
	w.random = random
	w.stats.format = "zip"
	// Where the first member starts is where the prefix ends.
	w.stats.prefix = firstZipMember(zr)
	w.walkZipFiles(zr, "", 0)
	return true
}

// inflated walks what one compression layer held: an archive (tar, cpio, NAR,
// ar), another compression layer, or a single file.
//
// An archive's members are reported under archivePrefix; a single file is
// reported as singleName. top marks the artifact itself (as opposed to a
// compressed member of another archive): there the detected format is recorded,
// a stream that cannot be read is an error rather than a note in the
// statistics, and a single file is accepted only when the caller opted in.
func (w *walker) inflated(dr io.Reader, suffix, archivePrefix, singleName string, depth, layers int, top bool) error {
	br := bufio.NewReaderSize(w.guard(dr), 4*peekBytes)
	head, perr := br.Peek(peekBytes)
	setFormat := func(base string) {
		if top {
			w.stats.format = base + "." + suffix
		}
	}
	if len(head) == 0 {
		// Nothing was decompressed. A limit or a canceled walk is reported through
		// the statistics; a genuinely empty stream is an archive with no members,
		// as an empty tar always was. Anything else is a stream that could not be
		// decompressed at all.
		if w.limited || w.ctx.Err() != nil || perr == nil || errors.Is(perr, io.EOF) {
			setFormat("tar")
			return nil
		}
		if top {
			if decoderMemoryError(perr) {
				return fmt.Errorf("%w: %w", errDictTooLarge, perr)
			}
			return fmt.Errorf("%w: %w", errUnrecognizedArchive, perr)
		}
		w.stats.addReason(stopNestedFormat)
		return nil
	}
	switch kind := sniffContainer(head); {
	case kind == containerTar:
		setFormat("tar")
		return w.walkTar(br, archivePrefix, depth)
	case kind == containerCpio:
		setFormat("cpio")
		return w.walkCpio(br, archivePrefix, depth, nil)
	case kind == containerNAR:
		setFormat("nar")
		return w.walkNAR(br, archivePrefix, depth)
	case kind == containerAr:
		setFormat("ar")
		return w.walkAr(br, archivePrefix, depth)
	case kind.compression() && layers < maxCompressionLayers:
		inner, closer, err := w.decompressor(kind, br)
		if err != nil {
			if top {
				return err
			}
			w.stats.addReason(stopNestedFormat)
			return nil
		}
		defer closer()
		return w.inflated(inner, kind.suffix()+"."+suffix, archivePrefix, stripCompressionSuffix(singleName), depth, layers+1, top)
	}

	// Not an archive: the compressed stream holds one file.
	if top && !w.opts.singleFile {
		return fmt.Errorf("%w: the compressed stream does not hold an archive", errUnrecognizedArchive)
	}
	if !w.countEntry() {
		return nil
	}
	if top {
		w.stats.format = suffix
	}
	data, hitCap, rerr := readBounded(br, w.b.maxFileBytes)
	size := int64(len(data))
	if hitCap && rerr == nil {
		// Count the rest, so the entry reports the file's real size. The guard
		// keeps this within the walk's decompression budget.
		n, cerr := io.Copy(io.Discard, br)
		size += n
		rerr = cerr
	}
	if rerr != nil {
		// The stream broke before its end: what was decoded is reported, and so
		// is the fact that it is not all of the file.
		w.broke()
		if len(data) == 0 {
			return nil
		}
	}
	w.emit(walkedFile{name: singleName, data: data, size: size, truncated: size > int64(len(data))})
	return nil
}

// finish seals the statistics: byte counters, and the input-cap reason when the
// artifact was larger than the walker was allowed to read.
func (w *walker) finish() walkStats {
	w.stats.compressed = w.consumed()
	if w.b.maxArchiveBytes > 0 && w.in.n > w.b.maxArchiveBytes {
		w.stats.addReason(stopArchiveBytes)
	}
	return w.stats
}

// consumed is the number of artifact bytes read so far, by stream and by
// random access.
func (w *walker) consumed() int64 {
	n := w.in.n
	if w.random != nil {
		n += w.random.n
	}
	return n
}

// guard wraps a decompressed stream so that every byte it yields — whether read
// into a file or skipped past — is counted against the decompressed-byte cap
// and the compression-ratio guard, and so that a canceled context stops the
// walk between reads rather than only between entries. Without it a single
// multi-gigabyte entry would be decompressed to completion merely to be skipped.
func (w *walker) guard(r io.Reader) io.Reader { return &guardReader{w: w, r: r} }

type guardReader struct {
	w *walker
	r io.Reader
}

func (g *guardReader) Read(p []byte) (int, error) {
	w := g.w
	if w.limited {
		return 0, errWalkLimit
	}
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := g.r.Read(p)
	w.stats.unpacked += int64(n)
	if w.b.maxTotalBytes > 0 && w.stats.unpacked > w.b.maxTotalBytes {
		w.limited = true
		w.stats.addReason(stopUnpackedBytes)
		return n, errWalkLimit
	}
	if w.b.maxRatio > 0 && w.stats.unpacked > ratioFloor {
		compressed := w.consumed()
		if compressed < 1 {
			compressed = 1
		}
		if float64(w.stats.unpacked) > w.b.maxRatio*float64(compressed) {
			w.limited = true
			w.stats.addReason(stopRatio)
			return n, errWalkLimit
		}
	}
	return n, err
}

// countEntry charges one archive member against the entry-count guard. It
// reports false once the guard has tripped.
func (w *walker) countEntry() bool {
	w.entries++
	if w.b.maxFiles > 0 && w.entries > w.b.maxFiles {
		w.stats.addReason(stopFiles)
		return false
	}
	return true
}

// done reports that the walk must not go on: the visitor stopped it, a hard
// limit tripped, or its context ended.
func (w *walker) done() bool {
	return w.stopped || w.limited || w.ctx.Err() != nil
}

// emit hands one regular file to the visitor.
func (w *walker) emit(wf walkedFile) {
	if wf.truncated {
		w.stats.addReason(stopFileBytes)
	}
	w.stats.files++
	if !w.visit(wf) {
		w.stopped = true
	}
}

// link reports one link member.
func (w *walker) link(name, target string, hard bool) {
	w.stats.links++
	if w.onLink != nil {
		w.onLink(walkedLink{name: name, target: target, hard: hard})
	}
}

// member handles one regular-file member of a container: it opens the member as
// a nested archive when the package format (or the caller) says to, and
// otherwise reads it, bounded, and hands it to the visitor. inner is the
// member's own name inside its container — what the nesting rules look at;
// reported is the name it is reported under (inner behind the container's
// prefix). r yields exactly the member's bytes. It returns false when the
// stream broke and the container's walk cannot continue.
func (w *walker) member(parent container, depth int, inner, reported string, size int64, mode uint32, r io.Reader) bool {
	if archivePrefix, generic, open := w.opensNested(parent, depth, inner, reported); open {
		br := bufio.NewReaderSize(r, 4*peekBytes)
		head, _ := br.Peek(peekBytes)
		if kind := sniffContainer(head); kind != containerNone {
			before := w.stats.files
			if generic {
				w.generic++
			}
			w.walkNested(kind, br, archivePrefix, reported, depth+1, size)
			if generic {
				w.generic--
			}
			if w.stats.files == before && !w.done() {
				// Nothing came out of it. Keep the member in the inventory as the
				// opaque file it is, so a nested archive the walker could not open
				// stays visible and is not mistaken for an empty one.
				w.emit(walkedFile{name: reported, data: append([]byte(nil), head...), size: size, truncated: size > int64(len(head)), mode: mode})
			}
			return true
		}
		r = br
	}
	data, hitCap, rerr := readBounded(r, w.b.maxFileBytes)
	if rerr != nil {
		return false
	}
	w.emit(walkedFile{name: reported, data: data, size: size, truncated: hitCap, mode: mode})
	return true
}

// opensNested decides whether a member is opened as a nested archive, and under
// which path prefix that archive's own members are reported.
//
// A package format that nests archives defines the first level: a RubyGems
// .gem carries its files in data.tar.gz, a Hex package in contents.tar.gz, a
// .conda in info-*.tar.zst and pkg-*.tar.zst, a .deb in control.tar.* and
// data.tar.*. Those are opened always, and in place — their members are the
// package's files, reported under the names the installer gives them (a .deb's
// control members under DEBIAN/, as `dpkg-deb --raw-extract` lays them out).
// Any other archive inside an archive is opened only when the caller asked for
// nesting, and its members are reported under "<member>!/".
func (w *walker) opensNested(parent container, depth int, inner, reported string) (archivePrefix string, generic, open bool) {
	if depth == 0 {
		outer := strings.TrimSuffix(reported, inner)
		switch parent {
		case containerTar:
			if isNestedTarGz(inner) || inner == "contents.tar.gz" {
				return outer, false, true
			}
		case containerZip:
			if !strings.Contains(inner, "/") && strings.HasSuffix(inner, ".tar.zst") &&
				(strings.HasPrefix(inner, "info-") || strings.HasPrefix(inner, "pkg-")) {
				return outer, false, true
			}
		case containerDeb:
			switch {
			case strings.HasPrefix(inner, "control.tar"):
				return outer + "DEBIAN/", false, true
			case strings.HasPrefix(inner, "data.tar"):
				return outer, false, true
			}
		}
	}
	if depth < w.opts.nested {
		return reported + "!/", true, true
	}
	return "", false, false
}

// walkNested walks an archive found inside another one. Failures are reported
// through the statistics, never as an error: the outer walk goes on.
func (w *walker) walkNested(kind container, br *bufio.Reader, archivePrefix, reported string, depth int, size int64) {
	switch {
	case kind.compression():
		dr, closer, err := w.decompressor(kind, br)
		if err != nil {
			w.stats.addReason(stopNestedFormat)
			return
		}
		defer closer()
		// A compressed member that holds one file, not an archive, is reported
		// where it sits, under its uncompressed name ("metadata.gz" -> "metadata").
		single := path.Join(path.Dir(reported), stripCompressionSuffix(path.Base(reported)))
		_ = w.inflated(dr, kind.suffix(), archivePrefix, single, depth, 1, false)
	case kind == containerZip:
		if size > nestedZipCap {
			w.stats.addReason(stopNestedFormat)
			return
		}
		_ = w.walkZip(br, archivePrefix, depth)
	case kind == containerTar:
		_ = w.walkTar(w.guard(br), archivePrefix, depth)
	case kind == containerAr:
		_ = w.walkAr(w.guard(br), archivePrefix, depth)
	case kind == containerCpio:
		_ = w.walkCpio(w.guard(br), archivePrefix, depth, nil)
	case kind == containerNAR:
		_ = w.walkNAR(w.guard(br), archivePrefix, depth)
	case kind == containerRPM:
		_ = w.walkRPM(br, archivePrefix, depth)
	}
}

// broke records that a container's structure ended before its end marker: a
// truncated or corrupt stream, a member table that stops making sense. What was
// read stands; what follows the break was never seen, and the statistics say
// so. A break that is merely the walker's own doing — a limit it enforced, its
// context ending, the input cap cutting the stream — is already named by that
// limit and is not reported a second time as damage.
//
// Damage to an archive that merely sits inside the package — a corrupt tarball
// among a library's test fixtures — is reported as a nested archive that could
// not be opened, not as damage to the package: the installer never unpacks it.
func (w *walker) broke() {
	if w.done() {
		return
	}
	if w.b.maxArchiveBytes > 0 && w.in.n > w.b.maxArchiveBytes {
		return
	}
	if w.generic > 0 {
		w.stats.addReason(stopNestedFormat)
		return
	}
	w.stats.addReason(stopMalformed)
}

// inventoryIncomplete reports whether the walk so far has missed members (as
// opposed to having merely cut a large file short).
func (w *walker) inventoryIncomplete() bool {
	if w.b.maxArchiveBytes > 0 && w.in.n > w.b.maxArchiveBytes {
		return true
	}
	for _, r := range w.stats.reasons {
		if r != stopFileBytes {
			return true
		}
	}
	return false
}

// walkTar walks a tar stream whose members are reported under prefix. depth is
// the archive nesting level. It returns an error only when the outermost stream
// is not a tar at all (no entry could be read); a mid-stream failure still
// yields what was read.
//
// A damaged header does not end the walk. Extractors differ in what they do
// with one: Go's reader, Python's tarfile and libarchive stop; node-tar (npm)
// skips the block and carries on with the next, and GNU tar prints "Skipping to
// next header" and does the same. A member placed behind a deliberately broken
// header would therefore be installed by npm while a walker that stopped at the
// damage never showed it to anyone. So the walker resynchronizes the way the
// lenient extractors do — it reads on, block by block, to the next valid header
// — and records the damage (stopMalformed) for what it is: evidence.
func (w *walker) walkTar(r io.Reader, prefix string, depth int) error {
	src := &tarSource{r: r}
	tr := tar.NewReader(src)
	seen := 0
	damaged := false
	var firstErr error
	reusedAt := int64(-1)
	for !w.stopped && !w.limited {
		if w.ctx.Err() != nil {
			return nil
		}
		hdr, herr := tr.Next()
		if herr == io.EOF {
			break
		}
		// An "insecure path" (absolute, or escaping via "..") is still a valid
		// header; nothing is ever extracted to a filesystem, so it is walked like
		// any other and left for the consumer to judge.
		if herr != nil && !errors.Is(herr, tar.ErrInsecurePath) {
			if firstErr == nil {
				firstErr = herr
			}
			if w.limited || w.ctx.Err() != nil {
				break
			}
			damaged = true
			next, ok := w.resyncTar(src, &reusedAt)
			if !ok {
				break
			}
			tr = tar.NewReader(next)
			continue
		}
		if hdr == nil {
			break
		}
		seen++
		if !w.countEntry() {
			return nil
		}
		inner := cleanName(hdr.Name)
		name := prefix + inner
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			w.link(name, hdr.Linkname, hdr.Typeflag == tar.TypeLink)
			continue
		case tar.TypeDir:
			continue
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo,
			tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			w.stats.others++
			continue
		default:
			// Regular files — and every other type that carries file data. A
			// contiguous file ('7'), a sparse file, or a type flag nobody defined is
			// written out as an ordinary file by the extractors packages are
			// installed with (GNU tar, Python's tarfile, node-tar). Skipping such an
			// entry here would let a payload be installed that was never examined.
		}

		// A nested archive the package format defines (a gem's data.tar.gz, a Hex
		// package's contents.tar.gz) is streamed, not buffered: its size is bounded
		// by the walk-wide limits, not by the per-file cap (which would cut a real
		// package's payload short).
		if !w.member(containerTar, depth, inner, name, hdr.Size, uint32(hdr.Mode)&0o7777, tr) {
			w.broke()
			return nil
		}
	}
	if damaged {
		if seen == 0 && depth == 0 && !w.limited && w.ctx.Err() == nil {
			return firstErr // not a tar at all
		}
		// What was read stands — and the break is recorded: an extractor that
		// stops at the damage never sees the members found after it.
		w.broke()
	}
	return nil
}

// tarBlock is the size of a tar header block.
const tarBlock = 512

// tarSource is the stream a tar is read from. It remembers the last block's
// worth of bytes it delivered: when the tar reader gives up on a header, that
// is the block it gave up on.
type tarSource struct {
	r    io.Reader
	n    int64
	last [tarBlock]byte
	have int
}

func (s *tarSource) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.n += int64(n)
		if n >= tarBlock {
			copy(s.last[:], p[n-tarBlock:n])
			s.have = tarBlock
		} else {
			copy(s.last[:], s.last[n:])
			copy(s.last[tarBlock-n:], p[:n])
			if s.have += n; s.have > tarBlock {
				s.have = tarBlock
			}
		}
	}
	return n, err
}

// resyncTar finds the next tar header after a damaged one and returns a stream
// that starts with it. It reports false when the stream ends first.
//
// The block the reader gave up on is looked at first. Go's reader rejects a
// single zero block followed by a header — one zero block is half an
// end-of-archive marker — and has consumed both by the time it reports the
// error; node-tar reads straight on. reusedAt keeps that second look from being
// taken twice at the same position, so every call makes progress.
func (w *walker) resyncTar(src *tarSource, reusedAt *int64) (io.Reader, bool) {
	isHeader := func(b []byte) bool { return !allZero(b) && looksLikeTarBlock(b) }
	if src.have == tarBlock && *reusedAt != src.n && isHeader(src.last[:]) {
		*reusedAt = src.n
		return io.MultiReader(bytes.NewReader(append([]byte(nil), src.last[:]...)), src), true
	}
	var block [tarBlock]byte
	for !w.done() {
		if _, err := io.ReadFull(src, block[:]); err != nil {
			return nil, false
		}
		if isHeader(block[:]) {
			return io.MultiReader(bytes.NewReader(append([]byte(nil), block[:]...)), src), true
		}
	}
	return nil, false
}

// isNestedTarGz reports whether an entry is a RubyGems inner data payload.
func isNestedTarGz(name string) bool {
	base := path.Base(name)
	return base == "data.tar.gz"
}

// zipDirectorySignature opens every record of a zip central directory.
var zipDirectorySignature = []byte{'P', 'K', 0x01, 0x02}

// walkZip buffers a zip (bounded by the archive budget — the central directory
// lives at the stream end) and walks its regular-file entries.
func (w *walker) walkZip(r io.Reader, prefix string, depth int) error {
	data, ok, err := w.readZip(r, depth)
	if err != nil || !ok {
		return err
	}
	return w.walkZipBytes(data, prefix, depth)
}

// readZip buffers a zip from its stream. ok is false when it could not be held
// (the reason is recorded) or, for a nested one, could not be read.
func (w *walker) readZip(r io.Reader, depth int) (data []byte, ok bool, err error) {
	limit := w.b.maxArchiveBytes
	if depth > 0 && (limit <= 0 || limit > nestedZipCap) {
		limit = nestedZipCap
	}
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		if depth > 0 {
			return nil, false, nil
		}
		return nil, false, err
	}
	if int64(len(data)) > limit {
		// Larger than we will buffer; the directory at its end was not read, so the
		// archive cannot be reliably parsed. Fail open (served unscanned).
		if depth > 0 {
			w.stats.addReason(stopNestedFormat)
		} else {
			w.stats.addReason(stopArchiveBytes)
		}
		return nil, false, nil
	}
	return data, true, nil
}

// walkZipBytes walks a zip held in memory.
func (w *walker) walkZipBytes(data []byte, prefix string, depth int) error {
	// The zip reader materializes one record per central-directory entry before
	// any entry-count guard can run, so a small archive declaring millions of
	// (possibly non-existent) members costs hundreds of megabytes just to open.
	// Every record starts with a fixed signature; counting those bounds the
	// directory without parsing it.
	if w.b.maxFiles > 0 {
		if records := bytes.Count(data, zipDirectorySignature); records > 4*w.b.maxFiles+zipDirectorySlack {
			w.stats.addReason(stopZipDirectory)
			return nil
		}
	}
	zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	// An "insecure path" still yields a usable reader; nothing is extracted to a
	// filesystem, so such entries are walked and left for the consumer to judge.
	if zerr != nil && !errors.Is(zerr, zip.ErrInsecurePath) {
		if depth > 0 {
			w.stats.addReason(stopNestedFormat)
			return nil
		}
		return zerr
	}
	w.walkZipFiles(zr, prefix, depth)
	return nil
}

// zipDirectoryEntryBytes is the room allowed per central-directory record when
// a zip's directory is read through random access: a record is 46 bytes plus
// the member's name, extra field and comment.
const zipDirectoryEntryBytes = 256

// walkZipAt walks the artifact as a zip through random access, without
// buffering it: the central directory is read from the end of the file and each
// member is opened on demand. It is how a zip larger than the input cap gets an
// inventory.
//
// The buffered path bounds the directory by counting record signatures before
// the zip reader materializes them. Here there is no buffer to count in, so the
// bound is on the bytes the reader may consume while parsing the directory: a
// directory needing more than the member limit allows is refused, as it is on
// the buffered path.
func (w *walker) walkZipAt(prefix string) error {
	w.random = &countingReaderAt{ra: w.opts.at, limit: -1}
	if w.b.maxFiles > 0 {
		w.random.limit = int64(4*w.b.maxFiles+zipDirectorySlack)*zipDirectoryEntryBytes + 256<<10
	}
	zr, zerr := zip.NewReader(w.random, w.opts.size)
	if w.random.exceeded {
		w.stats.addReason(stopZipDirectory)
		return nil
	}
	if zerr != nil && !errors.Is(zerr, zip.ErrInsecurePath) {
		return zerr
	}
	if w.b.maxFiles > 0 && len(zr.File) > 4*w.b.maxFiles+zipDirectorySlack {
		w.stats.addReason(stopZipDirectory)
		return nil
	}
	w.random.limit = -1 // the directory is read; members are bounded by the walk's own limits
	w.walkZipFiles(zr, prefix, 0)
	return nil
}

// countingReaderAt counts the bytes read through it and, while limit is not
// negative, refuses to read more than limit bytes in total.
type countingReaderAt struct {
	ra       io.ReaderAt
	n        int64
	limit    int64
	exceeded bool
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if c.limit >= 0 && c.n+int64(len(p)) > c.limit {
		c.exceeded = true
		return 0, errWalkLimit
	}
	n, err := c.ra.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

// walkZipFiles walks the members of an opened zip.
func (w *walker) walkZipFiles(zr *zip.Reader, prefix string, depth int) {
	for _, f := range zr.File {
		if w.stopped || w.limited || w.ctx.Err() != nil {
			return
		}
		// Only a trailing slash makes a member a directory. The mode bits in a zip
		// are advisory metadata the archive's author controls, and installers
		// disagree about them: Python's zipfile (pip) writes any member without a
		// trailing slash out as a regular file, whatever type its mode claims. A
		// payload labelled "directory", "symlink" or "fifo" must therefore still be
		// read as the file it will become.
		if strings.HasSuffix(f.Name, "/") || strings.HasSuffix(f.Name, `\`) {
			continue
		}
		if !w.countEntry() {
			return
		}
		inner := cleanName(f.Name)
		name := prefix + inner
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		mode := unixMode(f.Mode())
		if f.FileInfo().Mode()&fs.ModeSymlink != 0 {
			// A zip symlink stores its target as the member's content. It is
			// reported as a link AND examined as a file (see above).
			fdata, hitCap, rerr := readBounded(w.guard(rc), w.b.maxFileBytes)
			rc.Close()
			if rerr != nil {
				continue
			}
			target := fdata
			if len(target) > 4096 {
				target = target[:4096]
			}
			w.link(name, string(target), false)
			w.emit(walkedFile{name: name, data: fdata, size: int64(f.UncompressedSize64), truncated: hitCap, mode: mode})
			continue
		}
		w.member(containerZip, depth, inner, name, int64(f.UncompressedSize64), mode, w.guard(rc))
		rc.Close()
	}
}

// unixMode renders an fs.FileMode's permission and set-id bits the way a Unix
// mode word carries them.
func unixMode(m fs.FileMode) uint32 {
	mode := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return mode
}

// readBounded reads up to max bytes from r. hitCap reports that the limit was
// reached (so the caller can flag truncation). A zero/negative max reads
// nothing.
func readBounded(r io.Reader, max int64) (data []byte, hitCap bool, err error) {
	if max <= 0 {
		return nil, false, nil
	}
	data, err = io.ReadAll(io.LimitReader(r, max))
	if err != nil {
		return data, false, err
	}
	return data, int64(len(data)) >= max, nil
}

// countingReader enforces the overall archive-bytes budget across a streamed
// walk. It is transparent until the limit is exceeded.
type countingReader struct {
	r   io.Reader
	max int64
	n   int64
	// rec, when set, is handed every byte as it is read from the artifact.
	rec *streamRecorder
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if n > 0 && c.rec != nil {
		_, _ = c.rec.Write(p[:n])
	}
	return n, err
}
