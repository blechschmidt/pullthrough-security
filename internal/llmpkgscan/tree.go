package llmpkgscan

import (
	"bufio"
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
	// Strings reports that Data is not the member's content but the proxy's
	// extraction from a binary member: its printable strings, one per line,
	// preceded by a summary of its header where the format has one. A binary
	// with a strings view can be read and searched like text.
	Strings bool
	// Exec reports that the container marks the member executable; SetID that it
	// carries the set-uid or set-gid bit.
	Exec  bool
	SetID bool
	// Synthetic reports an entry the proxy composed from the container's own
	// metadata rather than a member of it: an RPM's scriptlets and header
	// summary, an image's config and build history.
	Synthetic bool
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

	// Format is the container format the unpacker detected ("tar.gz", "zip",
	// "deb", "rpm", "nar.xz", …), "file" for a payload that is a single file, or
	// "oci-image" for an assembled image.
	Format string
	// Kind says how the artifact was read: as an archive, as a single file, or
	// as an OCI image assembled from its manifest, config and layers.
	Kind string
	// Partial reports a metadata-only view: the artifact is larger than the scan
	// limit and only what lies within that limit was read.
	Partial bool
	// Image holds what the proxy established about an OCI image; nil otherwise.
	Image *ImageFacts

	// linkCount is the number of link members seen, listed or not.
	linkCount int
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

// Kinds of tree.
const (
	KindArchive = "archive"
	KindFile    = "file"
	KindImage   = "oci-image"
)

// nestedArchiveDepth is how many levels of archive-inside-archive the gate
// opens beyond those a package format defines. Malware is routinely shipped one
// level down — a zip the install script extracts, a jar inside a war — and a
// listing that says "payload.zip, 40 kB" tells a reviewer nothing.
const nestedArchiveDepth = 2

// treeOptions says what is known about the artifact a tree is built from.
type treeOptions struct {
	// filename is the artifact's file name. It names the tree's one file when
	// the artifact is not an archive, and says what the artifact claims to be.
	filename string
	// examine reports a resource already known to hold something to examine: its
	// backend called it a payload, or its bytes said so (Applicable). Without it,
	// bytes that start like no archive are not this gate's business
	// (errNotArchive).
	examine bool
	// single reports a payload that may legitimately be one file rather than an
	// archive (a build script, a recipe, a model weight file). See singleFileOK.
	single bool
	// partial builds a metadata-only view of an artifact larger than the scan
	// limit: at most lim.MaxArtifactBytes are read from the stream, and running
	// into that bound is expected rather than an error. size is the artifact's
	// real size; at, when non-nil, gives random access to it (a zip's directory
	// is at its end, so only random access can list one that large).
	partial bool
	size    int64
	at      io.ReaderAt
	// reread, when non-nil, gives random access to an artifact that is read
	// whole (size bytes long). It is used only to read the artifact a second
	// time when it turns out to be two archives at once (see
	// contentscan.ArchiveStats.SecondReading); the tree's digest is still that of
	// the stream.
	reread io.ReaderAt
	// rootFS reports an artifact known to be a piece of a root filesystem,
	// whatever its container format: an image layer pulled on its own. Its links
	// are judged like those of an OS package (see judgeLinks).
	rootFS bool
}

// singleFileOK decides whether an artifact that does not unpack as an archive
// is examined as the one file it is.
//
// It is the exception, not the rule. A package manager's extractor is often
// more forgiving than a careful parser: node-tar skips a damaged header block
// and carries on, GNU tar resynchronizes on the next header, a zip reader finds
// its directory at the end of the file whatever is in front. Reading "this does
// not parse as an archive" as "this is a harmless single file" would hand an
// attacker the recipe for hiding a package from the review: damage it just
// enough that the scanner gives up and the installer does not.
//
// So an artifact is taken as a single file only when a single file is what it
// may honestly be — its backend says so (a POM, a Package.swift, a weight
// file), or it starts like an executable, a script or a pickle, which nobody
// unpacks — and its name does not claim otherwise. Everything else that fails
// to unpack is a package that went unexamined (errUnsupported).
func singleFileOK(opts treeOptions, peeled []byte, peeledOK bool) bool {
	if claimsContainer(opts.filename) {
		return false
	}
	return opts.single || (peeledOK && executableMagic(peeled))
}

// treeBuilder accumulates a Tree from the entries one or more archive walks
// report. All walks of one artifact share its budgets.
type treeBuilder struct {
	t   *Tree
	lim Limits
	// prefix is put in front of every member path (an image layer's directory).
	prefix string

	retainedCap int64
	// filesLeft and unpackedLeft are what remains of the member and
	// decompressed-byte budgets across walks.
	filesLeft    int
	unpackedLeft int64

	tooDeep    int
	cut        int
	unretained int
	noStrings  int
	duplicates map[string]int
	// pending holds the links reported since the last judgeLinks.
	pending []pendingLink
}

func newTreeBuilder(lim Limits) *treeBuilder {
	b := &treeBuilder{
		t:            &Tree{index: make(map[string]*File), Kind: KindArchive},
		lim:          lim,
		retainedCap:  retainedTextCap,
		filesLeft:    lim.MaxFiles,
		unpackedLeft: lim.MaxUnpackedBytes,
		duplicates:   make(map[string]int),
	}
	if lim.MaxUnpackedBytes > 0 && lim.MaxUnpackedBytes < b.retainedCap {
		b.retainedCap = lim.MaxUnpackedBytes
	}
	return b
}

// archiveLimits is the walker's view of the remaining budget.
func (b *treeBuilder) archiveLimits(maxArchiveBytes int64) contentscan.ArchiveLimits {
	return contentscan.ArchiveLimits{
		MaxArchiveBytes:     maxArchiveBytes,
		MaxUnpackedBytes:    b.unpackedLeft,
		MaxFileBytes:        b.lim.MaxFileBytes,
		MaxFiles:            b.filesLeft,
		MaxCompressionRatio: b.lim.MaxCompressionRatio,
	}
}

// spend charges one walk's consumption against the shared budgets. It reports
// whether anything is left for a further walk.
func (b *treeBuilder) spend(stats contentscan.ArchiveStats) bool {
	if b.lim.MaxUnpackedBytes > 0 {
		if b.unpackedLeft -= stats.UnpackedBytes; b.unpackedLeft < 1 {
			b.unpackedLeft = 1 // zero would mean "no limit" to the walker
			return false
		}
	}
	if b.lim.MaxFiles > 0 {
		if b.filesLeft -= stats.Files + stats.Links + stats.Others; b.filesLeft < 1 {
			b.filesLeft = 1
			return false
		}
	}
	return true
}

// visit files one archive member in the tree.
func (b *treeBuilder) visit(e contentscan.ArchiveEntry) bool {
	t := b.t
	p, unsafe := safePath(b.prefix + e.Name)
	if _, unsafeMember := safePath(e.Name); unsafe || unsafeMember {
		t.strongAnomaly("member name escapes the package root or is not a plain relative path: %s", quoteUntrusted(e.Name, 160))
	}
	if b.lim.MaxDepth > 0 && strings.Count(p, "/")+1 > b.lim.MaxDepth {
		b.tooDeep++
		return true
	}
	// Two members with one name: an extractor keeps one of them and which one
	// depends on the extractor, so both are kept here, under distinct keys.
	if _, dup := t.index[p]; dup {
		b.duplicates[p]++
		if n := b.duplicates[p]; n <= maxDuplicateID {
			if n == 1 {
				t.anomaly("archive contains more than one member named %s", quoteUntrusted(p, 160))
			}
			p = fmt.Sprintf("%s [duplicate member %d]", p, n)
		} else {
			return true
		}
	}

	f := &File{Path: p, Size: e.Size, Truncated: e.Truncated, Exec: e.Mode&0o111 != 0, SetID: e.Mode&0o6000 != 0, Synthetic: e.Synthetic}
	if f.Size < int64(len(e.Data)) {
		f.Size = int64(len(e.Data))
	}
	text, isText := decodeText(e.Data)
	if !isText {
		f.Binary = true
		f.Kind = describeBinary(e.Data)
		// A binary cannot be shown, but what it says can: its strings, and for a
		// format with a readable header a summary of that.
		if t.RetainedBytes < b.retainedCap {
			if view := binaryView(e.Data, f.Kind); len(view) > 0 && t.RetainedBytes+int64(len(view)) <= b.retainedCap {
				f.Data = view
				f.Strings = true
				t.RetainedBytes += int64(len(view))
				f.indexLines()
			}
		} else {
			b.noStrings++
		}
	} else {
		f.Kind = "text"
		// A pickle written without its protocol header can be plain ASCII, and is
		// then shown as the text it is. What it imports is said here, in the
		// proxy's words, the way the summary of a binary pickle says it.
		if note := textPickleNote(e.Data); note != "" {
			t.anomaly("%s is a Python pickle (it has no protocol header and reads as text) that %s", quoteUntrusted(p, 160), note)
		}
		if t.RetainedBytes+int64(len(text)) > b.retainedCap {
			f.Unretained = true
			b.unretained++
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
		b.cut++
	}
	t.Files = append(t.Files, f)
	t.index[p] = f
	return true
}

// onLink records one link member. Whether it escapes is decided once the
// container's kind is known (judgeLinks).
func (b *treeBuilder) onLink(l contentscan.ArchiveLink) {
	b.pending = append(b.pending, pendingLink{prefix: b.prefix, link: l})
}

// pendingLink is a link member awaiting judgeLinks.
type pendingLink struct {
	prefix string
	link   contentscan.ArchiveLink
}

// judgeLinks files the links recorded since the last call, deciding for each
// whether it points outside its container.
//
// What "outside" means depends on what the container is. A language package is
// unpacked into a directory of its own: a link in it that is absolute, or that
// climbs above that directory, reaches the installing user's files — the shape
// of a link-based extraction attack. An OS package, a Nix archive or an image
// layer is a piece of a root filesystem, installed at "/": there an absolute
// target (/usr/bin/vi -> /etc/alternatives/vi) is how links are normally
// written and stays inside the filesystem the package belongs to. For those
// (rootFS) only a relative target that climbs above the root is an escape.
func (b *treeBuilder) judgeLinks(rootFS bool) {
	t := b.t
	for _, pl := range b.pending {
		l := pl.link
		p, unsafe := safePath(pl.prefix + l.Name)
		inner, unsafeMember := safePath(l.Name)
		escapes := unsafe || unsafeMember
		if rootFS {
			escapes = escapes || relativeLinkEscapes(inner, l.Target)
		} else {
			escapes = escapes || linkEscapes(inner, l.Target)
		}
		if escapes {
			kind := "symbolic link"
			if l.Hard {
				kind = "hard link"
			}
			t.strongAnomaly("%s %s points outside the package root: -> %s", kind, quoteUntrusted(l.Name, 120), quoteUntrusted(l.Target, 120))
		}
		t.linkCount++
		if len(t.Links) < maxLinks {
			t.Links = append(t.Links, Link{Path: p, Target: l.Target, Hard: l.Hard, Escapes: escapes})
		}
	}
	b.pending = b.pending[:0]
}

// rootFilesystemFormat reports whether a container format is a piece of a root
// filesystem rather than a self-contained package directory.
func rootFilesystemFormat(format string) bool {
	switch {
	case format == "deb", format == "rpm", format == "cpio", format == "nar",
		strings.HasPrefix(format, "cpio."), strings.HasPrefix(format, "nar."):
		return true
	}
	return false
}

// relativeLinkEscapes is linkEscapes for a container that is itself a root
// filesystem: an absolute target stays inside it, so only a relative target
// climbing above the root escapes.
func relativeLinkEscapes(p, target string) bool {
	tgt := strings.ReplaceAll(target, `\`, "/")
	if tgt == "" || strings.HasPrefix(tgt, "/") {
		return false
	}
	return linkEscapes(p, tgt)
}

// noteIncomplete records, in sentences the model is shown verbatim, what a walk
// left unexamined. where names the part of the artifact the walk covered ("" for
// the artifact itself, "Layer 3: " for one layer of an image).
func (b *treeBuilder) noteIncomplete(stats contentscan.ArchiveStats, where string, partial bool) {
	t, lim := b.t, b.lim
	for _, reason := range stats.Incomplete {
		switch reason {
		case contentscan.IncompleteFiles:
			t.note("%sThe archive has more members than the limit of %d. Members beyond that limit were NOT unpacked: they are invisible to this review and no tool can reach them.", where, lim.MaxFiles)
		case contentscan.IncompleteUnpackedBytes:
			t.note("%sUnpacking stopped after %d decompressed bytes (the limit). Whatever the archive holds beyond that point was NOT unpacked and is invisible to this review.", where, lim.MaxUnpackedBytes)
		case contentscan.IncompleteRatio:
			t.note("%sUnpacking stopped because the archive decompresses more than %g-fold. Whatever it holds beyond that point was NOT unpacked and is invisible to this review.", where, lim.MaxCompressionRatio)
			t.strongAnomaly("%sthe archive decompresses more than %g-fold — the profile of a decompression bomb", where, lim.MaxCompressionRatio)
		case contentscan.IncompleteZipDirectory:
			t.note("%sThe zip directory declares far more members than the limit of %d, so the archive was NOT unpacked.", where, lim.MaxFiles)
			t.strongAnomaly("%sthe zip directory declares an implausible number of members", where)
		case contentscan.IncompleteArchiveBytes:
			// In a metadata-only view this is the expected state and is stated once,
			// with the sizes, by the caller. Otherwise it is unreachable once the size
			// check passed; kept so a walker reason can never be silently dropped.
			if !partial {
				t.note("%sThe artifact is larger than the scanner reads; its tail was NOT examined.", where)
			}
		case contentscan.IncompleteNestedFormat:
			t.note("%sPart of the package is in a format or compression the scanner cannot open, or is an inner archive too large to open (an RPM payload, a nested archive). What it holds was NOT examined; where the container lists it, it appears as one opaque binary member.", where)
		case contentscan.IncompleteMalformed:
			if partial {
				// Reading only a prefix cuts the container mid-member; the caller's
				// note already says the rest was not read.
				continue
			}
			// Extractors disagree about a damaged archive: some stop at the damage,
			// others skip it and install what follows. The unpacker skips a damaged
			// tar header the way the tolerant ones do, so members behind it are
			// listed; where the stream could not be picked up again, the remainder
			// went unexamined. Either way the archive unpacks differently depending
			// on the tool, which is what the damage is for.
			t.note("%sThe archive's structure is damaged part-way: it is truncated or corrupt. Members found behind a damaged header are listed; whatever else follows the break was NOT examined — and extractors disagree about such an archive: some stop at the damage, others install what follows.", where)
			t.strongAnomaly("%sthe archive's structure breaks off part-way, so different extractors unpack different members of it", where)
		case contentscan.IncompleteSecondReading:
			// Reported with the second reading itself (noteSecondReading).
		case contentscan.IncompleteFileBytes:
			// Reported with the count in finish.
		default:
			t.note("%sUnpacking stopped early (%s); part of the archive was NOT examined.", where, reason)
		}
	}
}

// noteSecondReading records that an artifact is two archives at once (see
// contentscan.ArchiveStats.SecondReading). where is as for noteIncomplete.
//
// Which archive a tool sees depends on where it starts reading: a zip reader
// starts at the end of the file, everything else at the beginning. The unpacker
// reads the file both ways, so both sets of members are in the tree; what the
// model and the gate need to know is that there are two.
func (b *treeBuilder) noteSecondReading(stats contentscan.ArchiveStats, where string) {
	t := b.t
	switch stats.SecondReading {
	case "zip":
		if hasIncomplete(stats, contentscan.IncompleteSecondReading) {
			// The zip reading exists and could not be opened: an installer that
			// reads the file as a zip may unpack members nobody reviewed.
			t.note("%sThe file starts as %s but also ends like a zip archive, and was too large to be read a second time as one. An installer that opens it as a zip (pip, the JVM, NuGet, …) may unpack members this review never saw.", where, formatName(stats.Format))
			t.strongAnomaly("%sthe file starts as %s and also ends like a zip archive; the zip reading could not be examined", where, formatName(stats.Format))
			return
		}
		// A tarball whose last member is a zip reads this way too, so this is
		// stated, not held against the package: the members are there to be judged.
		t.anomaly("%sthe file is two archives at once: it starts as %s and is also a zip archive when read from its end, which is how zip-based installers (pip, the JVM, NuGet, …) read a file; its members as a zip are listed under %s", where, formatName(stats.Format), contentscan.ZipReadingPrefix)
	case "tar":
		// A zip whose first block carries a valid tar checksum was built to be
		// read both ways.
		t.strongAnomaly("%sthe file is two archives at once: a zip whose first bytes are also a valid tar header, so a tar extractor unpacks different members than a zip reader does; its members as a tar are listed under %s", where, contentscan.TarReadingPrefix)
	}
}

// formatName renders a walker format for a sentence.
func formatName(format string) string {
	if format == "" {
		return "another format"
	}
	return "a " + format + " archive"
}

// finish seals the tree: the notes that are counts, the ordering, the ranking.
// incomplete reports whether any walk stopped short; it decides how an empty
// tree is reported.
func (b *treeBuilder) finish(incomplete bool) (*Tree, error) {
	t, lim := b.t, b.lim
	if b.cut > 0 {
		t.note("%d file(s) are larger than the per-file limit of %d bytes. Only the first %d bytes of each are available; the rest of those files is invisible to this review.", b.cut, lim.MaxFileBytes, lim.MaxFileBytes)
	}
	if b.tooDeep > 0 {
		t.note("%d member(s) nested deeper than %d directories were NOT unpacked and are invisible to this review.", b.tooDeep, lim.MaxDepth)
		t.anomaly("%d member(s) are nested deeper than %d directories", b.tooDeep, lim.MaxDepth)
	}
	if b.unretained > 0 {
		t.note("The content of %d text file(s) was not kept because the scan's memory budget was spent. They appear in the listing but cannot be read.", b.unretained)
	}
	if b.noStrings > 0 {
		t.note("The printable strings of %d binary file(s) were not extracted because the scan's memory budget was spent. They appear in the listing with their kind only.", b.noStrings)
	}
	if t.linkCount > len(t.Links) {
		t.note("The archive has %d link members; only the first %d are listed.", t.linkCount, len(t.Links))
	}
	if len(t.Files) == 0 {
		if incomplete || b.tooDeep > 0 {
			return nil, errUnpackLimit
		}
		return nil, errEmpty
	}
	sort.Slice(t.Files, func(i, j int) bool { return t.Files[i].Path < t.Files[j].Path })
	rankFiles(t)
	return t, nil
}

// buildTree unpacks an artifact stream into a Tree, treating bytes that are not
// an archive as not this gate's business (errNotArchive). See buildTreeOpts.
func buildTree(ctx context.Context, r io.Reader, lim Limits) (*Tree, error) {
	return buildTreeOpts(ctx, r, lim, treeOptions{})
}

// buildTreeOpts unpacks an artifact stream into a Tree. It hashes the stream as
// it unpacks it — the digest it reports is therefore the digest of exactly the
// bytes that were examined, not of a second read that could have raced a cache
// refill.
//
// What the artifact is, is decided from its bytes:
//
//   - a container or compression format the walker opens is unpacked, archives
//     inside it too, a few levels down — including a zip behind a prefix, which
//     installers unpack like any other;
//   - bytes that are no archive are examined as a single file when that is what
//     the artifact may honestly be (singleFileOK);
//   - anything else — the signature of a format the walker does not open, an
//     archive that fails to unpack, a package-like name on bytes that are no
//     package — is a package that went unexamined (errUnsupported).
//
// In a partial (metadata-only) build the stream is read only up to the scan
// limit and is not hashed: the caller already knows the artifact's digest and
// size, and reading the rest would be the very cost the limit exists to avoid.
func buildTreeOpts(ctx context.Context, r io.Reader, lim Limits, opts treeOptions) (*Tree, error) {
	hasher := sha256.New()
	src := &countReader{r: io.TeeReader(r, hasher)}
	br := bufio.NewReaderSize(src, ProbeBytes)
	prefix, _ := br.Peek(headBytes)
	if NeedsLongProbe(prefix) {
		prefix, _ = br.Peek(ProbeBytes)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !opts.examine && !archiveMagic(prefix) {
		// Nothing says this is a package: a metadata document. There is no verdict
		// to file under a digest, so the rest of the stream is not read.
		return nil, errNotArchive
	}
	peeled, _, peeledOK := contentscan.PeelCompression(prefix)

	b := newTreeBuilder(lim)
	t := b.t
	aopts := contentscan.ArchiveOptions{
		Filename:    singleFileName(opts.filename),
		SingleFile:  singleFileOK(opts, peeled, peeledOK),
		NestedDepth: nestedArchiveDepth,
	}
	switch {
	case opts.partial && opts.at != nil:
		aopts.ReaderAt, aopts.Size = opts.at, opts.size
	case !opts.partial && opts.reread != nil && opts.size > 0:
		aopts.Reread, aopts.Size = opts.reread, opts.size
	}
	var walkErr error
	if unsupportedArchiveMagic(prefix) && !contentscan.Recognizes(prefix) {
		walkErr = errors.New("the container format is not one the scanner unpacks")
	}
	var stats contentscan.ArchiveStats
	if walkErr == nil {
		stats, walkErr = contentscan.WalkArtifact(ctx, br, b.archiveLimits(lim.MaxArtifactBytes), aopts, b.visit, b.onLink)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	t.Format = stats.Format
	t.UnpackedBytes = stats.UnpackedBytes
	incomplete := !stats.Complete()
	if singleFormat(stats.Format) {
		t.Kind = KindFile
	}
	b.judgeLinks(opts.rootFS || rootFilesystemFormat(stats.Format))
	b.noteIncomplete(stats, "", opts.partial)
	if stats.PrefixBytes > 0 {
		// A prefixed zip is how executable jars and zipapps are built, and also how
		// a package is padded to get past a check of its first bytes.
		t.anomaly("the zip archive does not start at the beginning of the file: %d bytes precede its first member (shown as %s)", stats.PrefixBytes, contentscan.PrefixEntryName)
	}
	b.noteSecondReading(stats, "")

	if opts.partial {
		t.Partial = true
		t.ArtifactBytes = opts.size
		if walkErr != nil {
			return nil, fmt.Errorf("%w: %v", errUnsupported, walkErr)
		}
		switch {
		case t.Kind == KindFile:
			t.note("The file is %d bytes, larger than the %d-byte limit for a full scan. Only its beginning was read: this is a metadata-only view.", opts.size, lim.MaxArtifactBytes)
		case aopts.ReaderAt != nil && stats.Format == "zip" && !hasIncomplete(stats, contentscan.IncompleteZipDirectory):
			t.note("The artifact is %d bytes, larger than the %d-byte limit for a full scan. Its directory was read in full, so the listing names every member, but file contents were read only within the scan limits: this is a metadata-only view.", opts.size, lim.MaxArtifactBytes)
		default:
			t.note("The artifact is %d bytes, larger than the %d-byte limit for a full scan. Only its first %d bytes were read: every member and all content beyond that point is NOT listed and was NOT examined. This is a metadata-only view.", opts.size, lim.MaxArtifactBytes, lim.MaxArtifactBytes)
		}
		return b.finish(true)
	}

	// Finish hashing: the unpacker stops at the end of the archive, which is not
	// necessarily the end of the stream. One byte past the limit is enough to
	// know the artifact is oversized.
	if remaining := lim.MaxArtifactBytes + 1 - src.n; remaining > 0 {
		if _, err := io.Copy(io.Discard, io.LimitReader(br, remaining)); err != nil {
			return nil, fmt.Errorf("llmpkgscan: reading artifact: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if src.n > lim.MaxArtifactBytes {
		return nil, errOversized
	}
	if walkErr != nil {
		return nil, fmt.Errorf("%w: %v", errUnsupported, walkErr)
	}
	if src.n == 0 {
		// Nothing at all: an empty file installs nothing and holds nothing to
		// examine.
		return nil, errNotArchive
	}
	t.Digest = hex.EncodeToString(hasher.Sum(nil))
	t.ArtifactBytes = src.n
	return b.finish(incomplete)
}

// singleFormat reports whether a walker format names a single file rather than
// an archive: "file", or a bare compression ("gz", "xz.gz").
func singleFormat(format string) bool {
	if format == "file" {
		return true
	}
	if format == "" {
		return false
	}
	for _, part := range strings.Split(format, ".") {
		switch part {
		case "gz", "bz2", "xz", "zst", "lzma":
		default:
			return false
		}
	}
	return true
}

func hasIncomplete(stats contentscan.ArchiveStats, reason string) bool {
	for _, r := range stats.Incomplete {
		if r == reason {
			return true
		}
	}
	return false
}

// singleFileName is the path a payload that is one file gets in its tree: the
// base of its file name, or "artifact" when it has none.
func singleFileName(filename string) string {
	name := strings.ReplaceAll(filename, `\`, "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	if name == "" || name == "." || name == ".." {
		return "artifact"
	}
	return name
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

// headBytes is how much of the start of a stream is examined to tell what it
// is: one tar block, which carries the "ustar" signature at offset 257.
const headBytes = 512

// SniffBytes is how many leading bytes LooksInstallable wants to see.
const SniffBytes = headBytes

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
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
	return contentscan.Recognizes(head) || unsupportedArchiveMagic(head)
}

// unsupportedArchiveMagic reports the signature of an archive or compression
// format the walker does not open. The formats it does open are the walker's
// own to recognize (contentscan.Recognizes), so the two lists cannot drift
// apart into a format that is neither unpacked nor reported.
func unsupportedArchiveMagic(head []byte) bool {
	at := func(off int, sig string) bool {
		return len(head) >= off+len(sig) && string(head[off:off+len(sig)]) == sig
	}
	switch {
	case at(0, "\x04\x22\x4d\x18"), // lz4
		at(0, "LZIP"),                        // lzip
		at(0, "\x5d\x00\x00"),                // lzma (alone) with a header the walker did not accept
		at(0, "7z\xbc\xaf\x27\x1c"),          // 7-zip
		at(0, "Rar!\x1a\x07"),                // rar
		at(0, "\x1f\x9d"), at(0, "\x1f\xa0"), // compress, lzh
		at(0, "xar!"),    // xar
		at(0, "MSCF"),    // cabinet
		at(0, "BZh"),     // bzip2 with an invalid level byte
		at(257, "ustar"): // a tar block whose checksum does not hold
		return true
	}
	return false
}

// executableMagic reports the signature of something a machine or an
// interpreter runs: a native executable or library, WebAssembly, JVM bytecode,
// a script with an interpreter line, a Python pickle.
func executableMagic(head []byte) bool {
	at := func(sig string) bool { return len(head) >= len(sig) && string(head[:len(sig)]) == sig }
	switch {
	case at("\x7fELF"), at("MZ"), at("\x00asm"), at("#!"),
		at("\xcf\xfa\xed\xfe"), at("\xce\xfa\xed\xfe"), at("\xfe\xed\xfa\xcf"), at("\xfe\xed\xfa\xce"),
		at("\xca\xfe\xba\xbe"):
		return true
	}
	return looksLikePickle(head)
}

// LooksInstallable reports whether content that begins with head (its first
// SniffBytes bytes), served under filename, is something this gate examines
// when its backend could not say what the resource is: an archive or
// compressed stream, an executable, a script with an interpreter line, a
// pickle — or anything named like an installable archive. A JSON index, an
// HTML listing, a checksum file are not.
//
// It is the rule Assess applies to an unclassified resource, exported so a
// caller that must decide before it has the artifact in hand (a response being
// streamed straight from the upstream) can apply the same one.
func LooksInstallable(head []byte, filename string) bool {
	return archiveMagic(head) || executableMagic(head) || claimsArchive(filename)
}

// archiveSuffixes are the file-name endings under which package managers accept
// an installable archive. A resource carrying one claims to be a package.
var archiveSuffixes = []string{
	".tgz", ".tar.gz", ".tar", ".taz", ".tar.z", ".tbz", ".tbz2", ".tar.bz2",
	".txz", ".tar.xz", ".tlz", ".tar.lz", ".tar.lzma", ".tzst", ".tar.zst",
	".tbr", ".tar.br", ".zip", ".whl", ".egg", ".gem", ".crate", ".nupkg",
	".snupkg", ".jar", ".war", ".ear", ".aar", ".phar", ".vsix", ".conda",
	".apk", ".deb", ".udeb", ".rpm", ".7z", ".rar", ".cab", ".nar", ".cpio",
	".ez", ".pyz", ".gz", ".bz2", ".xz", ".zst",
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

// bareCompressionSuffixes are the endings of a file that is merely compressed:
// what is inside may be an archive or a single file.
var bareCompressionSuffixes = []string{".gz", ".bz2", ".xz", ".zst"}

// claimsContainer reports whether a file name presents the resource as an
// archive of several members — a tar under any compression, a zip under any of
// its package names, an OS package — as opposed to a file that is at most
// compressed. Such a name is a promise that there is something to unpack.
func claimsContainer(filename string) bool {
	if !claimsArchive(filename) {
		return false
	}
	name := strings.ToLower(filename)
	for _, tar := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"} {
		if strings.HasSuffix(name, tar) {
			return true
		}
	}
	for _, suf := range bareCompressionSuffixes {
		if strings.HasSuffix(name, suf) {
			return false
		}
	}
	return true
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

// Readable reports whether the file has content a tool can show: a text file
// that was retained, or a binary with a strings view.
func (f *File) Readable() bool {
	if f.Binary {
		return f.Strings
	}
	return !f.Unretained
}

// describe renders the file's kind for listings.
func (f *File) describe() string {
	var d string
	switch {
	case f.Binary && f.Strings:
		d = fmt.Sprintf("binary: %s; %d lines of extracted strings", f.Kind, f.Lines)
	case f.Binary:
		d = "binary: " + f.Kind
	case f.Unretained:
		d = "text (content not retained)"
	case f.Truncated:
		d = fmt.Sprintf("text, %d lines (only the first %d bytes kept)", f.Lines, len(f.Data))
	default:
		d = fmt.Sprintf("text, %d lines", f.Lines)
	}
	if f.Binary && f.Truncated {
		d += " (first part of the file only)"
	}
	switch {
	case f.SetID:
		d += "; set-uid/set-gid executable"
	case f.Exec:
		d += "; executable"
	}
	if f.Synthetic {
		d += "; composed by the proxy"
	}
	return d
}
