package contentscan

import (
	"context"
	"io"
)

// This file exports the gate's archive walker so sibling gates unpack an
// artifact exactly the way this one does — same format detection, same nested
// RubyGems payload handling, same bounds — instead of growing a second,
// subtly-different unpacker. The LLM package-content gate (internal/llmpkgscan,
// Task 173) builds its read-only in-memory tree from it.
//
// The walker never touches a filesystem: an entry is a name and a byte slice
// handed to a callback. Path traversal therefore cannot write anywhere by
// construction; a name that tries (an absolute path, a ".." escape) is passed
// through verbatim so the consumer can see the attempt and judge it.

// ErrUnrecognizedArchive is returned by WalkArchive when the artifact is not an
// archive format the walker understands. See WalkArtifact for the formats.
var ErrUnrecognizedArchive = errUnrecognizedArchive

// Errors a walk returns for a compressed stream it refuses to decode. Both wrap
// nothing and are matched with errors.Is.
var (
	// ErrDecoderMemory: the stream declares an LZMA dictionary or zstd window
	// larger than the walker allows a publisher to make it allocate.
	ErrDecoderMemory = errDictTooLarge
	// ErrUnsupportedFilter: an xz stream uses a filter chain other than LZMA2.
	ErrUnsupportedFilter = errUnsupportedFilter
)

// ArchiveLimits bounds one WalkArchive call. Every dimension an attacker
// controls is bounded; a zero value disables that one bound (except
// MaxArchiveBytes and MaxFileBytes, where zero reads nothing).
type ArchiveLimits struct {
	// MaxArchiveBytes caps the bytes consumed from the (compressed) artifact.
	MaxArchiveBytes int64
	// MaxUnpackedBytes caps the decompressed bytes produced across the whole
	// archive, nested archives included, whether read into an entry or skipped.
	MaxUnpackedBytes int64
	// MaxFileBytes caps the bytes retained per entry; a larger entry is cut and
	// flagged truncated.
	MaxFileBytes int64
	// MaxFiles caps the archive members examined (files, directories and links
	// all count, so a flood of empty directories is cut off too).
	MaxFiles int
	// MaxCompressionRatio caps decompressed:compressed bytes once the archive has
	// produced a few megabytes — the decompression-bomb guard.
	MaxCompressionRatio float64
}

// ArchiveEntry is one file read out of an archive.
type ArchiveEntry struct {
	// Name is the member's path, cleaned of "./" and redundant separators but NOT
	// made safe: it may be absolute or climb out of the root with "..". The walker
	// writes nothing to disk, so this is evidence for the consumer, not a hazard.
	Name string
	// Data holds at most MaxFileBytes of the member.
	Data []byte
	// Size is the member's declared (uncompressed) size.
	Size int64
	// Truncated reports that Data is only a prefix of the member.
	Truncated bool
	// Mode holds the member's Unix permission bits — including set-uid (04000),
	// set-gid (02000) and sticky (01000) — when the container records them, and
	// zero when it does not. A NAR records only the executable bit.
	Mode uint32
	// Synthetic reports an entry the walker composed from the container's own
	// metadata rather than read out as a member: an RPM's scriptlets and header
	// summary, which live in the package header, not in its payload.
	Synthetic bool
}

// Executable reports whether any execute bit is set on the member.
func (e ArchiveEntry) Executable() bool { return e.Mode&0o111 != 0 }

// ArchiveLink is a symbolic or hard link member. Links are reported, never
// followed.
type ArchiveLink struct {
	Name   string
	Target string
	// Hard distinguishes a hard link from a symbolic one.
	Hard bool
}

// Reasons an archive walk stopped early, as reported in ArchiveStats.Incomplete.
const (
	IncompleteArchiveBytes  = stopArchiveBytes
	IncompleteFiles         = stopFiles
	IncompleteUnpackedBytes = stopUnpackedBytes
	IncompleteRatio         = stopRatio
	IncompleteZipDirectory  = stopZipDirectory
	IncompleteFileBytes     = stopFileBytes
	// IncompleteNestedFormat: a part of the artifact the installer unpacks (an
	// RPM's payload, a .deb's data archive, an archive inside the archive) is in
	// a format or compression the walker cannot open, or is too large to open;
	// its members were not examined.
	IncompleteNestedFormat = stopNestedFormat
	// IncompleteMalformed: the container's structure is damaged part-way (a
	// truncated or corrupt member table). A damaged tar header is skipped the way
	// lenient extractors skip it, so members behind it are still reported; where
	// the stream cannot be picked up again, what precedes the break was examined
	// and what follows was not.
	IncompleteMalformed = stopMalformed
	// IncompleteSecondReading: the artifact also ends like a zip archive, so a
	// zip reader would open it and may see members the format at its head does
	// not hold, and that reading could not be examined (see
	// ArchiveOptions.Reread).
	IncompleteSecondReading = stopSecondReading
)

// ArchiveOptions selects walker behaviour beyond the default. The zero value
// walks archives only and opens an archive inside another one only where the
// package format itself nests it.
type ArchiveOptions struct {
	// Filename is the artifact's file name. It names the one file inside a
	// compressed stream that is not an archive ("install.sh.gz" -> "install.sh").
	Filename string
	// SingleFile accepts content that is not an archive and walks it as the one
	// file it is: a compressed stream holding a single file is decompressed and
	// reported under its uncompressed name, anything else is reported as it is
	// (the detected format is then "file"). Without it such content is
	// ErrUnrecognizedArchive.
	//
	// It is for a caller that knows the artifact may legitimately be a single
	// file. An artifact that is supposed to be an archive must not be walked
	// with it: extractors differ in how much damage they tolerate, and "not an
	// archive to this walker" does not mean "not unpacked by the installer".
	SingleFile bool
	// NestedDepth is how many levels of archive-inside-archive are opened beyond
	// those a package format defines. Such an archive's members are reported
	// under "<member>!/"; a compressed single file is reported under its
	// uncompressed name. Zero opens none: a nested archive is one opaque member.
	NestedDepth int
	// ReaderAt, when set, gives random access to the artifact, which is Size
	// bytes long. A zip is then read through it — the directory from the end of
	// the file, each member on demand — instead of being buffered whole from the
	// stream, so a zip larger than MaxArchiveBytes can still be inventoried. The
	// stream passed to the walk is used only to recognize the format, and every
	// other format is still read from it. The member count, the per-file cap and
	// the decompression limits apply unchanged.
	ReaderAt io.ReaderAt
	Size     int64
	// Reread, when set, also gives random access to the artifact (Size bytes
	// long), but is used for one thing only: reading the artifact a second time,
	// as a zip from its end, when its first bytes named another format (see
	// ArchiveStats.SecondReading). The primary walk still reads the stream, and
	// Reread is ignored unless the stream turned out to be exactly Size bytes.
	// Without it an artifact larger than 16 MiB cannot be given that second
	// look, and one that needs it is reported with IncompleteSecondReading.
	Reread io.ReaderAt
}

// ArchiveStats summarizes a walk.
type ArchiveStats struct {
	// Format is the detected container: "tar.gz", "tar.xz", "tar.zst", "zip",
	// "tar", "deb", "rpm", "cpio", "nar.xz", "ar", or — for a compressed single
	// file — the compression alone ("gz").
	Format string
	// Files is the number of entries handed to the visitor.
	Files int
	// Links and Others count link members and other non-file members (devices,
	// fifos); neither is ever materialized.
	Links  int
	Others int
	// CompressedBytes is how much of the artifact was consumed; UnpackedBytes how
	// many decompressed bytes that produced.
	CompressedBytes int64
	UnpackedBytes   int64
	// Incomplete lists which limits cut the walk short, in the order they
	// tripped. Empty means every member was examined in full.
	Incomplete []string
	// PrefixBytes is the number of bytes in front of the first member of a zip
	// that does not start at the beginning of the file — a self-extracting
	// archive, a zipapp, an executable jar, or a package padded to slip past a
	// check of its first bytes. Installers unpack such a zip like any other, so
	// the walker does too; the prefix itself is reported as an entry named
	// PrefixEntryName. Zero for an ordinary archive.
	PrefixBytes int64
	// SecondReading is set when the file is two archives at once, and names the
	// second: "zip" when a file whose first bytes are another format (a tarball,
	// a compressed stream, an OS package) is also a zip from its end — which is
	// how every zip reader, pip's and the JVM's included, would open it — and
	// "tar" when a zip's first block is also a valid tar header. The members of
	// the second reading are reported under ZipReadingPrefix or TarReadingPrefix.
	// A tarball whose last member happens to be a zip reads this way too; a zip
	// that is also a tar does not come about by accident.
	SecondReading string
}

// PrefixEntryName is the name of the composed entry holding the bytes in front
// of a prefixed zip's first member (see ArchiveStats.PrefixBytes).
const PrefixEntryName = prefixName

// The prefixes under which the members of a second reading of the same file are
// reported (see ArchiveStats.SecondReading).
const (
	ZipReadingPrefix = zipReadingPrefix
	TarReadingPrefix = tarReadingPrefix
)

// Complete reports whether the whole archive was examined.
func (s ArchiveStats) Complete() bool { return len(s.Incomplete) == 0 }

// WalkArchive detects the artifact's container format and hands every file in
// it to visit, in archive order. visit returns false to stop early. onLink, when
// non-nil, receives each link member. It is WalkArtifact with the default
// options.
func WalkArchive(ctx context.Context, r io.Reader, lim ArchiveLimits, visit func(ArchiveEntry) bool, onLink func(ArchiveLink)) (ArchiveStats, error) {
	return WalkArtifact(ctx, r, lim, ArchiveOptions{}, visit, onLink)
}

// WalkArtifact detects the artifact's container format from its leading bytes
// and hands every file in it to visit, in archive order. visit returns false to
// stop early. onLink, when non-nil, receives each link member.
//
// Formats, all recognized by signature and never by file name:
//
//   - tar, plain or compressed with gzip, bzip2, xz, zstd or legacy lzma
//     (npm, sdist, .crate, Helm chart, conda .tar.bz2, CRAN, CPAN, Hackage,
//     pub, Ansible, Puppet, Julia, Homebrew bottle, OCI layer, …);
//   - zip (wheel, Go module, .nupkg, .jar, .vsix, Composer, Terraform provider,
//     Swift source archive, …), buffered up to the archive limit;
//   - a RubyGems .gem (tar with a nested data.tar.gz) and a Hex package (tar
//     with a nested contents.tar.gz);
//   - a .conda package (zip with nested info-*.tar.zst and pkg-*.tar.zst);
//   - a Debian package (ar with control.tar.* and data.tar.*): the control
//     members — the maintainer scripts among them — are reported under DEBIAN/;
//   - an RPM package (lead, signature header, header, compressed cpio payload):
//     the scriptlets and triggers, which live in the header, are reported as
//     composed entries under RPM/scriptlets/ and RPM/triggers/;
//   - cpio (newc and odc) and ar on their own;
//   - a Nix archive (NAR), plain or compressed;
//   - a zip behind a prefix (a self-extracting archive, a zipapp, an executable
//     jar): a zip is located from its end, so every installer unpacks one that
//     has other bytes in front of it, and so does the walker.
//
// It returns ErrUnrecognizedArchive (or the decoder's error) when the artifact
// is not a readable archive at all. Hitting a limit is NOT an error: the walk
// stops, what was read stands, and the limit is named in the returned stats —
// the caller decides what an incomplete view means. A canceled ctx likewise
// ends the walk without an error; the caller checks ctx itself.
//
// Decoder memory is bounded independently of the limits: an xz or lzma stream
// may ask for at most a 64 MiB dictionary and a zstd stream for a 128 MiB
// window (the strongest standard presets); a stream that asks for more is
// refused (ErrDecoderMemory) before anything is allocated.
func WalkArtifact(ctx context.Context, r io.Reader, lim ArchiveLimits, opts ArchiveOptions, visit func(ArchiveEntry) bool, onLink func(ArchiveLink)) (ArchiveStats, error) {
	b := budget{
		maxArchiveBytes: lim.MaxArchiveBytes,
		maxFileBytes:    lim.MaxFileBytes,
		maxFiles:        lim.MaxFiles,
		maxTotalBytes:   lim.MaxUnpackedBytes,
		maxRatio:        lim.MaxCompressionRatio,
	}
	var linkFn func(walkedLink)
	if onLink != nil {
		linkFn = func(l walkedLink) {
			onLink(ArchiveLink{Name: l.name, Target: l.target, Hard: l.hard})
		}
	}
	wo := walkOptions{name: opts.Filename, singleFile: opts.SingleFile, nested: opts.NestedDepth}
	if opts.ReaderAt != nil && opts.Size > 0 {
		wo.at, wo.size = opts.ReaderAt, opts.Size
	}
	if wo.nested < 0 {
		wo.nested = 0
	}
	if wo.nested > maxNestedDepth {
		wo.nested = maxNestedDepth
	}
	if opts.Reread != nil && opts.Size > 0 && wo.at == nil {
		wo.reread, wo.size = opts.Reread, opts.Size
	}
	stats, err := walkArtifactStats(ctx, r, b, wo, func(wf walkedFile) bool {
		return visit(ArchiveEntry{Name: wf.name, Data: wf.data, Size: wf.size, Truncated: wf.truncated, Mode: wf.mode, Synthetic: wf.synthetic})
	}, linkFn)
	return ArchiveStats{
		Format:          stats.format,
		Files:           stats.files,
		Links:           stats.links,
		Others:          stats.others,
		CompressedBytes: stats.compressed,
		UnpackedBytes:   stats.unpacked,
		Incomplete:      stats.reasons,
		PrefixBytes:     stats.prefix,
		SecondReading:   stats.second,
	}, err
}

// maxNestedDepth is the most levels of archive-inside-archive a caller can ask
// for. Recursion is bounded here, not by the caller's good sense.
const maxNestedDepth = 4

// Recognizes reports whether a stream beginning with head (its first bytes, up
// to one 512-byte tar block) starts like a container or compression format the
// walker opens. It is the walker's own format test, exported so a caller can
// tell "not an archive at all" from "an archive that failed to unpack" without
// keeping a second, drifting list of signatures.
func Recognizes(head []byte) bool { return sniffContainer(head) != containerNone }
