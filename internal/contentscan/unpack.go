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
// archive format the walker understands (gzip/bzip2-compressed tar, plain tar,
// zip, and a RubyGems .gem's nested data.tar.gz).
var ErrUnrecognizedArchive = errUnrecognizedArchive

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
}

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
)

// ArchiveStats summarizes a walk.
type ArchiveStats struct {
	// Format is the detected container: "tar.gz", "tar.bz2", "zip" or "tar".
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
}

// Complete reports whether the whole archive was examined.
func (s ArchiveStats) Complete() bool { return len(s.Incomplete) == 0 }

// WalkArchive detects the artifact's container format and hands every file in
// it to visit, in archive order. visit returns false to stop early. onLink, when
// non-nil, receives each link member.
//
// It returns ErrUnrecognizedArchive (or the decoder's error) when the artifact
// is not a readable archive at all. Hitting a limit is NOT an error: the walk
// stops, what was read stands, and the limit is named in the returned stats —
// the caller decides what an incomplete view means. A canceled ctx likewise
// ends the walk without an error; the caller checks ctx itself.
func WalkArchive(ctx context.Context, r io.Reader, lim ArchiveLimits, visit func(ArchiveEntry) bool, onLink func(ArchiveLink)) (ArchiveStats, error) {
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
	stats, err := walkArchiveStats(ctx, r, b, func(wf walkedFile) bool {
		return visit(ArchiveEntry{Name: wf.name, Data: wf.data, Size: wf.size, Truncated: wf.truncated})
	}, linkFn)
	return ArchiveStats{
		Format:          stats.format,
		Files:           stats.files,
		Links:           stats.links,
		Others:          stats.others,
		CompressedBytes: stats.compressed,
		UnpackedBytes:   stats.unpacked,
		Incomplete:      stats.reasons,
	}, err
}
