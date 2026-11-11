package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
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

// walkStats is what a walk learned about the archive.
type walkStats struct {
	// format is the detected container: "tar.gz", "tar.bz2", "zip" or "tar".
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

// walker carries the state of one archive walk, shared across nested archives
// so every bound is a bound on the whole artifact rather than on each layer.
type walker struct {
	ctx    context.Context
	b      budget
	visit  visitor
	onLink func(walkedLink)
	in     *countingReader
	stats  walkStats
	// entries counts every archive member seen (files, directories, links) against
	// the entry-count guard, so an archive of a million empty directories is cut
	// off as surely as one of a million files.
	entries int
	stopped bool // the visitor asked to stop
	limited bool // a hard limit tripped; nothing further may be read
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
	w := &walker{ctx: ctx, b: b, visit: visit, onLink: onLink}
	w.in = &countingReader{r: io.LimitReader(r, b.maxArchiveBytes+1), max: b.maxArchiveBytes}

	// Peek the first bytes to choose a decoder without consuming them.
	head := make([]byte, 8)
	n, _ := io.ReadFull(w.in, head)
	head = head[:n]
	combined := io.MultiReader(bytes.NewReader(head), w.in)

	var err error
	switch {
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b: // gzip
		w.stats.format = "tar.gz"
		gr, gerr := gzip.NewReader(combined)
		if gerr != nil {
			return w.finish(), gerr
		}
		defer gr.Close()
		err = w.walkTar(w.guard(gr), 0)
	case n >= 3 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h': // bzip2
		w.stats.format = "tar.bz2"
		err = w.walkTar(w.guard(bzip2.NewReader(combined)), 0)
	case n >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07): // zip
		w.stats.format = "zip"
		err = w.walkZip(combined)
	case looksLikeTar(head):
		w.stats.format = "tar"
		err = w.walkTar(w.guard(combined), 0)
	default:
		return w.finish(), errUnrecognizedArchive
	}
	return w.finish(), err
}

// finish seals the statistics: byte counters, and the input-cap reason when the
// artifact was larger than the walker was allowed to read.
func (w *walker) finish() walkStats {
	w.stats.compressed = w.in.n
	if w.b.maxArchiveBytes > 0 && w.in.n > w.b.maxArchiveBytes {
		w.stats.addReason(stopArchiveBytes)
	}
	return w.stats
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
		compressed := w.in.n
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

// emit hands one regular file to the visitor.
func (w *walker) emit(name string, data []byte, size int64, hitCap bool) {
	if hitCap {
		w.stats.addReason(stopFileBytes)
	}
	w.stats.files++
	if !w.visit(walkedFile{name: name, data: data, size: size, truncated: hitCap}) {
		w.stopped = true
	}
}

// looksLikeTar reports whether the leading bytes look like a (uncompressed) tar
// header. A tar block carries the "ustar" magic at offset 257, but we only have
// the first bytes here; the definitive check is deferred to tar.Reader, so this
// just rejects obvious non-tar data (we only reach it after gzip/bzip2/zip were
// ruled out).
func looksLikeTar(head []byte) bool {
	// A gem's outer tar starts with an ASCII filename ("metadata.gz\0..."); accept
	// a printable-ASCII lead as a tar candidate and let tar.Reader validate.
	for _, c := range head {
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(head) > 0
}

// walkTar walks a tar stream. depth bounds recursion into a nested data.tar.gz
// (a RubyGems .gem carries its real files in an inner data.tar.gz). It returns
// an error only when the stream is not a tar at all (no entry could be read at
// the outermost level); a mid-stream failure still yields what was read.
func (w *walker) walkTar(r io.Reader, depth int) error {
	tr := tar.NewReader(r)
	seen := 0
	for !w.stopped && !w.limited {
		if w.ctx.Err() != nil {
			return nil
		}
		hdr, herr := tr.Next()
		if herr == io.EOF {
			return nil
		}
		// An "insecure path" (absolute, or escaping via "..") is still a valid
		// header; nothing is ever extracted to a filesystem, so it is walked like
		// any other and left for the consumer to judge.
		if herr != nil && !errors.Is(herr, tar.ErrInsecurePath) {
			if seen == 0 && depth == 0 && !w.limited && w.ctx.Err() == nil {
				return herr // not a tar at all
			}
			return nil // a mid-stream error still yields what we read
		}
		if hdr == nil {
			return nil
		}
		seen++
		if !w.countEntry() {
			return nil
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			w.stats.links++
			if w.onLink != nil {
				w.onLink(walkedLink{name: name, target: hdr.Linkname, hard: hdr.Typeflag == tar.TypeLink})
			}
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

		// Recurse once into a RubyGems inner data.tar.gz so the gem's actual source
		// files are scanned rather than an opaque blob. The inner archive is
		// streamed, not buffered: its size is bounded by the walk-wide limits, not
		// by the per-file cap (which would cut a real gem's payload short).
		if depth == 0 && isNestedTarGz(name) {
			br := bufio.NewReaderSize(tr, 512)
			if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
				if gr, gerr := gzip.NewReader(br); gerr == nil {
					_ = w.walkTar(w.guard(gr), depth+1)
					_ = gr.Close()
					continue
				}
			}
			data, hitCap, rerr := readBounded(br, w.b.maxFileBytes)
			if rerr != nil {
				return nil
			}
			w.emit(name, data, hdr.Size, hitCap)
			continue
		}

		data, hitCap, rerr := readBounded(tr, w.b.maxFileBytes)
		if rerr != nil {
			return nil
		}
		w.emit(name, data, hdr.Size, hitCap)
	}
	return nil
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
func (w *walker) walkZip(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, w.b.maxArchiveBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > w.b.maxArchiveBytes {
		// Larger than we will buffer; the directory at its end was not read, so the
		// archive cannot be reliably parsed. Fail open (served unscanned).
		w.stats.addReason(stopArchiveBytes)
		return nil
	}
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
		return zerr
	}
	for _, f := range zr.File {
		if w.stopped || w.limited || w.ctx.Err() != nil {
			return nil
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
			return nil
		}
		name := path.Clean(strings.TrimPrefix(f.Name, "./"))
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		fdata, hitCap, rerr := readBounded(w.guard(rc), w.b.maxFileBytes)
		rc.Close()
		if rerr != nil {
			continue
		}
		if f.FileInfo().Mode()&fs.ModeSymlink != 0 {
			// A zip symlink stores its target as the member's content. It is
			// reported as a link AND examined as a file (see above).
			w.stats.links++
			if w.onLink != nil {
				target := fdata
				if len(target) > 4096 {
					target = target[:4096]
				}
				w.onLink(walkedLink{name: name, target: string(target)})
			}
		}
		w.emit(name, fdata, int64(f.UncompressedSize64), hitCap)
	}
	return nil
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
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
