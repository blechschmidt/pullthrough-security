package contentscan

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"io"
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
}

// visitor receives each extracted file. It returns false to stop the walk early
// (e.g. the finding budget is exhausted).
type visitor func(wf walkedFile) bool

// walkArchive detects the artifact's archive format from its leading bytes and
// walks every regular file, invoking visit for each (bounded per the budget).
// It returns whether the walk hit a size/entry bound (truncated) and a non-nil
// error only for an unrecognized or unreadable archive, which the caller treats
// as fail-open. The whole walk is bounded by ctx (the scan timeout).
func walkArchive(ctx context.Context, r io.Reader, b budget, visit visitor) (truncated bool, err error) {
	br := &countingReader{r: io.LimitReader(r, b.maxArchiveBytes+1), max: b.maxArchiveBytes}

	// Peek the first bytes to choose a decoder without consuming them.
	head := make([]byte, 8)
	n, _ := io.ReadFull(br, head)
	head = head[:n]
	combined := io.MultiReader(bytes.NewReader(head), br)

	switch {
	case n >= 2 && head[0] == 0x1f && head[1] == 0x8b: // gzip
		gr, gerr := gzip.NewReader(combined)
		if gerr != nil {
			return false, gerr
		}
		defer gr.Close()
		return walkTar(ctx, gr, b, 0, "", visit)
	case n >= 3 && head[0] == 'B' && head[1] == 'Z' && head[2] == 'h': // bzip2
		return walkTar(ctx, bzip2.NewReader(combined), b, 0, "", visit)
	case n >= 4 && head[0] == 'P' && head[1] == 'K' && (head[2] == 0x03 || head[2] == 0x05 || head[2] == 0x07): // zip
		return walkZip(ctx, combined, b, visit)
	case looksLikeTar(head):
		return walkTar(ctx, combined, b, 0, "", visit)
	default:
		return false, errUnrecognizedArchive
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
// (a RubyGems .gem carries its real files in an inner data.tar.gz); prefix is
// prepended to reported names for nested entries.
func walkTar(ctx context.Context, r io.Reader, b budget, depth int, prefix string, visit visitor) (truncated bool, err error) {
	tr := tar.NewReader(r)
	entries := 0
	for {
		if ctx.Err() != nil {
			return truncated, nil
		}
		hdr, herr := tr.Next()
		if herr == io.EOF {
			break
		}
		if herr != nil {
			if entries == 0 && depth == 0 {
				return truncated, herr // not a tar at all
			}
			break // a mid-stream error still yields what we read
		}
		entries++
		if b.maxFiles > 0 && entries > b.maxFiles {
			truncated = true
			break
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := prefix + path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		data, hitCap, rerr := readBounded(tr, b.maxFileBytes)
		if rerr != nil {
			break
		}
		if hitCap {
			truncated = true
		}
		// Recurse once into a RubyGems inner data.tar.gz so the gem's actual source
		// files are scanned rather than an opaque blob.
		if depth == 0 && isNestedTarGz(name) && len(data) > 0 {
			if gr, gerr := gzip.NewReader(bytes.NewReader(data)); gerr == nil {
				t2, _ := walkTar(ctx, gr, b, depth+1, "", visit)
				_ = gr.Close()
				truncated = truncated || t2
				continue
			}
		}
		if !visit(walkedFile{name: name, data: data}) {
			return truncated, nil
		}
	}
	return truncated, nil
}

// isNestedTarGz reports whether an entry is a RubyGems inner data payload.
func isNestedTarGz(name string) bool {
	base := path.Base(name)
	return base == "data.tar.gz"
}

// walkZip buffers a zip (bounded by the archive budget — the central directory
// lives at the stream end) and walks its regular-file entries.
func walkZip(ctx context.Context, r io.Reader, b budget, visit visitor) (truncated bool, err error) {
	data, err := io.ReadAll(io.LimitReader(r, b.maxArchiveBytes+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) > b.maxArchiveBytes {
		// Larger than we will buffer; the directory at its end was not read, so the
		// archive cannot be reliably parsed. Fail open (served unscanned).
		return true, nil
	}
	zr, zerr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if zerr != nil {
		return false, zerr
	}
	entries := 0
	for _, f := range zr.File {
		if ctx.Err() != nil {
			return truncated, nil
		}
		if f.FileInfo().IsDir() {
			continue
		}
		entries++
		if b.maxFiles > 0 && entries > b.maxFiles {
			truncated = true
			break
		}
		name := path.Clean(strings.TrimPrefix(f.Name, "./"))
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		fdata, hitCap, rerr := readBounded(rc, b.maxFileBytes)
		rc.Close()
		if rerr != nil {
			continue
		}
		if hitCap {
			truncated = true
		}
		if !visit(walkedFile{name: name, data: fdata}) {
			return truncated, nil
		}
	}
	return truncated, nil
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
