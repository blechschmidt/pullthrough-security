package nix

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"github.com/blechschmidt/pullthrough-security/internal/contentscan"
)

// A NAR file's name is a content address: /nar/<hash>.nar[.ext], where <hash>
// is a Nix base-32 SHA-256. Of what, a cache decides for itself, and the two
// conventions in use are both served by cache.nixos.org:
//
//   - the hash of the file as stored, i.e. of the compressed bytes (the
//     narinfo's FileHash) — how Nix's own binary-cache store names an xz NAR;
//   - the hash of the NAR itself, i.e. of the uncompressed content (the
//     narinfo's NarHash, the value its signature covers) — how the
//     zstd-compressed NARs of current channels are named.
//
// The request for a NAR does not say which. The backend therefore recomputes
// both as the file streams through to the cache and the client, and refuses to
// cache or serve a NAR whose name is neither: the SHA-256 of the bytes as they
// arrive, and — for a compression it can decode — the SHA-256 of what they
// decompress to. The second runs alongside the transfer through a decoder with
// bounded memory; nothing is buffered. A mismatch aborts the cache write (the
// partial blob is never committed) and the client stream.

// maxNarContentBytes bounds how much decompressed content is hashed for one
// NAR. It is far above any real store path; a stream that decompresses to more
// is not verified by its content (and so only by its file hash).
const maxNarContentBytes = int64(64) << 30

// FileHashMismatchError reports that a fetched NAR matched the content address
// named in its URL under neither reading: not as the SHA-256 of the file, and
// not as the SHA-256 of its uncompressed content.
type FileHashMismatchError struct {
	Filename string
	Expected string
	// Actual is the SHA-256 of the file as fetched. ActualContent is the SHA-256
	// of its uncompressed content, or empty when that could not be computed (an
	// uncompressed NAR, where the two are the same; a compression the backend
	// does not decode; a stream that does not decompress).
	Actual        string
	ActualContent string
	URL           string
}

func (e *FileHashMismatchError) Error() string {
	if e.ActualContent != "" {
		return fmt.Sprintf("nix: NAR content-address mismatch for %s (%s): expected %s; the file hashes to %s and its uncompressed content to %s",
			e.URL, e.Filename, e.Expected, e.Actual, e.ActualContent)
	}
	return fmt.Sprintf("nix: NAR file-hash mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// Ways a NAR's name was confirmed, as reported to the verifier's callback.
const (
	verifiedByFile    = "file"    // the name is the SHA-256 of the file
	verifiedByContent = "content" // the name is the SHA-256 of the uncompressed NAR
)

// fileHashVerifier wraps a NAR body and verifies, at end-of-stream, that the
// content address in its name is the SHA-256 of the bytes read or of what they
// decompress to. On mismatch it returns a *FileHashMismatchError in place of
// io.EOF, which propagates through io.Copy so the caching layer aborts the
// store and never commits unverified bytes.
type fileHashVerifier struct {
	src         io.ReadCloser
	hash        hash.Hash
	expectedB32 string
	filename    string
	url         string
	verified    bool
	onResult    func(ok bool, how string)

	// content is the side that hashes the uncompressed NAR; nil when the file is
	// not compressed in a way the backend decodes.
	content *contentHasher
}

// contentHasher decompresses a copy of the stream on a goroutine of its own
// and hashes the result. The verifier writes every byte it reads into pw; the
// pipe makes that write wait for the decoder, so the two stay in step and
// nothing accumulates.
type contentHasher struct {
	pw   *io.PipeWriter
	done chan string // the base-32 digest, or "" when the content could not be hashed
}

func newContentHasher() *contentHasher {
	pr, pw := io.Pipe()
	c := &contentHasher{pw: pw, done: make(chan string, 1)}
	go func() {
		digest := hashUncompressed(pr)
		// Whatever the decoder left unread — or everything, if it gave up — is
		// drained, so the writer side never blocks on a reader that is gone.
		_, _ = io.Copy(io.Discard, pr)
		c.done <- digest
	}()
	return c
}

// hashUncompressed returns the Nix base-32 SHA-256 of what r decompresses to,
// or "" when r is not a compressed stream the unpack layer decodes, does not
// decompress cleanly to its end, or decompresses to more than
// maxNarContentBytes. "Cleanly to its end" matters: bytes after the compressed
// stream would be part of the file a client receives but of no digest computed
// here.
func hashUncompressed(r io.Reader) string {
	br := bufio.NewReaderSize(r, 64<<10)
	dr, release, compressed, err := contentscan.OpenCompressed(br)
	defer release()
	if !compressed || err != nil {
		return ""
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(dr, maxNarContentBytes+1))
	if err != nil || n > maxNarContentBytes {
		return ""
	}
	if _, err := br.Peek(1); err != io.EOF {
		return "" // trailing bytes the decoder did not account for
	}
	return nixBase32Encode(h.Sum(nil))
}

// decodableExts are the NAR compression suffixes whose content the backend can
// hash. Brotli and lzip are served but not decoded: such a NAR is verified by
// its file hash only.
var decodableExts = map[string]bool{".xz": true, ".zst": true, ".zstd": true, ".bz2": true, ".gz": true}

// newFileHashVerifier wraps src so reads are checked against the expected Nix
// base-32 SHA-256. compressionExt is the file name's compression suffix ("" for
// an uncompressed NAR, whose file hash is its content hash). The returned
// ReadCloser takes ownership of src and closes it on Close. onResult, when
// non-nil, fires once at EOF with the outcome and, on success, how the name was
// confirmed.
func newFileHashVerifier(src io.ReadCloser, expectedB32, filename, url, compressionExt string, onResult func(ok bool, how string)) *fileHashVerifier {
	v := &fileHashVerifier{
		src:         src,
		hash:        sha256.New(),
		expectedB32: expectedB32,
		filename:    filename,
		url:         url,
		onResult:    onResult,
	}
	if decodableExts[compressionExt] {
		v.content = newContentHasher()
	}
	return v
}

func (v *fileHashVerifier) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		// hash.Hash.Write never returns an error.
		_, _ = v.hash.Write(p[:n])
		if v.content != nil {
			// The reader side drains the pipe to its end whatever happens, so this
			// returns; an error means the verifier was closed underneath.
			_, _ = v.content.pw.Write(p[:n])
		}
	}
	if err == io.EOF && !v.verified {
		v.verified = true
		got := nixBase32Encode(v.hash.Sum(nil))
		gotContent := v.finishContent()
		how := ""
		switch v.expectedB32 {
		case got:
			how = verifiedByFile
		case gotContent:
			if gotContent != "" {
				how = verifiedByContent
			}
		}
		if v.onResult != nil {
			v.onResult(how != "", how)
		}
		if how == "" {
			mismatch := &FileHashMismatchError{
				Filename: v.filename,
				Expected: "sha256:" + v.expectedB32,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
			if gotContent != "" {
				mismatch.ActualContent = "sha256:" + gotContent
			}
			return n, mismatch
		}
	}
	return n, err
}

// finishContent ends the content hasher's input and returns its digest ("" when
// there is none). It is safe to call more than once.
func (v *fileHashVerifier) finishContent() string {
	if v.content == nil {
		return ""
	}
	c := v.content
	v.content = nil
	_ = c.pw.Close()
	return <-c.done
}

func (v *fileHashVerifier) Close() error {
	// Stop the content hasher if the body is abandoned before its end.
	v.finishContent()
	return v.src.Close()
}
