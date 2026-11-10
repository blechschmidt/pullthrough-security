package nix

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
)

// A NAR file's name is its own content address: /nar/<filehash>.nar[.ext], where
// <filehash> is the Nix base-32 SHA-256 of the (compressed) file bytes. The
// backend recomputes that SHA-256 as the file streams through to the cache and
// client, refusing to cache or serve any NAR whose hash does not match the one
// named in its URL. Verification runs over the still-compressed bytes, so it
// needs no codec and never buffers the archive — mirroring the Julia backend's
// git-tree-sha1 check. A mismatch aborts the cache write (the partial blob is
// never committed) and the client stream.

// FileHashMismatchError reports that a fetched NAR's recomputed SHA-256 did not
// match the content-address hash named in its URL.
type FileHashMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *FileHashMismatchError) Error() string {
	return fmt.Sprintf("nix: NAR file-hash mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// fileHashVerifier wraps a NAR body and verifies, at end-of-stream, that the
// bytes read hash (SHA-256) to the expected Nix base-32 content address. On
// mismatch it returns a *FileHashMismatchError in place of io.EOF, which
// propagates through io.Copy so the caching layer aborts the store and never
// commits unverified bytes.
type fileHashVerifier struct {
	src         io.ReadCloser
	hash        hash.Hash
	expectedB32 string
	filename    string
	url         string
	verified    bool
	onResult    func(ok bool)
}

// newFileHashVerifier wraps src so reads are checked against the expected Nix
// base-32 SHA-256. The returned ReadCloser takes ownership of src and closes it
// on Close. onResult, when non-nil, fires once at EOF with the outcome.
func newFileHashVerifier(src io.ReadCloser, expectedB32, filename, url string, onResult func(ok bool)) *fileHashVerifier {
	return &fileHashVerifier{
		src:         src,
		hash:        sha256.New(),
		expectedB32: expectedB32,
		filename:    filename,
		url:         url,
		onResult:    onResult,
	}
}

func (v *fileHashVerifier) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		// hash.Hash.Write never returns an error.
		_, _ = v.hash.Write(p[:n])
	}
	if err == io.EOF && !v.verified {
		v.verified = true
		got := nixBase32Encode(v.hash.Sum(nil))
		ok := got == v.expectedB32
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &FileHashMismatchError{
				Filename: v.filename,
				Expected: "sha256:" + v.expectedB32,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *fileHashVerifier) Close() error { return v.src.Close() }
