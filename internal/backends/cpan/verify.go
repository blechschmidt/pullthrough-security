package cpan

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// CPAN's integrity model is the per-author CHECKSUMS file, which records a
// SHA-256 for every distribution in the directory. The proxy fetches the sibling
// CHECKSUMS on a cache miss and verifies each fetched tarball against it before
// the bytes are cached or streamed to the client, so a tampered or corrupt mirror
// can neither poison the cache nor reach a client. A distribution filename
// (name + version) addresses an immutable artifact, so the cache key is itself
// stable, and SHA-256 is collision-resistant, making this a strong end-to-end
// content check rather than the corruption-only guarantee MD5 affords.

// expectedChecksum pairs a parsed expected SHA-256 hex value with the filename it
// was recorded for.
type expectedChecksum struct {
	filename string
	sha256   string
}

// ChecksumMismatchError reports that a fetched distribution did not hash to the
// SHA-256 digest its CHECKSUMS file declared. It is returned by a verifyingReader
// at end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("cpan: sha256 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// verifyingReader wraps a distribution body and verifies, at end-of-stream, that
// the bytes read hash to the expected SHA-256. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedChecksum
	url      string
	verified bool
	// onResult, when non-nil, fires exactly once at end-of-stream with the
	// verification outcome, so the backend can count successes and mismatches
	// accurately (the result is only known once all bytes have been read).
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against expected. The returned
// ReadCloser takes ownership of src and closes it on Close. onResult, when
// non-nil, fires once at EOF with the outcome.
func newVerifyingReader(src io.ReadCloser, expected expectedChecksum, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:      src,
		hash:     sha256.New(),
		expected: expected,
		url:      url,
		onResult: onResult,
	}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		// hash.Hash.Write never returns an error.
		_, _ = v.hash.Write(p[:n])
	}
	if err == io.EOF && !v.verified {
		v.verified = true
		got := fmt.Sprintf("%x", v.hash.Sum(nil))
		ok := strings.EqualFold(got, v.expected.sha256)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Filename: v.expected.filename,
				Expected: "sha256:" + v.expected.sha256,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
