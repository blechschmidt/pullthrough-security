package hex

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Hex's integrity record is the outer_checksum the signed /packages/<name>
// resource declares for each release: a SHA-256 over the entire release tarball.
// The proxy fetches that sibling resource on a cache miss and verifies each
// fetched tarball against it before the bytes are cached or streamed to the
// client, so a tampered or corrupt mirror can neither poison the cache nor reach
// a client. Verification is streaming — the archive is never buffered — so a
// mismatch aborts the cache write and the client stream at end-of-stream.

// sha256Len is the byte length of a SHA-256 digest.
const sha256Len = sha256.Size

// expectedChecksum pairs a release's expected hex SHA-256 with the filename it
// was recorded for.
type expectedChecksum struct {
	filename string
	sha256   string
}

// ChecksumMismatchError reports that a fetched tarball did not hash to the
// outer_checksum its /packages/<name> resource declared. It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure instead
// of serving poisoned content.
type ChecksumMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("hex: sha256 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// verifyingReader wraps a tarball body and verifies, at end-of-stream, that the
// bytes read hash to the expected SHA-256. On mismatch it returns a
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

// newVerifyingReader wraps src so reads are checked against expected. The
// returned ReadCloser takes ownership of src and closes it on Close. onResult,
// when non-nil, fires once at EOF with the outcome.
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
		got := toHex(v.hash.Sum(nil))
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
