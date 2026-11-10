package cran

import (
	"crypto/md5"
	"fmt"
	"hash"
	"io"
	"strings"
)

// CRAN's integrity model is the per-area PACKAGES index, which records an MD5sum
// for every package tarball it describes. The proxy fetches the sibling PACKAGES
// index on a cache miss and verifies each fetched tarball against it before the
// bytes are cached or streamed to the client, so a tampered or corrupt mirror
// can neither poison the cache nor reach a client. This mirrors the checksum
// verification the Conan backend performs against conanmanifest.txt and the
// Debian/APT backend performs against the Packages index.
//
// MD5 is cryptographically broken for collision resistance; it is used here
// because it is the digest CRAN's PACKAGES format carries. It still detects
// accidental corruption and non-adversarial tampering, and a package filename
// (name + version) addresses an immutable artifact, so the cache key is itself
// stable. A future CRAN format carrying SHA-256 would slot in alongside this.

// expectedChecksum pairs a parsed expected MD5 hex value with the filename it
// was recorded for.
type expectedChecksum struct {
	filename string
	md5hex   string
}

// ChecksumMismatchError reports that a fetched tarball did not hash to the MD5
// digest its PACKAGES index declared. It is returned by a verifyingReader at
// end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("cran: md5 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// verifyingReader wraps a tarball body and verifies, at end-of-stream, that the
// bytes read hash to the expected MD5. On mismatch it returns a
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
		hash:     md5.New(),
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
		ok := strings.EqualFold(got, v.expected.md5hex)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Filename: v.expected.filename,
				Expected: "md5:" + v.expected.md5hex,
				Actual:   "md5:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
