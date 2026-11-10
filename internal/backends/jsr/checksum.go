package jsr

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// JSR's integrity record is the SHA-256 the version manifest declares for each
// published file. The proxy verifies a fetched module file against that digest
// before the bytes are cached or streamed to the client, so a tampered or
// corrupt mirror can neither poison the cache nor reach a client. Verification
// is streaming — the file is never buffered — so a mismatch aborts the cache
// write and the client stream at end-of-stream.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

// expectedChecksum carries the SHA-256 hex digest the version manifest declares
// for a module file, paired with the file path it was recorded for.
type expectedChecksum struct {
	filePath string
	hex      string
}

// isHex reports whether s is composed solely of hexadecimal digits.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

// ChecksumMismatchError reports that a fetched module file did not hash to the
// SHA-256 its version manifest declared. It is returned by a verifyingReader at
// end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	FilePath string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("jsr: sha256 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.FilePath, e.Expected, e.Actual)
}

// verifyingReader wraps a module-file body and verifies, at end-of-stream, that
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
		got := fmt.Sprintf("%x", v.hash.Sum(nil))
		ok := strings.EqualFold(got, v.expected.hex)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				FilePath: v.expected.filePath,
				Expected: "sha256:" + v.expected.hex,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
