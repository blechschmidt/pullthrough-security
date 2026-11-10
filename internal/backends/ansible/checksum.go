package ansible

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Ansible Galaxy's integrity record for a published collection is the SHA-256 of
// the artifact tarball, carried in the version-detail document's
// "artifact.sha256" field. The proxy verifies a fetched collection artifact
// against that digest before the bytes are cached or streamed to the client, so
// a tampered or corrupt mirror can neither poison the cache nor reach a client.
// Verification is streaming — the tarball is never buffered — so a mismatch
// aborts the cache write and the client stream at end-of-stream.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

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

// normalizeSHA256 returns the lowercase hex SHA-256 digest from a raw value,
// tolerating an optional "sha256:" prefix, and ok=false for any other form.
func normalizeSHA256(raw string) (hex string, ok bool) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, ":-"); i >= 0 {
		if alg := strings.ToLower(s[:i]); alg != "sha256" && alg != "sha-256" {
			return "", false
		}
		s = s[i+1:]
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != sha256HexLen || !isHex(s) {
		return "", false
	}
	return s, true
}

// ChecksumMismatchError reports that a fetched collection artifact did not hash
// to the SHA-256 the version-detail document declared. It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure
// instead of serving poisoned content.
type ChecksumMismatchError struct {
	Coordinate string
	Expected   string
	Actual     string
	URL        string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("ansible: sha256 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Coordinate, e.Expected, e.Actual)
}

// verifyingReader wraps a collection-artifact body and verifies, at
// end-of-stream, that the bytes read hash to the expected SHA-256. On mismatch
// it returns a *ChecksumMismatchError in place of io.EOF, which propagates
// through io.Copy so the caching layer aborts the store and never commits
// unverified bytes.
type verifyingReader struct {
	src        io.ReadCloser
	hash       hash.Hash
	expected   string // lowercase hex SHA-256
	coordinate string
	url        string
	verified   bool
	// onResult, when non-nil, fires exactly once at end-of-stream with the
	// verification outcome.
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against expected (a
// lowercase hex SHA-256). The returned ReadCloser takes ownership of src and
// closes it on Close. onResult, when non-nil, fires once at EOF with the
// outcome.
func newVerifyingReader(src io.ReadCloser, expected, coordinate, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:        src,
		hash:       sha256.New(),
		expected:   expected,
		coordinate: coordinate,
		url:        url,
		onResult:   onResult,
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
		ok := strings.EqualFold(got, v.expected)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Coordinate: v.coordinate,
				Expected:   "sha256:" + v.expected,
				Actual:     "sha256:" + got,
				URL:        v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
