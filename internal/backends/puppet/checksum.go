package puppet

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Puppet Forge records two integrity digests for every release tarball in the
// release-metadata document: file_sha256 (a SHA-256 hex digest) and file_md5
// (an MD5 hex digest). The proxy verifies a fetched release tarball against the
// SHA-256 when present — MD5 is a legacy fallback for older releases that
// predate the sha256 field — before the bytes are cached or streamed to the
// client, so a tampered or corrupt mirror can neither poison the cache nor reach
// a client. Verification is streaming — the tarball is never buffered — so a
// mismatch aborts the cache write and the client stream at end-of-stream.
//
// MD5 is cryptographically broken against collision attacks and is accepted only
// as a last resort when the upstream offers no stronger digest; the SHA-256 is
// always preferred and is what a modern Forge serves.

const (
	// sha256HexLen is the length of a lowercase hex SHA-256 digest.
	sha256HexLen = 64
	// md5HexLen is the length of a lowercase hex MD5 digest.
	md5HexLen = 32
)

// checksumAlgo identifies the digest algorithm a release tarball is verified
// against.
type checksumAlgo string

const (
	algoSHA256 checksumAlgo = "sha256"
	algoMD5    checksumAlgo = "md5"
)

// expectedChecksum carries the digest a release tarball must verify against and
// the algorithm it was recorded with.
type expectedChecksum struct {
	algo checksumAlgo
	hex  string // lowercase hex digest
}

// newHash returns a fresh hash for the checksum's algorithm.
func (e expectedChecksum) newHash() hash.Hash {
	if e.algo == algoMD5 {
		return md5.New()
	}
	return sha256.New()
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

// ChecksumMismatchError reports that a fetched release tarball did not hash to
// the digest the release-metadata document declared. It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure
// instead of serving poisoned content.
type ChecksumMismatchError struct {
	Coordinate string
	Algo       string
	Expected   string
	Actual     string
	URL        string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("puppet: %s checksum mismatch for %s (%s): expected %s, got %s",
		e.Algo, e.URL, e.Coordinate, e.Expected, e.Actual)
}

// verifyingReader wraps a release-tarball body and verifies, at end-of-stream,
// that the bytes read hash to the expected digest. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src        io.ReadCloser
	hash       hash.Hash
	expected   expectedChecksum
	coordinate string
	url        string
	verified   bool
	// onResult, when non-nil, fires exactly once at end-of-stream with the
	// verification outcome.
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against expected. The
// returned ReadCloser takes ownership of src and closes it on Close. onResult,
// when non-nil, fires once at EOF with the outcome.
func newVerifyingReader(src io.ReadCloser, expected expectedChecksum, coordinate, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:        src,
		hash:       expected.newHash(),
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
		ok := strings.EqualFold(got, v.expected.hex)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Coordinate: v.coordinate,
				Algo:       string(v.expected.algo),
				Expected:   string(v.expected.algo) + ":" + v.expected.hex,
				Actual:     string(v.expected.algo) + ":" + got,
				URL:        v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
