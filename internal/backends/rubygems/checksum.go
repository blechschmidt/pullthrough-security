package rubygems

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// RubyGems' compact index publishes, for every released version, the SHA-256
// digest of the corresponding .gem file in the per-gem info document
// (/info/<gem>) under the "checksum:" requirement. That digest is the upstream's
// own declared content address of the artifact, so the backend fetches the info
// document on a .gem cache miss, looks up the digest for the exact version (and
// platform) being fetched, and verifies the streamed bytes against it before
// they are cached or served. A mismatch aborts the cache write and the response,
// so a tampered or corrupt mirror can neither poison the cache nor reach a
// client. This mirrors the checksum verification the Maven backend performs
// against sidecar files and the digest verification the Docker/OCI backend
// performs on content-addressed blobs.
//
// SHA-256 is the only digest the compact index exposes, so it is the single
// algorithm the backend verifies against; there is no weaker fallback.

// gemChecksumHexLen is the expected length of a lowercase SHA-256 hex digest.
const gemChecksumHexLen = 64

// expectedChecksum is a parsed SHA-256 digest expected for a gem artifact.
type expectedChecksum struct {
	hex string
}

// newHash returns a fresh SHA-256 hasher.
func newHash() hash.Hash { return sha256.New() }

// ChecksumMismatchError reports that a fetched .gem did not hash to the SHA-256
// digest its compact-index info document declared. It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure instead
// of serving poisoned content.
type ChecksumMismatchError struct {
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("rubygems: sha256 checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps a .gem body and verifies, at end-of-stream, that the
// bytes read hash to the expected SHA-256 digest. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes. Gems
// can be large (native extensions, bundled assets), so they are verified as they
// stream rather than buffered.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedChecksum
	url      string
	verified bool
	// onResult, when non-nil, is invoked exactly once at end-of-stream with the
	// verification outcome (only known once all bytes have been read).
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against expected. The
// returned ReadCloser takes ownership of src and closes it on Close.
func newVerifyingReader(src io.ReadCloser, expected expectedChecksum, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:      src,
		hash:     newHash(),
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
				Expected: "sha256:" + v.expected.hex,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }

// isHex reports whether s is composed solely of hexadecimal digits.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}
