package composer

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Composer's package metadata declares, for every version's distributable
// archive, a "dist.shasum" — the SHA-1 digest of the dist zip — alongside the
// download URL and the source reference. That digest is the upstream's own
// declared content address of the archive, so on a dist cache miss the backend
// fetches the package's v2 metadata, looks up the shasum for the exact reference
// being fetched, and verifies the streamed zip against it before the bytes are
// cached or served. A mismatch aborts the cache write and the response, so a
// tampered or corrupt mirror can neither poison the cache nor reach a client.
// This mirrors the checksum verification the Maven and RubyGems backends perform.
//
// SHA-1 is what Composer publishes (it matches the git/archive convention the
// ecosystem grew up with); it is the only digest dist metadata carries, so it is
// the single algorithm the backend verifies against. SHA-1 is weak against
// chosen-prefix collisions but the digest still provides robust detection of the
// accidental corruption and naive tampering a mirror is most likely to exhibit;
// stronger end-to-end guarantees come from the separate sigverify gate.

// distShasumHexLen is the expected length of a lowercase SHA-1 hex digest.
const distShasumHexLen = 40

// expectedChecksum is a parsed SHA-1 digest expected for a dist archive.
type expectedChecksum struct {
	hex string
}

// newHash returns a fresh SHA-1 hasher.
func newHash() hash.Hash { return sha1.New() }

// ChecksumMismatchError reports that a fetched dist archive did not hash to the
// SHA-1 digest its package metadata declared. It is returned by a verifyingReader
// at end-of-stream so the cache rejects the write — the partial archive is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("composer: sha1 dist checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps a dist archive body and verifies, at end-of-stream, that
// the bytes read hash to the expected SHA-1 digest. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes. Dist
// zips can be large, so they are verified as they stream rather than buffered.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedChecksum
	url      string
	verified bool
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
				Expected: "sha1:" + v.expected.hex,
				Actual:   "sha1:" + got,
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
