package homebrew

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// A bottle's download URL is a content-addressed OCI blob reference whose final
// path component names the tarball's own SHA-256: /v2/<repo>/blobs/sha256:<hex>.
// This is the same digest the formula's bottle manifest records. The backend
// recomputes that SHA-256 as the tarball streams through to the cache and the
// client, refusing to cache or serve any bottle whose content does not match
// the hash named in its URL — verify-on-fetch, exactly like the Nix and Dart
// backends. Verification is streaming, so it never buffers the archive; a
// mismatch aborts the cache write (the partial blob is never committed) and the
// client stream, surfaced as a *DigestMismatchError.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

// DigestMismatchError reports that a fetched bottle's recomputed SHA-256 did not
// match the content-address digest named in its URL. It is returned by the
// verifying reader at end-of-stream so the cache rejects the write and the proxy
// surfaces the integrity failure instead of serving poisoned content.
type DigestMismatchError struct {
	Formula  string
	Version  string
	Expected string
	Actual   string
	URL      string
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("homebrew: bottle digest mismatch for %s %s (%s): expected %s, got %s",
		e.Formula, e.Version, e.URL, e.Expected, e.Actual)
}

// bottleVerifier wraps a bottle body and verifies, at end-of-stream, that the
// bytes read hash (SHA-256) to the expected content-address digest. On mismatch
// it returns a *DigestMismatchError in place of io.EOF, which propagates through
// io.Copy so the caching layer aborts the store and never commits unverified
// bytes.
type bottleVerifier struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected string // lowercase hex
	formula  string
	version  string
	url      string
	verified bool
	// onResult, when non-nil, fires exactly once at end-of-stream with the
	// verification outcome (known only once every byte has been read).
	onResult func(ok bool)
}

// newBottleVerifier wraps src so reads are checked against the expected
// lowercase-hex SHA-256. The returned ReadCloser takes ownership of src and
// closes it on Close.
func newBottleVerifier(src io.ReadCloser, expectedHex, formula, version, url string, onResult func(ok bool)) *bottleVerifier {
	return &bottleVerifier{
		src:      src,
		hash:     sha256.New(),
		expected: expectedHex,
		formula:  formula,
		version:  version,
		url:      url,
		onResult: onResult,
	}
}

func (v *bottleVerifier) Read(p []byte) (int, error) {
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
			return n, &DigestMismatchError{
				Formula:  v.formula,
				Version:  v.version,
				Expected: "sha256:" + v.expected,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *bottleVerifier) Close() error { return v.src.Close() }

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
