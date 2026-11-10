package helm

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Helm publishes a single SHA-256 digest per chart in the repository index
// (the `digest:` field of each entry in index.yaml) and, for OCI-hosted charts,
// the layer/manifest digest carries the same guarantee through the Registry v2
// content-addressing the docker backend already verifies. The classic backend
// therefore verifies a fetched .tgz against the index-declared SHA-256 before
// the bytes are cached or streamed to the client, mirroring the checksum
// verification the Maven and RubyGems backends perform. A mismatch aborts the
// cache write and the response, so a tampered or corrupt chart mirror can
// neither poison the cache nor reach a client.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

// expectedChecksum carries the SHA-256 hex digest the index declares for a chart.
type expectedChecksum struct {
	hex string
}

// normalizeDigest accepts the digest forms a Helm index (or an OCI descriptor)
// may publish — a bare 64-char hex string, or an algorithm-prefixed
// "sha256:<hex>" — and returns the lowercase hex when it is a well-formed
// SHA-256 digest. It returns ok=false for any other algorithm or a malformed
// value so a garbage digest is never treated as a passing check.
func normalizeDigest(raw string) (hex string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		alg := strings.ToLower(strings.TrimSpace(s[:i]))
		if alg != "sha256" {
			return "", false
		}
		s = strings.TrimSpace(s[i+1:])
	}
	s = strings.ToLower(s)
	if len(s) != sha256HexLen || !isHex(s) {
		return "", false
	}
	return s, true
}

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

// ChecksumMismatchError reports that a fetched chart did not hash to the SHA-256
// digest its repository index declared. It is returned by a verifyingReader at
// end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("helm: sha256 checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps a chart body and verifies, at end-of-stream, that the
// bytes read hash to the expected SHA-256. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedChecksum
	url      string
	verified bool
	// onResult, when non-nil, is invoked exactly once at end-of-stream with the
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
				Expected: "sha256:" + v.expected.hex,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
