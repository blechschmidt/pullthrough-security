package openvsx

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// OpenVSX's integrity record is the SHA-256 the registry publishes alongside
// every .vsix as a sibling ".sha256" file (the files.sha256 entry in a version's
// metadata). The proxy fetches that sidecar on a cache miss and verifies the
// fetched archive against it before the bytes are cached or streamed to the
// client, so a tampered or corrupt mirror/CDN can neither poison the cache nor
// reach a client. Verification is streaming — the archive is never buffered — so
// a mismatch aborts the cache write and the client stream at end-of-stream.
//
// OpenVSX does not publish a separate authenticated size record, so SHA-256 is
// the content check performed here (the task notes size where the registry
// exposes it; OpenVSX exposes only the digest sidecar).

// sha256HexLen is the length of a hex-encoded SHA-256 digest.
const sha256HexLen = sha256.Size * 2

// ChecksumMismatchError reports that a fetched .vsix did not hash to the SHA-256
// its sibling .sha256 sidecar declared. It is returned by a verifyingReader at
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
	return fmt.Sprintf("openvsx: sha256 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// expectedChecksum pairs a .vsix's expected hex SHA-256 with its filename.
type expectedChecksum struct {
	filename string
	sha256   string
}

// parseSHA256Sidecar extracts the hex SHA-256 digest from a .sha256 sidecar
// body. OpenVSX serves a bare 64-character hex string, but the parser also
// tolerates the GNU coreutils "sha256sum" form ("<hex>  <filename>") by taking
// the first whitespace-delimited token. It returns ok=false for any body that
// does not yield a well-formed 64-hex-character digest, so a malformed or
// truncated sidecar fails open (the archive is served unverified) rather than
// aborting a legitimate download.
func parseSHA256Sidecar(data []byte) (string, bool) {
	token := strings.TrimSpace(string(data))
	if i := strings.IndexAny(token, " \t\r\n"); i >= 0 {
		token = token[:i]
	}
	token = strings.TrimPrefix(token, "sha256:")
	if len(token) != sha256HexLen || !isHex(token) {
		return "", false
	}
	return strings.ToLower(token), true
}

// isHex reports whether s consists only of hex digits.
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
	return s != ""
}

// verifyingReader wraps a .vsix body and verifies, at end-of-stream, that the
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

// toHex renders bytes as a lowercase hex string.
func toHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
