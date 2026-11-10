package generic

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"net/url"
	"path"
	"strings"
)

// The generic backend's integrity record is a content digest the operator
// declares per route: either a sibling checksum file (the "sidecar" source) or a
// digest embedded in the request path (the "path" source, for content-addressed
// layouts). On a cache miss the fetched artifact is streamed through a hasher and
// the recomputed digest is compared to the expected one before the bytes are
// committed or served, so a tampered or corrupt mirror/CDN can neither poison the
// cache nor reach a client. Verification is streaming — the artifact is never
// buffered — so a mismatch aborts the cache write and the client stream at
// end-of-stream, mirroring the openvsx/nix/julia backends.

// digestHexLen returns the hex-string length of a digest for the named
// algorithm, used to sanity-check a recovered digest.
func digestHexLen(algorithm string) int {
	switch algorithm {
	case "sha256":
		return sha256.Size * 2
	case "sha512":
		return sha512.Size * 2
	case "sha1":
		return sha1.Size * 2
	default:
		return 0
	}
}

// newHash constructs the hash.Hash for a (pre-validated) algorithm.
func newHash(algorithm string) hash.Hash {
	switch algorithm {
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "sha1":
		return sha1.New()
	default:
		// Unreachable: algorithms are validated at config load. Fall back to
		// sha256 rather than panic so a future algorithm added to the allowlist
		// without a hasher degrades safely.
		return sha256.New()
	}
}

// ChecksumMismatchError reports that a fetched artifact did not hash to its
// declared digest. It is returned by a verifyingReader at end-of-stream in place
// of io.EOF so the cache rejects the write — the partial blob is never committed
// — and the proxy surfaces the integrity failure instead of serving poisoned
// content.
type ChecksumMismatchError struct {
	Algorithm string
	Expected  string
	Actual    string
	URL       string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("generic: %s checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Algorithm, e.Expected, e.Actual)
}

// verifyingReader wraps an artifact body and verifies, at end-of-stream, that
// the bytes read hash to the expected digest. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src       io.ReadCloser
	hash      hash.Hash
	algorithm string
	expected  string // lowercase hex
	url       string
	verified  bool
	// onResult, when non-nil, fires exactly once at end-of-stream with the
	// verification outcome (the result is only known once all bytes are read).
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against expected (lowercase
// hex). The returned ReadCloser takes ownership of src and closes it on Close.
func newVerifyingReader(src io.ReadCloser, algorithm, expected, rawURL string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:       src,
		hash:      newHash(algorithm),
		algorithm: algorithm,
		expected:  expected,
		url:       rawURL,
		onResult:  onResult,
	}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
		_, _ = v.hash.Write(p[:n]) // hash.Hash.Write never returns an error
	}
	if err == io.EOF && !v.verified {
		v.verified = true
		got := toHex(v.hash.Sum(nil))
		ok := strings.EqualFold(got, v.expected)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Algorithm: v.algorithm,
				Expected:  v.algorithm + ":" + v.expected,
				Actual:    v.algorithm + ":" + got,
				URL:       v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }

// parseChecksumSidecar extracts the hex digest from a sidecar checksum file for
// the given algorithm. It accepts a bare hex string, the GNU coreutils
// "<hex>  <filename>" form (first whitespace-delimited token), and an optional
// "<algo>:" prefix. It returns ok=false for any body that does not yield a
// well-formed digest of the expected length, so a malformed sidecar is handled
// by the route's fail-open/closed policy rather than aborting a legitimate
// download on garbage.
func parseChecksumSidecar(data []byte, algorithm string) (string, bool) {
	token := strings.TrimSpace(string(data))
	if i := strings.IndexAny(token, " \t\r\n"); i >= 0 {
		token = token[:i]
	}
	token = strings.TrimPrefix(token, algorithm+":")
	want := digestHexLen(algorithm)
	if want == 0 || len(token) != want || !isHex(token) {
		return "", false
	}
	return strings.ToLower(token), true
}

// normalizeEmbeddedDigest validates a digest captured from the request path and
// returns its lowercase-hex form. It tolerates an "<algo>:" prefix and is
// length-checked against the algorithm. It returns ok=false for a malformed
// capture.
func normalizeEmbeddedDigest(raw, algorithm string) (string, bool) {
	token := strings.TrimSpace(raw)
	token = strings.TrimPrefix(token, algorithm+":")
	want := digestHexLen(algorithm)
	if want == 0 || len(token) != want || !isHex(token) {
		return "", false
	}
	return strings.ToLower(token), true
}

// sidecarURL derives the checksum sidecar URL from an artifact URL per the
// route's verify rule: either appending SidecarSuffix to the path or replacing
// the path's final extension with it. The query is dropped (a sidecar is a plain
// file). It returns ok=false for an unparseable URL.
func sidecarURL(artifactURL string, v *VerifyConfig) (string, bool) {
	u, err := url.Parse(artifactURL)
	if err != nil {
		return "", false
	}
	p := u.Path
	if v.SidecarReplacesExtension {
		ext := path.Ext(p)
		p = strings.TrimSuffix(p, ext) + v.SidecarSuffix
	} else {
		p += v.SidecarSuffix
	}
	u.Path = p
	u.RawPath = ""
	u.RawQuery = ""
	return u.String(), true
}

// isHex reports whether s consists only of hex digits and is non-empty.
func isHex(s string) bool {
	if s == "" {
		return false
	}
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
	return true
}

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
