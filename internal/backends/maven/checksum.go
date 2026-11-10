package maven

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Checksum algorithms Maven repositories publish as artifact sidecars, in
// descending order of cryptographic strength. The proxy verifies a fetched
// artifact against the strongest sidecar the upstream actually serves before the
// bytes are cached or streamed to the client, so a tampered mirror cannot poison
// the cache. Verification is the cornerstone of the supply-chain guarantee for
// the JVM ecosystem, mirroring the digest verification the Docker/OCI backend
// performs on content-addressed blobs.
//
// MD5 is broken for collision resistance and is accepted only as a last resort
// when a (typically legacy) repository publishes nothing stronger; SHA-1 is the
// realistic floor for Maven Central and most enterprise mirrors.
type checksumAlg struct {
	// ext is the sidecar file extension, including the leading dot (e.g. ".sha256").
	ext string
	// name is the algorithm label used in diagnostics and metrics.
	name string
	// hexLen is the expected length of the lowercase hex encoding.
	hexLen int
	// newHash returns a fresh hasher for the algorithm.
	newHash func() hash.Hash
}

// verifyAlgorithms lists the algorithms the backend will verify against, in the
// order it prefers them. The first algorithm whose sidecar the upstream serves
// is used.
var verifyAlgorithms = []checksumAlg{
	{ext: ".sha512", name: "sha512", hexLen: 128, newHash: sha512.New},
	{ext: ".sha256", name: "sha256", hexLen: 64, newHash: sha256.New},
	{ext: ".sha1", name: "sha1", hexLen: 40, newHash: sha1.New},
	{ext: ".md5", name: "md5", hexLen: 32, newHash: md5.New},
}

// checksumExtensions is the set of sidecar extensions the backend recognizes as
// checksum (not signature) sidecars, used during request classification.
var checksumExtensions = func() map[string]checksumAlg {
	m := make(map[string]checksumAlg, len(verifyAlgorithms))
	for _, a := range verifyAlgorithms {
		m[a.ext] = a
	}
	return m
}()

// expectedChecksum pairs a parsed expected hex value with the algorithm that
// produced it.
type expectedChecksum struct {
	alg checksumAlg
	hex string
}

// parseChecksumValue extracts the hex digest from a Maven checksum sidecar body.
// Repositories publish these in several shapes:
//
//	"<hex>"
//	"<hex>  <filename>"          (coreutils style)
//	"<filename>: <HEX>"          (BSD style, occasionally seen)
//
// It returns the first whitespace-delimited token that is valid hex of the
// expected length, lowercased. An empty or malformed body is an error so the
// caller can fall back to a weaker algorithm or fail closed rather than treat a
// garbage sidecar as a passing check.
func parseChecksumValue(body []byte, alg checksumAlg) (string, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "", fmt.Errorf("maven: empty %s checksum sidecar", alg.name)
	}
	for _, tok := range strings.Fields(text) {
		tok = strings.TrimSuffix(tok, ":")
		if len(tok) != alg.hexLen {
			continue
		}
		if !isHex(tok) {
			continue
		}
		return strings.ToLower(tok), nil
	}
	return "", fmt.Errorf("maven: %s checksum sidecar carries no valid %d-char hex digest", alg.name, alg.hexLen)
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

// ChecksumMismatchError reports that a fetched artifact did not hash to the
// digest its upstream checksum sidecar declared. It is returned by a
// verifyingReader at end-of-stream (and by verifyBytes for buffered artifacts)
// so the cache rejects the write — the partial blob is never committed — and the
// proxy surfaces the integrity failure instead of serving poisoned content.
type ChecksumMismatchError struct {
	Algorithm string
	Expected  string
	Actual    string
	URL       string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("maven: %s checksum mismatch for %s: expected %s, got %s",
		e.Algorithm, e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps an artifact body and verifies, at end-of-stream, that
// the bytes read hash to the expected checksum. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes. It is
// the streaming counterpart to verifyBytes (used for large artifacts such as
// .jar/.war that must not be buffered).
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
		hash:     expected.alg.newHash(),
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
				Algorithm: v.expected.alg.name,
				Expected:  v.expected.alg.name + ":" + v.expected.hex,
				Actual:    v.expected.alg.name + ":" + got,
				URL:       v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }

// verifyBytes checks an already-buffered artifact (e.g. a POM, which is small
// and is parsed in memory) against the expected checksum, returning a
// *ChecksumMismatchError on failure.
func verifyBytes(data []byte, expected expectedChecksum, url string) error {
	h := expected.alg.newHash()
	_, _ = h.Write(data)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if !strings.EqualFold(got, expected.hex) {
		return &ChecksumMismatchError{
			Algorithm: expected.alg.name,
			Expected:  expected.alg.name + ":" + expected.hex,
			Actual:    expected.alg.name + ":" + got,
			URL:       url,
		}
	}
	return nil
}
