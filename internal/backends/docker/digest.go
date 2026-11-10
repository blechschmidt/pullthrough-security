package docker

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strings"
)

// Digest is an OCI content digest of the form "<algorithm>:<hex>", e.g.
// "sha256:6b...". Digests are the content-addressable identity of blobs and
// (when referenced by digest) manifests; verifying them is the cornerstone of a
// supply-chain-secure registry cache, so we never serve or store bytes that do
// not hash to the digest the client asked for.
type Digest struct {
	Algorithm string // "sha256" or "sha512"
	Hex       string // lowercase hex encoding of the digest value
}

// digestPattern matches the registry digest grammar for the algorithms we
// support. The hex length is enforced per-algorithm in ParseDigest.
var digestPattern = regexp.MustCompile(`^(sha256|sha512):([0-9a-f]+)$`)

// ParseDigest validates s and returns the parsed Digest. It rejects unknown
// algorithms, non-lowercase hex, and incorrect digest lengths.
func ParseDigest(s string) (Digest, error) {
	m := digestPattern.FindStringSubmatch(s)
	if m == nil {
		return Digest{}, fmt.Errorf("docker: invalid digest %q", s)
	}
	algo, hexVal := m[1], m[2]
	want := hexLenFor(algo)
	if len(hexVal) != want {
		return Digest{}, fmt.Errorf("docker: digest %q has %d hex chars, want %d for %s", s, len(hexVal), want, algo)
	}
	return Digest{Algorithm: algo, Hex: hexVal}, nil
}

// IsDigest reports whether s is a well-formed, supported content digest. It is
// used to distinguish a manifest reference that is a digest (immutable,
// cacheable) from one that is a tag (mutable).
func IsDigest(s string) bool {
	_, err := ParseDigest(s)
	return err == nil
}

// String renders the digest in canonical "<algorithm>:<hex>" form.
func (d Digest) String() string { return d.Algorithm + ":" + d.Hex }

// newHash returns a fresh hash.Hash for the digest's algorithm.
func (d Digest) newHash() hash.Hash {
	switch d.Algorithm {
	case "sha512":
		return sha512.New()
	default:
		return sha256.New()
	}
}

func hexLenFor(algo string) int {
	switch algo {
	case "sha512":
		return 128
	default: // sha256
		return 64
	}
}

// DigestMismatchError reports that fetched content did not hash to the expected
// digest. It is returned by a verifyingReader at end-of-stream so the cache
// rejects the write (the partial blob is never committed) and the proxy surfaces
// the integrity failure rather than serving poisoned content.
type DigestMismatchError struct {
	Expected string
	Actual   string
}

func (e *DigestMismatchError) Error() string {
	return fmt.Sprintf("docker: content digest mismatch: expected %s, got %s", e.Expected, e.Actual)
}

// verifyingReader wraps an upstream body and verifies, at end-of-stream, that
// the bytes read hash to the expected digest. On mismatch it returns a
// *DigestMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected Digest
	verified bool
}

// newVerifyingReader wraps src so reads are checked against expected. The
// returned ReadCloser takes ownership of src and closes it on Close.
func newVerifyingReader(src io.ReadCloser, expected Digest) *verifyingReader {
	return &verifyingReader{
		src:      src,
		hash:     expected.newHash(),
		expected: expected,
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
		if !strings.EqualFold(got, v.expected.Hex) {
			return n, &DigestMismatchError{
				Expected: v.expected.String(),
				Actual:   v.expected.Algorithm + ":" + got,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
