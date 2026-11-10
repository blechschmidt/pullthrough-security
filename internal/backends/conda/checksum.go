package conda

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Conda's integrity model is the per-subdir repodata.json, which records both a
// strong SHA-256 and a legacy MD5 digest for every package archive. The proxy
// fetches that index on a cache miss and verifies each fetched package against
// it before the bytes are cached or streamed to the client, so a tampered or
// corrupt mirror can neither poison the cache nor reach a client. SHA-256 is
// preferred whenever the index records it; MD5 is only used as a fallback for
// older indices that omit SHA-256. This mirrors the checksum verification the
// Maven backend performs against its .sha256 sidecars and the digest
// verification the Docker/OCI backend performs on content-addressed blobs.

// expectedChecksum pairs a parsed expected digest with the filename and
// algorithm it was recorded for.
type expectedChecksum struct {
	filename string
	algo     string // "sha256" (preferred) or "md5"
	hex      string
}

// newHash returns a fresh hasher for the expected checksum's algorithm.
func (e expectedChecksum) newHash() hash.Hash {
	if e.algo == "md5" {
		return md5.New()
	}
	return sha256.New()
}

// chooseChecksum prefers the strong SHA-256 digest and falls back to MD5,
// returning ok=false when neither is available.
func chooseChecksum(filename, sha256hex, md5hex string) (expectedChecksum, bool) {
	if sha256hex != "" {
		return expectedChecksum{filename: filename, algo: "sha256", hex: sha256hex}, true
	}
	if md5hex != "" {
		return expectedChecksum{filename: filename, algo: "md5", hex: md5hex}, true
	}
	return expectedChecksum{}, false
}

// ChecksumMismatchError reports that a fetched package did not hash to the digest
// its subdir's repodata.json declared. It is returned by a verifyingReader at
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
	return fmt.Sprintf("conda: checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// verifyingReader wraps a package body and verifies, at end-of-stream, that the
// bytes read hash to the expected digest. On mismatch it returns a
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
		hash:     expected.newHash(),
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
				Filename: v.expected.filename,
				Expected: v.expected.algo + ":" + v.expected.hex,
				Actual:   v.expected.algo + ":" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
