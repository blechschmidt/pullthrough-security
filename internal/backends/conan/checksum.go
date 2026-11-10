package conan

import (
	"crypto/md5"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// Conan's integrity model is the per-revision conanmanifest.txt, which records
// an MD5 digest for every file of the recipe or package revision in its unpacked
// form. The proxy fetches that manifest on a cache miss and verifies each
// fetched content file against it before the bytes are cached or streamed to the
// client, so a tampered or corrupt transfer can neither poison the cache nor
// reach a client. This mirrors the checksum verification the Maven backend
// performs against its .sha256/.sha1 sidecars and the digest verification the
// Docker/OCI backend performs on content-addressed blobs.
//
// "Unpacked form" matters: a real manifest names conanfile.py and conaninfo.txt
// directly, but for conan_export.tgz, conan_sources.tgz, and conan_package.tgz
// it names the files inside them, never the archive. The archives are therefore
// verified against the MD5 the upstream declares for the transferred file itself
// — the X-Checksum-Md5 response header every Artifactory-based remote
// (ConanCenter included) sends (see headerMD5). Like the manifest, that header
// is served by the same upstream as the bytes, so both detect corruption and
// truncation in transit or at rest upstream, not a compromised upstream.
//
// MD5 is cryptographically broken for collision resistance; it is used here
// because it is the only digest Conan's manifest format carries. It still
// detects accidental corruption and non-adversarial tampering, and the
// recipe/package revision that addresses the file is itself a content hash of
// these same files, so the cache key provides the content-addressable guarantee
// that the weak digest cannot.

// checksumMD5Header is the per-file MD5 digest Artifactory-based remotes send
// with every file download (alongside X-Checksum-Sha1 and X-Checksum-Sha256).
const checksumMD5Header = "X-Checksum-Md5"

// headerMD5 returns the lowercase hex MD5 the upstream declared for the
// transferred file in its X-Checksum-Md5 response header. A missing or
// malformed value yields ok=false, so it is never mistaken for a digest.
func headerMD5(h http.Header) (string, bool) {
	v := strings.TrimSpace(h.Get(checksumMD5Header))
	if len(v) != md5HexLen || !isHex(v) {
		return "", false
	}
	return strings.ToLower(v), true
}

// expectedChecksum pairs a parsed expected MD5 hex value with the filename it
// was recorded for.
type expectedChecksum struct {
	filename string
	md5hex   string
}

// newMD5 returns a fresh MD5 hasher. It exists so the hashing construction is
// named in one place alongside the rationale above.
func newMD5() hash.Hash { return md5.New() }

// ChecksumMismatchError reports that a fetched file did not hash to the MD5
// digest the upstream declared for it (in the revision's conanmanifest.txt or,
// for a file the manifest does not list, X-Checksum-Md5). It is returned by a
// verifyingReader at end-of-stream (and by verifyBytes for buffered content) so
// the cache rejects the write — the partial blob is never committed — and the
// proxy surfaces the integrity failure instead of serving poisoned content.
type ChecksumMismatchError struct {
	Filename string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("conan: md5 checksum mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Filename, e.Expected, e.Actual)
}

// verifyingReader wraps a file body and verifies, at end-of-stream, that the
// bytes read hash to the expected MD5. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes. It is
// the streaming counterpart to verifyBytes (used for large files such as
// conan_package.tgz that must not be buffered).
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
		hash:     newMD5(),
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
		ok := strings.EqualFold(got, v.expected.md5hex)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			return n, &ChecksumMismatchError{
				Filename: v.expected.filename,
				Expected: "md5:" + v.expected.md5hex,
				Actual:   "md5:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }

// verifyBytes checks an already-buffered file (e.g. conaninfo.txt, which is
// small and parsed in memory) against the expected MD5, returning a
// *ChecksumMismatchError on failure.
func verifyBytes(data []byte, expected expectedChecksum, url string) error {
	h := newMD5()
	_, _ = h.Write(data)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if !strings.EqualFold(got, expected.md5hex) {
		return &ChecksumMismatchError{
			Filename: expected.filename,
			Expected: "md5:" + expected.md5hex,
			Actual:   "md5:" + got,
			URL:      url,
		}
	}
	return nil
}
