package yum

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
)

// An RPM/YUM repository binds its artifacts into a checksum chain rooted at the
// (optionally GPG-signed) repodata/repomd.xml: repomd.xml publishes the digest of
// every metadata file (primary.xml, filelists.xml, ...), and primary.xml
// publishes the digest of every .rpm. The backend verifies a fetched .rpm against
// the digest primary.xml declared before the bytes are cached or streamed to the
// client, mirroring the verification the Maven and Helm backends perform. A
// mismatch aborts the cache write and the response, so a tampered or corrupt
// mirror can neither poison the cache nor reach a client.
//
// Unlike a digest sidecar, repomd/primary declare the algorithm per entry
// ("sha256", "sha512", "sha1"/"sha"), so the backend carries the algorithm
// alongside the expected hex and hashes the artifact with the matching function.

// checksumAlg is one supported digest algorithm the metadata may declare, in
// descending order of strength.
type checksumAlg struct {
	name    string
	hexLen  int
	newHash func() hash.Hash
}

var (
	algSHA512 = checksumAlg{name: "sha512", hexLen: 128, newHash: sha512.New}
	algSHA256 = checksumAlg{name: "sha256", hexLen: 64, newHash: sha256.New}
	algSHA1   = checksumAlg{name: "sha1", hexLen: 40, newHash: sha1.New}
)

// algForType maps a repomd/primary checksum "type" attribute to a supported
// algorithm. The legacy "sha" alias denotes SHA-1. Unknown/weaker algorithms
// (md5) are rejected so a garbage or downgraded digest is never trusted.
func algForType(t string) (checksumAlg, bool) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "sha512":
		return algSHA512, true
	case "sha256":
		return algSHA256, true
	case "sha1", "sha":
		return algSHA1, true
	default:
		return checksumAlg{}, false
	}
}

// expectedChecksum pairs an algorithm with the expected lowercase hex digest.
type expectedChecksum struct {
	alg checksumAlg
	hex string
}

// parseChecksum validates a (type, value) checksum pair from the metadata,
// returning ok=false for an unsupported algorithm or a malformed hex value.
func parseChecksum(typ, value string) (expectedChecksum, bool) {
	alg, ok := algForType(typ)
	if !ok {
		return expectedChecksum{}, false
	}
	hex := strings.ToLower(strings.TrimSpace(value))
	if len(hex) != alg.hexLen || !isHex(hex) {
		return expectedChecksum{}, false
	}
	return expectedChecksum{alg: alg, hex: hex}, true
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

// digestStore is a bounded, concurrency-safe map from a repository-root-relative
// .rpm path to the checksum primary.xml declared for it. It is populated as the
// backend parses primary.xml documents and consulted when an .rpm is fetched.
// When full it is cleared wholesale (createrepo republishes metadata atomically,
// so the next primary.xml fetch repopulates it).
type digestStore struct {
	mu      sync.Mutex
	max     int
	entries map[string]expectedChecksum
}

const defaultDigestStoreMax = 1 << 18 // 262144 entries

func newDigestStore(max int) *digestStore {
	if max <= 0 {
		max = defaultDigestStoreMax
	}
	return &digestStore{max: max, entries: make(map[string]expectedChecksum)}
}

func (s *digestStore) put(rpmPath string, c expectedChecksum) {
	key := strings.TrimLeft(rpmPath, "/")
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= s.max {
		s.entries = make(map[string]expectedChecksum)
	}
	s.entries[key] = c
}

func (s *digestStore) get(rpmPath string) (expectedChecksum, bool) {
	key := strings.TrimLeft(rpmPath, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.entries[key]
	return c, ok
}

func (s *digestStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// ChecksumMismatchError reports that a fetched .rpm did not hash to the digest
// primary.xml declared. It is returned by a verifyingReader at end-of-stream so
// the cache rejects the write — the partial blob is never committed — and the
// proxy surfaces the integrity failure instead of serving poisoned content.
type ChecksumMismatchError struct {
	Algorithm string
	Expected  string
	Actual    string
	URL       string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("yum: %s checksum mismatch for %s: expected %s, got %s",
		e.Algorithm, e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps an .rpm body and verifies, at end-of-stream, that the
// bytes read hash to the expected digest. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedChecksum
	url      string
	verified bool
	onResult func(ok bool)
}

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

// verifyBytes checks an already-buffered artifact against the expected checksum,
// returning a *ChecksumMismatchError on failure.
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
