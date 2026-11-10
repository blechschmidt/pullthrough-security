package apt

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strings"
	"sync"
)

// An APT repository binds its artifacts into a single SHA-256 chain rooted at the
// (GPG-signed) Release file: Release publishes the SHA-256 of every Packages
// index, and each Packages index publishes the SHA-256 of every .deb it lists.
// The backend verifies a fetched .deb against the digest its Packages stanza
// declared before the bytes are cached or streamed to the client, mirroring the
// checksum verification the Maven and Helm backends perform. A mismatch aborts
// the cache write and the response, so a tampered or corrupt mirror can neither
// poison the cache nor reach a client.
//
// The pool layout decouples a .deb's URL ("/pool/...") from the Packages index
// that references it, and a .deb is reachable from many indices, so the expected
// digest cannot be recovered on demand from the .deb path alone (unlike a
// RubyGems /info or a Helm index lookup). Instead the backend records every
// (pool-path -> SHA-256) it sees while proxying and parsing Packages indices into
// a bounded in-memory store, and consults it when the corresponding .deb is
// fetched. An APT client always fetches the indices before the packages they
// describe, so by the time a .deb is requested its digest is known.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

// expectedChecksum carries the SHA-256 hex digest expected for an artifact.
type expectedChecksum struct {
	hex string
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

// normalizeSHA256 lowercases and validates a SHA-256 hex string, returning
// ok=false for any malformed value so a garbage digest is never treated as a
// passing check.
func normalizeSHA256(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) != sha256HexLen || !isHex(s) {
		return "", false
	}
	return s, true
}

// digestStore is a bounded, concurrency-safe map from a repository-root-relative
// pool path to the SHA-256 digest the Packages index declared for it. It is
// populated as the backend parses Packages indices and consulted when a .deb is
// fetched. When the store reaches its capacity it is cleared wholesale rather
// than evicting per-entry: APT indices are republished atomically, so a full
// reset simply forces the next index fetch to repopulate, which an APT client
// performs anyway before pulling further packages.
type digestStore struct {
	mu      sync.Mutex
	max     int
	entries map[string]string
}

// newDigestStore returns a store bounded to max entries (a non-positive max
// applies a sane default).
func newDigestStore(max int) *digestStore {
	if max <= 0 {
		max = defaultDigestStoreMax
	}
	return &digestStore{max: max, entries: make(map[string]string)}
}

// defaultDigestStoreMax bounds the pool-path digest store. A large suite
// (e.g. Debian main) publishes on the order of 10^5 packages; this cap holds a
// couple of those while bounding memory to a few MiB of short strings.
const defaultDigestStoreMax = 1 << 18 // 262144 entries

// put records the digest for a pool path, normalizing the key to be
// leading-slash-insensitive so a Packages "Filename" and a request path match.
func (s *digestStore) put(poolPath, hex string) {
	hex, ok := normalizeSHA256(hex)
	if !ok {
		return
	}
	key := strings.TrimLeft(poolPath, "/")
	if key == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= s.max {
		s.entries = make(map[string]string)
	}
	s.entries[key] = hex
}

// get returns the recorded digest for a pool path, if known.
func (s *digestStore) get(poolPath string) (expectedChecksum, bool) {
	key := strings.TrimLeft(poolPath, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	hex, ok := s.entries[key]
	if !ok {
		return expectedChecksum{}, false
	}
	return expectedChecksum{hex: hex}, true
}

// len reports the number of recorded digests (used in diagnostics/tests).
func (s *digestStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// ChecksumMismatchError reports that a fetched .deb did not hash to the SHA-256
// digest its Packages index declared. It is returned by a verifyingReader at
// end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type ChecksumMismatchError struct {
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("apt: sha256 checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps a .deb body and verifies, at end-of-stream, that the
// bytes read hash to the expected SHA-256. On mismatch it returns a
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

// verifyBytes checks an already-buffered artifact against the expected checksum,
// returning a *ChecksumMismatchError on failure.
func verifyBytes(data []byte, expected expectedChecksum, url string) error {
	h := sha256.New()
	_, _ = h.Write(data)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if !strings.EqualFold(got, expected.hex) {
		return &ChecksumMismatchError{
			Expected: "sha256:" + expected.hex,
			Actual:   "sha256:" + got,
			URL:      url,
		}
	}
	return nil
}
