package huggingface

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"
)

// Hugging Face stores large weight files in Git LFS. On the resolve endpoint the
// Hub advertises the true content digest of an LFS object out-of-band via the
// X-Linked-Etag response header (the object's SHA-256), independent of the ETag
// of the pointer/redirect itself, and serves the bytes from a CDN (the redirect
// the HTTP client follows transparently). The backend verifies the delivered
// bytes against that SHA-256 before they are cached or streamed to a client, so a
// tampered or corrupt mirror/CDN can neither poison the cache nor reach a client.
// This mirrors the per-file checksum verification the Conan, Maven, Swift, and
// Terraform backends perform.
//
// A resolve request that is NOT followed through LFS (or a misconfigured mirror)
// can return the small git-lfs pointer text file in place of the object. The
// backend recognizes that pointer format so the pointer's declared oid/size are
// surfaced as metadata and the tiny text blob is never mistaken by the ML
// weight-scanning gate for a real (pickle) weight file.

// pointerPrefix is the canonical first line of a git-lfs pointer file.
const pointerPrefix = "version https://git-lfs.github.com/spec/v1"

// maxPointerBytes bounds how much of a body is inspected for the pointer format;
// a real pointer is a few hundred bytes.
const maxPointerBytes = 1024

// lfsPointer is a parsed git-lfs pointer file.
type lfsPointer struct {
	oid  string // hex SHA-256 of the real object
	size int64
}

// parsePointer recognizes a git-lfs pointer file and extracts its SHA-256 oid and
// size. It returns ok=false for any body that is not a well-formed pointer (the
// common case on the resolve path, where real content is returned).
func parsePointer(body []byte) (lfsPointer, bool) {
	if len(body) == 0 || len(body) > maxPointerBytes {
		return lfsPointer{}, false
	}
	text := string(body)
	if !strings.HasPrefix(text, pointerPrefix) {
		return lfsPointer{}, false
	}
	var p lfsPointer
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "oid":
			// "sha256:<hex>"
			if v := strings.TrimPrefix(fields[1], "sha256:"); v != fields[1] {
				p.oid = strings.ToLower(v)
			}
		case "size":
			if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil && n >= 0 {
				p.size = n
			}
		}
	}
	if !isSHA256Hex(p.oid) {
		return lfsPointer{}, false
	}
	return p, true
}

// normalizeLinkedETag extracts a bare lowercase SHA-256 hex digest from an
// X-Linked-Etag (or ETag) header value, stripping the W/ weak marker, surrounding
// quotes, and an optional "sha256:" prefix. It returns ok=false when the value is
// not a 64-hex SHA-256 (e.g. a Git blob SHA-1 on a non-LFS file), so verification
// is attempted only when a real content hash is available.
func normalizeLinkedETag(v string) (string, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "W/")
	v = strings.Trim(v, `"`)
	v = strings.TrimPrefix(v, "sha256:")
	v = strings.ToLower(v)
	if !isSHA256Hex(v) {
		return "", false
	}
	return v, true
}

// isSHA256Hex reports whether s is a 64-character lowercase hex string.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ChecksumMismatchError reports that a fetched blob did not hash to the SHA-256
// the resolve response advertised (X-Linked-Etag). It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure instead
// of serving poisoned content.
type ChecksumMismatchError struct {
	Path     string
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("huggingface: sha256 mismatch for %s (%s): expected %s, got %s",
		e.URL, e.Path, e.Expected, e.Actual)
}

// verifyingReader wraps a blob body and verifies, at end-of-stream, that the
// bytes read hash to the expected SHA-256. On mismatch it returns a
// *ChecksumMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected string // lowercase hex SHA-256
	path     string
	url      string
	verified bool
	// onResult, when non-nil, is invoked exactly once at end-of-stream with the
	// verification outcome, so the backend can count successes and mismatches
	// accurately (the result is only known once all bytes have been read).
	onResult func(ok bool)
}

// newVerifyingReader wraps src so reads are checked against the expected SHA-256.
// The returned ReadCloser takes ownership of src and closes it on Close.
func newVerifyingReader(src io.ReadCloser, expected, path, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:      src,
		hash:     sha256.New(),
		expected: expected,
		path:     path,
		url:      url,
		onResult: onResult,
	}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.src.Read(p)
	if n > 0 {
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
			return n, &ChecksumMismatchError{
				Path:     v.path,
				Expected: "sha256:" + v.expected,
				Actual:   "sha256:" + got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
