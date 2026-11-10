package cachefed

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"hash"
	"io"
	"strings"
)

// digestVerifier wraps a peer response body with a streaming content-digest
// check. The hash is computed incrementally as the body is read, and on EOF the
// running digest is compared (in constant time) against the expected value; a
// mismatch is substituted for the EOF so the downstream cache fill aborts before
// any tampered byte is committed. This is the "never trust peer bytes blindly"
// guarantee, and it mirrors the gateway's own fill-time digest verifier so peer
// bytes are held to exactly the same fixity standard as upstream bytes.
type digestVerifier struct {
	inner    io.ReadCloser
	hasher   hash.Hash
	expect   []byte // decoded expected digest bytes
	finished bool
	onResult func(ok bool) // called exactly once at stream end (success or mismatch)
	onClose  func()        // called from Close (e.g. to release the per-peer context)
}

// newDigestVerifier returns a verifying read-closer for inner, or (nil, false)
// when the expected digest is empty, malformed, or uses an unsupported
// algorithm — in which case the caller must not trust the peer (it cannot
// re-verify). Supported algorithms are sha256 and sha512, matching the cache's
// content-addressing.
func newDigestVerifier(inner io.ReadCloser, expectDigest string, onResult func(ok bool), onClose func()) (*digestVerifier, bool) {
	algo, hexsum, ok := splitDigest(expectDigest)
	if !ok {
		return nil, false
	}
	var h hash.Hash
	switch algo {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return nil, false
	}
	want, err := hex.DecodeString(hexsum)
	if err != nil || len(want) != h.Size() {
		return nil, false
	}
	return &digestVerifier{
		inner:    inner,
		hasher:   h,
		expect:   want,
		onResult: onResult,
		onClose:  onClose,
	}, true
}

// Read copies from the inner body, folding the bytes into the hash. On EOF it
// verifies the accumulated digest and, on mismatch, returns ErrDigestMismatch
// instead of io.EOF.
func (v *digestVerifier) Read(p []byte) (int, error) {
	n, err := v.inner.Read(p)
	if n > 0 {
		// A hash.Hash never returns an error from Write.
		_, _ = v.hasher.Write(p[:n])
	}
	if err == io.EOF {
		if !v.finished {
			v.finished = true
			if subtle.ConstantTimeCompare(v.hasher.Sum(nil), v.expect) == 1 {
				if v.onResult != nil {
					v.onResult(true)
				}
			} else {
				if v.onResult != nil {
					v.onResult(false)
				}
				return n, ErrDigestMismatch
			}
		}
		return n, io.EOF
	}
	if err != nil && !v.finished {
		// A transport error mid-stream is a peer failure, not a verified success.
		v.finished = true
		if v.onResult != nil {
			v.onResult(false)
		}
	}
	return n, err
}

// Close closes the inner body and releases any attached resources. If the stream
// was abandoned before EOF (e.g. the caller gave up), it is recorded as a
// failure so a peer that stalls mid-body is penalized rather than silently
// forgotten.
func (v *digestVerifier) Close() error {
	if !v.finished {
		v.finished = true
		if v.onResult != nil {
			v.onResult(false)
		}
	}
	err := v.inner.Close()
	if v.onClose != nil {
		v.onClose()
	}
	return err
}

// splitDigest parses an "algo:hexdigest" string into a lowercased algorithm and
// hex payload. ok is false when the value is empty or has no ":" separator.
func splitDigest(d string) (algo, hexsum string, ok bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return "", "", false
	}
	algo, hexsum, found := strings.Cut(d, ":")
	if !found || algo == "" || hexsum == "" {
		return "", "", false
	}
	return algo, hexsum, true
}

// looksLikeDigest reports whether s is a well-formed, supported content digest
// of the "algo:hexdigest" form. It is used to derive an expected digest from a
// content-addressed cache key when the caller supplied none.
func looksLikeDigest(s string) bool {
	algo, hexsum, ok := splitDigest(s)
	if !ok {
		return false
	}
	var size int
	switch algo {
	case "sha256":
		size = sha256.Size
	case "sha512":
		size = sha512.Size
	default:
		return false
	}
	if len(hexsum) != size*2 {
		return false
	}
	_, err := hex.DecodeString(hexsum)
	return err == nil
}
