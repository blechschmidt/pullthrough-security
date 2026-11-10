package bazel

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Bazel's integrity model for a registry module is the Subresource-Integrity
// (SRI) string recorded in source.json's "integrity" field — "<algo>-<base64>",
// where algo is sha256 (by far the most common for Bazel modules), sha384, or
// sha512 and the base64 payload is the standard-encoded raw digest of the
// referenced source archive. Bazel itself verifies a downloaded archive against
// this value; the proxy performs the same verification on the pull path, before
// the bytes are cached or streamed to the client, so a tampered or corrupt
// mirror can neither poison the cache nor reach a client. This mirrors the
// checksum verification the Conda, CRAN, and Hex backends perform against their
// own ecosystems' integrity records.

// sri algorithm → raw digest length (bytes).
var sriAlgoLen = map[string]int{
	"sha256": sha256.Size,
	"sha384": sha512.Size384,
	"sha512": sha512.Size,
}

// sriStrength orders algorithms so the strongest is preferred when an integrity
// string carries several space-separated candidates.
var sriStrength = map[string]int{
	"sha256": 1,
	"sha384": 2,
	"sha512": 3,
}

// expectedIntegrity is a parsed, validated SRI digest for the source archive.
type expectedIntegrity struct {
	algo string // "sha256" | "sha384" | "sha512"
	raw  []byte // decoded expected digest bytes
	sri  string // the canonical "<algo>-<base64>" form, for diagnostics
}

// newHash returns a fresh hasher for the integrity's algorithm.
func (e expectedIntegrity) newHash() hash.Hash {
	switch e.algo {
	case "sha512":
		return sha512.New()
	case "sha384":
		return sha512.New384()
	default:
		return sha256.New()
	}
}

// parseIntegrity parses an SRI integrity string into the strongest well-formed
// digest it carries. An SRI value may list several whitespace-separated
// candidates ("sha256-... sha512-..."); the strongest decodable one wins. It
// returns ok=false when the string is empty or no candidate is a recognized
// algorithm with a correctly sized base64 digest, so a malformed or absent
// integrity is treated as "no integrity" (the archive is then served unverified)
// rather than silently trusted.
func parseIntegrity(s string) (expectedIntegrity, bool) {
	best := expectedIntegrity{}
	bestStrength := 0
	for _, cand := range strings.Fields(s) {
		dash := strings.IndexByte(cand, '-')
		if dash <= 0 {
			continue
		}
		algo := strings.ToLower(cand[:dash])
		wantLen, known := sriAlgoLen[algo]
		if !known {
			continue
		}
		b64 := cand[dash+1:]
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) != wantLen {
			continue
		}
		if sriStrength[algo] > bestStrength {
			best = expectedIntegrity{algo: algo, raw: raw, sri: algo + "-" + base64.StdEncoding.EncodeToString(raw)}
			bestStrength = sriStrength[algo]
		}
	}
	if bestStrength == 0 {
		return expectedIntegrity{}, false
	}
	return best, true
}

// IntegrityMismatchError reports that a fetched source archive did not hash to
// the SRI integrity its source.json declared. It is returned by a verifyingReader
// at end-of-stream so the cache rejects the write — the partial blob is never
// committed — and the proxy surfaces the integrity failure instead of serving
// poisoned content.
type IntegrityMismatchError struct {
	Module   string
	Version  string
	Expected string // expected SRI
	Actual   string // computed SRI
	URL      string
}

func (e *IntegrityMismatchError) Error() string {
	return fmt.Sprintf("bazel: integrity mismatch for %s@%s archive %s: expected %s, got %s",
		e.Module, e.Version, e.URL, e.Expected, e.Actual)
}

// verifyingReader wraps a source-archive body and verifies, at end-of-stream,
// that the bytes read hash to the expected SRI digest. On mismatch it returns an
// *IntegrityMismatchError in place of io.EOF, which propagates through io.Copy so
// the caching layer aborts the store and never commits unverified bytes.
type verifyingReader struct {
	src      io.ReadCloser
	hash     hash.Hash
	expected expectedIntegrity
	module   string
	version  string
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
func newVerifyingReader(src io.ReadCloser, expected expectedIntegrity, module, version, url string, onResult func(ok bool)) *verifyingReader {
	return &verifyingReader{
		src:      src,
		hash:     expected.newHash(),
		expected: expected,
		module:   module,
		version:  version,
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
		sum := v.hash.Sum(nil)
		ok := string(sum) == string(v.expected.raw)
		if v.onResult != nil {
			v.onResult(ok)
		}
		if !ok {
			got := v.expected.algo + "-" + base64.StdEncoding.EncodeToString(sum)
			return n, &IntegrityMismatchError{
				Module:   v.module,
				Version:  v.version,
				Expected: v.expected.sri,
				Actual:   got,
				URL:      v.url,
			}
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return v.src.Close() }
