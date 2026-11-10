package terraform

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	//lint:ignore SA1019 x/crypto/openpgp is frozen but remains the only in-tree
	// implementation of detached PGP verification; it is used here purely to
	// validate a provider's SHASUMS manifest against the GPG keys the registry
	// asserts for the provider, layered on top of the SHA-256 content chain as
	// defense in depth (mirroring the apt/yum Release-signature handling).
	"golang.org/x/crypto/openpgp"
)

// Terraform/OpenTofu providers publish a per-version SHA256SUMS manifest listing
// the SHA-256 of every release ZIP, and a detached OpenPGP signature
// (SHA256SUMS.sig) over that manifest signed by the provider's GPG key. The
// registry's download descriptor embeds the manifest URL, the signature URL, the
// expected per-ZIP SHA-256 ("shasum"), and the trusted GPG public keys. The
// proxy independently verifies, on a cache miss, that (a) the fetched ZIP hashes
// to the SHASUMS-declared digest and (b) the SHASUMS manifest carries a valid
// signature from one of the registry-asserted keys, before the bytes are cached
// or streamed. A digest mismatch aborts the store and the response; a present
// but invalid signature is a hard failure (it cannot be downgraded to unsigned).
// This is the cornerstone supply-chain guarantee for the IaC ecosystem.

// sha256HexLen is the length of a lowercase hex SHA-256 digest.
const sha256HexLen = 64

// signatureStatus classifies the outcome of verifying a SHASUMS manifest's
// detached GPG signature.
type signatureStatus string

const (
	// sigVerified: the manifest carried a valid signature from a registry-asserted key.
	sigVerified signatureStatus = "verified"
	// sigUnsigned: the registry provided no signature and/or no keys to verify against.
	sigUnsigned signatureStatus = "unsigned"
	// sigInvalid: a signature and keys were present but verification failed (refused).
	sigInvalid signatureStatus = "invalid"
)

// ChecksumMismatchError reports that a fetched provider ZIP did not hash to the
// SHA-256 its signed SHASUMS manifest declared. It is returned by a
// verifyingReader at end-of-stream so the cache rejects the write — the partial
// blob is never committed — and the proxy surfaces the integrity failure instead
// of serving poisoned content.
type ChecksumMismatchError struct {
	Expected string
	Actual   string
	URL      string
}

func (e *ChecksumMismatchError) Error() string {
	return fmt.Sprintf("terraform: sha256 checksum mismatch for %s: expected %s, got %s",
		e.URL, e.Expected, e.Actual)
}

// SignatureError reports that a provider's SHASUMS manifest carried a signature
// that did not verify against the registry-asserted GPG keys. It is a hard
// failure: a tampered or forged signature must not be downgraded to "unsigned".
type SignatureError struct {
	URL    string
	Reason string
}

func (e *SignatureError) Error() string {
	return fmt.Sprintf("terraform: SHASUMS signature verification failed for %s: %s", e.URL, e.Reason)
}

// expectedChecksum carries the lowercase-hex SHA-256 the SHASUMS manifest
// declares for a provider ZIP.
type expectedChecksum struct {
	hex string
}

// parseSHASUMS parses a SHA256SUMS manifest (coreutils `sha256sum` format:
// "<64-hex>␠␠<filename>" per line) into a filename→hex map. Lines that are blank
// or malformed are skipped; a non-empty manifest with no usable line yields an
// empty map (the caller fails closed when the target filename is absent).
func parseSHASUMS(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hexsum := strings.ToLower(fields[0])
		if len(hexsum) != sha256HexLen || !isHex(hexsum) {
			continue
		}
		// The filename is the final field; coreutils prefixes a binary-mode marker
		// ("*") which is stripped. Names never contain spaces in published manifests.
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == "" {
			continue
		}
		out[name] = hexsum
	}
	return out
}

// verifySHASUMSSignature verifies a detached OpenPGP signature (binary or
// armored) over the SHASUMS bytes against the provided ASCII-armored public
// keys. It returns sigUnsigned when no signature or no keys were supplied,
// sigVerified on a good signature, and a *SignatureError when a signature and
// keys were present but none validated.
func verifySHASUMSSignature(shasums, sig []byte, armoredKeys []string, url string) (signatureStatus, error) {
	if len(bytes.TrimSpace(sig)) == 0 || len(armoredKeys) == 0 {
		return sigUnsigned, nil
	}
	var entities openpgp.EntityList
	for _, armored := range armoredKeys {
		if strings.TrimSpace(armored) == "" {
			continue
		}
		el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armored))
		if err != nil {
			continue
		}
		entities = append(entities, el...)
	}
	if len(entities) == 0 {
		// Keys were advertised but none parsed: treat as unsigned rather than a hard
		// failure, since the registry — not the artifact — supplied a bad key.
		return sigUnsigned, nil
	}
	// Accept both the binary and armored detached-signature encodings.
	if _, err := openpgp.CheckDetachedSignature(entities, bytes.NewReader(shasums), bytes.NewReader(sig)); err == nil {
		return sigVerified, nil
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(entities, bytes.NewReader(shasums), bytes.NewReader(sig)); err == nil {
		return sigVerified, nil
	}
	return sigInvalid, &SignatureError{URL: url, Reason: "no registry-asserted key produced a valid signature"}
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

// normalizeHex returns the lowercase form of a candidate SHA-256 hex digest, or
// ok=false when it is not a well-formed 64-char hex string, so a garbage value is
// never treated as a passing check.
func normalizeHex(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) != sha256HexLen || !isHex(s) {
		return "", false
	}
	return s, true
}

// verifyingReader wraps a provider ZIP body and verifies, at end-of-stream, that
// the bytes read hash to the expected SHA-256. On mismatch it returns a
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
	if errors.Is(err, io.EOF) && !v.verified {
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
