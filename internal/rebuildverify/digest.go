package rebuildverify

import "strings"

// Digest is a parsed, normalized content digest: a lowercased algorithm and a
// lowercased hex value. It is the comparison unit for reproducible-build
// verification, where the rebuilt artifact's digest is compared against the
// upstream-served artifact's digest.
//
// Digests reach this code from two untrusted-ish directions — the upstream
// registry's content-address string and a pluggable builder's output — in a
// variety of spellings ("sha256:ABC…", raw hex, with surrounding whitespace or
// quotes, multihash-prefixed). parseDigest normalizes all of them so the
// comparison is robust, and it is exercised by a fuzz target (fuzz_test.go) to
// guarantee it never panics on hostile input.
type Digest struct {
	Algo string
	Hex  string
}

// String renders the canonical "algo:hex" form.
func (d Digest) String() string {
	if d.Hex == "" {
		return ""
	}
	return d.Algo + ":" + d.Hex
}

// Short renders a truncated "algo:hex12…" form for messages.
func (d Digest) Short() string {
	if d.Hex == "" {
		return "(none)"
	}
	hex := d.Hex
	if len(hex) > 12 {
		hex = hex[:12] + "…"
	}
	return d.Algo + ":" + hex
}

// Equal reports whether two digests are the same non-empty algorithm+value.
func (d Digest) Equal(o Digest) bool {
	return d.Hex != "" && d.Algo == o.Algo && d.Hex == o.Hex
}

// expectedHexLen returns the hex-string length for a known algorithm.
func expectedHexLen(algo string) (int, bool) {
	switch algo {
	case "md5":
		return 32, true
	case "sha1":
		return 40, true
	case "sha256":
		return 64, true
	case "sha384":
		return 96, true
	case "sha512":
		return 128, true
	default:
		return 0, false
	}
}

// parseDigest normalizes a digest string into a Digest, returning ok=false when
// the value cannot be interpreted as a digest. It is total (never panics) for
// any input: surrounding whitespace and quotes are stripped, an optional
// "algo:" (or multihash "algo:") prefix is honored (defaulting to sha256), the
// hex is lowercased and validated, and a known algorithm's hex length is
// enforced. An unknown algorithm requires a non-empty, even-length hex string.
func parseDigest(s string) (Digest, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'")
	s = strings.TrimSpace(s)
	if s == "" {
		return Digest{}, false
	}

	algo := "sha256"
	hex := s
	if i := strings.IndexByte(s, ':'); i >= 0 {
		algo = strings.ToLower(strings.TrimSpace(s[:i]))
		hex = strings.TrimSpace(s[i+1:])
		if algo == "" {
			algo = "sha256"
		}
	}
	hex = strings.ToLower(hex)
	if !isHex(hex) {
		return Digest{}, false
	}
	if n, known := expectedHexLen(algo); known {
		if len(hex) != n {
			return Digest{}, false
		}
	} else {
		// Unknown algorithm: accept a non-empty, even-length hex string so a custom
		// digest scheme still compares, but reject obvious garbage.
		if len(hex) == 0 || len(hex)%2 != 0 {
			return Digest{}, false
		}
	}
	return Digest{Algo: algo, Hex: hex}, true
}

// NormalizeDigest parses s and returns its canonical "algo:hex" string, or
// ok=false when s is not a digest. It is the exported entry point used to
// normalize a builder's output before comparison.
func NormalizeDigest(s string) (string, bool) {
	d, ok := parseDigest(s)
	if !ok {
		return "", false
	}
	return d.String(), true
}

// isHex reports whether s is a non-empty string of hex digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
