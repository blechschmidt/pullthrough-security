package nix

import "fmt"

// Nix addresses content by a base-32 encoding of a hash digest that is its own,
// not RFC 4648: the alphabet omits the vowels "e", "o", "u" and the letter "t"
// to avoid accidental rude words and transcription ambiguity, and the digits are
// consumed least-significant-first. Every narinfo FileHash/NarHash and every NAR
// URL filename is written in this encoding, so the backend must speak it to
// verify the content-addressable storage-hash invariant.
//
// This is the same algorithm Nix implements in libutil (hash.cc); it is
// reproduced here (not pulled from a dependency) so the proxy stays
// self-contained, exactly as the Julia backend reproduces git's tree hash.

// nixBase32Alphabet is Nix's base-32 digit set (see libutil/hash.cc).
const nixBase32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

// sha256Bytes is the digest length (in bytes) of a SHA-256 hash.
const sha256Bytes = 32

// nixBase32Len returns the number of base-32 characters that encode hashSize
// bytes. For a 32-byte SHA-256 digest this is 52.
func nixBase32Len(hashSize int) int {
	if hashSize <= 0 {
		return 0
	}
	return (hashSize*8-1)/5 + 1
}

// nixBase32Encode renders raw digest bytes in Nix's base-32 encoding.
func nixBase32Encode(hash []byte) string {
	n := nixBase32Len(len(hash))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		// Characters are emitted most-significant-first, but each character's
		// value is read least-significant-first from the digest, so the
		// character at output index i corresponds to source position (n-1-i).
		pos := n - 1 - i
		b := pos * 5
		byteIdx := b / 8
		bitIdx := b % 8
		var c uint16 = uint16(hash[byteIdx]) >> uint(bitIdx)
		if byteIdx+1 < len(hash) {
			c |= uint16(hash[byteIdx+1]) << uint(8-bitIdx)
		}
		out[i] = nixBase32Alphabet[c&0x1f]
	}
	return string(out)
}

// nixBase32Decode decodes a Nix base-32 string of the length that encodes
// hashSize bytes into those raw bytes. It rejects any character outside the
// alphabet and any non-zero padding bits in the final character, so a malformed
// hash can never silently decode to a passing comparison.
func nixBase32Decode(s string, hashSize int) ([]byte, error) {
	if len(s) != nixBase32Len(hashSize) {
		return nil, fmt.Errorf("nix: base32 string %q has wrong length for a %d-byte hash", s, hashSize)
	}
	out := make([]byte, hashSize)
	for n := 0; n < len(s); n++ {
		c := s[len(s)-1-n]
		digit := indexInAlphabet(c)
		if digit < 0 {
			return nil, fmt.Errorf("nix: invalid base32 character %q", string(c))
		}
		b := n * 5
		byteIdx := b / 8
		bitIdx := b % 8
		out[byteIdx] |= byte(digit << uint(bitIdx))
		carry := byte(digit >> uint(8-bitIdx))
		if byteIdx+1 < hashSize {
			out[byteIdx+1] |= carry
		} else if carry != 0 {
			return nil, fmt.Errorf("nix: base32 string %q has non-zero padding bits", s)
		}
	}
	return out, nil
}

// indexInAlphabet returns the base-32 value of c, or -1 if c is not a Nix
// base-32 digit.
func indexInAlphabet(c byte) int {
	for i := 0; i < len(nixBase32Alphabet); i++ {
		if nixBase32Alphabet[i] == c {
			return i
		}
	}
	return -1
}

// isNixBase32 reports whether s is non-empty and composed solely of Nix base-32
// digits.
func isNixBase32(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if indexInAlphabet(s[i]) < 0 {
			return false
		}
	}
	return true
}
