package userlinks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"strings"
)

// A token is the secret that names a personal link. It is what stands between
// "/u/" and "/v1/" in a personal URL, and what a client presents as a password
// where it can present one.
//
//	ptl1 abcdefghijklmnopqrstuvwxyz234567 aaaaaaa
//	──┬─ ───────────────┬──────────────── ───┬───
//	  │                 │                    └ checksum: CRC-32 of everything before it
//	  │                 └ 160 random bits, base32
//	  └ fixed prefix: "pull-through link", format version 1
//
// Three properties of the spelling are deliberate:
//
//   - It uses lower-case letters and the digits 2-7 only. A token must survive
//     being a URL path segment, a component of a container image reference
//     (which admits nothing else), a value in a dozen configuration file
//     formats, and being read aloud. There is nothing in it to escape, and no
//     two characters that look alike.
//   - It carries a checksum. A token that was truncated by a line break or
//     mistyped is recognised as not being one without a lookup — which also
//     means that junk in a request path costs nothing but a comparison.
//   - It starts with a fixed prefix. A secret scanner can be given the pattern
//     ptl1[a-z2-7]{39} and will find a token that was committed by mistake,
//     with the checksum to rule out false positives.
//
// The checksum is not a secret and adds no security: the 160 random bits do.
const (
	// TokenPrefix is what every token starts with.
	TokenPrefix = "ptl1"
	// tokenRandomBytes is how many random bytes a token carries.
	tokenRandomBytes = 20
	// tokenBodyLen is the length of those bytes in base32 (no padding).
	tokenBodyLen = 32
	// tokenSumLen is the length of the CRC-32 in base32 (no padding).
	tokenSumLen = 7
	// TokenLen is the length of a token.
	TokenLen = len(TokenPrefix) + tokenBodyLen + tokenSumLen
)

// tokenAlphabet is RFC 4648 base32 in lower case.
const tokenAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

var tokenEncoding = base32.NewEncoding(tokenAlphabet).WithPadding(base32.NoPadding)

// NewToken returns a fresh token.
func NewToken() (string, error) {
	var raw [tokenRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("userlinks: generating a token: %w", err)
	}
	return tokenFromBytes(raw), nil
}

// tokenFromBytes spells the token for the given random bytes.
func tokenFromBytes(raw [tokenRandomBytes]byte) string {
	head := TokenPrefix + tokenEncoding.EncodeToString(raw[:])
	return head + tokenChecksum(head)
}

// tokenChecksum returns the checksum characters for a token's head (its prefix
// and random part).
func tokenChecksum(head string) string {
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.ChecksumIEEE([]byte(head)))
	return tokenEncoding.EncodeToString(sum[:])
}

// WellFormed reports whether s is spelled like a token: the prefix, the
// alphabet, the length, and a checksum that matches. It says nothing about
// whether a link with that token exists.
func WellFormed(s string) bool {
	if len(s) != TokenLen || !strings.HasPrefix(s, TokenPrefix) {
		return false
	}
	for i := len(TokenPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return false
		}
	}
	head := s[:TokenLen-tokenSumLen]
	return s[TokenLen-tokenSumLen:] == tokenChecksum(head)
}

// hashToken returns the hex SHA-256 of a token: the form in which the registry
// knows it. A token is 160 bits of randomness, so a plain hash — rather than a
// slow password hash — is the right tool: there is nothing to guess.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// linkIDLen is the length of a link's public identifier.
const linkIDLen = 16

// linkIDFromHash derives a link's public identifier from its token hash: the
// first 64 bits of it. The identifier is what the console, the download log and
// the audit trail call the link by. Knowing it gives no handle on the token.
func linkIDFromHash(hash string) string {
	if len(hash) < linkIDLen {
		return hash
	}
	return hash[:linkIDLen]
}

// validHex reports whether s consists of exactly n lower-case hex digits.
func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidLinkID reports whether s is spelled like a link identifier.
func ValidLinkID(s string) bool { return validHex(s, linkIDLen) }
