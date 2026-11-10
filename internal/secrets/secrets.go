// Package secrets provides authenticated encryption for secret material stored
// at rest (upstream credentials, API tokens, OIDC client secrets). It uses
// AES-256-GCM, an AEAD construction that provides both confidentiality and
// integrity: a tampered ciphertext fails to decrypt rather than yielding
// corrupted plaintext.
//
// Encrypted values are encoded as a self-describing, URL-safe string with the
// form "enc:v1:<base64(nonce||ciphertext||tag)>" so the rest of the codebase
// can recognize an encrypted value and decrypt it transparently, while plain
// (un-encrypted) values pass through unchanged during a migration.
//
// The master key is supplied out-of-band (an environment variable or a file
// with restrictive permissions) and never written to disk by this package. A
// passphrase may instead be stretched into a key via scrypt.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Prefix marks a string as an encrypted-at-rest value produced by this package.
const Prefix = "enc:v1:"

// KeySize is the required master-key length in bytes (AES-256).
const KeySize = 32

var (
	// ErrInvalidKey indicates the supplied key is not KeySize bytes.
	ErrInvalidKey = errors.New("secrets: key must be 32 bytes")
	// ErrNotEncrypted indicates a value lacks the encrypted-value prefix.
	ErrNotEncrypted = errors.New("secrets: value is not encrypted")
	// ErrMalformed indicates a structurally invalid encrypted value.
	ErrMalformed = errors.New("secrets: malformed encrypted value")
	// ErrNoCipher indicates an operation requiring a configured cipher was
	// attempted on a nil/disabled Cipher.
	ErrNoCipher = errors.New("secrets: no encryption key configured")
)

// Cipher encrypts and decrypts secret values with AES-256-GCM. A nil *Cipher is
// valid and represents "encryption disabled": IsEncrypted/Decrypt of plain
// values still work, but Encrypt and Decrypt of encrypted values report
// ErrNoCipher. This lets callers treat encryption as optional without nil
// checks scattered across the codebase.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher constructs a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// DeriveKey stretches a passphrase into a KeySize key using scrypt with the
// given salt. The salt need not be secret but must be stable for a given
// deployment (otherwise previously encrypted values cannot be decrypted).
func DeriveKey(passphrase string, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("secrets: salt must not be empty")
	}
	// N=2^15 is a reasonable interactive cost; r=8, p=1 are the standard params.
	return scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, KeySize)
}

// ParseKey decodes a master key supplied as a hex or base64 string and verifies
// its length. It accepts standard and URL-safe base64, with or without padding.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrInvalidKey
	}
	// Try hex first (64 chars), then base64 variants.
	if len(s) == hex.EncodedLen(KeySize) {
		if b, err := hex.DecodeString(s); err == nil && len(b) == KeySize {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == KeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w (want %d-byte hex or base64)", ErrInvalidKey, KeySize)
}

// LoadKeyFromEnvOrFile resolves a master key from, in order: the named
// environment variable (hex/base64), or the named file. The file may contain
// either raw 32 bytes or a hex/base64 text encoding. It returns (nil, nil) when
// neither source is configured, so the caller can run with encryption disabled.
func LoadKeyFromEnvOrFile(envVar, keyFile string) ([]byte, error) {
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			key, err := ParseKey(v)
			if err != nil {
				return nil, fmt.Errorf("secrets: env %s: %w", envVar, err)
			}
			return key, nil
		}
	}
	if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("secrets: reading key file: %w", err)
		}
		if len(data) == KeySize {
			return data, nil
		}
		key, err := ParseKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("secrets: key file %q: %w", keyFile, err)
		}
		return key, nil
	}
	return nil, nil
}

// Encrypt encrypts plaintext and returns a self-describing encrypted value
// string. A fresh random nonce is generated per call so identical plaintexts
// produce distinct ciphertexts.
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	if c == nil {
		return "", ErrNoCipher
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secrets: nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return Prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// EncryptString is a convenience wrapper over Encrypt.
func (c *Cipher) EncryptString(s string) (string, error) { return c.Encrypt([]byte(s)) }

// Decrypt decrypts a value produced by Encrypt. It returns ErrNotEncrypted if
// the value lacks the prefix, so callers can distinguish "plain value" from a
// real decryption failure (which indicates tampering or a wrong key).
func (c *Cipher) Decrypt(value string) ([]byte, error) {
	if !IsEncrypted(value) {
		return nil, ErrNotEncrypted
	}
	if c == nil {
		return nil, ErrNoCipher
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return nil, ErrMalformed
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		// GCM authentication failed: wrong key or tampered ciphertext.
		return nil, fmt.Errorf("secrets: decrypt failed (wrong key or tampered data)")
	}
	return pt, nil
}

// Resolve returns the cleartext for a value that may or may not be encrypted:
// encrypted values are decrypted; plain values are returned unchanged. This is
// the transparent read path used when loading config that may contain a mix of
// encrypted and plaintext secrets.
func (c *Cipher) Resolve(value string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}
	pt, err := c.Decrypt(value)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// IsEncrypted reports whether a value carries the encrypted-value prefix.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, Prefix)
}

// ConstantTimeEqual compares two secrets in constant time to avoid leaking
// length-independent timing information. It is exported for reuse by the auth
// package's token comparisons.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
