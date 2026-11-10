package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func newTestCipher(t *testing.T) *Cipher {
	t.Helper()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	plaintext := "hunter2-super-secret-token"

	enc, err := c.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Fatalf("encrypted value lacks prefix: %q", enc)
	}
	if strings.Contains(enc, plaintext) {
		t.Fatalf("ciphertext leaks plaintext")
	}

	got, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptIsNonDeterministic(t *testing.T) {
	c := newTestCipher(t)
	a, _ := c.EncryptString("same")
	b, _ := c.EncryptString("same")
	if a == b {
		t.Fatalf("encryption must be randomized per call (nonce reuse)")
	}
}

func TestDecryptTamperedFails(t *testing.T) {
	c := newTestCipher(t)
	enc, _ := c.EncryptString("payload")

	// Flip a byte in the base64 ciphertext body.
	body := strings.TrimPrefix(enc, Prefix)
	raw, _ := base64.RawURLEncoding.DecodeString(body)
	raw[len(raw)-1] ^= 0xFF
	tampered := Prefix + base64.RawURLEncoding.EncodeToString(raw)

	if _, err := c.Decrypt(tampered); err == nil {
		t.Fatalf("expected decryption of tampered ciphertext to fail")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	c1 := newTestCipher(t)
	c2 := newTestCipher(t)
	enc, _ := c1.EncryptString("payload")
	if _, err := c2.Decrypt(enc); err == nil {
		t.Fatalf("decrypting with the wrong key must fail")
	}
}

func TestResolvePassesThroughPlaintext(t *testing.T) {
	c := newTestCipher(t)
	got, err := c.Resolve("plain-value")
	if err != nil {
		t.Fatalf("resolve plaintext: %v", err)
	}
	if got != "plain-value" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptNotEncrypted(t *testing.T) {
	c := newTestCipher(t)
	if _, err := c.Decrypt("not-encrypted"); err != ErrNotEncrypted {
		t.Fatalf("want ErrNotEncrypted, got %v", err)
	}
}

func TestNilCipherBehavior(t *testing.T) {
	var c *Cipher
	if _, err := c.EncryptString("x"); err != ErrNoCipher {
		t.Fatalf("nil encrypt want ErrNoCipher, got %v", err)
	}
	// Resolve of a plaintext value must work even with a nil cipher.
	got, err := c.Resolve("plain")
	if err != nil || got != "plain" {
		t.Fatalf("nil resolve plain: %q %v", got, err)
	}
	// Resolve of an encrypted value with no cipher must error, not leak ciphertext.
	if _, err := c.Resolve(Prefix + "abc"); err != ErrNoCipher {
		t.Fatalf("nil resolve encrypted want ErrNoCipher, got %v", err)
	}
}

func TestParseKeyFormats(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	for name, encoded := range map[string]string{
		"hex":       hex.EncodeToString(key),
		"stdBase64": base64.StdEncoding.EncodeToString(key),
		"urlBase64": base64.RawURLEncoding.EncodeToString(key),
	} {
		got, err := ParseKey(encoded)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != string(key) {
			t.Fatalf("%s: key mismatch", name)
		}
	}
	if _, err := ParseKey("tooshort"); err == nil {
		t.Fatalf("expected error for short key")
	}
}

func TestDeriveKeyStable(t *testing.T) {
	a, err := DeriveKey("passphrase", []byte("salt-value"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	b, _ := DeriveKey("passphrase", []byte("salt-value"))
	if string(a) != string(b) {
		t.Fatalf("derivation must be deterministic")
	}
	if len(a) != KeySize {
		t.Fatalf("derived key wrong length %d", len(a))
	}
	c, _ := DeriveKey("passphrase", []byte("different-salt"))
	if string(a) == string(c) {
		t.Fatalf("different salt must yield different key")
	}
}
