package backup

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestEncryptedRoundTripPassphrase(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", strings.Repeat("secret-payload-", 1000)) // spans multiple frames
	put(t, src, "k2", "small")

	key := EncryptionKey{Passphrase: []byte("correct horse battery staple")}
	buf, res := backupToBuffer(t, Options{Cache: src, Encryption: key})
	if !res.Encrypted {
		t.Fatal("result not marked encrypted")
	}
	// The ciphertext must not contain the plaintext.
	if bytes.Contains(buf.Bytes(), []byte("secret-payload-")) {
		t.Fatal("plaintext leaked into encrypted snapshot")
	}
	if !bytes.HasPrefix(buf.Bytes(), envelopeMagic) {
		t.Fatal("encrypted snapshot missing envelope magic")
	}

	dst := newStore(t)
	if _, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache:                  dst,
		Encryption:             key,
		ExpectedManifestDigest: res.ManifestDigest,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := mustGet(t, dst, "k1"); got != strings.Repeat("secret-payload-", 1000) {
		t.Error("k1 content mismatch after encrypted round-trip")
	}
}

func TestEncryptedRoundTripRawKey(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "raw-key-content")
	raw := bytes.Repeat([]byte{0x42}, 32)
	key := EncryptionKey{RawKey: raw}

	buf, res := backupToBuffer(t, Options{Cache: src, Encryption: key})
	dst := newStore(t)
	if _, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache: dst, Encryption: key, ExpectedManifestDigest: res.ManifestDigest,
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := mustGet(t, dst, "k1"); got != "raw-key-content" {
		t.Error("content mismatch after raw-key round-trip")
	}
}

func TestDecryptWrongPassphraseFails(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	buf, _ := backupToBuffer(t, Options{Cache: src, Encryption: EncryptionKey{Passphrase: []byte("right")}})

	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache:      dst,
		Encryption: EncryptionKey{Passphrase: []byte("wrong")},
	})
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected authentication failure, got %v", err)
	}
}

func TestDecryptMissingKeyFails(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", "v1")
	buf, _ := backupToBuffer(t, Options{Cache: src, Encryption: EncryptionKey{Passphrase: []byte("pw")}})

	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{Cache: dst})
	if err == nil || !strings.Contains(err.Error(), "no decryption key") {
		t.Fatalf("expected missing-key failure, got %v", err)
	}
}

func TestEncryptedTamperedFrameFails(t *testing.T) {
	src := newStore(t)
	put(t, src, "k1", strings.Repeat("x", 4096))
	key := EncryptionKey{Passphrase: []byte("pw")}
	buf, _ := backupToBuffer(t, Options{Cache: src, Encryption: key})

	raw := buf.Bytes()
	// Flip a byte well past the plaintext header, inside a ciphertext frame.
	raw[len(raw)-20] ^= 0xff

	dst := newStore(t)
	_, err := NewRestorer().Restore(context.Background(), bytes.NewReader(raw), RestoreOptions{Cache: dst, Encryption: key})
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("expected authentication failure on tampered frame, got %v", err)
	}
}

func TestPlaintextSnapshotIgnoresKey(t *testing.T) {
	// A plaintext snapshot must restore even if a (spurious) key is supplied: the
	// magic is absent, so no decryption is attempted.
	src := newStore(t)
	put(t, src, "k1", "v1")
	buf, res := backupToBuffer(t, Options{Cache: src})

	dst := newStore(t)
	rres, err := NewRestorer().Restore(context.Background(), bytes.NewReader(buf.Bytes()), RestoreOptions{
		Cache:                  dst,
		Encryption:             EncryptionKey{Passphrase: []byte("ignored")},
		ExpectedManifestDigest: res.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rres.Encrypted {
		t.Error("plaintext snapshot reported as encrypted")
	}
}
