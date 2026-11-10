package apt

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
)

// testKeypair generates a throwaway PGP entity and returns it plus its
// ASCII-armored public key, for exercising the Release signature path.
func testKeypair(t *testing.T) (*openpgp.Entity, []byte) {
	t.Helper()
	ent, err := openpgp.NewEntity("Test Repo", "apt test", "repo@test", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var pub bytes.Buffer
	aw, err := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := ent.Serialize(aw); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	_ = aw.Close()
	return ent, pub.Bytes()
}

func clearsignBytes(t *testing.T, ent *openpgp.Entity, plaintext []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := clearsign.Encode(&out, ent.PrivateKey, nil)
	if err != nil {
		t.Fatalf("clearsign.Encode: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("clearsign close: %v", err)
	}
	return out.Bytes()
}

func TestVerifyClearsignedGood(t *testing.T) {
	ent, pub := testKeypair(t)
	kr, err := loadKeyring(pub)
	if err != nil {
		t.Fatalf("loadKeyring: %v", err)
	}
	if !kr.enabled() {
		t.Fatal("keyring should be enabled")
	}
	body := []byte("Origin: Debian\nSHA256:\n aaaa 10 main/Packages\n")
	signed := clearsignBytes(t, ent, body)
	if err := kr.verifyClearsigned(signed); err != nil {
		t.Errorf("verifyClearsigned good = %v, want nil", err)
	}
}

func TestVerifyClearsignedTampered(t *testing.T) {
	ent, pub := testKeypair(t)
	kr, _ := loadKeyring(pub)
	signed := clearsignBytes(t, ent, []byte("Origin: Debian\nSHA256:\n aaaa 10 main/Packages\n"))
	// Flip a byte inside the signed body.
	tampered := bytes.Replace(signed, []byte("Origin: Debian"), []byte("Origin: Evilian"), 1)
	if err := kr.verifyClearsigned(tampered); err == nil {
		t.Error("verifyClearsigned tampered = nil, want error")
	}
}

func TestVerifyClearsignedWrongKey(t *testing.T) {
	ent, _ := testKeypair(t)
	_, otherPub := testKeypair(t)
	kr, _ := loadKeyring(otherPub) // trust a DIFFERENT key
	signed := clearsignBytes(t, ent, []byte("Origin: Debian\nSHA256:\n aaaa 10 main/Packages\n"))
	if err := kr.verifyClearsigned(signed); err == nil {
		t.Error("verifyClearsigned with untrusted signer = nil, want error")
	}
}

func TestNilKeyringDisabled(t *testing.T) {
	kr, err := loadKeyring(nil)
	if err != nil {
		t.Fatalf("loadKeyring(nil): %v", err)
	}
	if kr.enabled() {
		t.Error("nil keyring should be disabled")
	}
	// A disabled keyring is a no-op verifier.
	if err := kr.verifyClearsigned([]byte("anything")); err != nil {
		t.Errorf("disabled verifyClearsigned = %v, want nil", err)
	}
}

func TestLoadKeyringGarbageFails(t *testing.T) {
	if _, err := loadKeyring([]byte("not a key at all")); err == nil {
		t.Error("loadKeyring(garbage) = nil, want error")
	}
}

// TestSignedInReleaseEndToEnd serves a clearsigned InRelease and asserts the
// backend validates it against the configured keyring and refuses a tampered one.
func TestSignedInReleaseEndToEnd(t *testing.T) {
	ent, pub := testKeypair(t)
	fr := newFakeRepo(t)

	body := string(fr.files["/dists/bookworm/Release"])
	fr.files["/dists/bookworm/InRelease"] = clearsignBytes(t, ent, []byte(body))

	m := &Metrics{}
	b := testBackend(t, fr, Options{GPGKey: pub, Metrics: m})

	res := resolve(t, b, "/dists/bookworm/InRelease")
	fres, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch signed InRelease: %v", err)
	}
	if fres.Resolved.Metadata[MetaSignatureVerified] != "trusted" {
		t.Errorf("signatureVerified = %q, want trusted", fres.Resolved.Metadata[MetaSignatureVerified])
	}
	if m.Stats().SignatureVerified != 1 {
		t.Errorf("SignatureVerified = %v, want 1", m.Stats().SignatureVerified)
	}

	// Tamper with the signed InRelease: the fetch must now fail closed.
	fr.files["/dists/bookworm/InRelease"] = bytes.Replace(
		fr.files["/dists/bookworm/InRelease"], []byte("Origin: Test"), []byte("Origin: Evil"), 1)
	res2 := resolve(t, b, "/dists/bookworm/InRelease")
	if _, _, err := fetchAll(t, b, res2); err == nil {
		t.Error("tampered InRelease fetch = nil, want signature error")
	}
	if m.Stats().SignatureFailures != 1 {
		t.Errorf("SignatureFailures = %v, want 1", m.Stats().SignatureFailures)
	}
}
