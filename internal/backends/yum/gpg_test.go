package yum

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func testKeypair(t *testing.T) (*openpgp.Entity, []byte) {
	t.Helper()
	ent, err := openpgp.NewEntity("Test Repo", "yum test", "repo@test", nil)
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

func detachSign(t *testing.T, ent *openpgp.Entity, message []byte) []byte {
	t.Helper()
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, ent, bytes.NewReader(message), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}
	return sig.Bytes()
}

func TestVerifyDetachedGood(t *testing.T) {
	ent, pub := testKeypair(t)
	kr, err := loadKeyring(pub)
	if err != nil {
		t.Fatalf("loadKeyring: %v", err)
	}
	msg := []byte("<repomd><data type=\"primary\"/></repomd>")
	sig := detachSign(t, ent, msg)
	if err := kr.verifyDetached(msg, sig); err != nil {
		t.Errorf("verifyDetached good = %v, want nil", err)
	}
}

func TestVerifyDetachedTampered(t *testing.T) {
	ent, pub := testKeypair(t)
	kr, _ := loadKeyring(pub)
	msg := []byte("<repomd>original</repomd>")
	sig := detachSign(t, ent, msg)
	if err := kr.verifyDetached([]byte("<repomd>tampered</repomd>"), sig); err == nil {
		t.Error("verifyDetached tampered = nil, want error")
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
	if err := kr.verifyDetached([]byte("x"), []byte("y")); err != nil {
		t.Errorf("disabled verifyDetached = %v, want nil", err)
	}
}

// TestSignedRepomdEndToEnd serves a detached-signed repomd.xml and asserts the
// backend validates it and refuses a tampered one.
func TestSignedRepomdEndToEnd(t *testing.T) {
	ent, pub := testKeypair(t)
	fr := newFakeRepo(t)
	repomd := fr.files["/repodata/repomd.xml"]
	fr.files["/repodata/repomd.xml.asc"] = detachSign(t, ent, repomd)

	m := &Metrics{}
	b := testBackend(t, fr, Options{GPGKey: pub, Metrics: m})

	res := resolve(t, b, "/repodata/repomd.xml")
	fres, _, err := fetchAll(t, b, res)
	if err != nil {
		t.Fatalf("fetch signed repomd: %v", err)
	}
	if fres.Resolved.Metadata[MetaSignatureVerified] != "trusted" {
		t.Errorf("signatureVerified = %q, want trusted", fres.Resolved.Metadata[MetaSignatureVerified])
	}
	if m.Stats().SignatureVerified != 1 {
		t.Errorf("SignatureVerified = %v, want 1", m.Stats().SignatureVerified)
	}

	// Tamper with repomd.xml so the detached signature no longer matches.
	fr.files["/repodata/repomd.xml"] = append([]byte("<!-- evil -->"), repomd...)
	res2 := resolve(t, b, "/repodata/repomd.xml")
	if _, _, err := fetchAll(t, b, res2); err == nil {
		t.Error("tampered repomd fetch = nil, want signature error")
	}
	if m.Stats().SignatureFailures != 1 {
		t.Errorf("SignatureFailures = %v, want 1", m.Stats().SignatureFailures)
	}
}
