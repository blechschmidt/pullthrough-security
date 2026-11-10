package sigverify

import (
	"bytes"
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policy"
)

func TestTrustBundleRoundTripAndVerify(t *testing.T) {
	root, rootKey, _ := makeRoot(t)
	leaf, leafKey := makeLeaf(t, root, rootKey, testIdentity, testIssuer)
	rekorKey := newKey(t)

	bundle := &TrustBundle{
		FormatVersion: TrustBundleFormatVersion,
		Generator:     trustBundleGenerator,
		CreatedAt:     time.Unix(1700000000, 0).UTC(),
		Roots:         []string{rootPoolPEM(t, root)},
		RekorKeys:     []string{publicKeyPEM(t, rekorKey)},
		Identities:    []TrustBundleIdentity{{Issuer: testIssuer, SubjectPattern: `^https://github\.com/acme/.*`}},
	}

	digest, err := bundle.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}

	var buf bytes.Buffer
	if err := bundle.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	loaded, err := LoadTrustBundle(bytes.NewReader(buf.Bytes()), digest)
	if err != nil {
		t.Fatalf("LoadTrustBundle: %v", err)
	}

	roots, rekorKeys, keys, identities, err := loaded.Material()
	if err != nil {
		t.Fatalf("Material: %v", err)
	}
	if roots == nil {
		t.Fatal("expected a root pool from the bundle")
	}
	_ = keys

	// Build a service from the bundle's trust material and verify a signature
	// that chains to the bundled root with a bundled-policy identity.
	cfg := Config{
		RequireSignature: true,
		Roots:            roots,
		Identities:       identities,
		RekorKeys:        rekorKeys,
	}
	sig := keylessSignature(t, leafKey, leaf, testDigest)
	svc, err := NewService(cfg, &fakeSource{material: &Material{Signatures: []SimpleSignature{sig}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := svc.Verify(context.Background(), artifact())
	if !report.VerifiedSignature {
		t.Fatalf("expected signature verified via bundled trust, findings=%+v", report.Findings)
	}
	if d := svc.Gate(report); d.Action != policy.ActionAllow {
		t.Fatalf("expected allow via bundled trust, got %s", d.Action)
	}

	// RekorKeys parsed from the bundle should be usable for SET verification.
	if len(rekorKeys) != 1 {
		t.Fatalf("expected 1 rekor key from bundle, got %d", len(rekorKeys))
	}
	var _ crypto.PublicKey = rekorKeys[0]
}

func TestTrustBundleDigestMismatchRejected(t *testing.T) {
	bundle := &TrustBundle{FormatVersion: TrustBundleFormatVersion, Generator: trustBundleGenerator}
	var buf bytes.Buffer
	if err := bundle.Write(&buf); err != nil {
		t.Fatal(err)
	}
	_, err := LoadTrustBundle(bytes.NewReader(buf.Bytes()), "sha256:deadbeef")
	if err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

func TestTrustBundleUnknownVersionRejected(t *testing.T) {
	bad := []byte(`{"formatVersion":999}`)
	if _, err := LoadTrustBundle(bytes.NewReader(bad), ""); err == nil {
		t.Fatal("expected unsupported version error")
	}
}
