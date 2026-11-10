package attestbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// TestAttest_SubmitsToRekor confirms that when a Rekor client is wired, signing
// a bundle submits its DSSE envelope to the transparency log, verifies the
// returned entry, and republishes the bundle carrying a verified log pointer.
func TestAttest_SubmitsToRekor(t *testing.T) {
	signer := fixedSigner(t)
	log := rekor.NewFakeLog(nil)
	m := rekor.NewMetrics()

	svc, err := NewService(Config{
		Signer:   signer,
		Attester: sampleAttester(),
		Rekor: &RekorConfig{
			Client:       log,
			Verifier:     log.Verifier(),
			PublicKeyPEM: signerPublicKeyPEM(t, signer),
			BaseURL:      "https://rekor.example",
			Metrics:      m,
		},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if !svc.RekorEnabled() {
		t.Fatal("expected RekorEnabled")
	}

	bundle, err := svc.Attest(sampleInput(), Options{ServedAt: time.Unix(1700000000, 0).UTC()})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	// The returned bundle is the pre-submission copy (no pointer yet).
	if bundle.Rekor != nil {
		t.Error("returned bundle should not carry a pointer synchronously")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := svc.WaitForRekor(ctx); err != nil {
		t.Fatalf("WaitForRekor: %v", err)
	}

	// The stored bundle was republished with a verified transparency-log pointer.
	got, ok := svc.Get("acme", "left-pad@1.3.0")
	if !ok {
		t.Fatal("bundle not found after submission")
	}
	if got.Rekor == nil {
		t.Fatal("stored bundle has no Rekor pointer")
	}
	if !got.Rekor.InclusionProofVerified {
		t.Error("expected a verified inclusion proof")
	}
	if !got.Rekor.SETVerified {
		t.Error("expected a verified SET")
	}
	if got.Rekor.URL == "" {
		t.Error("expected a synthesized entry URL")
	}
	if s := m.Snapshot(); s.Submissions != 1 || s.SubmissionProofs != 1 {
		t.Errorf("unexpected submit metrics: %+v", s)
	}

	snap := svc.Snapshot()
	if !snap.RekorEnabled || snap.RekorSubmitted != 1 || snap.RekorWithProof != 1 {
		t.Errorf("unexpected service snapshot: %+v", snap)
	}
}

// signerPublicKeyPEM renders the signer's public key as PEM for Rekor submission.
func signerPublicKeyPEM(t *testing.T, s *Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(s.PublicKey())
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
