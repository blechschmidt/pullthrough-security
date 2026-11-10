package sigverify

import (
	"crypto"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
)

// bundleFromEntry maps a rekor.LogEntry onto the cosign/Rekor bundle shape the
// inbound gate parses, so a real log entry (from the in-memory fake log) drives
// the gate's SET + inclusion-proof verification.
func bundleFromEntry(e *rekor.LogEntry) *rekorBundle {
	b := &rekorBundle{SignedEntryTimestamp: e.SET}
	b.Payload.Body = e.Body
	b.Payload.IntegratedTime = e.IntegratedTime
	b.Payload.LogIndex = e.LogIndex
	b.Payload.LogID = e.LogID
	if ip := e.InclusionProof; ip != nil {
		b.InclusionProof = &rekorInclusionProof{
			LogIndex:   ip.LogIndex,
			RootHash:   ip.RootHash,
			TreeSize:   ip.TreeSize,
			Hashes:     ip.Hashes,
			Checkpoint: ip.Checkpoint,
		}
	}
	return b
}

// TestVerifyRekorInclusionProof confirms the gate's Rekor verification validates
// both the SET and the Merkle inclusion proof of a genuine log entry, and that a
// tampered root hash fails the inclusion check while the SET still verifies.
func TestVerifyRekorInclusionProof(t *testing.T) {
	log := rekor.NewFakeLog(nil)
	// Seed the log so the target sits at a non-trivial index with a real path.
	log.Append([]byte("other-0"))
	log.Append([]byte("other-1"))
	entry := log.Append([]byte("the-attestation-body"))

	v, err := NewVerifier(nil, nil, nil, []crypto.PublicKey{log.PublicKey()})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	setOK, inclOK := v.verifyRekor(bundleFromEntry(entry))
	if !setOK {
		t.Error("expected the SET to verify")
	}
	if !inclOK {
		t.Error("expected the inclusion proof to verify")
	}

	// Tamper the root hash: inclusion must fail, SET must still pass (it does not
	// cover the proof).
	tampered := bundleFromEntry(entry)
	tampered.InclusionProof.RootHash = "00" + tampered.InclusionProof.RootHash[2:]
	setOK, inclOK = v.verifyRekor(tampered)
	if !setOK {
		t.Error("SET should still verify on a tampered root")
	}
	if inclOK {
		t.Error("inclusion proof must fail on a tampered root")
	}
}

// TestGateRequiresInclusionProof confirms RequireInclusionProof blocks a trusted
// keyless signature that carries no verified Merkle inclusion proof, and allows
// one that does.
func TestGateRequiresInclusionProof(t *testing.T) {
	rootCert, rootKey, pool := makeRoot(t)
	const identity = "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"
	const issuer = "https://token.actions.githubusercontent.com"
	leafCert, leafKey := makeLeaf(t, rootCert, rootKey, identity, issuer)
	log := rekor.NewFakeLog(nil)

	const digest = "sha256:" + "11223344556677889900112233445566778899001122334455667788990011aa"

	withProof := func() SimpleSignature {
		sig := keylessSignature(t, leafKey, leafCert, digest)
		entry := log.Append(sig.Payload)
		sig.RekorBundle = bundleFromEntry(entry)
		return sig
	}
	withoutProof := func() SimpleSignature {
		sig := keylessSignature(t, leafKey, leafCert, digest)
		entry := log.Append(sig.Payload)
		b := bundleFromEntry(entry)
		b.InclusionProof = nil // SET only, no Merkle proof
		sig.RekorBundle = b
		return sig
	}

	newGate := func(mat *Material) *Service {
		svc, err := NewService(Config{
			Action:                "block",
			FailSeverity:          SeverityHigh,
			RequireInclusionProof: true,
			Roots:                 pool,
			Identities:            []Identity{{Issuer: issuer, SubjectPattern: "^https://github\\.com/acme/.*"}},
			RekorKeys:             []crypto.PublicKey{log.PublicKey()},
		}, &fakeSource{material: mat}, nil)
		if err != nil {
			t.Fatalf("NewService: %v", err)
		}
		return svc
	}

	// With a verified inclusion proof present, the gate raises no missing-proof
	// finding.
	mat1 := &Material{Source: "test", Signatures: []SimpleSignature{withProof()}}
	rep := newGate(mat1).verify(Artifact{Ecosystem: "docker", Digest: digest}, mat1)
	if !rep.VerifiedSignature {
		t.Fatalf("expected a trusted signature; findings=%+v", rep.Findings)
	}
	if w := rep.Worst(); w != nil && w.Kind == KindMissingRekorProof {
		t.Errorf("did not expect a missing-proof finding when a valid inclusion proof is present: %+v", w)
	}

	// Without an inclusion proof, RequireInclusionProof produces a finding.
	mat2 := &Material{Source: "test", Signatures: []SimpleSignature{withoutProof()}}
	rep2 := newGate(mat2).verify(Artifact{Ecosystem: "docker", Digest: digest}, mat2)
	if w := rep2.Worst(); w == nil || w.Kind != KindMissingRekorProof {
		t.Errorf("expected a missing-rekor-proof finding, got %+v", rep2.Findings)
	}
}
