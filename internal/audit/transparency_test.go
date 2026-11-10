package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
)

func newTransparencyLogger(t *testing.T, sink Sink, opts *TransparencyOptions) *Logger {
	t.Helper()
	l, err := NewLogger(context.Background(), Options{
		Key:          testKey,
		Sink:         sink,
		Now:          fixedClock(),
		Transparency: opts,
	})
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	return l
}

func logN(t *testing.T, l *Logger, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := l.Log(context.Background(), Event{Type: EventPolicy, Subject: "alice", Decision: DecisionDeny}); err != nil {
			t.Fatalf("log %d: %v", i, err)
		}
	}
}

func TestTransparencyInclusionProofVerifies(t *testing.T) {
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1})
	logN(t, l, 9)

	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	cp, ok := l.LatestCheckpoint()
	if !ok || cp.TreeSize != 9 {
		t.Fatalf("expected checkpoint of size 9, got %+v (ok=%v)", cp, ok)
	}

	recs := sink.Records()
	for _, rec := range recs {
		proof, err := l.InclusionProof(rec.Seq)
		if err != nil {
			t.Fatalf("inclusion proof seq %d: %v", rec.Seq, err)
		}
		if proof.RootHash != cp.RootHash {
			t.Fatalf("proof for seq %d not anchored to checkpoint root", rec.Seq)
		}
		if err := VerifyInclusionForRecord(rec, proof); err != nil {
			t.Fatalf("verify inclusion seq %d: %v", rec.Seq, err)
		}
	}

	// A proof for a non-existent sequence is an error.
	if _, err := l.InclusionProof(uint64(len(recs)) + 1); err == nil {
		t.Fatalf("expected error for out-of-range sequence")
	}
}

func TestInclusionProofRejectsWrongRecord(t *testing.T) {
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1})
	logN(t, l, 5)

	proof, err := l.InclusionProof(2)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	// Bind the proof to a different record: must be rejected.
	other := sink.Records()[3]
	if err := VerifyInclusionForRecord(other, proof); err == nil {
		t.Fatalf("proof for seq 2 wrongly verified against record seq %d", other.Seq)
	}
}

func TestConsistencyProofVerifies(t *testing.T) {
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1})
	logN(t, l, 7)

	proof, err := l.ConsistencyProof(3, 7)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if err := VerifyConsistency(proof); err != nil {
		t.Fatalf("verify consistency: %v", err)
	}

	// from > to is rejected.
	if _, err := l.ConsistencyProof(8, 7); err == nil {
		t.Fatalf("expected error for from > to")
	}
}

func TestAutoSealEvery(t *testing.T) {
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: 4})
	logN(t, l, 4)

	cp, ok := l.LatestCheckpoint()
	if !ok {
		t.Fatalf("expected an automatic checkpoint after 4 records")
	}
	if cp.TreeSize != 4 {
		t.Fatalf("auto-sealed checkpoint size = %d, want 4", cp.TreeSize)
	}
	st := l.Stats()
	if st.Checkpoints != 1 || st.ChainLength != 4 || st.TreeSize != 4 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

func TestCheckpointDetectsTamperWithoutKey(t *testing.T) {
	// The signed/sealed checkpoint must detect an edit to a past record even by a
	// verifier that does NOT recompute the HMAC chain — i.e. purely from the
	// Merkle root over the records.
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1})
	logN(t, l, 6)
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	cp, _ := l.LatestCheckpoint()

	recs := sink.Records()
	// Tamper with a record's stored Hash (as a file-rewriting attacker might).
	recs[2].Hash = "0000000000000000000000000000000000000000000000000000000000000000"

	if got := RootOverRecords(recs[:cp.TreeSize]); got == cp.RootHash {
		t.Fatalf("Merkle root unchanged after tampering — tamper not detectable")
	}
}

func TestVerifyLogCrossCheck(t *testing.T) {
	store := NewMemoryCheckpointStore()
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: 3, Store: store})
	logN(t, l, 9) // auto-seals at 3, 6, 9

	recs := sink.Records()
	cps, _ := store.All(context.Background())
	if len(cps) != 3 {
		t.Fatalf("expected 3 checkpoints, got %d", len(cps))
	}

	results, err := VerifyLog(recs, cps, nil)
	if err != nil {
		t.Fatalf("VerifyLog on intact log: %v", err)
	}
	for _, r := range results {
		if !r.OK() || !r.RootMatches || !r.Consistent {
			t.Fatalf("checkpoint %d not OK: %+v", r.TreeSize, r)
		}
	}

	// Tamper with a record covered by the first checkpoint: VerifyLog must flag it.
	tampered := append([]Record(nil), recs...)
	tampered[1].Hash = "deadbeef"
	if _, err := VerifyLog(tampered, cps, nil); err == nil {
		t.Fatalf("VerifyLog must detect a tampered record against sealed checkpoints")
	}

	// Truncating records below a checkpoint's coverage must also be flagged.
	if _, err := VerifyLog(recs[:5], cps, nil); err == nil {
		t.Fatalf("VerifyLog must detect deleted records (checkpoint covers more than present)")
	}
}

func TestSignedCheckpointEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer := signerFromKey(t, priv)

	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1, Signer: signer})
	logN(t, l, 4)
	cp, _, err := l.Seal(context.Background())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !cp.Signed() {
		t.Fatalf("checkpoint should be signed")
	}
	if err := VerifyCheckpointSignature(pub, cp); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	// Tampering with the sealed root invalidates the signature.
	bad := cp
	bad.RootHash = "00" + bad.RootHash[2:]
	if err := VerifyCheckpointSignature(pub, bad); err == nil {
		t.Fatalf("signature must not verify over a tampered checkpoint")
	}
}

func TestSignedCheckpointECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer := signerFromKey(t, priv)
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1, Signer: signer})
	logN(t, l, 3)
	cp, _, err := l.Seal(context.Background())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := VerifyCheckpointSignature(&priv.PublicKey, cp); err != nil {
		t.Fatalf("verify ecdsa signature: %v", err)
	}
}

func TestLoadSignerPEMRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := LoadSigner(pemBytes)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	if signer.KeyID() == "" {
		t.Fatalf("expected a non-empty key id")
	}
}

func TestTransparencyResumeFromFile(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	ckPath := filepath.Join(dir, "audit.checkpoints")

	openLogger := func() (*Logger, *FileSink, *FileCheckpointStore) {
		sink, err := NewFileSink(logPath)
		if err != nil {
			t.Fatalf("file sink: %v", err)
		}
		store, err := NewFileCheckpointStore(ckPath)
		if err != nil {
			t.Fatalf("checkpoint store: %v", err)
		}
		l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1, Store: store})
		return l, sink, store
	}

	l, sink, store := openLogger()
	logN(t, l, 5)
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	_ = store.Close()
	_ = sink.Close()

	// Reopen: the Merkle tree must be rebuilt from disk so new proofs/checkpoints
	// continue the same tree.
	l2, sink2, store2 := openLogger()
	defer store2.Close()
	defer sink2.Close()

	if got := l2.Stats().TreeSize; got != 5 {
		t.Fatalf("resumed tree size = %d, want 5", got)
	}
	logN(t, l2, 3)
	cp, _, err := l2.Seal(context.Background())
	if err != nil {
		t.Fatalf("seal after resume: %v", err)
	}
	if cp.TreeSize != 8 {
		t.Fatalf("post-resume checkpoint size = %d, want 8", cp.TreeSize)
	}

	// The on-disk records and all checkpoints must cross-verify.
	recs, err := ReadAllRecords(logPath)
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	cps, err := ReadCheckpoints(ckPath)
	if err != nil {
		t.Fatalf("read checkpoints: %v", err)
	}
	if _, err := VerifyLog(recs, cps, nil); err != nil {
		t.Fatalf("cross-verify after resume: %v", err)
	}
	if idx, err := VerifyChain(testKey, recs); err != nil {
		t.Fatalf("hash chain broken at %d after resume: %v", idx, err)
	}
}

func TestVerificationFailureCounter(t *testing.T) {
	sink := NewMemorySink()
	l := newTransparencyLogger(t, sink, &TransparencyOptions{SealEvery: -1})
	logN(t, l, 2)
	if got := l.Stats().VerificationFailures; got != 0 {
		t.Fatalf("expected 0 failures initially, got %d", got)
	}
	l.RecordVerificationFailure()
	l.RecordVerificationFailure()
	if got := l.Stats().VerificationFailures; got != 2 {
		t.Fatalf("expected 2 failures, got %d", got)
	}
}

func TestNilLoggerTransparencyNoop(t *testing.T) {
	var l *Logger
	if l.TransparencyEnabled() {
		t.Fatalf("nil logger should report transparency disabled")
	}
	if _, ok := l.LatestCheckpoint(); ok {
		t.Fatalf("nil logger should have no checkpoint")
	}
	if _, _, err := l.Seal(context.Background()); err != nil {
		t.Fatalf("nil logger Seal should be a no-op, got %v", err)
	}
	if got := l.Stats().ChainLength; got != 0 {
		t.Fatalf("nil logger stats should be zero")
	}
}

// signerFromKey wraps an already-generated private key in a Signer via PEM, to
// exercise the production LoadSigner path in tests.
func signerFromKey(t *testing.T, priv any) *Signer {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := LoadSigner(pemBytes)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	return signer
}
