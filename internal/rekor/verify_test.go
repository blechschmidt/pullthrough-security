package rekor

import (
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadEntry reads a golden log-entry fixture.
func loadEntry(t *testing.T, name string) *LogEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	var e LogEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decoding fixture %s: %v", name, err)
	}
	return &e
}

func loadVerifier(t *testing.T) *Verifier {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("testdata", "log_pubkey.pem"))
	if err != nil {
		t.Fatalf("reading log pubkey: %v", err)
	}
	v, err := NewVerifierFromPEM(pem)
	if err != nil {
		t.Fatalf("building verifier: %v", err)
	}
	return v
}

// TestGoldenEntryVerifies verifies the committed golden log entry: both the
// inclusion proof and the SET validate against the committed log public key.
func TestGoldenEntryVerifies(t *testing.T) {
	v := loadVerifier(t)
	entry := loadEntry(t, "entry.json")

	res := v.VerifyEntry(entry)
	if res.Err != "" {
		t.Fatalf("unexpected error: %s", res.Err)
	}
	if !res.InclusionVerified {
		t.Error("expected inclusion proof to verify")
	}
	if !res.SETVerified {
		t.Error("expected SET to verify")
	}
	if !res.LeafMatched {
		t.Error("expected the entry body to bind to the proof leaf")
	}
	if !res.OK(Options{RequireInclusionProof: true, RequireSET: true}) {
		t.Error("expected OK under both requirements")
	}
}

// TestGoldenTamperedEntryFails verifies the committed tampered entry (flipped
// root hash): the inclusion proof must fail while the SET — which does not cover
// the proof — may still validate; OK must be false when a proof is required.
func TestGoldenTamperedEntryFails(t *testing.T) {
	v := loadVerifier(t)
	entry := loadEntry(t, "entry_tampered.json")

	res := v.VerifyEntry(entry)
	if res.InclusionVerified {
		t.Error("expected inclusion proof verification to fail on a flipped root")
	}
	if res.OK(Options{RequireInclusionProof: true}) {
		t.Error("expected OK=false when an inclusion proof is required but invalid")
	}
}

// TestWrongKeyRejectsSET confirms the SET fails against a verifier holding an
// unrelated key, even though the inclusion proof (key-independent) still passes.
func TestWrongKeyRejectsSET(t *testing.T) {
	other := NewFakeLog(nil)
	v := NewVerifier([]crypto.PublicKey{other.PublicKey()})
	entry := loadEntry(t, "entry.json")

	res := v.VerifyEntry(entry)
	if res.SETVerified {
		t.Error("expected SET to fail against an unrelated log key")
	}
	if !res.InclusionVerified {
		t.Error("inclusion proof is key-independent and should still verify")
	}
	if res.OK(Options{RequireSET: true}) {
		t.Error("expected OK=false when a SET is required but unverifiable")
	}
}

// TestSubmitVerifyRoundTrip drives the full submit → record → verify flow
// against the in-memory fake log acting as the Client, as the outbound attester
// path does in production.
func TestSubmitVerifyRoundTrip(t *testing.T) {
	log := NewFakeLog(nil)
	var client Client = log

	env := []byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"YQ=="}]}`)
	entry, err := client.Submit(context.Background(), SubmitRequest{Envelope: env, PublicKeyPEM: log.PublicKeyPEM()})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if entry.LogIndex != 0 || entry.InclusionProof == nil {
		t.Fatalf("unexpected entry: index=%d proof=%v", entry.LogIndex, entry.InclusionProof)
	}

	res := log.Verifier().VerifyEntry(entry)
	if !res.OK(Options{RequireInclusionProof: true, RequireSET: true}) {
		t.Fatalf("round-trip verification failed: %+v", res)
	}

	ptr := entry.Pointer("https://rekor.example", res)
	if ptr.LogIndex != entry.LogIndex || !ptr.InclusionProofVerified || !ptr.SETVerified {
		t.Fatalf("unexpected pointer: %+v", ptr)
	}
	if ptr.URL == "" {
		t.Error("expected a synthesized entry URL")
	}
}
