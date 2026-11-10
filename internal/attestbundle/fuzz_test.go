//go:build fuzz
// +build fuzz

// Fuzz target for the outbound-attestation DSSE envelope parser (Task 46, harness
// from Task 30).
//
// The `attest verify` CLI and any downstream consumer decode an untrusted DSSE
// bundle/envelope and run VerifyEnvelope over it. The decode → base64 → PAE →
// signature-check → statement-unmarshal pipeline must never panic on adversarial
// input, and must never report a successful verification for input the proxy did
// not sign. This target asserts both: it fuzzes the envelope decode/verify path
// against a fixed public key and fails only on a panic or a false-accept.
//
// Build-tag gated (`fuzz`) so the default `go test ./...` stays fast. Run with:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzVerifyEnvelope ./internal/attestbundle/
package attestbundle

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

var envSeeds = []string{
	`{}`,
	`{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}`,
	`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AAAA"}]}`,
	`{"payload":"!!!notbase64!!!","signatures":[{"sig":"x"}]}`,
	`{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEifQ==","signatures":[{"keyid":"k","sig":"Zm9v"}]}`,
	`not json`,
}

func FuzzVerifyEnvelope(f *testing.F) {
	// A fixed verification key the fuzzer cannot produce a valid signature for.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 11)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public()

	for _, s := range envSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return // malformed JSON is a normal rejection, not a crash
		}
		// Must not panic, regardless of how malformed the fields are.
		stmt, err := VerifyEnvelope(pub, env)
		if err != nil {
			return
		}
		// A successful verification against a key the fuzzer does not hold would be
		// a catastrophic false-accept. The only way err==nil here is an astronomical
		// signature collision, so treat it as a failure to surface any logic bug.
		t.Fatalf("VerifyEnvelope accepted unsigned/forged input as valid: %+v", stmt)
	})
}
