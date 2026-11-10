//go:build fuzz
// +build fuzz

package buildprov

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseAttestations exercises the inbound bundle parser — the untrusted-input
// surface fed by upstream registries (a malicious registry can return arbitrary
// JSON). The parser must never panic and must never return material it could not
// structurally decode; any returned attestation must carry a DSSE envelope.
func FuzzParseAttestations(f *testing.F) {
	seeds := []string{
		`{}`,
		`[]`,
		`null`,
		`{"attestations":[]}`,
		`{"attestations":[{"bundle":{}}]}`,
		`{"attestations":[{"bundle":{"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"","signatures":[]}}}]}`,
		`{"attestations":[{"envelope":{"payload":"e30=","signatures":[{"sig":"AA=="}]},"verification_material":{"certificate":{"rawBytes":"AAAA"}}}]}`,
		`{"attestation_bundles":[{"attestations":[{"envelope":{"payload":"e30=","signatures":[]}}]}]}`,
		`{"attestations":[{"bundle":{"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"!!!notbase64"}]}},"dsseEnvelope":{"payload":"e30="}}}]}`,
		`not json`,
		``,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	// Seed with the committed golden fixture too.
	if b, err := os.ReadFile(filepath.Join("testdata", "npm-provenance.json")); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		atts, err := ParseAttestations(data)
		if err != nil {
			// A decode error must yield no material.
			if atts != nil {
				t.Fatalf("error returned with non-nil attestations: %v", err)
			}
			return
		}
		for i := range atts {
			// The parser must only surface attestations carrying an envelope.
			if atts[i].Envelope == nil {
				t.Fatalf("attestation %d has a nil envelope", i)
			}
		}
	})
}
