package pypiattest

import "testing"

// FuzzParseProvenance asserts the PEP 740 provenance parser never panics on
// malformed/adversarial input — it is the untrusted-input surface a malicious
// upstream can drive. A well-formed object with no usable attestations yields an
// empty slice; undecodable top-level JSON yields an error. Either way, no panic.
func FuzzParseProvenance(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"attestation_bundles":[]}`))
	f.Add([]byte(`{"attestation_bundles":[{"publisher":{"kind":"GitHub"},"attestations":[{"envelope":{"statement":"eyJ9","signature":"AA=="}}]}]}`))
	f.Add([]byte(`{"attestation_bundles":[{"attestations":[{"verification_material":{"certificate":"not-base64!!"},"envelope":{"statement":"","signature":""}}]}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"attestation_bundles":[{"attestations":[{"verification_material":{"transparency_entries":[{"logIndex":"x","inclusionProof":{"hashes":["@@@"]}}]},"envelope":{"statement":"AA","signature":"AA"}}]}]}`))

	f.Fuzz(func(t *testing.T, body []byte) {
		atts, err := parseProvenance(body)
		if err != nil {
			return
		}
		// A successful parse must yield only well-formed attestations (envelope set).
		for _, a := range atts {
			if a.DSSE.Envelope == nil {
				t.Fatal("parsed attestation has a nil envelope")
			}
		}
	})
}
