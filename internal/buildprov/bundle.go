package buildprov

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// This file parses the inbound provenance response shapes registries publish into
// the signature gate's DSSEAttestation, the input the shared verifier consumes.
// It is the untrusted-input surface this subsystem exposes (a malicious upstream
// can return arbitrary JSON), so it is hand-rolled, allocation-bounded, and
// covered by a fuzz target (fuzz_test.go). Parsing never trusts a byte: every
// decoded attestation is cryptographically verified downstream before it can
// influence a decision.

// maxAttestationBytes bounds a provenance response read.
const maxAttestationBytes = 8 << 20 // 8 MiB

// providerDocument is the union of the response shapes the understood providers
// use to expose Sigstore attestations:
//
//   - npm: {"attestations":[{"predicateType":...,"bundle":{<sigstore bundle>}}]}
//   - GitHub: {"attestations":[{"bundle":{<sigstore bundle>}}]}
//   - PEP 740 inline: {"attestation_bundles":[{"attestations":[{"envelope":...,
//     "verification_material":...}]}]}
//
// The npm and GitHub shapes coincide on the {"attestations":[{"bundle":...}]}
// envelope, so one parser handles both.
type providerDocument struct {
	Attestations []struct {
		Bundle json.RawMessage `json:"bundle"`
		// Inline (PEP 740) form.
		Envelope             *sigverify.Envelope         `json:"envelope"`
		VerificationMaterial *bundleVerificationMaterial `json:"verification_material"`
	} `json:"attestations"`
	AttestationBundles []struct {
		Attestations []struct {
			Envelope             *sigverify.Envelope         `json:"envelope"`
			VerificationMaterial *bundleVerificationMaterial `json:"verification_material"`
		} `json:"attestations"`
	} `json:"attestation_bundles"`
}

// sigstoreBundle is the Sigstore bundle (protobuf-JSON) carrying the signing
// certificate (or chain) and the DSSE envelope.
type sigstoreBundle struct {
	MediaType            string                     `json:"mediaType"`
	VerificationMaterial bundleVerificationMaterial `json:"verificationMaterial"`
	DSSEEnvelope         *sigverify.Envelope        `json:"dsseEnvelope"`
}

// bundleVerificationMaterial carries the signing certificate (single, v0.3+) or
// chain (older bundles). The transparency-log entries are tolerated but not
// consumed here (inbound Rekor SET verification is out of scope for this gate).
type bundleVerificationMaterial struct {
	Certificate *struct {
		RawBytes string `json:"rawBytes"`
	} `json:"certificate"`
	X509CertificateChain *struct {
		Certificates []struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificates"`
	} `json:"x509CertificateChain"`
	TlogEntries []json.RawMessage `json:"tlogEntries"`
}

// certificates parses the leaf certificate and chain from verification material.
func (m *bundleVerificationMaterial) certificates() (leaf *x509.Certificate, chain []*x509.Certificate) {
	if m == nil {
		return nil, nil
	}
	var raws []string
	if m.Certificate != nil && m.Certificate.RawBytes != "" {
		raws = append(raws, m.Certificate.RawBytes)
	}
	if m.X509CertificateChain != nil {
		for _, c := range m.X509CertificateChain.Certificates {
			if c.RawBytes != "" {
				raws = append(raws, c.RawBytes)
			}
		}
	}
	var certs []*x509.Certificate
	for _, raw := range raws {
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(der); err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return certs[0], certs[1:]
}

// ParseAttestations decodes a provider attestation response (npm provenance or a
// GitHub artifact-attestation document) into DSSE attestation material. It
// tolerates the npm/GitHub bundle-wrapped form and the PEP 740 inline form, and
// never panics on malformed input (the fuzz target asserts this). It returns an
// error only when the top-level JSON is undecodable; a well-formed document with
// no usable attestations yields an empty slice.
func ParseAttestations(body []byte) ([]sigverify.DSSEAttestation, error) {
	var doc providerDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decoding attestation document: %w", err)
	}

	var out []sigverify.DSSEAttestation
	for _, a := range doc.Attestations {
		if len(a.Bundle) > 0 {
			if att, ok := attestationFromBundle(a.Bundle); ok {
				out = append(out, att)
			}
			continue
		}
		if a.Envelope != nil {
			out = append(out, attestationFromInline(a.Envelope, a.VerificationMaterial))
		}
	}
	for _, b := range doc.AttestationBundles {
		for _, a := range b.Attestations {
			if a.Envelope != nil {
				out = append(out, attestationFromInline(a.Envelope, a.VerificationMaterial))
			}
		}
	}
	return out, nil
}

// attestationFromBundle decodes a Sigstore bundle into attestation material.
func attestationFromBundle(raw json.RawMessage) (sigverify.DSSEAttestation, bool) {
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil || b.DSSEEnvelope == nil {
		return sigverify.DSSEAttestation{}, false
	}
	leaf, chain := b.VerificationMaterial.certificates()
	return sigverify.DSSEAttestation{Envelope: b.DSSEEnvelope, Cert: leaf, Chain: chain}, true
}

// attestationFromInline builds attestation material from a PEP 740 inline
// envelope + verification material.
func attestationFromInline(env *sigverify.Envelope, vm *bundleVerificationMaterial) sigverify.DSSEAttestation {
	att := sigverify.DSSEAttestation{Envelope: env}
	if vm != nil {
		att.Cert, att.Chain = vm.certificates()
	}
	return att
}
