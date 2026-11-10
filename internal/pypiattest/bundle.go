package pypiattest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/rekor"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
)

// This file parses the PEP 740 provenance object PyPI serves into the signature
// gate's DSSEAttestation, the input the shared verifier consumes. It is the
// untrusted-input surface this subsystem exposes (a malicious upstream can return
// arbitrary JSON), so it is hand-rolled, allocation-bounded, and covered by a
// fuzz target (fuzz_test.go). Parsing never trusts a byte: every decoded
// attestation is cryptographically verified downstream before it can influence a
// decision.
//
// The PEP 740 attestation envelope is NOT a standard DSSE envelope on the wire.
// It is the compact {"statement": <base64 in-toto statement>, "signature":
// <base64 signature>} form. in-toto/DSSE verification (and the shared
// sigverify.Verifier) expects a DSSE envelope: a payloadType, the base64 payload,
// and a list of base64 signatures. The signature was produced over the DSSE
// pre-authentication encoding (PAE) of ("application/vnd.in-toto+json", statement)
// — the Sigstore in-toto payload type — so we reconstruct exactly that envelope.
// Getting this reconstruction right is the core of correct PEP 740 verification.

// maxProvenanceBytes bounds a provenance response read.
const maxProvenanceBytes = 8 << 20 // 8 MiB

// inTotoPayloadType is the DSSE payload type Sigstore/in-toto attestations (and
// PyPI PEP 740) are signed under.
const inTotoPayloadType = "application/vnd.in-toto+json"

// provenanceObject is the PEP 740 provenance object:
//
//	{
//	  "version": 1,
//	  "attestation_bundles": [
//	    {
//	      "publisher": {"kind": "GitHub", "repository": "o/r", "workflow": "...", ...},
//	      "attestations": [
//	        {
//	          "version": 1,
//	          "verification_material": {"certificate": "<b64 DER>", "transparency_entries": [ ... ]},
//	          "envelope": {"statement": "<b64>", "signature": "<b64>"}
//	        }
//	      ]
//	    }
//	  ]
//	}
type provenanceObject struct {
	Version            int `json:"version"`
	AttestationBundles []struct {
		Publisher    pep740Publisher     `json:"publisher"`
		Attestations []pep740Attestation `json:"attestations"`
	} `json:"attestation_bundles"`
}

type pep740Publisher struct {
	Kind        string `json:"kind"`
	Repository  string `json:"repository"`
	Workflow    string `json:"workflow"`
	Environment string `json:"environment"`
}

type pep740Attestation struct {
	Version              int `json:"version"`
	VerificationMaterial struct {
		// Certificate is the base64-encoded signing certificate. PyPI/sigstore encode
		// the DER; some producers encode PEM. Both are tolerated.
		Certificate         string                 `json:"certificate"`
		TransparencyEntries []transparencyLogEntry `json:"transparency_entries"`
		// X509CertificateChain is tolerated for bundles that carry a chain instead of
		// a single certificate.
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509_certificate_chain"`
	} `json:"verification_material"`
	Envelope struct {
		Statement string `json:"statement"`
		Signature string `json:"signature"`
	} `json:"envelope"`
}

// transparencyLogEntry mirrors the Sigstore protobuf-JSON TransparencyLogEntry
// PyPI embeds. All binary fields are base64 (the protobuf-JSON convention); the
// shared rekor verifier expects hex for the Merkle hashes and log id, so the
// mapping re-encodes them.
type transparencyLogEntry struct {
	LogIndex string `json:"logIndex"`
	LogID    struct {
		KeyID string `json:"keyId"`
	} `json:"logId"`
	IntegratedTime   string `json:"integratedTime"`
	InclusionPromise struct {
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof struct {
		LogIndex   string   `json:"logIndex"`
		RootHash   string   `json:"rootHash"`
		TreeSize   string   `json:"treeSize"`
		Hashes     []string `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
	CanonicalizedBody string `json:"canonicalizedBody"`
}

// parseProvenance decodes a PEP 740 provenance object into attestation material.
// It never panics on malformed input (the fuzz target asserts this). It returns
// an error only when the top-level JSON is undecodable; a well-formed object with
// no usable attestations yields an empty slice.
func parseProvenance(body []byte) ([]ParsedAttestation, error) {
	var obj provenanceObject
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("decoding PEP 740 provenance object: %w", err)
	}

	var out []ParsedAttestation
	for _, bundle := range obj.AttestationBundles {
		pub := Publisher{
			Kind:        strings.TrimSpace(bundle.Publisher.Kind),
			Repository:  strings.TrimSpace(bundle.Publisher.Repository),
			Workflow:    strings.TrimSpace(bundle.Publisher.Workflow),
			Environment: strings.TrimSpace(bundle.Publisher.Environment),
		}
		for i := range bundle.Attestations {
			att := &bundle.Attestations[i]
			dsse, ok := reconstructDSSE(att)
			if !ok {
				continue
			}
			out = append(out, ParsedAttestation{
				DSSE:       dsse,
				Publisher:  pub,
				LogEntries: mapTransparencyEntries(att.VerificationMaterial.TransparencyEntries),
			})
		}
	}
	return out, nil
}

// reconstructDSSE rebuilds the standard DSSE envelope and certificate material the
// shared verifier consumes from a PEP 740 attestation's compact {statement,
// signature} envelope. ok is false when the attestation carries no statement or
// signature (nothing verifiable).
func reconstructDSSE(att *pep740Attestation) (sigverify.DSSEAttestation, bool) {
	stmt := strings.TrimSpace(att.Envelope.Statement)
	sig := strings.TrimSpace(att.Envelope.Signature)
	if stmt == "" || sig == "" {
		return sigverify.DSSEAttestation{}, false
	}
	env := &sigverify.Envelope{
		PayloadType: inTotoPayloadType,
		Payload:     stmt,
		Signatures:  []sigverify.EnvelopeSignature{{Sig: sig}},
	}
	leaf, chain := att.certificates()
	return sigverify.DSSEAttestation{Envelope: env, Cert: leaf, Chain: chain}, true
}

// certificates parses the signing certificate (and any chain) from a PEP 740
// attestation's verification material, tolerating both base64-DER and PEM.
func (att *pep740Attestation) certificates() (leaf *x509.Certificate, chain []*x509.Certificate) {
	var certs []*x509.Certificate
	if c := parseCertificate(att.VerificationMaterial.Certificate); c != nil {
		certs = append(certs, c)
	}
	if ch := att.VerificationMaterial.X509CertificateChain; ch != nil {
		for _, c := range ch.Certificates {
			if cert := parseCertificate(c.RawBytes); cert != nil {
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	return certs[0], certs[1:]
}

// parseCertificate decodes a certificate encoded as base64 DER or PEM. It returns
// nil on any decode/parse failure (never panics).
func parseCertificate(encoded string) *x509.Certificate {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil
	}
	// PEM carried verbatim.
	if strings.Contains(s, "-----BEGIN") {
		if block, _ := pem.Decode([]byte(s)); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert
			}
		}
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	// A base64-encoded PEM block (some producers do this).
	if block, _ := pem.Decode(der); block != nil {
		if cert, perr := x509.ParseCertificate(block.Bytes); perr == nil {
			return cert
		}
	}
	if cert, perr := x509.ParseCertificate(der); perr == nil {
		return cert
	}
	return nil
}

// mapTransparencyEntries converts PEP 740 transparency entries into the shared
// rekor.LogEntry shape. The protobuf-JSON binary fields are base64; rekor's
// verifier expects the Merkle hashes and log id in hex (matching the cosign
// bundle form the signature gate already understands), so they are re-encoded.
// Malformed entries are skipped rather than failing the whole parse.
func mapTransparencyEntries(entries []transparencyLogEntry) []*rekor.LogEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]*rekor.LogEntry, 0, len(entries))
	for i := range entries {
		if e := mapTransparencyEntry(&entries[i]); e != nil {
			out = append(out, e)
		}
	}
	return out
}

func mapTransparencyEntry(t *transparencyLogEntry) *rekor.LogEntry {
	if strings.TrimSpace(t.CanonicalizedBody) == "" {
		return nil
	}
	e := &rekor.LogEntry{
		LogIndex:       parseInt64(t.LogIndex),
		IntegratedTime: parseInt64(t.IntegratedTime),
		Body:           strings.TrimSpace(t.CanonicalizedBody),
		SET:            strings.TrimSpace(t.InclusionPromise.SignedEntryTimestamp),
		LogID:          base64ToHex(t.LogID.KeyID),
	}
	if ip := t.InclusionProof; strings.TrimSpace(ip.RootHash) != "" {
		hashes := make([]string, 0, len(ip.Hashes))
		for _, h := range ip.Hashes {
			hashes = append(hashes, base64ToHex(h))
		}
		e.InclusionProof = &rekor.InclusionProof{
			LogIndex:   parseInt64(ip.LogIndex),
			RootHash:   base64ToHex(ip.RootHash),
			TreeSize:   parseInt64(ip.TreeSize),
			Hashes:     hashes,
			Checkpoint: strings.TrimSpace(ip.Checkpoint.Envelope),
		}
	}
	return e
}

// base64ToHex decodes a base64 (std or url-safe) string and re-encodes it as
// lower-hex. A value that is already valid hex is returned unchanged, so an
// entry that happens to carry hex (a non-conformant producer) still works.
func base64ToHex(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return hex.EncodeToString(b)
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return hex.EncodeToString(b)
	}
	if _, err := hex.DecodeString(s); err == nil {
		return strings.ToLower(s)
	}
	return ""
}

func parseInt64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
