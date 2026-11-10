package provenance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// This file establishes trust in an attestation. Two independent properties must
// both hold before a Link is labeled ConfidenceAttested:
//
//  1. Signature integrity — the DSSE envelope's signature verifies, over the
//     PAE-encoded payload, against the public key in the signing certificate.
//  2. Certificate trust — that signing certificate chains to a root the operator
//     trusts (Sigstore's Fulcio root for keyless signing, or a corporate CA).
//
// Without (1) the payload can be tampered with; without (2) anyone can self-sign
// a certificate and forge "valid" provenance. The Verifier couples them: a
// missing trust root degrades the result to ConfidenceClaimed rather than
// silently accepting an unrooted certificate as attested.
//
// SECURITY (scope): we deliberately do NOT implement Rekor transparency-log
// inclusion proofs or Fulcio certificate-extension policy (OIDC issuer / SAN
// allow-listing) here — those require pinning Sigstore's log public keys and a
// policy engine, and are layered by the policy stage (Task 9). What we provide is
// the cryptographic core every higher layer depends on, with an honest
// confidence label so a partially-verified attestation is never overstated.

// ErrUntrusted indicates an attestation's signature did not verify or its
// certificate did not chain to a trusted root.
var ErrUntrusted = errors.New("provenance: attestation failed verification")

// VerifiedAttestation is the result of verifying an attestation bundle: the
// authenticated in-toto statement plus the trust facts established about it.
type VerifiedAttestation struct {
	Statement *inTotoStatement
	// SignatureValid reports that the DSSE signature verified against the signing
	// certificate's public key.
	SignatureValid bool
	// ChainTrusted reports that the signing certificate chained to a configured
	// trust root. When no trust root is configured it is false and the caller
	// must treat the attestation as claimed, not attested.
	ChainTrusted bool
	// SignerIdentity is the certificate's first SAN URI (the keyless signing
	// identity, e.g. the GitHub Actions workflow ref), when present.
	SignerIdentity string
	// Raw is the original bundle bytes, retained for audit/storage.
	Raw []byte
}

// Confidence maps the verification facts to a provenance Confidence.
func (v *VerifiedAttestation) confidence() Confidence {
	switch {
	case v.SignatureValid && v.ChainTrusted:
		return ConfidenceAttested
	case v.SignatureValid:
		// Authentic envelope, but the signer is not anchored to a trusted root:
		// cryptographically present yet not provably from the expected build
		// system. Treat as a claim, not an attestation.
		return ConfidenceClaimed
	default:
		return ConfidenceHeuristic
	}
}

// Verifier verifies attestation bundles. Roots, when non-nil, is the trust anchor
// the signing certificate must chain to (e.g. the Fulcio root). When nil, chain
// trust cannot be established and verified attestations are labeled claimed.
type Verifier struct {
	roots *x509.CertPool
	// now supplies the verification time; injectable for tests. The signing
	// certificate's validity window is checked against it.
	now func() time.Time
}

// NewVerifier constructs a Verifier trusting roots (may be nil).
func NewVerifier(roots *x509.CertPool) *Verifier {
	return &Verifier{roots: roots, now: time.Now}
}

// sigstoreBundle is the subset of a Sigstore bundle (protobuf-JSON) we consume:
// the signing certificate and the DSSE envelope.
type sigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		// Newer bundles (v0.3) carry a single certificate.
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		// Older bundles carry a chain.
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
	} `json:"verificationMaterial"`
	DSSEEnvelope *dsseEnvelope `json:"dsseEnvelope"`
}

// certificates returns the leaf and any intermediates from the bundle's
// verification material, leaf first.
func (b *sigstoreBundle) certificates() ([]*x509.Certificate, error) {
	var rawList []string
	switch {
	case b.VerificationMaterial.Certificate != nil:
		rawList = []string{b.VerificationMaterial.Certificate.RawBytes}
	case b.VerificationMaterial.X509CertificateChain != nil:
		for _, c := range b.VerificationMaterial.X509CertificateChain.Certificates {
			rawList = append(rawList, c.RawBytes)
		}
	}
	if len(rawList) == 0 {
		return nil, fmt.Errorf("provenance: bundle carries no signing certificate")
	}
	out := make([]*x509.Certificate, 0, len(rawList))
	for _, raw := range rawList {
		der, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("provenance: decoding certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("provenance: parsing certificate: %w", err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// VerifyBundle verifies a Sigstore bundle (as served by GitHub's attestation API
// or cosign) and returns the authenticated statement and trust facts. It does NOT
// check the subject digest binding — the caller does that against the specific
// artifact via VerifiedAttestation.Statement.BindsDigest.
func (v *Verifier) VerifyBundle(raw []byte) (*VerifiedAttestation, error) {
	var bundle sigstoreBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("provenance: decoding bundle: %w", err)
	}
	if bundle.DSSEEnvelope == nil {
		return nil, fmt.Errorf("provenance: bundle has no DSSE envelope")
	}
	return v.verifyEnvelope(bundle.DSSEEnvelope, &bundle, raw)
}

// VerifyEnvelope verifies a bare DSSE envelope that carries its own signing
// certificate out of band (the OCI/cosign layer supplies the cert chain it pulled
// from the attestation manifest). certs is leaf-first.
func (v *Verifier) VerifyEnvelope(env *dsseEnvelope, certs []*x509.Certificate, raw []byte) (*VerifiedAttestation, error) {
	return v.verifyWithCerts(env, certs, raw)
}

func (v *Verifier) verifyEnvelope(env *dsseEnvelope, bundle *sigstoreBundle, raw []byte) (*VerifiedAttestation, error) {
	certs, err := bundle.certificates()
	if err != nil {
		return nil, err
	}
	return v.verifyWithCerts(env, certs, raw)
}

func (v *Verifier) verifyWithCerts(env *dsseEnvelope, certs []*x509.Certificate, raw []byte) (*VerifiedAttestation, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("provenance: no signing certificate to verify against")
	}
	leaf := certs[0]

	payload, err := env.decodedPayload()
	if err != nil {
		return nil, err
	}
	pae := dssePAE(env.PayloadType, payload)

	sigValid := false
	for _, s := range env.Signatures {
		sig, derr := base64.StdEncoding.DecodeString(s.Sig)
		if derr != nil {
			continue
		}
		if verifySignature(leaf.PublicKey, pae, sig) {
			sigValid = true
			break
		}
	}
	if !sigValid {
		return nil, fmt.Errorf("%w: DSSE signature does not verify", ErrUntrusted)
	}

	stmt, err := parseStatement(payload)
	if err != nil {
		return nil, err
	}

	att := &VerifiedAttestation{
		Statement:      stmt,
		SignatureValid: true,
		SignerIdentity: signerIdentity(leaf),
		Raw:            raw,
	}
	att.ChainTrusted = v.chainTrusted(certs)
	return att, nil
}

// chainTrusted verifies that the leaf certificate chains to a configured root.
// With no roots configured it returns false (cannot establish trust).
func (v *Verifier) chainTrusted(certs []*x509.Certificate) bool {
	if v.roots == nil || len(certs) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		// Code-signing certs (Fulcio) carry ExtKeyUsageCodeSigning; accept any so
		// we do not reject a valid chain over EKU pedantry the policy layer owns.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// signerIdentity returns the leaf certificate's first SAN URI, which for keyless
// (Fulcio) signing is the workload identity that signed — e.g. the GitHub Actions
// workflow ref. Empty when the certificate carries no URI SAN.
func signerIdentity(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	return ""
}

// dssePAE computes the DSSE Pre-Authentication Encoding, the exact byte string
// that is signed: "DSSEv1 <len(type)> <type> <len(payload)> <payload>". Binding
// the payloadType length-prefixed into the signed bytes prevents a payload from
// being reinterpreted under a different type.
func dssePAE(payloadType string, payload []byte) []byte {
	const prefix = "DSSEv1"
	out := make([]byte, 0, len(prefix)+len(payloadType)+len(payload)+24)
	out = append(out, prefix...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payload))...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// verifySignature checks sig over message using pub, dispatching on key type.
// ECDSA and RSA signatures are over the SHA-256 of the message; Ed25519 signs the
// message directly.
func verifySignature(pub crypto.PublicKey, message, sig []byte) bool {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(key, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(key, message, sig)
	default:
		return false
	}
}
