package compliance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// SignedReport is an exportable compliance-report artifact for auditors. It
// embeds the scorecard verbatim alongside a digest and an optional cryptographic
// signature over the canonical JSON encoding of the scorecard, so a third party
// can verify the report was produced by the proxy and has not been altered.
type SignedReport struct {
	// Scorecard is the report payload.
	Scorecard Scorecard `json:"scorecard"`
	// Digest is the hex SHA-256 of the canonical scorecard JSON (the signed bytes).
	Digest string `json:"digest"`
	// Algorithm is the signature scheme ("ed25519", "ecdsa-p256-sha256",
	// "rsa-pkcs1-sha256"), or "" when the report is unsigned.
	Algorithm string `json:"algorithm,omitempty"`
	// KeyID identifies the signing key (empty when unsigned).
	KeyID string `json:"keyId,omitempty"`
	// Signature is the base64-encoded signature over Digest's preimage (empty when
	// unsigned).
	Signature string `json:"signature,omitempty"`
}

// Signed reports whether the artifact carries a signature.
func (r SignedReport) Signed() bool { return r.Signature != "" }

// Signer signs compliance reports with an operator-supplied private key, reusing
// the same PEM key-material conventions as the audit checkpoint signer (ECDSA,
// RSA, and Ed25519 are supported; the corresponding public key, loadable via
// sigverify.ParsePublicKeyPEM, verifies the report).
type Signer struct {
	priv  crypto.Signer
	keyID string
	alg   string
}

// LoadSigner parses a PEM-encoded private key (PKCS#8, SEC1 "EC PRIVATE KEY", or
// PKCS#1 "RSA PRIVATE KEY") and returns a report Signer.
func LoadSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("compliance: no PEM block found in signing key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("compliance: unsupported signing key PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("compliance: parsing signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("compliance: signing key of type %T does not implement crypto.Signer", key)
	}
	alg, err := algorithmFor(signer.Public())
	if err != nil {
		return nil, err
	}
	return &Signer{priv: signer, keyID: keyID(signer.Public()), alg: alg}, nil
}

// LoadSignerFile reads and parses a PEM private key from path.
func LoadSignerFile(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("compliance: reading signing key: %w", err)
	}
	return LoadSigner(data)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the signer's public key, for callers that want to verify.
func (s *Signer) PublicKey() crypto.PublicKey { return s.priv.Public() }

// BuildSignedReport canonicalizes the scorecard, computes its digest, and signs
// it when a signer is supplied. A nil signer yields an unsigned-but-digested
// artifact.
func BuildSignedReport(card Scorecard, signer *Signer) (SignedReport, error) {
	canon, err := canonicalJSON(card)
	if err != nil {
		return SignedReport{}, fmt.Errorf("compliance: canonicalizing report: %w", err)
	}
	digest := sha256.Sum256(canon)
	report := SignedReport{
		Scorecard: card,
		Digest:    hex(digest[:]),
	}
	if signer == nil {
		return report, nil
	}
	sig, err := signMessage(signer.priv, canon)
	if err != nil {
		return SignedReport{}, fmt.Errorf("compliance: signing report: %w", err)
	}
	report.Algorithm = signer.alg
	report.KeyID = signer.keyID
	report.Signature = base64.StdEncoding.EncodeToString(sig)
	return report, nil
}

// VerifySignedReport recomputes the report's canonical digest and verifies its
// signature against pub. It returns nil only when the digest matches the embedded
// scorecard and the signature is valid. pub may be obtained from
// sigverify.ParsePublicKeyPEM.
func VerifySignedReport(pub crypto.PublicKey, r SignedReport) error {
	canon, err := canonicalJSON(r.Scorecard)
	if err != nil {
		return fmt.Errorf("compliance: canonicalizing report: %w", err)
	}
	digest := sha256.Sum256(canon)
	if hex(digest[:]) != r.Digest {
		return fmt.Errorf("compliance: report digest mismatch (the scorecard was altered)")
	}
	if r.Signature == "" {
		return fmt.Errorf("compliance: report is unsigned")
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("compliance: decoding signature: %w", err)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, canon, sig) {
			return fmt.Errorf("compliance: report signature invalid (ed25519)")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return fmt.Errorf("compliance: report signature invalid (ecdsa)")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("compliance: report signature invalid (rsa): %w", err)
		}
	default:
		return fmt.Errorf("compliance: unsupported public key type %T", pub)
	}
	return nil
}

// canonicalJSON produces a deterministic JSON encoding of the scorecard: Go
// marshals struct fields in declaration order and map keys sorted, so a plain
// Marshal is stable across runs and platforms.
func canonicalJSON(card Scorecard) ([]byte, error) {
	return json.Marshal(card)
}

// signMessage signs msg with the appropriate scheme for the key type: Ed25519
// signs the message directly; ECDSA and RSA sign its SHA-256 digest.
func signMessage(priv crypto.Signer, msg []byte) ([]byte, error) {
	switch priv.Public().(type) {
	case ed25519.PublicKey:
		return priv.Sign(rand.Reader, msg, crypto.Hash(0))
	default:
		digest := sha256.Sum256(msg)
		return priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}

// algorithmFor names the signature scheme for a public key.
func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch pub.(type) {
	case ed25519.PublicKey:
		return "ed25519", nil
	case *ecdsa.PublicKey:
		return "ecdsa-p256-sha256", nil
	case *rsa.PublicKey:
		return "rsa-pkcs1-sha256", nil
	default:
		return "", fmt.Errorf("compliance: unsupported signing key type %T", pub)
	}
}

// keyID derives a short, stable identifier from a public key: the first 8 bytes
// of the SHA-256 of its PKIX/DER encoding, hex-encoded.
func keyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex(sum[:8])
}

// hex encodes bytes as a lowercase hex string.
func hex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0xf]
	}
	return string(out)
}
