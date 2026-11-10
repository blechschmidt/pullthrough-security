package vexexport

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
)

// Signer produces a detached signature over the exact bytes of an exported VEX
// document, reusing the same PEM key-material conventions as the audit
// checkpoint, outbound-attestation, and compliance-report signers (ECDSA-P256,
// RSA-PKCS1v15, and Ed25519 are supported; the matching public key verifies via
// sigverify.ParsePublicKeyPEM). A detached signature leaves the document itself
// byte-for-byte unmodified, so a cosign-signed export still re-ingests cleanly
// through the VEX suppression gate.
type Signer struct {
	priv  crypto.Signer
	keyID string
	alg   string
}

// Signature is a detached signature over a document's exact bytes.
type Signature struct {
	// Algorithm is the signature scheme ("ed25519", "ecdsa-p256-sha256",
	// "rsa-pkcs1-sha256").
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key (first 8 bytes of the SHA-256 of the PKIX
	// public key, hex-encoded).
	KeyID string `json:"keyId"`
	// Digest is the hex SHA-256 of the signed document bytes.
	Digest string `json:"digest"`
	// Value is the base64-encoded signature.
	Value string `json:"signature"`
}

// LoadSigner parses a PEM-encoded private key (PKCS#8, SEC1 "EC PRIVATE KEY", or
// PKCS#1 "RSA PRIVATE KEY") and returns a document Signer.
func LoadSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("vexexport: no PEM block found in signing key")
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
		return nil, fmt.Errorf("vexexport: unsupported signing key PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("vexexport: parsing signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("vexexport: signing key of type %T does not implement crypto.Signer", key)
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
		return nil, fmt.Errorf("vexexport: reading signing key: %w", err)
	}
	return LoadSigner(data)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// Algorithm returns the signer's signature scheme.
func (s *Signer) Algorithm() string { return s.alg }

// PublicKey returns the signer's public key, for callers that want to verify.
func (s *Signer) PublicKey() crypto.PublicKey { return s.priv.Public() }

// Sign computes a detached signature over doc (the exact bytes a consumer will
// verify). Ed25519 signs the message directly; ECDSA and RSA sign its SHA-256
// digest — matching the verification scheme in VerifySignature.
func (s *Signer) Sign(doc []byte) (Signature, error) {
	digest := sha256.Sum256(doc)
	var raw []byte
	var err error
	switch s.priv.Public().(type) {
	case ed25519.PublicKey:
		raw, err = s.priv.Sign(rand.Reader, doc, crypto.Hash(0))
	default:
		raw, err = s.priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return Signature{}, fmt.Errorf("vexexport: signing document: %w", err)
	}
	return Signature{
		Algorithm: s.alg,
		KeyID:     s.keyID,
		Digest:    hex.EncodeToString(digest[:]),
		Value:     base64.StdEncoding.EncodeToString(raw),
	}, nil
}

// VerifySignature verifies a detached signature over doc against pub. It returns
// nil only when the embedded digest matches doc and the signature is valid. pub
// may be obtained from sigverify.ParsePublicKeyPEM.
func VerifySignature(pub crypto.PublicKey, doc []byte, sig Signature) error {
	digest := sha256.Sum256(doc)
	if hex.EncodeToString(digest[:]) != sig.Digest {
		return fmt.Errorf("vexexport: document digest mismatch (the document was altered)")
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("vexexport: decoding signature: %w", err)
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, doc, raw) {
			return fmt.Errorf("vexexport: signature invalid (ed25519)")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest[:], raw) {
			return fmt.Errorf("vexexport: signature invalid (ecdsa)")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], raw); err != nil {
			return fmt.Errorf("vexexport: signature invalid (rsa): %w", err)
		}
	default:
		return fmt.Errorf("vexexport: unsupported public key type %T", pub)
	}
	return nil
}

func algorithmFor(pub crypto.PublicKey) (string, error) {
	switch pub.(type) {
	case ed25519.PublicKey:
		return "ed25519", nil
	case *ecdsa.PublicKey:
		return "ecdsa-p256-sha256", nil
	case *rsa.PublicKey:
		return "rsa-pkcs1-sha256", nil
	default:
		return "", fmt.Errorf("vexexport: unsupported signing key type %T", pub)
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
	return hex.EncodeToString(sum[:8])
}
