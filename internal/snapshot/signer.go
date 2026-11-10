package snapshot

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

// Signer signs snapshot manifests with an operator-supplied private key. The same
// key-material conventions as the audit checkpoint signer and the attestbundle
// DSSE signer apply: ECDSA, RSA, and Ed25519 PEM keys are accepted, so the proxy
// reuses its audit-log signing key to sign snapshots — a snapshot is, like a
// checkpoint, a signed commitment to a point-in-time state. A nil *Signer is
// valid and yields unsigned manifests; construct one via LoadSigner /
// LoadSignerFile / NewSigner.
type Signer struct {
	priv  crypto.Signer
	keyID string
}

// NewSigner wraps an existing crypto.Signer (e.g. one loaded elsewhere) so the
// proxy can share a single key across the audit, attestation, and snapshot
// subsystems.
func NewSigner(priv crypto.Signer) (*Signer, error) {
	if priv == nil {
		return nil, fmt.Errorf("snapshot: nil signer")
	}
	switch priv.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("snapshot: unsupported signing key type %T", priv.Public())
	}
	return &Signer{priv: priv, keyID: keyID(priv.Public())}, nil
}

// LoadSigner parses a PEM-encoded private key (PKCS#8, SEC1 "EC PRIVATE KEY", or
// PKCS#1 "RSA PRIVATE KEY") and returns a snapshot Signer.
func LoadSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("snapshot: no PEM block found in signing key")
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("snapshot: parsing signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("snapshot: signing key of type %T does not implement crypto.Signer", key)
	}
	return NewSigner(signer)
}

// LoadSignerFile loads a PEM private key from a file.
func LoadSignerFile(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("snapshot: reading signing key file: %w", err)
	}
	return LoadSigner(data)
}

// KeyID returns the signer's stable key identifier.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// PublicKey returns the public half of the signing key, for verification.
func (s *Signer) PublicKey() crypto.PublicKey {
	if s == nil {
		return nil
	}
	return s.priv.Public()
}

// sign signs msg and returns the base64-encoded signature.
func (s *Signer) sign(msg []byte) (string, error) {
	sig, err := signMessage(s.priv, msg)
	if err != nil {
		return "", fmt.Errorf("snapshot: signing manifest: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// signMessage signs msg with the scheme appropriate to the key: Ed25519 signs the
// message directly; ECDSA and RSA sign its SHA-256 digest (RSA via PKCS#1 v1.5).
func signMessage(priv crypto.Signer, msg []byte) ([]byte, error) {
	switch priv.Public().(type) {
	case ed25519.PublicKey:
		return priv.Sign(nil, msg, crypto.Hash(0))
	default:
		digest := sha256.Sum256(msg)
		return priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}

// VerifyManifest verifies the signature on m against pub. It recomputes the
// content digest over the manifest's content and checks both that it matches the
// recorded ContentDigest (content addressing) and that the signature is valid.
// It returns nil on success. An unsigned manifest (no signature) returns an
// error; callers that accept unsigned manifests should check m.Signature first.
func VerifyManifest(pub crypto.PublicKey, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("snapshot: nil manifest")
	}
	want := m.computeDigest()
	if want != m.ContentDigest {
		return fmt.Errorf("snapshot: content digest mismatch: manifest claims %s, recomputed %s", m.ContentDigest, want)
	}
	if m.Signature == "" {
		return fmt.Errorf("snapshot: manifest is unsigned")
	}
	raw, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("snapshot: decoding signature: %w", err)
	}
	if !verifySignature(pub, []byte(m.ContentDigest), raw) {
		return fmt.Errorf("snapshot: signature does not verify against the provided key")
	}
	return nil
}

// verifySignature checks a raw signature over message against pub for the
// supported key types.
func verifySignature(pub crypto.PublicKey, message, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, message, sig)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(k, digest[:], sig)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) == nil
	default:
		return false
	}
}

// keyID derives a short, stable identifier from a public key: the first 8 bytes
// of the SHA-256 of its PKIX/DER encoding, hex-encoded. It matches the audit and
// attestbundle keyID derivation so the same key reports the same id everywhere.
func keyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}
