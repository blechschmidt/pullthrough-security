package attestbundle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
)

// This file implements the DSSE (Dead Simple Signing Envelope) wrapping and
// signing of the in-toto statement, plus verification against a public key. The
// PAE (Pre-Authentication Encoding) and signature schemes are byte-for-byte the
// same as the inbound provenance verifier (internal/provenance) and the audit
// checkpoint signer (internal/audit), so a bundle the proxy emits can be verified
// with the same trust material the proxy already manages.

// Envelope is a DSSE envelope wrapping the base64-encoded in-toto statement.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature over the PAE-encoded payload.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Signer signs DSSE payloads with an operator-supplied private key. The same key
// material conventions as the audit checkpoint signer apply: ECDSA, RSA, and
// Ed25519 PEM keys are accepted, so the proxy can reuse its audit-log signing key
// or a dedicated cosign key. A nil *Signer is invalid; construct one via
// LoadSigner / LoadSignerFile / NewSigner.
type Signer struct {
	priv  crypto.Signer
	keyID string
}

// NewSigner wraps an existing crypto.Signer (e.g. one loaded elsewhere).
func NewSigner(priv crypto.Signer) (*Signer, error) {
	if priv == nil {
		return nil, fmt.Errorf("attestbundle: nil signer")
	}
	switch priv.Public().(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("attestbundle: unsupported signing key type %T", priv.Public())
	}
	return &Signer{priv: priv, keyID: keyID(priv.Public())}, nil
}

// LoadSigner parses a PEM-encoded private key (PKCS#8, SEC1 "EC PRIVATE KEY", or
// PKCS#1 "RSA PRIVATE KEY") into a Signer.
func LoadSigner(pemData []byte) (*Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("attestbundle: no PEM block found in signing key")
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
		return nil, fmt.Errorf("attestbundle: unsupported signing key PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("attestbundle: parsing signing key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("attestbundle: signing key of type %T does not implement crypto.Signer", key)
	}
	return NewSigner(signer)
}

// LoadSignerFile reads and parses a PEM private key from path.
func LoadSignerFile(path string) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("attestbundle: reading signing key: %w", err)
	}
	return LoadSigner(data)
}

// KeyID returns the signer's stable key identifier.
func (s *Signer) KeyID() string { return s.keyID }

// PublicKey returns the signer's public key, for callers that want to verify or
// publish the corresponding verification material.
func (s *Signer) PublicKey() crypto.PublicKey { return s.priv.Public() }

// SignStatement marshals the statement to its canonical payload, DSSE-encodes it,
// signs the PAE, and returns the populated envelope.
func (s *Signer) SignStatement(stmt Statement) (Envelope, error) {
	payload, err := canonicalStatement(stmt)
	if err != nil {
		return Envelope{}, fmt.Errorf("attestbundle: marshaling statement: %w", err)
	}
	return s.signPayload(DSSEPayloadType, payload)
}

func (s *Signer) signPayload(payloadType string, payload []byte) (Envelope, error) {
	sig, err := signMessage(s.priv, dssePAE(payloadType, payload))
	if err != nil {
		return Envelope{}, fmt.Errorf("attestbundle: signing payload: %w", err)
	}
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: s.keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// dssePAE computes the DSSE Pre-Authentication Encoding — the exact bytes signed:
// "DSSEv1 <len(type)> <type> <len(payload)> <payload>". Length-prefixing the
// payloadType into the signed bytes prevents a payload from being reinterpreted
// under a different type.
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

// signMessage signs msg with the scheme appropriate to the key: Ed25519 signs the
// message directly; ECDSA and RSA sign its SHA-256 digest (RSA via PKCS#1 v1.5).
func signMessage(priv crypto.Signer, msg []byte) ([]byte, error) {
	switch priv.Public().(type) {
	case ed25519.PublicKey:
		return priv.Sign(nil, msg, crypto.Hash(0))
	default:
		digest := sha256.Sum256(msg)
		return priv.Sign(randReader, digest[:], crypto.SHA256)
	}
}

// VerifyEnvelope verifies the DSSE signature(s) on env against pub and returns the
// decoded statement. It returns an error if no signature verifies or the payload
// is malformed. This is the verification a downstream consumer (or the
// `attest verify` CLI) performs with the proxy's public key.
func VerifyEnvelope(pub crypto.PublicKey, env Envelope) (Statement, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("attestbundle: decoding payload: %w", err)
	}
	if len(env.Signatures) == 0 {
		return Statement{}, fmt.Errorf("attestbundle: envelope has no signatures")
	}
	pae := dssePAE(env.PayloadType, payload)
	verified := false
	for _, s := range env.Signatures {
		raw, derr := base64.StdEncoding.DecodeString(s.Sig)
		if derr != nil {
			continue
		}
		if verifySignature(pub, pae, raw) {
			verified = true
			break
		}
	}
	if !verified {
		return Statement{}, fmt.Errorf("attestbundle: no DSSE signature verified against the provided key")
	}
	stmt, err := decodeStatement(payload)
	if err != nil {
		return Statement{}, err
	}
	return stmt, nil
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
// of the SHA-256 of its PKIX/DER encoding, hex-encoded. It matches the audit
// package's keyID derivation so the same key reports the same id everywhere.
func keyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}
