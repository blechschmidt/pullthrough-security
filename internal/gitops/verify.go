package gitops

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// VerifyResult records the outcome of verifying a fetched bundle against the
// configured trust material.
type VerifyResult struct {
	// Digest is the SHA-256 of the bundle bytes, always computed.
	Digest string `json:"digest"`
	// DigestPinned reports whether an expected digest was configured.
	DigestPinned bool `json:"digestPinned"`
	// DigestOK reports whether the bundle matched the pinned digest (true when no
	// digest is pinned).
	DigestOK bool `json:"digestOk"`
	// SignatureChecked reports whether a signature verification was attempted (a
	// trusted public key was configured and a detached signature was present).
	SignatureChecked bool `json:"signatureChecked"`
	// SignatureOK reports whether the detached signature verified against the
	// trusted key.
	SignatureOK bool `json:"signatureOk"`
	// KeyID is the trusted public key's stable identifier, when configured.
	KeyID string `json:"keyId,omitempty"`
	// Verified is the overall verdict: every configured check passed.
	Verified bool `json:"verified"`
	// Reason explains a failed or skipped verification.
	Reason string `json:"reason,omitempty"`
}

// Verifier checks a fetched bundle's integrity and authenticity against operator-
// configured trust material: an optional pinned content digest (air-gap friendly)
// and an optional trusted public key against which a detached signature is checked.
// The signature scheme is byte-for-byte the audit/attestbundle convention: Ed25519
// signs the message directly; ECDSA and RSA sign its SHA-256 digest. A Verifier
// with neither a pinned digest nor a key configured performs only the (always-on)
// digest computation and reports Verified=true (unverified-but-allowed); the
// service's fail-closed policy decides whether that is acceptable.
type Verifier struct {
	expectedDigest string
	pub            crypto.PublicKey
	keyID          string
}

// NewVerifier builds a Verifier from a PEM-encoded trusted public key (optional)
// and a pinned hex SHA-256 digest (optional). An empty/whitespace key or digest is
// treated as "not configured".
func NewVerifier(pubKeyPEM []byte, expectedDigest string) (*Verifier, error) {
	v := &Verifier{expectedDigest: strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expectedDigest), "sha256:")))}
	if len(strings.TrimSpace(string(pubKeyPEM))) > 0 {
		pub, kid, err := parsePublicKey(pubKeyPEM)
		if err != nil {
			return nil, err
		}
		v.pub = pub
		v.keyID = kid
	}
	return v, nil
}

// HasKey reports whether a trusted public key is configured.
func (v *Verifier) HasKey() bool { return v != nil && v.pub != nil }

// HasDigestPin reports whether a content digest is pinned.
func (v *Verifier) HasDigestPin() bool { return v != nil && v.expectedDigest != "" }

// KeyID returns the trusted key's identifier ("" when no key is configured).
func (v *Verifier) KeyID() string {
	if v == nil {
		return ""
	}
	return v.keyID
}

// Verify computes the bundle digest, checks it against any pinned digest, and (when
// a key is configured and a detached signature is supplied) verifies the signature.
// signature may be nil/empty; rawSig is interpreted as base64 first and, failing
// that, as raw signature bytes, so a `.sig` file may hold either form.
func (v *Verifier) Verify(bundle, signature []byte) VerifyResult {
	res := VerifyResult{Digest: Digest(bundle), DigestOK: true}
	if v == nil {
		res.Verified = true
		return res
	}
	res.KeyID = v.keyID

	if v.expectedDigest != "" {
		res.DigestPinned = true
		res.DigestOK = res.Digest == v.expectedDigest
		if !res.DigestOK {
			res.Reason = fmt.Sprintf("bundle digest %s does not match pinned digest %s", res.Digest, v.expectedDigest)
			res.Verified = false
			return res
		}
	}

	if v.pub != nil {
		res.SignatureChecked = true
		sig := decodeSignature(signature)
		if len(sig) == 0 {
			res.SignatureOK = false
			res.Reason = "a trusted key is configured but the bundle carries no detached signature"
			res.Verified = false
			return res
		}
		res.SignatureOK = verifyDetached(v.pub, bundle, sig)
		if !res.SignatureOK {
			res.Reason = "detached signature did not verify against the trusted key"
			res.Verified = false
			return res
		}
	}

	res.Verified = res.DigestOK && (!res.SignatureChecked || res.SignatureOK)
	return res
}

// decodeSignature interprets a detached-signature blob as base64 first, then as raw
// bytes. Whitespace is trimmed so a `.sig` file with a trailing newline works.
func decodeSignature(sig []byte) []byte {
	trimmed := strings.TrimSpace(string(sig))
	if trimmed == "" {
		return nil
	}
	if raw, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(raw) > 0 {
		return raw
	}
	return []byte(trimmed)
}

// parsePublicKey parses a PEM-encoded public key (PKIX/SubjectPublicKeyInfo) into a
// crypto.PublicKey and derives the same short key id the audit/attestbundle signer
// reports for the corresponding private key.
func parsePublicKey(pemData []byte) (crypto.PublicKey, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", fmt.Errorf("gitops: no PEM block found in trusted public key")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("gitops: parsing trusted public key: %w", err)
		}
		switch pub.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
			return pub, keyID(pub), nil
		default:
			return nil, "", fmt.Errorf("gitops: unsupported trusted public key type %T", pub)
		}
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("gitops: parsing RSA trusted public key: %w", err)
		}
		return pub, keyID(pub), nil
	default:
		return nil, "", fmt.Errorf("gitops: unsupported trusted public key PEM block type %q (expected PUBLIC KEY)", block.Type)
	}
}

// keyID derives a short, stable identifier from a public key — the first 8 bytes of
// the SHA-256 of its PKIX/DER encoding, hex-encoded — matching the derivation in
// internal/audit and internal/attestbundle so the same key reports the same id
// everywhere.
func keyID(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hexEncode(sum[:8])
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// verifyDetached checks a detached signature over message against pub using the
// audit/attestbundle scheme: Ed25519 verifies the message directly; ECDSA verifies
// an ASN.1 signature over the SHA-256 digest; RSA verifies PKCS#1 v1.5 over the
// SHA-256 digest.
func verifyDetached(pub crypto.PublicKey, message, sig []byte) bool {
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

// signDetached produces a detached signature over message with priv using the same
// scheme as verifyDetached. It backs test fixtures and any tooling that signs a
// bundle for the proxy to verify.
func signDetached(priv crypto.Signer, message []byte) ([]byte, error) {
	switch priv.Public().(type) {
	case ed25519.PublicKey:
		return priv.Sign(nil, message, crypto.Hash(0))
	default:
		digest := sha256.Sum256(message)
		return priv.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
}
