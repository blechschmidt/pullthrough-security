package webauthn

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// Attestation-statement verification (WebAuthn §8). At registration an
// authenticated admin is enrolling their own passkey, so the trust anchor is
// the authenticated admin session rather than a manufacturer attestation CA;
// nonetheless we cryptographically verify the attestation statement when its
// format lets us, so a malformed or forged statement is rejected and the result
// is recorded on the credential.
//
// Formats handled:
//   - "none":      no statement to verify; accepted.
//   - "packed":    self attestation (verify with the credential key) and the
//                  x5c full-attestation path (verify with the leaf certificate).
//   - other:       accepted only when the caller allows unverified attestation,
//                  and always flagged as unverified on the stored credential.

// attestationResult records what the verifier concluded, for storage and audit.
type attestationResult struct {
	Format   string
	Verified bool
	Detail   string
}

// verifyAttestation verifies the attestation statement of a registration. ad is
// the already-parsed authenticator data; clientDataHash is SHA-256 of the raw
// clientDataJSON. allowUnverified controls whether an unrecognised format is
// accepted (flagged unverified) or rejected.
func verifyAttestation(ao *attestationObject, ad *authData, clientDataHash []byte, allowUnverified bool) (attestationResult, error) {
	res := attestationResult{Format: ao.Fmt}
	switch ao.Fmt {
	case "none":
		res.Verified = true
		res.Detail = "no attestation statement (self-asserted)"
		return res, nil
	case "packed":
		if err := verifyPackedAttestation(ao, ad, clientDataHash, &res); err != nil {
			return res, err
		}
		return res, nil
	default:
		if !allowUnverified {
			return res, fmt.Errorf("webauthn: attestation format %q is not supported", ao.Fmt)
		}
		res.Verified = false
		res.Detail = "attestation format accepted without cryptographic verification"
		return res, nil
	}
}

// verifyPackedAttestation implements the "packed" format: the signature covers
// authenticatorData || clientDataHash. With an x5c chain the leaf certificate's
// key verifies it; without x5c it is self attestation verified by the freshly
// minted credential key, whose algorithm must equal the statement's alg.
func verifyPackedAttestation(ao *attestationObject, ad *authData, clientDataHash []byte, res *attestationResult) error {
	if ao.AttStmt == nil {
		return errors.New("webauthn: packed attestation missing statement")
	}
	algV, ok := ao.AttStmt["alg"]
	if !ok {
		return errors.New("webauthn: packed attestation missing alg")
	}
	alg, ok := cborInt(algV)
	if !ok {
		return errors.New("webauthn: packed attestation alg is not an integer")
	}
	sigV, ok := ao.AttStmt["sig"]
	if !ok {
		return errors.New("webauthn: packed attestation missing sig")
	}
	sig, ok := cborBytes(sigV)
	if !ok {
		return errors.New("webauthn: packed attestation sig is not a byte string")
	}

	signed := make([]byte, 0, len(ao.AuthData)+len(clientDataHash))
	signed = append(signed, ao.AuthData...)
	signed = append(signed, clientDataHash...)

	if x5cV, ok := ao.AttStmt["x5c"]; ok {
		return verifyPackedX5C(x5cV, alg, signed, sig, res)
	}

	// Self attestation: alg must match the credential key's algorithm and the
	// credential key verifies the signature.
	if ad.CredKey == nil {
		return errors.New("webauthn: self attestation without a credential key")
	}
	if alg != ad.CredKey.Alg {
		return fmt.Errorf("webauthn: self attestation alg %d != credential alg %d", alg, ad.CredKey.Alg)
	}
	if err := ad.CredKey.verify(signed, sig); err != nil {
		return fmt.Errorf("webauthn: packed self attestation: %w", err)
	}
	res.Verified = true
	res.Detail = "packed self attestation verified"
	return nil
}

// verifyPackedX5C verifies the full-attestation path: the leaf certificate's
// public key must verify the statement signature. We verify the leaf signature
// (the security-relevant check that the statement was produced by the holder of
// the attestation private key) but do not pin a manufacturer root, since this
// deployment's trust anchor is the authenticated enrolment session.
func verifyPackedX5C(x5cV any, alg int64, signed, sig []byte, res *attestationResult) error {
	chain, ok := x5cV.([]any)
	if !ok || len(chain) == 0 {
		return errors.New("webauthn: packed attestation x5c is not a non-empty array")
	}
	leafDER, ok := cborBytes(chain[0])
	if !ok {
		return errors.New("webauthn: packed attestation leaf certificate is not a byte string")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("webauthn: parsing attestation leaf certificate: %w", err)
	}
	key := &coseKey{Alg: alg, Pub: leaf.PublicKey}
	if err := key.verify(signed, sig); err != nil {
		return fmt.Errorf("webauthn: packed x5c attestation: %w", err)
	}
	res.Verified = true
	res.Detail = fmt.Sprintf("packed attestation verified against leaf certificate %q", leaf.Subject.CommonName)
	return nil
}

// clientDataHash returns SHA-256 of the raw clientDataJSON bytes.
func clientDataHash(clientDataJSON []byte) []byte {
	h := sha256.Sum256(clientDataJSON)
	return h[:]
}
