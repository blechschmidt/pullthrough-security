package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// COSE key and algorithm handling (RFC 8152 / RFC 9053). A WebAuthn credential
// public key is a COSE_Key — a CBOR map keyed by integer labels. We parse the
// three algorithm families authenticators actually ship: ES256 (ECDSA P-256),
// RS256 (RSA PKCS#1 v1.5), and EdDSA (Ed25519). Each is reduced to a stdlib
// crypto public key plus a verify closure so the assertion path never cares
// about the wire format again.

// COSE key-type (kty) label values.
const (
	coseKtyOKP = 1 // Octet Key Pair (Ed25519)
	coseKtyEC2 = 2 // Elliptic Curve, two coordinates
	coseKtyRSA = 3 // RSA
)

// COSE algorithm (alg) identifiers used by WebAuthn authenticators.
const (
	algES256 = -7
	algEdDSA = -8
	algES384 = -35
	algES512 = -36
	algRS256 = -257
	algRS384 = -258
	algRS512 = -259
	algPS256 = -37
)

// COSE_Key common label values.
const (
	labelKty    = 1
	labelAlg    = 3
	labelCrvOrN = -1 // crv for EC2/OKP; modulus n for RSA
	labelXOrE   = -2 // x coordinate for EC2/OKP; exponent e for RSA
	labelY      = -3 // y coordinate for EC2
)

// COSE elliptic-curve (crv) label values.
const (
	crvP256    = 1
	crvP384    = 2
	crvP521    = 3
	crvEd25519 = 6
)

// coseKey is a parsed credential public key: the algorithm it signs with, the
// stdlib public key, and the raw COSE bytes (retained so a credential can be
// re-parsed after being reloaded from durable storage).
type coseKey struct {
	Alg int64
	Pub crypto.PublicKey
}

// parseCOSEKey decodes a COSE_Key from its CBOR map form.
func parseCOSEKey(m map[any]any) (*coseKey, error) {
	ktyV, ok := cborMapInt(m, labelKty)
	if !ok {
		return nil, errors.New("webauthn: COSE key missing kty")
	}
	kty, ok := cborInt(ktyV)
	if !ok {
		return nil, errors.New("webauthn: COSE key kty is not an integer")
	}
	algV, ok := cborMapInt(m, labelAlg)
	if !ok {
		return nil, errors.New("webauthn: COSE key missing alg")
	}
	alg, ok := cborInt(algV)
	if !ok {
		return nil, errors.New("webauthn: COSE key alg is not an integer")
	}

	switch kty {
	case coseKtyEC2:
		return parseEC2Key(m, alg)
	case coseKtyOKP:
		return parseOKPKey(m, alg)
	case coseKtyRSA:
		return parseRSAKey(m, alg)
	default:
		return nil, fmt.Errorf("webauthn: unsupported COSE key type %d", kty)
	}
}

func parseEC2Key(m map[any]any, alg int64) (*coseKey, error) {
	crvV, ok := cborMapInt(m, labelCrvOrN)
	if !ok {
		return nil, errors.New("webauthn: EC2 key missing crv")
	}
	crv, ok := cborInt(crvV)
	if !ok {
		return nil, errors.New("webauthn: EC2 key crv is not an integer")
	}
	var curve elliptic.Curve
	switch crv {
	case crvP256:
		curve = elliptic.P256()
	case crvP384:
		curve = elliptic.P384()
	case crvP521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("webauthn: unsupported EC2 curve %d", crv)
	}
	xV, ok := cborMapInt(m, labelXOrE)
	if !ok {
		return nil, errors.New("webauthn: EC2 key missing x coordinate")
	}
	x, ok := cborBytes(xV)
	if !ok {
		return nil, errors.New("webauthn: EC2 key x coordinate is not a byte string")
	}
	yV, ok := cborMapInt(m, labelY)
	if !ok {
		return nil, errors.New("webauthn: EC2 key missing y coordinate")
	}
	y, ok := cborBytes(yV)
	if !ok {
		return nil, errors.New("webauthn: EC2 key y coordinate is not a byte string")
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(x) != byteLen || len(y) != byteLen {
		return nil, fmt.Errorf("webauthn: EC2 coordinate length mismatch (got %d/%d, want %d)", len(x), len(y), byteLen)
	}
	px := new(big.Int).SetBytes(x)
	py := new(big.Int).SetBytes(y)
	if !curve.IsOnCurve(px, py) {
		return nil, errors.New("webauthn: EC2 public key point is not on the curve")
	}
	return &coseKey{Alg: alg, Pub: &ecdsa.PublicKey{Curve: curve, X: px, Y: py}}, nil
}

func parseOKPKey(m map[any]any, alg int64) (*coseKey, error) {
	crvV, ok := cborMapInt(m, labelCrvOrN)
	if !ok {
		return nil, errors.New("webauthn: OKP key missing crv")
	}
	crv, ok := cborInt(crvV)
	if !ok {
		return nil, errors.New("webauthn: OKP key crv is not an integer")
	}
	if crv != crvEd25519 {
		return nil, fmt.Errorf("webauthn: unsupported OKP curve %d", crv)
	}
	xV, ok := cborMapInt(m, labelXOrE)
	if !ok {
		return nil, errors.New("webauthn: OKP key missing public key")
	}
	x, ok := cborBytes(xV)
	if !ok {
		return nil, errors.New("webauthn: OKP public key is not a byte string")
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("webauthn: Ed25519 public key wrong length %d", len(x))
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, x)
	return &coseKey{Alg: alg, Pub: pub}, nil
}

func parseRSAKey(m map[any]any, alg int64) (*coseKey, error) {
	nV, ok := cborMapInt(m, labelCrvOrN)
	if !ok {
		return nil, errors.New("webauthn: RSA key missing modulus")
	}
	nBytes, ok := cborBytes(nV)
	if !ok {
		return nil, errors.New("webauthn: RSA modulus is not a byte string")
	}
	eV, ok := cborMapInt(m, labelXOrE)
	if !ok {
		return nil, errors.New("webauthn: RSA key missing exponent")
	}
	eBytes, ok := cborBytes(eV)
	if !ok {
		return nil, errors.New("webauthn: RSA exponent is not a byte string")
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("webauthn: RSA modulus/exponent empty")
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > (1<<31-1) {
		return nil, errors.New("webauthn: RSA exponent out of range")
	}
	return &coseKey{Alg: alg, Pub: &rsa.PublicKey{N: n, E: int(e.Int64())}}, nil
}

// verify checks sig over message using the key's declared algorithm. message is
// the raw signed data (authenticatorData || SHA-256(clientDataJSON)); this
// function applies the algorithm's own digest.
func (k *coseKey) verify(message, sig []byte) error {
	switch pub := k.Pub.(type) {
	case *ecdsa.PublicKey:
		digest, err := hashFor(k.Alg, message)
		if err != nil {
			return err
		}
		// WebAuthn ECDSA signatures are ASN.1 DER encoded (r,s).
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			return errors.New("webauthn: ECDSA signature verification failed")
		}
		return nil
	case ed25519.PublicKey:
		if k.Alg != algEdDSA {
			return fmt.Errorf("webauthn: Ed25519 key with unexpected alg %d", k.Alg)
		}
		// Ed25519 signs the message directly (no external prehash).
		if !ed25519.Verify(pub, message, sig) {
			return errors.New("webauthn: Ed25519 signature verification failed")
		}
		return nil
	case *rsa.PublicKey:
		digest, err := hashFor(k.Alg, message)
		if err != nil {
			return err
		}
		h, err := cryptoHashFor(k.Alg)
		if err != nil {
			return err
		}
		if k.Alg == algPS256 {
			if err := rsa.VerifyPSS(pub, h, digest, sig, nil); err != nil {
				return errors.New("webauthn: RSA-PSS signature verification failed")
			}
			return nil
		}
		if err := rsa.VerifyPKCS1v15(pub, h, digest, sig); err != nil {
			return errors.New("webauthn: RSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("webauthn: unsupported public key type %T", k.Pub)
	}
}

// hashFor returns the digest of message under the hash the COSE algorithm uses.
func hashFor(alg int64, message []byte) ([]byte, error) {
	switch alg {
	case algES256, algRS256, algPS256:
		h := sha256.Sum256(message)
		return h[:], nil
	case algES384, algRS384:
		h := sha512.Sum384(message)
		return h[:], nil
	case algES512, algRS512, algEdDSA:
		// EdDSA never reaches here (it verifies the message directly); included
		// for the RSA/ECDSA 512 variants only.
		h := sha512.Sum512(message)
		return h[:], nil
	default:
		return nil, fmt.Errorf("webauthn: unsupported signature algorithm %d", alg)
	}
}

// cryptoHashFor maps a COSE algorithm to the crypto.Hash the RSA verifiers need.
func cryptoHashFor(alg int64) (crypto.Hash, error) {
	switch alg {
	case algRS256, algPS256:
		return crypto.SHA256, nil
	case algRS384:
		return crypto.SHA384, nil
	case algRS512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("webauthn: unsupported RSA algorithm %d", alg)
	}
}

// supportedAlgorithms is the credentialParameters advertised during
// registration, most-preferred first.
func supportedAlgorithms() []int64 {
	return []int64{algES256, algEdDSA, algRS256}
}
