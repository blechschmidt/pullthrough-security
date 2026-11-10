package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Authenticator-data and attestation-object parsing (WebAuthn §6.1, §6.5).
//
// authenticatorData layout:
//
//	rpIdHash      32 bytes   SHA-256 of the RP ID
//	flags          1 byte    bit0 UP, bit2 UV, bit3 BE, bit4 BS, bit6 AT, bit7 ED
//	signCount      4 bytes   big-endian authenticator signature counter
//	[attestedCred] var        present iff AT flag set (registration only)
//	[extensions]  var        present iff ED flag set (CBOR map; ignored)
//
// attestedCredentialData layout:
//
//	aaguid        16 bytes
//	credIdLen      2 bytes   big-endian
//	credentialId  credIdLen bytes
//	credPublicKey var        COSE_Key (CBOR)

// Authenticator-data flag bits.
const (
	flagUP = 1 << 0 // user present
	flagUV = 1 << 2 // user verified
	flagAT = 1 << 6 // attested credential data included
	flagED = 1 << 7 // extension data included
)

// authenticatorData is the parsed, validated form of the raw authData blob.
type authData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32

	// Set only when the AT flag is present (registration).
	AAGUID     []byte
	CredID     []byte
	CredKey    *coseKey
	CredKeyRaw []byte // the credential public key's raw COSE bytes, for storage
}

func (a *authData) userPresent() bool  { return a.Flags&flagUP != 0 }
func (a *authData) userVerified() bool { return a.Flags&flagUV != 0 }

// parseAuthData decodes authenticatorData. When expectCred is true the attested
// credential data must be present (registration); otherwise it must be absent
// (assertion).
func parseAuthData(raw []byte, expectCred bool) (*authData, error) {
	if len(raw) < 37 {
		return nil, fmt.Errorf("webauthn: authenticator data too short (%d bytes)", len(raw))
	}
	a := &authData{
		RPIDHash:  raw[0:32],
		Flags:     raw[32],
		SignCount: uint32(raw[33])<<24 | uint32(raw[34])<<16 | uint32(raw[35])<<8 | uint32(raw[36]),
	}
	rest := raw[37:]
	hasAT := a.Flags&flagAT != 0
	if expectCred && !hasAT {
		return nil, errors.New("webauthn: registration authenticator data has no attested credential data")
	}
	if !expectCred && hasAT {
		return nil, errors.New("webauthn: assertion authenticator data unexpectedly carries attested credential data")
	}

	if hasAT {
		if len(rest) < 18 {
			return nil, errors.New("webauthn: attested credential data truncated")
		}
		a.AAGUID = rest[0:16]
		credIDLen := int(rest[16])<<8 | int(rest[17])
		rest = rest[18:]
		if credIDLen == 0 || credIDLen > 1023 {
			return nil, fmt.Errorf("webauthn: invalid credential id length %d", credIDLen)
		}
		if len(rest) < credIDLen {
			return nil, errors.New("webauthn: credential id truncated")
		}
		a.CredID = rest[:credIDLen]
		rest = rest[credIDLen:]
		// The COSE public key is a CBOR map occupying a variable, unframed span.
		v, n, err := cborDecodePrefix(rest)
		if err != nil {
			return nil, fmt.Errorf("webauthn: decoding credential public key: %w", err)
		}
		m, ok := v.(map[any]any)
		if !ok {
			return nil, errors.New("webauthn: credential public key is not a CBOR map")
		}
		key, err := parseCOSEKey(m)
		if err != nil {
			return nil, err
		}
		a.CredKey = key
		a.CredKeyRaw = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
	}

	// Any remaining bytes must be the extension-data CBOR map (ED flag). We do
	// not consume extensions, but a trailing blob without the ED flag indicates a
	// malformed structure.
	if len(rest) > 0 && a.Flags&flagED == 0 {
		return nil, errors.New("webauthn: trailing bytes in authenticator data without extension flag")
	}
	return a, nil
}

// verifyRPIDHash constant-time compares the authenticator's RP ID hash against
// SHA-256(rpID).
func (a *authData) verifyRPIDHash(rpID string) error {
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(a.RPIDHash, want[:]) != 1 {
		return errors.New("webauthn: RP ID hash mismatch")
	}
	return nil
}

// attestationObject is the decoded attestation-object envelope.
type attestationObject struct {
	Fmt      string
	AuthData []byte
	AttStmt  map[any]any
}

// parseAttestationObject decodes the CBOR attestation object.
func parseAttestationObject(raw []byte) (*attestationObject, error) {
	v, err := cborDecode(raw)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decoding attestation object: %w", err)
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("webauthn: attestation object is not a CBOR map")
	}
	fmtV, ok := m["fmt"]
	if !ok {
		return nil, errors.New("webauthn: attestation object missing fmt")
	}
	fmtStr, ok := fmtV.(string)
	if !ok {
		return nil, errors.New("webauthn: attestation fmt is not a text string")
	}
	authV, ok := m["authData"]
	if !ok {
		return nil, errors.New("webauthn: attestation object missing authData")
	}
	authBytes, ok := authV.([]byte)
	if !ok {
		return nil, errors.New("webauthn: attestation authData is not a byte string")
	}
	ao := &attestationObject{Fmt: fmtStr, AuthData: authBytes}
	if stmtV, ok := m["attStmt"]; ok {
		if stmt, ok := stmtV.(map[any]any); ok {
			ao.AttStmt = stmt
		}
	}
	return ao, nil
}
