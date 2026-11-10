package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sort"
	"testing"
)

// This file provides a minimal software authenticator for the tests: it builds
// the CBOR attestation object, authenticator data, client data, and valid
// signatures exactly as a real FIDO2 authenticator would, so the ceremonies can
// be exercised end-to-end without hardware. It includes a tiny CBOR *encoder*
// (the production code only decodes).

// --- tiny CBOR encoder (test only) -----------------------------------------

func cborEncodeUint(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n < 1<<32:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

func cborEncodeInt(v int64) []byte {
	if v >= 0 {
		return cborEncodeUint(0, uint64(v))
	}
	return cborEncodeUint(1, uint64(-1-v))
}

func cborEncodeBytes(b []byte) []byte {
	return append(cborEncodeUint(2, uint64(len(b))), b...)
}

func cborEncodeText(s string) []byte {
	return append(cborEncodeUint(3, uint64(len(s))), []byte(s)...)
}

// cborEncodeIntMap encodes a map with integer keys in ascending key order.
func cborEncodeIntMap(m map[int64][]byte) []byte {
	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := cborEncodeUint(5, uint64(len(m)))
	for _, k := range keys {
		out = append(out, cborEncodeInt(k)...)
		out = append(out, m[k]...)
	}
	return out
}

// cborEncodeTextMap encodes a map with text keys (insertion order supplied).
func cborEncodeTextMap(keys []string, vals map[string][]byte) []byte {
	out := cborEncodeUint(5, uint64(len(keys)))
	for _, k := range keys {
		out = append(out, cborEncodeText(k)...)
		out = append(out, vals[k]...)
	}
	return out
}

// --- fake authenticator -----------------------------------------------------

type fakeAuthenticator struct {
	t      *testing.T
	alg    int64
	ecKey  *ecdsa.PrivateKey
	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey
	credID []byte
	aaguid []byte
}

func newFakeAuthenticator(t *testing.T, alg int64) *fakeAuthenticator {
	t.Helper()
	fa := &fakeAuthenticator{t: t, alg: alg, credID: randBytes(t, 32), aaguid: make([]byte, 16)}
	switch alg {
	case algES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating EC key: %v", err)
		}
		fa.ecKey = k
	case algEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating Ed25519 key: %v", err)
		}
		fa.edPriv, fa.edPub = priv, pub
	default:
		t.Fatalf("unsupported alg %d", alg)
	}
	return fa
}

// coseKeyCBOR returns the credential public key as a COSE_Key CBOR map.
func (fa *fakeAuthenticator) coseKeyCBOR() []byte {
	switch fa.alg {
	case algES256:
		byteLen := 32
		x := fa.ecKey.X.Bytes()
		y := fa.ecKey.Y.Bytes()
		return cborEncodeIntMap(map[int64][]byte{
			1:  cborEncodeInt(coseKtyEC2),
			3:  cborEncodeInt(algES256),
			-1: cborEncodeInt(crvP256),
			-2: cborEncodeBytes(leftPad(x, byteLen)),
			-3: cborEncodeBytes(leftPad(y, byteLen)),
		})
	case algEdDSA:
		return cborEncodeIntMap(map[int64][]byte{
			1:  cborEncodeInt(coseKtyOKP),
			3:  cborEncodeInt(algEdDSA),
			-1: cborEncodeInt(crvEd25519),
			-2: cborEncodeBytes(fa.edPub),
		})
	}
	return nil
}

// authData builds authenticator data. When includeCred is true the attested
// credential data (aaguid + credId + COSE key) is appended and the AT flag set.
func (fa *fakeAuthenticator) authData(rpID string, uv bool, signCount uint32, includeCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	flags := byte(flagUP)
	if uv {
		flags |= flagUV
	}
	if includeCred {
		flags |= flagAT
	}
	out := make([]byte, 0, 37)
	out = append(out, h[:]...)
	out = append(out, flags)
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], signCount)
	out = append(out, sc[:]...)
	if includeCred {
		out = append(out, fa.aaguid...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(fa.credID)))
		out = append(out, l[:]...)
		out = append(out, fa.credID...)
		out = append(out, fa.coseKeyCBOR()...)
	}
	return out
}

// attestationObject builds a "none"-format attestation object.
func (fa *fakeAuthenticator) attestationObject(authData []byte) []byte {
	return cborEncodeTextMap(
		[]string{"fmt", "attStmt", "authData"},
		map[string][]byte{
			"fmt":      cborEncodeText("none"),
			"attStmt":  cborEncodeUint(5, 0), // empty map
			"authData": cborEncodeBytes(authData),
		},
	)
}

func (fa *fakeAuthenticator) clientDataJSON(typ, challenge, origin string) []byte {
	cd := clientData{Type: typ, Challenge: challenge, Origin: origin}
	b, err := json.Marshal(cd)
	if err != nil {
		fa.t.Fatalf("marshaling client data: %v", err)
	}
	return b
}

// sign produces an assertion signature over authData || SHA-256(clientDataJSON).
func (fa *fakeAuthenticator) sign(authData, clientDataJSON []byte) []byte {
	signed := append(append([]byte{}, authData...), hashSHA256(clientDataJSON)...)
	switch fa.alg {
	case algES256:
		sig, err := ecdsa.SignASN1(rand.Reader, fa.ecKey, hashSHA256(signed))
		if err != nil {
			fa.t.Fatalf("signing: %v", err)
		}
		return sig
	case algEdDSA:
		return ed25519.Sign(fa.edPriv, signed)
	}
	return nil
}

// register runs a full registration ceremony against svc for subject.
func (fa *fakeAuthenticator) register(svc *Service, subject, label, origin string, uv bool, signCount uint32) (CredentialView, error) {
	ch, err := svc.BeginRegistration(subject, subject)
	if err != nil {
		return CredentialView{}, err
	}
	ad := fa.authData(ch.RPID, uv, signCount, true)
	cdj := fa.clientDataJSON("webauthn.create", ch.Challenge, origin)
	return svc.FinishRegistration(testCtx(), subject, RegistrationResponse{
		Label:             label,
		ClientDataJSON:    b64urlEncode(cdj),
		AttestationObject: b64urlEncode(fa.attestationObject(ad)),
	})
}

// assert runs a full assertion ceremony against svc for subject.
func (fa *fakeAuthenticator) assert(svc *Service, subject, action, origin string, uv bool, signCount uint32) (StepUpResult, error) {
	ch, err := svc.BeginAssertion(subject, action)
	if err != nil {
		return StepUpResult{}, err
	}
	ad := fa.authData(ch.RPID, uv, signCount, false)
	cdj := fa.clientDataJSON("webauthn.get", ch.Challenge, origin)
	sig := fa.sign(ad, cdj)
	return svc.FinishAssertion(testCtx(), subject, AssertionResponse{
		CredentialID:      b64urlEncode(fa.credID),
		ClientDataJSON:    b64urlEncode(cdj),
		AuthenticatorData: b64urlEncode(ad),
		Signature:         b64urlEncode(sig),
	})
}

// --- helpers ----------------------------------------------------------------

func hashSHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}
