//go:build fuzz
// +build fuzz

// Fuzz targets for the hand-rolled CBOR / attestation-object / authenticator-data
// parsers (Task 30, Task 161).
//
// These parsers consume attacker-influenced bytes: the attestation object and
// COSE credential public key come from a client's authenticator during
// registration, and the authenticator data comes from every assertion. They
// must never panic or allocate without bound on hostile input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=Fuzz -fuzz=FuzzCBORDecode ./internal/webauthn/
package webauthn

import "testing"

func FuzzCBORDecode(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},                               // uint 0
		{0x20},                               // negative -1
		{0x40},                               // empty byte string
		{0x60},                               // empty text string
		{0xa0},                               // empty map
		{0x80},                               // empty array
		{0xa1, 0x01, 0x02},                   // {1: 2}
		{0xa1, 0x20, 0x41, 0xff},             // {-1: h'ff'}
		{0x9f, 0xff},                         // indefinite array (unsupported)
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // garbage
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if v, err := cborDecode(data); err == nil {
			// A map decode must be re-walkable without panic.
			if m, ok := v.(map[any]any); ok {
				_, _ = parseCOSEKey(m)
			}
		}
		_, _, _ = cborDecodePrefix(data)
	})
}

func FuzzParseAttestationObject(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Add([]byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'})
	f.Fuzz(func(t *testing.T, data []byte) {
		ao, err := parseAttestationObject(data)
		if err != nil {
			return
		}
		// A successfully decoded envelope must parse its authData without panic.
		_, _ = parseAuthData(ao.AuthData, true)
		_, _ = parseAuthData(ao.AuthData, false)
	})
}

func FuzzParseAuthData(f *testing.F) {
	f.Add(make([]byte, 37))
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseAuthData(data, true)
		_, _ = parseAuthData(data, false)
	})
}
