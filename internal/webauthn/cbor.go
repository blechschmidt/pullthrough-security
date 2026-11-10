package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// This file implements the small, self-contained subset of CBOR (RFC 8949)
// decoding that WebAuthn needs: the attestation object is a CBOR map and the
// credential public key is a COSE_Key, itself a CBOR map with integer labels.
// The project convention is to hand-roll narrow parsers for untrusted upstream
// formats rather than pull in a general-purpose dependency (see the Nix,
// Julia, and Hex backends), so we decode exactly the major types these
// structures use — unsigned/negative integers, byte strings, text strings,
// arrays, maps, and the three simple values — and reject everything else.
//
// The decoder is strictly bounded: every length is checked against the
// remaining input before it is consumed, nesting is depth-limited, and integer
// map keys are normalised to int64 so COSE's negative labels compare correctly.
// It is a decoder only; the project never needs to emit CBOR.

// maxCBORDepth bounds nesting so a hostile attestation object cannot exhaust the
// stack. WebAuthn structures are shallow (map → bstr → nested COSE map), so a
// generous ceiling still rejects pathological input.
const maxCBORDepth = 16

// maxCBORElements bounds the element count of any single array/map so a crafted
// header claiming a huge count cannot drive an enormous allocation. Real
// attestation objects and COSE keys have a handful of entries.
const maxCBORElements = 1 << 16

var (
	errCBORTruncated = errors.New("webauthn: truncated CBOR input")
	errCBORTrailing  = errors.New("webauthn: trailing bytes after CBOR value")
	errCBORDepth     = errors.New("webauthn: CBOR nesting too deep")
)

// cborDecoder walks a byte slice, tracking the read offset.
type cborDecoder struct {
	data []byte
	pos  int
}

// cborDecode parses exactly one CBOR data item from data and requires that the
// item consume the entire slice (no trailing bytes). It is the entry point for
// fixed-size payloads such as the attestation object.
func cborDecode(data []byte) (any, error) {
	d := &cborDecoder{data: data}
	v, err := d.decodeValue(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, errCBORTrailing
	}
	return v, nil
}

// cborDecodePrefix parses one CBOR item from the front of data and returns it
// together with the number of bytes consumed. The credential public key is a
// COSE_Key sitting at the tail of the attested-credential-data with no length
// prefix, so the caller must learn how many bytes it occupied.
func cborDecodePrefix(data []byte) (any, int, error) {
	d := &cborDecoder{data: data}
	v, err := d.decodeValue(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// readByte consumes and returns the next byte.
func (d *cborDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, errCBORTruncated
	}
	b := d.data[d.pos]
	d.pos++
	return b, nil
}

// readN consumes and returns the next n bytes as a sub-slice (a copy is made by
// callers that retain it).
func (d *cborDecoder) readN(n int) ([]byte, error) {
	if n < 0 || d.pos+n > len(d.data) || d.pos+n < d.pos {
		return nil, errCBORTruncated
	}
	b := d.data[d.pos : d.pos+n]
	d.pos += n
	return b, nil
}

// decodeArg reads the additional-information argument following an initial byte,
// returning the argument value. It implements the 0..23 inline / 24 (1 byte) /
// 25 (2 bytes) / 26 (4 bytes) / 27 (8 bytes) encoding shared by every major
// type's length/value field.
func (d *cborDecoder) decodeArg(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		b, err := d.readByte()
		return uint64(b), err
	case ai == 25:
		b, err := d.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint16(b)), nil
	case ai == 26:
		b, err := d.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(binary.BigEndian.Uint32(b)), nil
	case ai == 27:
		b, err := d.readN(8)
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(b), nil
	default:
		return 0, fmt.Errorf("webauthn: unsupported CBOR additional info %d", ai)
	}
}

// decodeValue decodes one data item at the current position.
func (d *cborDecoder) decodeValue(depth int) (any, error) {
	if depth > maxCBORDepth {
		return nil, errCBORDepth
	}
	ib, err := d.readByte()
	if err != nil {
		return nil, err
	}
	major := ib >> 5
	ai := ib & 0x1f

	switch major {
	case 0: // unsigned integer
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		return int64(n), nil
	case 1: // negative integer: value is -1 - n
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		if n > math.MaxInt64 {
			return nil, errors.New("webauthn: CBOR negative integer out of range")
		}
		return -1 - int64(n), nil
	case 2: // byte string
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		raw, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(raw))
		copy(out, raw)
		return out, nil
	case 3: // text string
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		raw, err := d.readN(int(n))
		if err != nil {
			return nil, err
		}
		return string(raw), nil
	case 4: // array
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		if n > maxCBORElements {
			return nil, errors.New("webauthn: CBOR array too large")
		}
		arr := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, err := d.decodeValue(depth + 1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		return arr, nil
	case 5: // map
		n, err := d.decodeArg(ai)
		if err != nil {
			return nil, err
		}
		if n > maxCBORElements {
			return nil, errors.New("webauthn: CBOR map too large")
		}
		m := make(map[any]any, n)
		for i := uint64(0); i < n; i++ {
			k, err := d.decodeValue(depth + 1)
			if err != nil {
				return nil, err
			}
			// Map keys must be hashable scalars. COSE uses integer and text keys.
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("webauthn: unsupported CBOR map key type %T", k)
			}
			v, err := d.decodeValue(depth + 1)
			if err != nil {
				return nil, err
			}
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("webauthn: duplicate CBOR map key %v", k)
			}
			m[k] = v
		}
		return m, nil
	case 7: // simple values (false/true/null) — floats are not used by WebAuthn
		switch ai {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22, 23: // null, undefined
			return nil, nil
		default:
			return nil, fmt.Errorf("webauthn: unsupported CBOR simple value %d", ai)
		}
	default:
		return nil, fmt.Errorf("webauthn: unsupported CBOR major type %d", major)
	}
}

// cborMapInt extracts an integer-keyed entry from a decoded CBOR map.
func cborMapInt(m map[any]any, key int64) (any, bool) {
	v, ok := m[key]
	return v, ok
}

// cborInt coerces a decoded CBOR value to int64.
func cborInt(v any) (int64, bool) {
	n, ok := v.(int64)
	return n, ok
}

// cborBytes coerces a decoded CBOR value to a byte string.
func cborBytes(v any) ([]byte, bool) {
	b, ok := v.([]byte)
	return b, ok
}
