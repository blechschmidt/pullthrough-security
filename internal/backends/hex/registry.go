package hex

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Hex's integrity model is the signed /packages/<name> registry resource. It is
// a gzip-compressed, protobuf-encoded Signed envelope whose payload is a Package
// message; each release in it carries an outer_checksum — a SHA-256 over the
// entire release tarball (the hex.pm registry-v2 spec). The proxy fetches this
// sibling resource on a cache miss and verifies each fetched tarball against the
// digest it declares before the bytes are cached or streamed, so a tampered or
// corrupt mirror can neither poison the cache nor reach a client. This mirrors
// the checksum verification the CRAN backend performs against the PACKAGES index
// and the Conda backend against repodata.json.
//
// The protobuf wire format is decoded by a small, dependency-free reader (the
// proxy carries no protobuf runtime): only the handful of fields the proxy needs
// are read, and every other field is skipped by wire type. The parser never
// trusts a length prefix past the end of the buffer and bounds total input, so a
// hostile upstream cannot drive it to panic or unbounded allocation.
//
// Message shapes (from hexpm/hex_core proto/*.proto):
//
//	Signed  { bytes payload = 1; bytes signature = 2; }
//	Package { repeated Release releases = 1; string name = 2; ... }
//	Release { string version = 1; bytes inner_checksum = 2; ...;
//	          bytes outer_checksum = 5; ... }

// maxRegistryBytes bounds how much of a (compressed) registry resource the
// backend reads for verification, and the decompressed size it will expand to.
// A single package's /packages/<name> resource is far smaller; the cap is
// generous while bounding memory against a hostile upstream.
const (
	maxRegistryBytes      = 16 << 20  // 16 MiB compressed
	maxRegistryDecodedLen = 128 << 20 // 128 MiB decompressed
)

// Wire types (protobuf).
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

// Field numbers the parser reads.
const (
	fieldSignedPayload  = 1 // Signed.payload
	fieldPackageRelease = 1 // Package.releases (repeated)
	fieldReleaseVersion = 1 // Release.version
	fieldReleaseOuter   = 5 // Release.outer_checksum
)

// PackageIndex maps each release's version to its lowercase hex-encoded SHA-256
// outer_checksum, recovered from a decoded /packages/<name> resource.
type PackageIndex struct {
	outer map[string]string
}

// ParsePackageResource decodes a /packages/<name> registry resource into the
// digest index the backend verifies tarballs against. It gunzips the body (Hex
// registry resources are always gzip-compressed), unwraps the Signed envelope to
// obtain the Package payload, and reads each release's version and
// outer_checksum. A release without a well-formed outer_checksum is skipped (it
// cannot anchor a verification) rather than failing the whole parse, so one
// malformed release does not deny verification for the rest.
//
// The signature in the Signed envelope is not cryptographically verified here:
// like the CRAN and Conda backends, the proxy uses the registry-declared digest
// to bind an immutable tarball to its coordinate (defending the cache and client
// against a tampered mirror), not as a repository-authenticity root. The raw
// bytes are passed through to the client unchanged, so a Hex client that pins the
// repository public key still performs its own end-to-end signature check.
func ParsePackageResource(body []byte) (*PackageIndex, error) {
	payload, err := gunzip(body)
	if err != nil {
		return nil, err
	}
	signedPayload, err := extractSignedPayload(payload)
	if err != nil {
		return nil, err
	}
	idx := &PackageIndex{outer: map[string]string{}}
	err = forEachField(signedPayload, func(field, wire int, val []byte) error {
		if field == fieldPackageRelease && wire == wireLen {
			version, outer, ok := parseRelease(val)
			if ok {
				idx.outer[version] = outer
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return idx, nil
}

// outerFor returns the recorded hex SHA-256 outer_checksum for a release
// version.
func (i *PackageIndex) outerFor(version string) (string, bool) {
	if i == nil || version == "" {
		return "", false
	}
	d, ok := i.outer[version]
	return d, ok
}

// gunzip decompresses a gzip-wrapped registry resource with bounded output. If
// the body is not gzip-compressed it is returned unchanged, so the parser stays
// robust to a transport layer (or test) that already decompressed it.
func gunzip(body []byte) ([]byte, error) {
	if len(body) > maxRegistryBytes {
		return nil, fmt.Errorf("hex: registry resource exceeds %d bytes", maxRegistryBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		// Not gzip — treat the body as the already-decompressed payload.
		return body, nil
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxRegistryDecodedLen+1))
	if err != nil {
		return nil, fmt.Errorf("hex: decompressing registry resource: %w", err)
	}
	if int64(len(out)) > maxRegistryDecodedLen {
		return nil, fmt.Errorf("hex: decompressed registry resource exceeds %d bytes", maxRegistryDecodedLen)
	}
	return out, nil
}

// extractSignedPayload unwraps a Signed envelope and returns its payload field.
func extractSignedPayload(buf []byte) ([]byte, error) {
	var payload []byte
	var found bool
	err := forEachField(buf, func(field, wire int, val []byte) error {
		if field == fieldSignedPayload && wire == wireLen {
			payload = val
			found = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("hex: Signed envelope has no payload")
	}
	return payload, nil
}

// parseRelease reads a Release message, returning its version and lowercase hex
// outer_checksum. ok is false unless both a non-empty version and a 32-byte
// outer_checksum are present.
func parseRelease(buf []byte) (version, outerHex string, ok bool) {
	var ver string
	var outer []byte
	_ = forEachField(buf, func(field, wire int, val []byte) error {
		switch {
		case field == fieldReleaseVersion && wire == wireLen:
			ver = string(val)
		case field == fieldReleaseOuter && wire == wireLen:
			outer = val
		}
		return nil
	})
	if ver == "" || len(outer) != sha256Len {
		return "", "", false
	}
	return ver, toHex(outer), true
}

// forEachField walks a protobuf message, invoking fn for each top-level field
// with its field number, wire type, and (for length-delimited fields) the raw
// value bytes. Fields of other wire types are skipped; fn receives a nil value
// for them. It fails closed (returns an error) on any truncated or malformed
// framing rather than reading out of bounds.
func forEachField(buf []byte, fn func(field, wire int, val []byte) error) error {
	i := 0
	for i < len(buf) {
		tag, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			return errors.New("hex: malformed protobuf tag")
		}
		i += n
		field := int(tag >> 3)
		wire := int(tag & 0x7)
		if field == 0 {
			return errors.New("hex: invalid protobuf field number 0")
		}
		switch wire {
		case wireVarint:
			_, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return errors.New("hex: malformed protobuf varint")
			}
			i += n
			if err := fn(field, wire, nil); err != nil {
				return err
			}
		case wireI64:
			if i+8 > len(buf) {
				return errors.New("hex: truncated 64-bit protobuf field")
			}
			i += 8
			if err := fn(field, wire, nil); err != nil {
				return err
			}
		case wireI32:
			if i+4 > len(buf) {
				return errors.New("hex: truncated 32-bit protobuf field")
			}
			i += 4
			if err := fn(field, wire, nil); err != nil {
				return err
			}
		case wireLen:
			ln, n := binary.Uvarint(buf[i:])
			if n <= 0 {
				return errors.New("hex: malformed protobuf length prefix")
			}
			i += n
			if ln > uint64(len(buf)-i) {
				return errors.New("hex: protobuf length prefix exceeds message")
			}
			val := buf[i : i+int(ln)]
			i += int(ln)
			if err := fn(field, wire, val); err != nil {
				return err
			}
		default:
			return fmt.Errorf("hex: unsupported protobuf wire type %d", wire)
		}
	}
	return nil
}

const hexDigits = "0123456789abcdef"

// toHex lowercase-hex-encodes b without allocating via fmt.
func toHex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}
