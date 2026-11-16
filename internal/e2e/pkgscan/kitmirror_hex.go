//go:build integration
// +build integration

package pkgscan

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
)

// This file is the hex stub registry's part for the full-mirror suite
// (internal/e2e/fullmirror, Task 194). Besides each package's
// "/packages/<name>", a Hex repository publishes two registry resources that
// list everything it holds: "/names", every package with the time it last
// changed, and "/versions", every package with its versions and which of them
// are retired. The full mirror follows a Hex repository by polling both, so
// that suite serves them in front of the stub registry — built here, because
// they must be signed with the key "/packages/<name>" is signed with, the
// repository's (hexpmKey).

// HexRepositoryName is the repository every resource of the hex stub registry
// names: hex.pm's, as the proxy plays a mirror of hex.pm (HEX_MIRROR).
const HexRepositoryName = hexpmRepository

// HexNamesEntry is one package of a "/names" resource.
type HexNamesEntry struct {
	Name string
	// Updated is when the package last changed.
	Updated time.Time
}

// HexVersionsEntry is one package of a "/versions" resource.
type HexVersionsEntry struct {
	Name string
	// Versions are the package's versions, oldest first; Retired the indexes
	// of those retired.
	Versions []string
	Retired  []int
}

// HexSignedNames builds the "/names" resource of the given packages as
// hex_registry builds it: gzip(Signed{payload: Names, signature}), the
// packages sorted by name, signed with the stub repository's key.
//
//	Names     { repeated Package packages = 1; string repository = 2; }
//	Package   { string name = 1; Timestamp updated_at = 3; }
//	Timestamp { int64 seconds = 1; int32 nanos = 2; }
func HexSignedNames(entries []HexNamesEntry) ([]byte, error) {
	sorted := append([]HexNamesEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var payload []byte
	for _, e := range sorted {
		ts := hexpmVarintField(1, uint64(e.Updated.Unix()))
		ts = append(ts, hexpmVarintField(2, uint64(e.Updated.Nanosecond()))...)
		pkg := append(hexpmField(1, []byte(e.Name)), hexpmField(3, ts)...)
		payload = append(payload, hexpmField(1, pkg)...)
	}
	payload = append(payload, hexpmField(2, []byte(hexpmRepository))...)
	return hexpmSigned(payload, "/names")
}

// HexSignedVersions builds the "/versions" resource of the given packages as
// hex_registry builds it: gzip(Signed{payload: Versions, signature}), the
// packages sorted by name, signed with the stub repository's key.
//
//	Versions { repeated Package packages = 1; string repository = 2; }
//	Package  { string name = 1; repeated string versions = 2;
//	           repeated int32 retired = 3 [packed = true]; }
func HexSignedVersions(entries []HexVersionsEntry) ([]byte, error) {
	sorted := append([]HexVersionsEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var payload []byte
	for _, e := range sorted {
		pkg := hexpmField(1, []byte(e.Name))
		for _, v := range e.Versions {
			pkg = append(pkg, hexpmField(2, []byte(v))...)
		}
		if len(e.Retired) > 0 {
			var packed []byte
			for _, i := range e.Retired {
				packed = binary.AppendUvarint(packed, uint64(i))
			}
			pkg = append(pkg, hexpmField(3, packed)...)
		}
		payload = append(payload, hexpmField(1, pkg)...)
	}
	payload = append(payload, hexpmField(2, []byte(hexpmRepository))...)
	return hexpmSigned(payload, "/versions")
}

// hexpmSigned wraps a registry resource's payload as the repository serves
// it: gzip(Signed{payload, signature}), the signature an RSA signature
// (PKCS #1 v1.5) of the payload's SHA-512 with the repository's key.
func hexpmSigned(payload []byte, what string) ([]byte, error) {
	key, err := hexpmKey()
	if err != nil {
		return nil, fmt.Errorf("generating the repository key: %w", err)
	}
	digest := sha512.Sum512(payload)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing the %s registry resource: %w", what, err)
	}
	signed := append(hexpmField(1, payload), hexpmField(2, signature)...)
	return gzipOf(signed), nil
}

// hexpmVarintField encodes one varint protobuf field (wire type 0).
func hexpmVarintField(number int, value uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, uint64(number)<<3), value)
}
