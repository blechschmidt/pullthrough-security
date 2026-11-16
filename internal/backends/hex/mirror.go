package hex

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// This file exports what the full-mirror feed adapter (internal/fullmirror,
// Task 191) follows a Hex repository with. A repository publishes two signed
// resources that list everything it holds — /names, every package with the
// time it last changed, and /versions, every package with its versions and
// which of them are retired — and the adapter diffs one copy of them against
// the next. They are read with the parser the backend verifies tarballs with
// (registry.go): the same gunzip, the same Signed envelope, the same bounded
// protobuf walk.
//
// Message shapes (hexpm/specifications registry/names.proto, versions.proto):
//
//	Names     { repeated Package packages = 1; string repository = 2; }
//	Package   { string name = 1; Timestamp updated_at = 3; }
//	Timestamp { int64 seconds = 1; int32 nanos = 2; }
//
//	Versions  { repeated Package packages = 1; string repository = 2; }
//	Package   { string name = 1; repeated string versions = 2;
//	            repeated int32 retired = 3 [packed = true];
//	            repeated int32 with_advisories = 5 [packed = true]; }

// Field numbers of the index resources.
const (
	fieldSignedSignature  = 2 // Signed.signature
	fieldIndexPackage     = 1 // Names.packages, Versions.packages
	fieldIndexRepository  = 2 // Names.repository, Versions.repository
	fieldEntryName        = 1 // Package.name (both)
	fieldNamesUpdatedAt   = 3 // Names' Package.updated_at
	fieldVersionsVersion  = 2 // Versions' Package.versions
	fieldVersionsRetired  = 3 // Versions' Package.retired
	fieldTimestampSeconds = 1 // Timestamp.seconds
	fieldTimestampNanos   = 2 // Timestamp.nanos
)

// OpenSignedResource gunzips a registry resource (/names, /versions,
// /packages/<name>) and returns its Signed envelope's payload and signature
// (empty when the envelope carries none). The resource is bounded as the
// backend bounds it: at most 16 MiB as served, 128 MiB decompressed.
func OpenSignedResource(body []byte) (payload, signature []byte, err error) {
	raw, err := gunzip(body)
	if err != nil {
		return nil, nil, err
	}
	if payload, err = extractSignedPayload(raw); err != nil {
		return nil, nil, err
	}
	_ = forEachField(raw, func(field, wire int, val []byte) error {
		if field == fieldSignedSignature && wire == wireLen {
			signature = val
		}
		return nil
	})
	return payload, signature, nil
}

// VerifyResourceSignature checks a registry resource's signature: an RSA
// signature (PKCS #1 v1.5) of the SHA-512 digest of the payload, made with the
// repository's private key (registry-v2.md, "Signing"). The backend itself
// passes the resources to clients byte for byte and leaves this check to them.
func VerifyResourceSignature(payload, signature []byte, key *rsa.PublicKey) error {
	if key == nil {
		return errors.New("hex: no public key to verify the resource with")
	}
	if len(signature) == 0 {
		return errors.New("hex: the resource is not signed")
	}
	sum := sha512.Sum512(payload)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA512, sum[:], signature); err != nil {
		return fmt.Errorf("hex: the resource's signature does not verify with the repository's public key: %w", err)
	}
	return nil
}

// NamesEntry is one package of a /names resource.
type NamesEntry struct {
	Name string
	// Updated is when the package last changed; zero when the entry does not
	// say.
	Updated time.Time
}

// ParseNames reads the payload of a /names resource, calling fn for every
// package in the order listed, and returns the repository name the resource
// states. A payload whose framing does not read is an error; an entry that
// does not read, or names no package, is skipped. An error fn returns stops
// the walk and is returned.
func ParseNames(payload []byte, fn func(NamesEntry) error) (repository string, err error) {
	err = forEachField(payload, func(field, wire int, val []byte) error {
		switch {
		case field == fieldIndexRepository && wire == wireLen:
			repository = string(val)
		case field == fieldIndexPackage && wire == wireLen:
			var e NamesEntry
			var bad bool
			if forEachField(val, func(f, w int, v []byte) error {
				switch {
				case f == fieldEntryName && w == wireLen:
					e.Name = string(v)
				case f == fieldNamesUpdatedAt && w == wireLen:
					t, ok := parseTimestamp(v)
					if !ok {
						bad = true
					}
					e.Updated = t
				}
				return nil
			}) != nil || bad || e.Name == "" {
				return nil
			}
			return fn(e)
		}
		return nil
	})
	return repository, err
}

// VersionsEntry is one package of a /versions resource.
type VersionsEntry struct {
	Name string
	// Versions are the package's versions in the order listed (hex.pm lists
	// them by version, oldest first).
	Versions []string
	// Retired marks, by position in Versions, the versions the repository
	// lists as retired. It is as long as Versions.
	Retired []bool
}

// ParseVersions reads the payload of a /versions resource, calling fn for
// every package in the order listed, and returns the repository name the
// resource states. A payload whose framing does not read is an error; an
// entry that does not read — a malformed field, a packed retired list that is
// not a run of varints — or names no package is skipped. Retired indexes
// outside the version list are ignored. An error fn returns stops the walk
// and is returned.
func ParseVersions(payload []byte, fn func(VersionsEntry) error) (repository string, err error) {
	err = forEachField(payload, func(field, wire int, val []byte) error {
		switch {
		case field == fieldIndexRepository && wire == wireLen:
			repository = string(val)
		case field == fieldIndexPackage && wire == wireLen:
			e, ok := parseVersionsEntry(val)
			if !ok {
				return nil
			}
			return fn(e)
		}
		return nil
	})
	return repository, err
}

// parseVersionsEntry reads one Package message of a /versions resource.
func parseVersionsEntry(msg []byte) (VersionsEntry, bool) {
	var e VersionsEntry
	var retired []uint64
	bad := false
	err := forEachField(msg, func(field, wire int, val []byte) error {
		switch {
		case field == fieldEntryName && wire == wireLen:
			e.Name = string(val)
		case field == fieldVersionsVersion && wire == wireLen:
			e.Versions = append(e.Versions, string(val))
		case field == fieldVersionsRetired && wire == wireLen:
			// Packed: a run of varints (a field may repeat; the runs
			// concatenate).
			for len(val) > 0 {
				x, n := binary.Uvarint(val)
				if n <= 0 {
					bad = true
					return nil
				}
				retired = append(retired, x)
				val = val[n:]
			}
		}
		// The unpacked form of retired (varint fields) is legal protobuf,
		// but the walk does not hand over a varint's value: such an entry
		// keeps its versions without retirement marks. Retirement is advisory
		// (clients must not refuse a retired release), so its versions are
		// still mirrored.
		return nil
	})
	if err != nil || bad || e.Name == "" {
		return VersionsEntry{}, false
	}
	e.Retired = make([]bool, len(e.Versions))
	for _, i := range retired {
		if i < uint64(len(e.Versions)) {
			e.Retired[i] = true
		}
	}
	return e, true
}

// parseTimestamp reads a Timestamp message, whose two fields are varints.
// Any other field, or a value out of range, makes it unreadable.
func parseTimestamp(msg []byte) (time.Time, bool) {
	var secs, nanos uint64
	for len(msg) > 0 {
		tag, n := binary.Uvarint(msg)
		if n <= 0 || tag&0x7 != wireVarint {
			return time.Time{}, false
		}
		msg = msg[n:]
		v, n := binary.Uvarint(msg)
		if n <= 0 {
			return time.Time{}, false
		}
		msg = msg[n:]
		switch tag >> 3 {
		case fieldTimestampSeconds:
			secs = v
		case fieldTimestampNanos:
			nanos = v
		}
	}
	// int64 seconds (negative ones are ten-byte varints, refused here as no
	// package changed before 1970) and nanos below a second.
	if secs > 1<<62 || nanos >= uint64(time.Second) {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), int64(nanos)).UTC(), true
}

// ValidPackageName reports whether s is a package name the backend serves
// (lower-case ASCII letters, digits and "_"): the rule its paths are
// classified by.
func ValidPackageName(s string) bool { return validPackageName(s) }

// TarballCoordinate reads the package and version a request path names as a
// release tarball ("/tarballs/<name>-<version>.tar"), as the backend
// classifies it; ok is false for a path the backend does not serve as one.
func TarballCoordinate(path string) (name, version string, ok bool) {
	res, ok := classify(path)
	if !ok || res.kind != kindTarball {
		return "", "", false
	}
	return res.name, res.version, true
}
