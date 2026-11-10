//go:build fuzz
// +build fuzz

// Fuzz targets for the Hex pull-through parsers (Task 30, Task 122).
//
// A malicious or compromised upstream repository controls the /packages/<name>
// protobuf resource body and (via the client) the request path. Both are parsed
// on the pull path before any content is cached or served, so the parsers must
// never panic, must not allocate without bound, and must fail closed on
// malformed input.
//
// Build-tag gated (`fuzz`). Run e.g.:
//
//	go test -tags fuzz -run=^$ -fuzz=FuzzClassify ./internal/backends/hex/
package hex

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func FuzzClassify(f *testing.F) {
	seeds := []string{
		"/names",
		"/versions",
		"/packages/jason",
		"/packages/plug_cowboy",
		"/tarballs/jason-1.4.1.tar",
		"/tarballs/foo-1.0.0-rc.1.tar",
		"/tarballs/../etc/passwd.tar",
		"/packages/../../etc/passwd",
		"", "/", "////",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		res, ok := classify(path)
		if !ok {
			return
		}
		_ = res.cacheable()
		_ = res.kindLabel()
		_ = res.coordinateName()
		_ = res.isRegistryResource()
		if res.verifiableFile() {
			if res.filename == "" {
				t.Fatalf("verifiable tarball with empty filename: %q", path)
			}
			if res.name == "" || res.version == "" {
				t.Fatalf("tarball with incomplete coordinate: %q -> %+v", path, res)
			}
		}
	})
}

func FuzzParsePackageResource(f *testing.F) {
	// Seed with a well-formed gzipped Signed{Package} and some near-misses.
	f.Add(encodeSeed("jason", "1.4.1"))
	f.Add([]byte("not gzip, not protobuf"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00}) // gzip magic, truncated
	f.Add([]byte(""))
	f.Add([]byte{0x0a, 0xff}) // length prefix past end
	f.Fuzz(func(t *testing.T, body []byte) {
		idx, err := ParsePackageResource(body)
		if err != nil {
			return
		}
		// Every recorded digest must be a 64-char lowercase hex SHA-256, and
		// lookups must be safe for arbitrary keys.
		for version, d := range idx.outer {
			if len(d) != sha256Len*2 {
				t.Fatalf("index accepted wrong-length digest %q for %q", d, version)
			}
			for i := 0; i < len(d); i++ {
				c := d[i]
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Fatalf("index accepted non-hex digest %q for %q", d, version)
				}
			}
		}
		_, _ = idx.outerFor("1.4.1")
		_, _ = idx.outerFor("")
	})
}

// encodeSeed builds a minimal valid gzipped Signed{Package{Release}} body for
// the fuzz corpus. It is self-contained (a tiny protobuf+gzip encoder) so the
// fuzz target does not depend on the *testing.T-based helpers in hex_test.go.
func encodeSeed(name, version string) []byte {
	fv := func(b []byte, field int, val []byte) []byte {
		var vb [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(vb[:], uint64(field<<3|wireLen))
		b = append(b, vb[:n]...)
		n = binary.PutUvarint(vb[:], uint64(len(val)))
		b = append(b, vb[:n]...)
		return append(b, val...)
	}
	sum := sha256.Sum256([]byte(name + "-" + version))
	var rel []byte
	rel = fv(rel, fieldReleaseVersion, []byte(version))
	rel = fv(rel, fieldReleaseOuter, sum[:])
	var pkg []byte
	pkg = fv(pkg, fieldPackageRelease, rel)
	pkg = fv(pkg, 2, []byte(name))
	var signed []byte
	signed = fv(signed, fieldSignedPayload, pkg)
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	_, _ = zw.Write(signed)
	_ = zw.Close()
	return zbuf.Bytes()
}
