//go:build fuzz
// +build fuzz

// Fuzz targets for the hex feed's parsers (Task 191): the payloads of
// /versions and /names, the signed envelope around them, and the option
// publicKey. None may panic; what they accept must stay bounded and well
// formed.
//
//	go test -tags fuzz -run='^$' -fuzz='^FuzzHexVersions$' -fuzztime=20s ./internal/fullmirror/
package fullmirror

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	hexbackend "github.com/blechschmidt/pullthrough-security/internal/backends/hex"
)

func hexFuzzFixture(f *testing.F, name string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", "feeds", "hex", name))
	if err != nil {
		f.Fatal(err)
	}
	return data
}

func FuzzHexVersions(f *testing.F) {
	f.Add(hexFuzzFixture(f, "versions.pb"))
	f.Add(hexFuzzFixture(f, "names.pb"))
	f.Add(hexEncodeVersions([]hexbackend.VersionsEntry{{Name: "x", Versions: []string{"1.0.0", "../1", "1.0.0/x"}, Retired: []bool{true}}}, "hexpm"))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x03, 0x0a, 0x01, 'x'})
	f.Add([]byte{0x0a, 0x06, 0x0a, 0x01, 'x', 0x1a, 0x01, 0x80})
	k, err := newKit(Env{Upstream: "hex-fuzz", Type: "hex", URL: "https://repo.hex.pm"})
	if err != nil {
		f.Fatal(err)
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, payload []byte) {
		b := files{dir: dir}.newSnapBuilder("hex")
		defer b.Abort()
		if _, err := hexAddVersions(context.Background(), k, payload, b); err != nil && !IsPermanent(err) {
			t.Fatalf("a malformed payload is not a permanent error: %v", err)
		}
		if len(b.lines) > len(payload) {
			t.Fatalf("%d records from %d bytes", len(b.lines), len(payload))
		}
		for _, l := range b.lines {
			rec, ok := snapDecodeLine([]byte(l))
			if !ok {
				t.Fatalf("record %q does not read back", l)
			}
			if !hexbackend.ValidPackageName(rec.Name) || !hexValidVersion(rec.Version) {
				t.Fatalf("record %+v", rec)
			}
			dec, err := url.PathUnescape(rec.Path)
			if err != nil {
				t.Fatalf("path %q: %v", rec.Path, err)
			}
			if n, v, ok := hexbackend.TarballCoordinate(dec); !ok || n != rec.Name || v != rec.Version {
				t.Fatalf("record %+v: the backend reads its path as %q %q %v", rec, n, v, ok)
			}
		}
	})
}

func FuzzHexNames(f *testing.F) {
	f.Add(hexFuzzFixture(f, "names.pb"))
	f.Add(hexFuzzFixture(f, "versions.pb"))
	f.Add(hexEncodeNames([]hexbackend.NamesEntry{{Name: "x", Updated: time.Unix(1, 2)}}, "hexpm"))
	f.Add([]byte{0x0a, 0x08, 0x0a, 0x01, 'x', 0x1a, 0x03, 0x08, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, payload []byte) {
		newest, _, err := hexNamesNewest(payload)
		if err != nil {
			if !IsPermanent(err) {
				t.Fatalf("a malformed payload is not a permanent error: %v", err)
			}
			return
		}
		if !newest.IsZero() && (newest.Before(time.Unix(0, 0)) || newest.Location() != time.UTC) {
			t.Fatalf("newest change %v", newest)
		}
	})
}

func FuzzHexResource(f *testing.F) {
	key := hexTestKey(f)
	f.Add(hexFuzzFixture(f, "packages-aatree"))
	f.Add(hexResource(f, hexFuzzFixture(f, "versions.pb"), key))
	f.Add(hexResource(f, hexFuzzFixture(f, "names.pb"), nil))
	f.Add([]byte("<html>"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00})
	signed := &hexSource{key: &key.PublicKey}
	unchecked := &hexSource{}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, s := range []*hexSource{signed, unchecked} {
			payload, err := s.open(body, "/versions")
			if err != nil {
				if !IsPermanent(err) {
					t.Fatalf("not a permanent error: %v", err)
				}
				continue
			}
			if len(payload) > 128<<20 {
				t.Fatalf("a payload of %d bytes", len(payload))
			}
		}
	})
}

func FuzzHexPublicKey(f *testing.F) {
	for _, s := range []string{"", "none", "NONE", hexPublicKey, hexKeyOption(f, &hexTestKey(f).PublicKey), "-----BEGIN PUBLIC KEY----- AAAA -----END PUBLIC KEY-----", "!!", "MIIB"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		key, err := hexParseKey(v)
		if err != nil {
			return
		}
		if key != nil && key.N.BitLen() < hexMinKeyBits {
			t.Fatalf("%q gave a %d-bit key", v, key.N.BitLen())
		}
	})
}
