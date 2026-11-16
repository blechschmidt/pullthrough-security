package hex

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

var (
	mirrorKeyOnce sync.Once
	mirrorKey     *rsa.PrivateKey
)

// mirrorTestKey is a repository key made for the test.
func mirrorTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	mirrorKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		mirrorKey = k
	})
	return mirrorKey
}

// mirrorSigned wraps a payload as a repository serves it: gzip(Signed{payload,
// signature}), signed with key (unsigned when key is nil).
func mirrorSigned(t *testing.T, payload []byte, key *rsa.PrivateKey) []byte {
	t.Helper()
	signed := pbLenField(fieldSignedPayload, payload)
	if key != nil {
		sum := sha512.Sum512(payload)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		signed = append(signed, pbLenField(fieldSignedSignature, sig)...)
	}
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	_, _ = zw.Write(signed)
	_ = zw.Close()
	return zbuf.Bytes()
}

func TestOpenSignedResourceAndItsSignature(t *testing.T) {
	key := mirrorTestKey(t)
	payload := append(pbLenField(fieldIndexPackage, pbString(fieldEntryName, "jason")), pbString(fieldIndexRepository, "hexpm")...)
	body := mirrorSigned(t, payload, key)
	got, sig, err := OpenSignedResource(body)
	if err != nil || !bytes.Equal(got, payload) || len(sig) != 256 {
		t.Fatalf("OpenSignedResource: %d bytes, signature %d bytes, %v", len(got), len(sig), err)
	}
	if err := VerifyResourceSignature(got, sig, &key.PublicKey); err != nil {
		t.Errorf("a resource signed with the key: %v", err)
	}
	// Another key, a changed payload, no signature, no key: refused.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResourceSignature(got, sig, &other.PublicKey); err == nil {
		t.Errorf("verified with another key")
	}
	tampered := append([]byte(nil), got...)
	tampered[len(tampered)-1] ^= 1
	if err := VerifyResourceSignature(tampered, sig, &key.PublicKey); err == nil {
		t.Errorf("a changed payload verified")
	}
	_, unsigned, err := OpenSignedResource(mirrorSigned(t, payload, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResourceSignature(got, unsigned, &key.PublicKey); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Errorf("an unsigned resource: %v", err)
	}
	if err := VerifyResourceSignature(got, sig, nil); err == nil {
		t.Errorf("verified without a key")
	}
	// A body that is not a Signed envelope.
	for _, bad := range [][]byte{{0xff, 0xff}, pbString(2, "signature only")} {
		if _, _, err := OpenSignedResource(bad); err == nil {
			t.Errorf("%x accepted", bad)
		}
	}
}

// timestampMsg encodes a Timestamp{seconds, nanos}.
func timestampMsg(secs, nanos uint64) []byte {
	b := append(pbTag(fieldTimestampSeconds, wireVarint), pbVarint(secs)...)
	return append(append(b, pbTag(fieldTimestampNanos, wireVarint)...), pbVarint(nanos)...)
}

func TestParseNames(t *testing.T) {
	entry := func(fields ...[]byte) []byte { return pbLenField(fieldIndexPackage, bytes.Join(fields, nil)) }
	payload := bytes.Join([][]byte{
		entry(pbString(fieldEntryName, "jason"), pbLenField(fieldNamesUpdatedAt, timestampMsg(1793121360, 692202000))),
		entry(pbString(fieldEntryName, "no_time")),
		entry(pbLenField(fieldNamesUpdatedAt, timestampMsg(1, 0))),                                       // no name
		entry(pbString(fieldEntryName, "bad_time"), pbLenField(fieldNamesUpdatedAt, []byte{0x0a, 0x01})), // not varints
		entry(pbString(fieldEntryName, "bad_nanos"), pbLenField(fieldNamesUpdatedAt, timestampMsg(1, 2e9))),
		entry([]byte{0x0a, 0x7f}), // a length past the message
		pbString(fieldIndexRepository, "hexpm"),
	}, nil)
	var got []string
	repo, err := ParseNames(payload, func(e NamesEntry) error {
		got = append(got, fmt.Sprintf("%s@%s", e.Name, e.Updated.Format(time.RFC3339Nano)))
		return nil
	})
	if err != nil || repo != "hexpm" {
		t.Fatalf("ParseNames: %q %v", repo, err)
	}
	if want := "[jason@2026-10-27T17:16:00.692202Z no_time@0001-01-01T00:00:00Z]"; fmt.Sprint(got) != want {
		t.Errorf("entries %v, want %s", got, want)
	}
	stop := errors.New("stop")
	if _, err := ParseNames(payload, func(NamesEntry) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("fn's error: %v", err)
	}
	if _, err := ParseNames([]byte{0x0a, 0x05, 0x01}, func(NamesEntry) error { return nil }); err == nil {
		t.Errorf("a truncated payload was read")
	}
}

func TestParseVersions(t *testing.T) {
	entry := func(fields ...[]byte) []byte { return pbLenField(fieldIndexPackage, bytes.Join(fields, nil)) }
	versions := func(vs ...string) []byte {
		var b []byte
		for _, v := range vs {
			b = append(b, pbString(fieldVersionsVersion, v)...)
		}
		return b
	}
	packed := func(xs ...uint64) []byte {
		var b []byte
		for _, x := range xs {
			b = append(b, pbVarint(x)...)
		}
		return pbLenField(fieldVersionsRetired, b)
	}
	many := make([]string, 300)
	for i := range many {
		many[i] = fmt.Sprintf("0.0.%d", i)
	}
	payload := bytes.Join([][]byte{
		entry(pbString(fieldEntryName, "a2ui"), versions("0.1.0", "0.2.0", "0.3.0", "0.3.1"), packed(1, 2)),
		// A retired index past a varint's first byte, one out of range, and
		// with_advisories (field 5), which is not read.
		entry(pbString(fieldEntryName, "many"), versions(many...), packed(299, 300, 1<<40), pbLenField(5, pbVarint(3))),
		// Retired split over two runs.
		entry(pbString(fieldEntryName, "split"), versions("1.0.0", "2.0.0"), packed(0), packed(1)),
		// The unpacked form: versions kept, unmarked.
		entry(pbString(fieldEntryName, "unpacked"), versions("1.0.0"), pbTag(fieldVersionsRetired, wireVarint), pbVarint(0)),
		entry(pbString(fieldEntryName, "none")),
		entry(versions("1.0.0")), // no name
		entry(pbString(fieldEntryName, "bad_retired"), versions("1.0.0"), pbLenField(fieldVersionsRetired, []byte{0x80})),
		entry([]byte{0x12, 0x09, 'x'}), // a version's length past the message
		pbString(fieldIndexRepository, "acme"),
	}, nil)
	var got []string
	repo, err := ParseVersions(payload, func(e VersionsEntry) error {
		if len(e.Retired) != len(e.Versions) {
			t.Errorf("%s: %d retired marks for %d versions", e.Name, len(e.Retired), len(e.Versions))
		}
		var retired []string
		for i, r := range e.Retired {
			if r {
				retired = append(retired, e.Versions[i])
			}
		}
		got = append(got, fmt.Sprintf("%s:%d:%v", e.Name, len(e.Versions), retired))
		return nil
	})
	if err != nil || repo != "acme" {
		t.Fatalf("ParseVersions: %q %v", repo, err)
	}
	if want := "[a2ui:4:[0.2.0 0.3.0] many:300:[0.0.299] split:2:[1.0.0 2.0.0] unpacked:1:[] none:0:[]]"; fmt.Sprint(got) != want {
		t.Errorf("entries %v, want %s", got, want)
	}
	if _, err := ParseVersions([]byte{0x0a}, func(VersionsEntry) error { return nil }); err == nil {
		t.Errorf("a truncated payload was read")
	}
}

// TarballCoordinate reads back what the hex locator builds, as Resolve does.
func TestTarballCoordinateRoundTripsThroughResolve(t *testing.T) {
	b, err := New(Options{Name: "hex", UpstreamURL: "https://repo.hex.pm", Client: upstream.NewWithHTTPClient(http.DefaultClient, "test")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, version string }{{"jason", "1.4.4"}, {"a2ui", "0.3.1"}, {"altcha", "2.0.0-beta.1"}, {"x_1", "1.0.0+build.7"}} {
		p := "/tarballs/" + tc.name + "-" + tc.version + ".tar"
		n, v, ok := TarballCoordinate(p)
		if !ok || n != tc.name || v != tc.version {
			t.Errorf("%s: %q %q %v", p, n, v, ok)
		}
		res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: p, Query: url.Values{}, Header: http.Header{}})
		if err != nil || !res.Cacheable || res.Coordinate.Name != tc.name || res.Coordinate.Version != tc.version {
			t.Errorf("%s: %+v %v", p, res, err)
		}
		if !ValidPackageName(tc.name) {
			t.Errorf("%s is a valid name", tc.name)
		}
	}
	for _, p := range []string{"/tarballs/addressBook-0.1.0.tar", "/packages/jason", "/tarballs/jason.tar", "/tarballs/jason-1.0.0.tgz", "/names"} {
		if n, v, ok := TarballCoordinate(p); ok {
			t.Errorf("%s read as %s %s", p, n, v)
		}
	}
	for _, bad := range []string{"", "addressBook", "a-b", "a.b", "ä"} {
		if ValidPackageName(bad) {
			t.Errorf("%q is not a valid name", bad)
		}
	}
}
