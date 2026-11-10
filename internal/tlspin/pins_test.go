package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// newTestCert mints a fresh self-signed certificate with a new key pair and
// returns the parsed leaf.
func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}

func TestParsePins(t *testing.T) {
	cert := newTestCert(t, "example")
	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	certSum := sha256.Sum256(cert.Raw)

	spkiB64 := base64.StdEncoding.EncodeToString(spkiSum[:])
	certHex := hex.EncodeToString(certSum[:])

	cases := []struct {
		name string
		spec string
		want Kind
		hash [32]byte
	}{
		{"spki base64", "spki-sha256:" + spkiB64, KindSPKI, spkiSum},
		{"spki hpkp alias", "sha256//" + spkiB64, KindSPKI, spkiSum},
		{"pin-sha256 alias", "pin-sha256:" + spkiB64, KindSPKI, spkiSum},
		{"cert hex", "cert-sha256:" + certHex, KindCert, certSum},
		{"cert base64", "cert-sha256:" + base64.StdEncoding.EncodeToString(certSum[:]), KindCert, certSum},
		{"ca hex", "ca-sha256:" + certHex, KindCA, certSum},
		{"case-insensitive prefix", "SPKI-SHA256:" + spkiB64, KindSPKI, spkiSum},
		{"whitespace trimmed", "  cert-sha256:" + certHex + "  ", KindCert, certSum},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pins, err := ParsePins([]string{tc.spec})
			if err != nil {
				t.Fatalf("ParsePins(%q): %v", tc.spec, err)
			}
			if len(pins) != 1 {
				t.Fatalf("got %d pins, want 1", len(pins))
			}
			if pins[0].Kind != tc.want {
				t.Errorf("kind = %v, want %v", pins[0].Kind, tc.want)
			}
			if pins[0].Hash != tc.hash {
				t.Errorf("hash mismatch")
			}
		})
	}
}

func TestParsePinsErrors(t *testing.T) {
	cases := []string{
		"no-prefix-deadbeef",
		"spki-sha256:not-base64-or-hex!!",
		"cert-sha256:abcd",                     // too short
		"ca-sha256:" + strings.Repeat("z", 64), // 64 chars but not hex
		"md5:" + strings.Repeat("a", 32),       // unsupported digest prefix
	}
	for _, spec := range cases {
		if _, err := ParsePins([]string{spec}); err == nil {
			t.Errorf("ParsePins(%q): expected error, got nil", spec)
		}
	}
}

func TestParsePinsSkipsBlank(t *testing.T) {
	pins, err := ParsePins([]string{"", "   ", ""})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(pins) != 0 {
		t.Fatalf("got %d pins, want 0", len(pins))
	}
}

func TestMatchPinsLeaf(t *testing.T) {
	leaf := newTestCert(t, "leaf")
	other := newTestCert(t, "other")

	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	// Correct SPKI pin matches.
	pins, _ := ParsePins([]string{LeafSPKIPin(leaf)})
	if ok, _ := matchPins(cs, pins); !ok {
		t.Error("correct SPKI pin should match")
	}
	// Correct cert pin matches.
	pins, _ = ParsePins([]string{LeafCertPin(leaf)})
	if ok, _ := matchPins(cs, pins); !ok {
		t.Error("correct cert pin should match")
	}
	// A pin for a different cert does not match.
	pins, _ = ParsePins([]string{LeafSPKIPin(other)})
	ok, present := matchPins(cs, pins)
	if ok {
		t.Error("wrong SPKI pin should not match")
	}
	// The presented leaf hashes are reported for diagnostics/rotation.
	if present.SPKISHA256 != strings.TrimPrefix(LeafSPKIPin(leaf), "spki-sha256:") {
		t.Errorf("present SPKI = %q, want leaf SPKI", present.SPKISHA256)
	}

	// Rotation: listing both the old (wrong) and new (correct) pin matches.
	pins, _ = ParsePins([]string{LeafSPKIPin(other), LeafSPKIPin(leaf)})
	if ok, _ := matchPins(cs, pins); !ok {
		t.Error("rotation pin set (old+new) should match on the new pin")
	}
}

func TestMatchPinsCAInChain(t *testing.T) {
	leaf := newTestCert(t, "leaf")
	ca := newTestCert(t, "ca")

	// Peer presents a chain [leaf, ca]; a ca-sha256 pin for the CA must match even
	// though the CA is not the leaf.
	cs := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, ca}}
	pins, _ := ParsePins([]string{CertPin(ca)})
	if ok, _ := matchPins(cs, pins); !ok {
		t.Error("ca pin for an in-chain CA should match")
	}

	// A CA pin whose cert is not in the chain does not match.
	absent := newTestCert(t, "absent-ca")
	pins, _ = ParsePins([]string{CertPin(absent)})
	if ok, _ := matchPins(cs, pins); ok {
		t.Error("ca pin for an absent CA should not match")
	}
}

func TestMatchPinsNoPeerCerts(t *testing.T) {
	pins, _ := ParsePins([]string{"spki-sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))})
	if ok, _ := matchPins(tls.ConnectionState{}, pins); ok {
		t.Error("a connection with no peer certs must not match any pin")
	}
}
