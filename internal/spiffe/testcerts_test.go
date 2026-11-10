package spiffe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// testCA is a self-signed CA used to issue SVID leaf certificates in tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

// newTestCA generates a fresh self-signed CA with the given common name.
func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &testCA{cert: cert, key: key, der: der}
}

// pemBundle renders the CA certificate as a PEM trust bundle.
func (ca *testCA) pemBundle() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
}

// leafOptions tunes an issued SVID leaf certificate.
type leafOptions struct {
	spiffeID  string // SAN URI; empty omits the SPIFFE SAN
	extraURIs []string
	notBefore time.Time
	notAfter  time.Time
	serial    int64
}

// issueLeaf signs a leaf certificate carrying the requested SPIFFE SAN URI.
func (ca *testCA) issueLeaf(t *testing.T, opts leafOptions) *x509.Certificate {
	cert, _ := ca.issueLeafWithKey(t, opts)
	return cert
}

// issueLeafWithKey signs a leaf and also returns its private key, for tests that
// must present the certificate over a real TLS handshake.
func (ca *testCA) issueLeafWithKey(t *testing.T, opts leafOptions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	nb := opts.notBefore
	if nb.IsZero() {
		nb = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	na := opts.notAfter
	if na.IsZero() {
		na = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	serial := opts.serial
	if serial == 0 {
		serial = 2
	}
	var uris []*url.URL
	if opts.spiffeID != "" {
		u, perr := url.Parse(opts.spiffeID)
		if perr != nil {
			t.Fatalf("parse spiffe id %q: %v", opts.spiffeID, perr)
		}
		uris = append(uris, u)
	}
	for _, extra := range opts.extraURIs {
		u, perr := url.Parse(extra)
		if perr != nil {
			t.Fatalf("parse uri %q: %v", extra, perr)
		}
		uris = append(uris, u)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return cert, key
}
