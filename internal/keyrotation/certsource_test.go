package keyrotation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir, name string, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test." + name},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	path := filepath.Join(dir, name+".pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func TestCertSource_ReadsNotAfter(t *testing.T) {
	dir := t.TempDir()
	notAfter := time.Date(2027, 6, 1, 12, 0, 0, 0, time.UTC)
	path := writeTestCert(t, dir, "leaf", notAfter)

	src := NewCertSource([]CertSpec{
		{ID: "tls.leaf", Path: path, Kind: KindTLSCert},
	}, nil)
	mats, err := src.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(mats) != 1 {
		t.Fatalf("got %d materials, want 1", len(mats))
	}
	m := mats[0]
	if !m.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %s, want %s", m.NotAfter, notAfter)
	}
	if m.KeyID == "" {
		t.Fatal("expected a derived key id from the certificate SPKI")
	}
	if m.Kind != KindTLSCert {
		t.Fatalf("kind = %q, want tls-cert", m.Kind)
	}
	if m.Description == "" {
		t.Fatal("expected the subject common name as the default description")
	}

	// End-to-end through Evaluate: a cert 90 days out is healthy.
	now := notAfter.Add(-90 * 24 * time.Hour)
	st := Evaluate(now, m, Thresholds{Warn: 14 * 24 * time.Hour, Critical: 3 * 24 * time.Hour})
	if st.Status != StatusOK || !st.HasExpiry {
		t.Fatalf("evaluate = %+v, want healthy with expiry", st)
	}
}

func TestCertSource_MissingFileIsReportedNotFatal(t *testing.T) {
	src := NewCertSource([]CertSpec{
		{ID: "tls.absent", Path: "/nonexistent/path/cert.pem", Kind: KindCA, Description: "pinned CA"},
	}, nil)
	mats, err := src.Scan(context.Background())
	if err != nil {
		t.Fatalf("a missing file must not fail the scan: %v", err)
	}
	if len(mats) != 1 {
		t.Fatalf("got %d materials, want 1", len(mats))
	}
	m := mats[0]
	if !m.NotAfter.IsZero() {
		t.Fatal("a missing cert must have no expiry")
	}
	if m.Description == "" || m.Kind != KindCA {
		t.Fatalf("missing cert should be reported with its kind and a note: %+v", m)
	}
}
