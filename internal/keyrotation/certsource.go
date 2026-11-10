package keyrotation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// CertSpec identifies one x509 certificate file to monitor for expiry. It is the
// concrete, out-of-the-box source of hard-expiry material: an operator points
// the subsystem at the leaf/CA certificates they pin for upstream egress (Task
// 128) or terminate TLS with, and the scanner reads each certificate's NotAfter.
type CertSpec struct {
	// ID is the stable material id, e.g. "tls.upstream.github".
	ID string
	// Path is the PEM file on disk. The first CERTIFICATE block is used.
	Path string
	// Kind classifies the certificate (KindTLSCert or KindCA). Defaults to
	// KindTLSCert when empty.
	Kind Kind
	// Description is an optional operator-facing label.
	Description string
}

// CertSource reads a fixed set of certificate files on each scan and reports
// their NotAfter as hard expiry. A file that is missing or unparseable yields a
// Material with a descriptive note (and no expiry) rather than failing the scan,
// so one bad path cannot blind the monitor to the rest.
type CertSource struct {
	specs []CertSpec
	now   func() time.Time
}

// NewCertSource constructs a CertSource over the given specs. A nil clock uses
// time.Now.
func NewCertSource(specs []CertSpec, now func() time.Time) *CertSource {
	if now == nil {
		now = time.Now
	}
	return &CertSource{specs: specs, now: now}
}

// Scan implements Source.
func (c *CertSource) Scan(_ context.Context) ([]Material, error) {
	out := make([]Material, 0, len(c.specs))
	for _, sp := range c.specs {
		kind := sp.Kind
		if kind == "" {
			kind = KindTLSCert
		}
		m := Material{ID: sp.ID, Kind: kind, Description: sp.Description}
		cert, err := loadLeafCertificate(sp.Path)
		if err != nil {
			// Surface the problem as an evaluable material note; never leak file
			// contents. An unreadable pinned cert is itself worth an operator's
			// attention, so it is reported rather than silently dropped.
			m.Description = fmt.Sprintf("%s (unavailable: %v)", sp.Description, err)
			out = append(out, m)
			continue
		}
		m.NotAfter = cert.NotAfter
		m.LastRotated = cert.NotBefore
		m.KeyID = certificateKeyID(cert)
		if m.Description == "" {
			m.Description = cert.Subject.CommonName
		}
		out = append(out, m)
	}
	return out, nil
}

// loadLeafCertificate reads a PEM file and parses its first CERTIFICATE block.
func loadLeafCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no CERTIFICATE block in %s", path)
}

// certificateKeyID returns a stable, non-secret identifier for a certificate:
// the first 8 bytes of SHA-256 over its SubjectPublicKeyInfo, hex-encoded. This
// matches the key-id scheme the audit/attest signers use and is stable across
// re-issues under the same key (an SPKI pin), so a rotation is visible as a
// changed id.
func certificateKeyID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:8])
}
