package intercept

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile: filepath.Join(dir, "ca.crt"),
		KeyFile:  filepath.Join(dir, "ca.key"),
		Generate: true,
	})
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	return ca
}

func TestLoadOrGenerateCA_GeneratesAndReloads(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	ca, err := LoadOrGenerateCA(CAOptions{CertFile: certFile, KeyFile: keyFile, Generate: true})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !fileExists(certFile) || !fileExists(keyFile) {
		t.Fatalf("CA files were not persisted")
	}
	first := ca.CertPEM()

	// A second load (files now present) must reuse the same CA, not regenerate.
	ca2, err := LoadOrGenerateCA(CAOptions{CertFile: certFile, KeyFile: keyFile, Generate: true})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(first) != string(ca2.CertPEM()) {
		t.Fatalf("reloaded CA differs from generated CA")
	}
}

func TestLoadOrGenerateCA_MissingWithoutGenerate(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadOrGenerateCA(CAOptions{
		CertFile: filepath.Join(dir, "ca.crt"),
		KeyFile:  filepath.Join(dir, "ca.key"),
		Generate: false,
	})
	if err == nil {
		t.Fatal("expected error for missing CA without generate")
	}
}

func TestLoadOrGenerateCA_HalfPresent(t *testing.T) {
	ca := newTestCA(t)
	_ = ca
	dir := t.TempDir()
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	// Generate a CA, then delete only the key.
	if _, err := LoadOrGenerateCA(CAOptions{CertFile: certFile, KeyFile: keyFile, Generate: true}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := os.Remove(keyFile); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, err := LoadOrGenerateCA(CAOptions{CertFile: certFile, KeyFile: keyFile, Generate: true}); err == nil {
		t.Fatal("expected error for half-present CA")
	}
}

func TestLeafForHost_VerifiesAgainstCA(t *testing.T) {
	ca := newTestCA(t)

	leaf, err := ca.LeafForHost("registry.npmjs.org")
	if err != nil {
		t.Fatalf("LeafForHost: %v", err)
	}
	if leaf.Leaf == nil {
		t.Fatal("leaf.Leaf not populated")
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to add CA to pool")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		DNSName: "registry.npmjs.org",
		Roots:   roots,
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}

	// Wrong host must fail verification.
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{DNSName: "evil.example.com", Roots: roots}); err == nil {
		t.Fatal("leaf verified for the wrong host")
	}
}

func TestLeafForHost_IPAddress(t *testing.T) {
	ca := newTestCA(t)
	leaf, err := ca.LeafForHost("10.0.0.5")
	if err != nil {
		t.Fatalf("LeafForHost(ip): %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 {
		t.Fatalf("expected IP SAN, got %v", leaf.Leaf.IPAddresses)
	}
}

func TestLeafForHost_CachedAndStable(t *testing.T) {
	ca := newTestCA(t)
	a, err := ca.LeafForHost("pypi.org")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, err := ca.LeafForHost("pypi.org:443") // port stripped -> same host
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if a != b {
		t.Fatal("expected cached leaf to be returned for the same host")
	}
	if ca.cache.len() != 1 {
		t.Fatalf("expected 1 cached cert, got %d", ca.cache.len())
	}
}

func TestCertCacheEviction(t *testing.T) {
	c := newCertCache(2)
	cert := &tls.Certificate{}
	c.put("a", cert)
	c.put("b", cert)
	c.put("c", cert) // evicts "a"
	if _, ok := c.get("a"); ok {
		t.Fatal("expected 'a' to be evicted")
	}
	if _, ok := c.get("c"); !ok {
		t.Fatal("expected 'c' present")
	}
	if c.len() != 2 {
		t.Fatalf("expected size 2, got %d", c.len())
	}
}

func TestNewCAFromPEM_RejectsNonCA(t *testing.T) {
	// A minted leaf is not a CA; wrapping it as a CA must be rejected.
	ca := newTestCA(t)
	leaf, err := ca.LeafForHost("example.com")
	if err != nil {
		t.Fatalf("LeafForHost: %v", err)
	}
	if leaf.Leaf.IsCA {
		t.Fatal("leaf should not be a CA")
	}
}

func TestGenerateCA_LeafTTLApplied(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrGenerateCA(CAOptions{
		CertFile: filepath.Join(dir, "c"),
		KeyFile:  filepath.Join(dir, "k"),
		Generate: true,
		LeafTTL:  2 * time.Hour,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	leaf, err := ca.LeafForHost("h.example")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	life := leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore)
	// NotBefore is backdated 1h, so total span is TTL + 1h.
	if life < 2*time.Hour || life > 4*time.Hour {
		t.Fatalf("unexpected leaf lifetime %s", life)
	}
}
