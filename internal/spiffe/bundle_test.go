package spiffe

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTrustBundlePEM(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	b, err := ParseTrustBundle(ca.pemBundle(), FormatAuto, "example.org")
	if err != nil {
		t.Fatalf("ParseTrustBundle: %v", err)
	}
	if _, ok := b.Roots("example.org"); !ok {
		t.Fatal("expected roots for example.org")
	}
	if _, ok := b.Roots("other.org"); ok {
		t.Fatal("did not expect roots for other.org")
	}
	if b.Count() != 1 {
		t.Fatalf("Count = %d, want 1", b.Count())
	}
	if got := b.SoonestExpiry(); !got.Equal(ca.cert.NotAfter) {
		t.Fatalf("SoonestExpiry = %v, want %v", got, ca.cert.NotAfter)
	}
}

func TestParseTrustBundlePEMRequiresDomain(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	if _, err := ParseTrustBundle(ca.pemBundle(), FormatPEM, ""); err == nil {
		t.Fatal("expected error: PEM bundle needs a default trust domain")
	}
}

func TestParseTrustBundleSPIFFESingleDomain(t *testing.T) {
	ca := newTestCA(t, "test-ca")
	doc := map[string]any{
		"keys": []map[string]any{
			{"use": "x509-svid", "x5c": []string{base64.StdEncoding.EncodeToString(ca.der)}},
			// A jwt-svid key must be ignored, not fail the parse.
			{"use": "jwt-svid", "kid": "k1", "kty": "RSA"},
		},
		"spiffe_sequence":     1,
		"spiffe_refresh_hint": 10,
	}
	data, _ := json.Marshal(doc)
	b, err := ParseTrustBundle(data, FormatAuto, "example.org")
	if err != nil {
		t.Fatalf("ParseTrustBundle: %v", err)
	}
	if _, ok := b.Roots("example.org"); !ok {
		t.Fatal("expected roots for example.org")
	}
}

func TestParseTrustBundleSPIFFEFederated(t *testing.T) {
	ca1 := newTestCA(t, "ca1")
	ca2 := newTestCA(t, "ca2")
	doc := map[string]any{
		"trust_domains": map[string]any{
			"a.example": map[string]any{
				"keys": []map[string]any{{"use": "x509-svid", "x5c": []string{base64.StdEncoding.EncodeToString(ca1.der)}}},
			},
			"b.example": map[string]any{
				"keys": []map[string]any{{"use": "x509-svid", "x5c": []string{base64.StdEncoding.EncodeToString(ca2.der)}}},
			},
		},
	}
	data, _ := json.Marshal(doc)
	// No default domain needed: every domain is named explicitly.
	b, err := ParseTrustBundle(data, FormatSPIFFE, "")
	if err != nil {
		t.Fatalf("ParseTrustBundle: %v", err)
	}
	for _, d := range []string{"a.example", "b.example"} {
		if _, ok := b.Roots(d); !ok {
			t.Fatalf("expected roots for %s", d)
		}
	}
	if b.Count() != 2 {
		t.Fatalf("Count = %d, want 2", b.Count())
	}
}

func TestBundleSourceReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	ca1 := newTestCA(t, "ca1")
	if err := os.WriteFile(path, ca1.pemBundle(), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewBundleSource(path, FormatPEM, "example.org")
	if err != nil {
		t.Fatalf("NewBundleSource: %v", err)
	}
	if src.Stats().Roots != 1 {
		t.Fatalf("initial roots = %d", src.Stats().Roots)
	}

	// Replace the bundle with two roots and reload.
	ca2 := newTestCA(t, "ca2")
	combined := append(ca1.pemBundle(), ca2.pemBundle()...)
	if err := os.WriteFile(path, combined, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := src.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := src.Stats().Roots; got != 2 {
		t.Fatalf("reloaded roots = %d, want 2", got)
	}
	if src.Stats().Reloads != 2 {
		t.Fatalf("reload count = %d, want 2", src.Stats().Reloads)
	}
}

func TestBundleSourceReloadFailsSafe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	ca := newTestCA(t, "ca")
	if err := os.WriteFile(path, ca.pemBundle(), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewBundleSource(path, FormatPEM, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the file; the reload must fail but keep the previous good bundle.
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := src.Reload(); err == nil {
		t.Fatal("expected reload error on corrupt bundle")
	}
	if _, ok := src.Current().Roots("example.org"); !ok {
		t.Fatal("previous good bundle should remain after a failed reload")
	}
	if src.Stats().LastError == "" {
		t.Fatal("expected LastError to be recorded")
	}
}

func TestNewBundleSourceInitialLoadError(t *testing.T) {
	if _, err := NewBundleSource(filepath.Join(t.TempDir(), "missing.pem"), FormatPEM, "example.org"); err == nil {
		t.Fatal("expected error for missing bundle file")
	}
}

func TestBundleSoonestExpiry(t *testing.T) {
	ca := newTestCA(t, "ca")
	b, _ := ParseTrustBundle(ca.pemBundle(), FormatPEM, "example.org")
	if b.SoonestExpiry().Before(time.Now()) {
		t.Fatal("test CA should not be expired")
	}
}
