package k8swebhook

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/dossier"
)

// writeSelfSignedCert writes a throwaway self-signed serving cert/key for
// 127.0.0.1 to dir and returns their paths.
func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// TestServerTLSEndToEnd starts the real TLS webhook server on an ephemeral port
// and drives a full HTTPS AdmissionReview round-trip, asserting a block verdict
// denies the Pod.
func TestServerTLSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)

	// Bind an ephemeral port, then hand its address to the server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Addr = addr
	cfg.TLSCertFile = certFile
	cfg.TLSKeyFile = keyFile

	src := &fakeSource{verdicts: map[string]Verdict{"org/evil": {Decision: dossier.VerdictBlock, Summary: "malware"}}}
	srv, err := NewServer(cfg, src, nil, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-runErr; err != nil {
			t.Errorf("server Run returned: %v", err)
		}
	}()

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed test cert
	}

	review := AdmissionReview{
		APIVersion: admissionAPIVersion,
		Kind:       admissionKind,
		Request:    podReview("prod", "ghcr.io/org/evil:1.0"),
	}
	body, _ := json.Marshal(review)

	// Retry briefly until the listener is accepting (no sleep in the hot path).
	url := "https://" + addr + "/validate"
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Post(url, "application/json", bytes.NewReader(body))
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("POST never succeeded: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 envelope, got %d", resp.StatusCode)
	}
	var out AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatalf("expected deny, got %+v", out.Response)
	}

	// Health endpoint over the same TLS listener.
	hresp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz GET: %v", err)
	}
	_ = hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d, want 200", hresp.StatusCode)
	}
}

func TestNewServerRequiresCert(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	if _, err := NewServer(cfg, &fakeSource{}, nil, nil); err == nil {
		t.Fatal("expected an error when no serving certificate is configured")
	}
}
