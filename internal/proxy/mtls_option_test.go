package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
)

func mtlsTestDeps() Dependencies {
	return Dependencies{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cache:    cache.NewMemoryCache(),
		Backends: backends.NewRegistry(),
	}
}

// TestNewRejectsMTLSWithoutTLS verifies that requesting client-certificate auth
// without TLS termination is a configuration error (mTLS terminates at the
// gateway).
func TestNewRejectsMTLSWithoutTLS(t *testing.T) {
	_, err := New(mtlsTestDeps(), Options{
		HTTPAddr:      ":0",
		TLSClientAuth: tls.RequireAnyClientCert,
	})
	if err == nil {
		t.Fatal("expected error: mTLS client auth without TLS termination")
	}
}

// TestNewAppliesClientAuthMode verifies the TLS client-auth mode is propagated
// onto the server's TLS config when TLS is enabled.
func TestNewAppliesClientAuthMode(t *testing.T) {
	g, err := New(mtlsTestDeps(), Options{
		HTTPAddr:      ":0",
		TLSCertFile:   "/tls/cert.pem",
		TLSKeyFile:    "/tls/key.pem",
		TLSClientAuth: tls.RequestClientCert,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.server.TLSConfig == nil {
		t.Fatal("TLSConfig not set")
	}
	if g.server.TLSConfig.ClientAuth != tls.RequestClientCert {
		t.Fatalf("ClientAuth = %v, want RequestClientCert", g.server.TLSConfig.ClientAuth)
	}
	if g.server.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", g.server.TLSConfig.MinVersion)
	}
}
