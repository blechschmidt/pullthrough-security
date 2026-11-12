package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/admin"
	"github.com/blechschmidt/pullthrough-security/internal/intercept"
)

// interceptFixture serves the admin API of a proxy whose interception routes
// two upstreams, and returns the global flags that reach it.
func interceptFixture(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	ca, err := intercept.LoadOrGenerateCA(intercept.CAOptions{
		CertFile: filepath.Join(dir, "ca.crt"), KeyFile: filepath.Join(dir, "ca.key"), Generate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := intercept.New(intercept.Options{
		ListenAddr: ":3128", NATListenAddr: ":8443",
		Router: intercept.NewRouter(map[string]string{"deb.debian.org/debian": "apt", "pypi.org": "pip"}),
		CA:     ca,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(admin.Options{Cache: emptyCache{}, Intercept: p, Token: "t0ken"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return []string{"--url", ts.URL, "--token", "t0ken"}
}

func TestInterceptCommands(t *testing.T) {
	flags := interceptFixture(t)

	out, err := runCaptured(t, append([]string{"intercept", "status"}, flags...)...)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{":3128", ":8443", "not run", "deb.debian.org/debian", "apt", "pypi.org", "refused", "intercept", "nat"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}

	out, err = runCaptured(t, append([]string{"intercept", "hosts", "--address", "10.0.0.5"}, flags...)...)
	if err != nil || out != "10.0.0.5\tdeb.debian.org\n10.0.0.5\tpypi.org\n" {
		t.Errorf("hosts: %q, %v", out, err)
	}

	certPath := filepath.Join(t.TempDir(), "ca.crt")
	if _, err := runCaptured(t, append([]string{"intercept", "ca", "--out", certPath}, flags...)...); err != nil {
		t.Fatalf("ca: %v", err)
	}
	pem, err := os.ReadFile(certPath)
	if err != nil || !strings.HasPrefix(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("the CA written is %q (%v)", pem, err)
	}

	if _, err := runCaptured(t, "intercept", "frobnicate"); err == nil {
		t.Error("an unknown action was accepted")
	}
}
