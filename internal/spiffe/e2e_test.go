package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEndToEndMutualTLS drives a real TLS handshake: a test server configured
// with tls.RequestClientCert receives a client presenting an SVID, and the
// authenticator (reading r.TLS.PeerCertificates populated by the handshake)
// resolves it to a tenant. This validates the full transport-to-principal path,
// not just an injected ConnectionState.
func TestEndToEndMutualTLS(t *testing.T) {
	ca := newTestCA(t, "mesh-ca")
	// Use the real clock: the test CA/leaf are valid 2020-2035, which spans now.
	a := buildAuth(t, ca, "example.org", []Rule{
		{Pattern: "spiffe://example.org/ns/prod/sa/*", Tenant: "prod", Roles: []string{"reader"}},
	}, func(o *Options) { o.Now = nil })

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := a.Authenticate(context.Background(), r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, p.Subject+"|"+p.Team)
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()

	leaf, key := ca.issueLeafWithKey(t, leafOptions{spiffeID: "spiffe://example.org/ns/prod/sa/web"})

	// httptest's server certificate is self-signed; trust it for the test client.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(srv.Certificate())

	clientCert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{clientCert},
	}}}

	resp, err := client.Get(srv.URL + "/v1/npm/pkg.tgz")
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if string(body) != "spiffe://example.org/ns/prod/sa/web|prod" {
		t.Fatalf("body = %q", body)
	}

	// A client presenting no certificate falls through (this minimal handler has
	// no token fallback, so it returns 401).
	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootPool}}}
	resp2, err := noCertClient.Get(srv.URL + "/v1/npm/pkg.tgz")
	if err != nil {
		t.Fatalf("no-cert GET: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-cert status = %d, want 401", resp2.StatusCode)
	}
}
