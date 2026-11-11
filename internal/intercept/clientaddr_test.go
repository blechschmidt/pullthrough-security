package intercept

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

// The gateway attributes what it serves to the address a request came from —
// the download log's "which address pulled this package" (Task 176), the audit
// log's remoteAddr. In interception mode the request the gateway sees is one
// this proxy re-creates from a decrypted connection, so it is this proxy's job
// to hand over the client's address, not its own.
func TestDispatchedRequestsCarryTheClientAddress(t *testing.T) {
	// A source address no other connection of the test uses, so "the client's
	// address" cannot be confused with a default.
	const clientAddr = "127.0.42.7"
	probe, err := net.Listen("tcp", net.JoinHostPort(clientAddr, "0"))
	if err != nil {
		t.Skipf("cannot bind %s (needs a system where all of 127.0.0.0/8 is local): %v", clientAddr, err)
	}
	_ = probe.Close()

	var mu sync.Mutex
	seen := map[string]string{} // request path -> remote host
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		mu.Lock()
		seen[r.URL.Path] = host
		mu.Unlock()
		_, _ = io.WriteString(w, "ok")
	})
	router := NewRouter(map[string]string{"index.crates.io": "cargo", "mirror.local": "go"})
	addr, ca := startProxy(t, Options{Router: router, AllowPlainHTTP: true}, dispatch)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to load CA into pool")
	}
	proxyURL, _ := url.Parse("http://" + addr)
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientAddr)}, Timeout: 5 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			DialContext:     dialer.DialContext,
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	// Intercepted TLS (CONNECT, then decrypted requests) and plain-HTTP proxying
	// are separate code paths; both must pass the address on.
	for _, target := range []string{
		"https://index.crates.io/api/v1/crates/cfg-if/1.0.0/download",
		"http://mirror.local/rsc.io/quote/@v/v1.5.2.zip",
	} {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", target, resp.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for path, want := range map[string]string{
		"/v1/cargo/api/v1/crates/cfg-if/1.0.0/download": clientAddr,
		"/v1/go/rsc.io/quote/@v/v1.5.2.zip":             clientAddr,
	} {
		if got, ok := seen[path]; !ok || got != want {
			t.Errorf("the request for %s was dispatched with remote address %q (dispatched: %v), want the client's %s", path, got, ok, want)
		}
	}
}
