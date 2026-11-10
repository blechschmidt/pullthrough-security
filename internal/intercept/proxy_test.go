package intercept

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// startProxy binds a proxy on a loopback port and returns its address plus a
// cancel func. dispatch receives the rewritten requests.
func startProxy(t *testing.T, opts Options, dispatch http.Handler) (addr string, ca *CA) {
	t.Helper()
	if opts.CA == nil {
		opts.CA = newTestCA(t)
	}
	ca = opts.CA
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Serve(ctx, ln, dispatch)
	}()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), ca
}

// clientThrough builds an http.Client that proxies through proxyAddr and trusts
// the intercept CA.
func clientThrough(t *testing.T, proxyAddr string, ca *CA) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to load CA into pool")
	}
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

func TestProxyInterceptsAndRewrites(t *testing.T) {
	var gotPath, gotHost, gotInterceptHeader atomic.Value
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		gotHost.Store(r.Host)
		gotInterceptHeader.Store(r.Header.Get("X-Pullthrough-Intercepted-Host"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	})

	router := NewRouter(map[string]string{"registry.npmjs.org": "npm"})
	addr, ca := startProxy(t, Options{Router: router}, dispatch)
	client := clientThrough(t, addr, ca)

	resp, err := client.Get("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
	if err != nil {
		t.Fatalf("GET through intercept proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", body)
	}
	if got := gotPath.Load(); got != "/v1/npm/lodash/-/lodash-4.17.21.tgz" {
		t.Fatalf("rewritten path = %q, want /v1/npm/lodash/-/lodash-4.17.21.tgz", got)
	}
	if got := gotHost.Load(); got != "registry.npmjs.org" {
		t.Fatalf("host = %q, want registry.npmjs.org", got)
	}
	if got := gotInterceptHeader.Load(); got != "registry.npmjs.org" {
		t.Fatalf("intercept header = %q", got)
	}
}

func TestProxyMultipleRequestsKeepAlive(t *testing.T) {
	var count int64
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		fmt.Fprintf(w, "req %d", atomic.LoadInt64(&count))
	})
	router := NewRouter(map[string]string{"pypi.org": "pip"})
	addr, ca := startProxy(t, Options{Router: router}, dispatch)
	client := clientThrough(t, addr, ca)

	for i := 0; i < 3; i++ {
		resp, err := client.Get("https://pypi.org/simple/requests/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if atomic.LoadInt64(&count) != 3 {
		t.Fatalf("expected 3 dispatched requests, got %d", count)
	}
}

func TestProxyRefusesUnconfiguredHost(t *testing.T) {
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("dispatch must not be called for an unconfigured host")
	})
	router := NewRouter(map[string]string{"pypi.org": "pip"})
	addr, ca := startProxy(t, Options{Router: router, PassthroughUnmatched: false}, dispatch)
	client := clientThrough(t, addr, ca)

	_, err := client.Get("https://evil.example.com/payload")
	if err == nil {
		t.Fatal("expected error connecting to an unconfigured host")
	}
}

func TestProxyPassthroughUnconfiguredHost(t *testing.T) {
	// Stand up a real TLS origin the proxy will blind-tunnel to. The client must
	// see the ORIGIN's certificate (not a minted one), proving no interception.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "passthrough body")
	}))
	t.Cleanup(origin.Close)

	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("dispatch must not be called in passthrough")
	})
	router := NewRouter(map[string]string{"pypi.org": "pip"}) // origin host not configured
	addr, ca := startProxy(t, Options{Router: router, PassthroughUnmatched: true}, dispatch)

	// Client trusts the origin's cert directly (NOT the intercept CA).
	originPool := x509.NewCertPool()
	originPool.AddCert(origin.Certificate())
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: originPool},
		},
	}
	_ = ca

	// The proxy tunnels CONNECT <origin-host:port> straight to the origin.
	resp, err := client.Get("https://" + origin.Listener.Addr().String() + "/")
	if err != nil {
		t.Fatalf("passthrough GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "passthrough body" {
		t.Fatalf("unexpected passthrough body: %s", body)
	}
}

func TestProxyPlainHTTPInterception(t *testing.T) {
	var gotPath atomic.Value
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath.Store(r.URL.Path)
		fmt.Fprint(w, "plain ok")
	})
	router := NewRouter(map[string]string{"mirror.local": "go"})

	// Plain-HTTP disabled -> refused.
	addrOff, caOff := startProxy(t, Options{Router: router, AllowPlainHTTP: false}, dispatch)
	off := plainClient(t, addrOff)
	_ = caOff
	resp, err := off.Get("http://mirror.local/x/y")
	if err != nil {
		t.Fatalf("plain GET (disabled): %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when plain HTTP disabled, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Plain-HTTP enabled -> intercepted and rewritten.
	addrOn, _ := startProxy(t, Options{Router: router, AllowPlainHTTP: true}, dispatch)
	on := plainClient(t, addrOn)
	resp2, err := on.Get("http://mirror.local/golang.org/x/net/@v/list")
	if err != nil {
		t.Fatalf("plain GET (enabled): %v", err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if string(body) != "plain ok" {
		t.Fatalf("unexpected body: %s", body)
	}
	if got := gotPath.Load(); got != "/v1/go/golang.org/x/net/@v/list" {
		t.Fatalf("rewritten plain path = %q", got)
	}
}

func plainClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}
