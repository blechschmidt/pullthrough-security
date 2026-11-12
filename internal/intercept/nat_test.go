package intercept

import (
	"context"
	"crypto/fips140"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// dispatched records what reached the dispatch handler.
type dispatched struct {
	mu   sync.Mutex
	reqs []dispatchedReq
}

type dispatchedReq struct {
	path, rawPath, host, remote, auth, proxyAuth string
	info                                         Info
	hasInfo                                      bool
}

func (d *dispatched) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info, ok := InfoFrom(r.Context())
		d.mu.Lock()
		d.reqs = append(d.reqs, dispatchedReq{
			path: r.URL.Path, rawPath: r.URL.RawPath, host: r.Host, remote: r.RemoteAddr,
			auth: r.Header.Get("Authorization"), proxyAuth: r.Header.Get("Proxy-Authorization"),
			info: info, hasInfo: ok,
		})
		d.mu.Unlock()
		fmt.Fprintf(w, "served %s", r.URL.Path)
	})
}

func (d *dispatched) last(t *testing.T) dispatchedReq {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.reqs) == 0 {
		t.Fatal("nothing was dispatched")
	}
	return d.reqs[len(d.reqs)-1]
}

func (d *dispatched) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.reqs)
}

// natProxy starts a proxy whose NAT TLS and NAT HTTP listeners are bound on
// loopback. It returns the proxy and both addresses.
func natProxy(t *testing.T, opts Options, dispatch http.Handler) (p *Proxy, tlsAddr, httpAddr string) {
	t.Helper()
	if opts.CA == nil {
		opts.CA = newTestCA(t)
	}
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = p.ServeNAT(ctx, tlsLn, dispatch) }()
	go func() { defer wg.Done(); _ = p.ServeNATHTTP(ctx, httpLn, dispatch) }()
	t.Cleanup(func() { cancel(); wg.Wait() })
	return p, tlsLn.Addr().String(), httpLn.Addr().String()
}

// redirectedClient is a client whose every connection — whatever host it is
// for — lands on target, the way a NAT redirect (or DNS naming the proxy) lands
// it there. TLS is verified against pool for the host the URL names.
func redirectedClient(t *testing.T, tlsTarget, httpTarget string, pool *x509.CertPool, local net.IP) *http.Client {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if local != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: local}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)
				if port == "80" {
					return dialer.DialContext(ctx, network, httpTarget)
				}
				return dialer.DialContext(ctx, network, tlsTarget)
			},
			TLSClientConfig:   &tls.Config{RootCAs: pool},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func caPool(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("cannot load the CA")
	}
	return pool
}

func get(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestNATRoutesTLSByServerName(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{
		"registry.npmjs.org":    "npm",
		"deb.debian.org/debian": "apt",
		"pypi.org":              "pip",
	})
	p, tlsAddr, httpAddr := natProxy(t, Options{Router: router, CA: ca}, d.handler())
	client := redirectedClient(t, tlsAddr, httpAddr, caPool(t, ca), nil)

	cases := []struct {
		url, wantPath string
		want          Info
	}{
		{"https://registry.npmjs.org/is-number", "/v1/npm/is-number",
			Info{ModeNAT, "registry.npmjs.org", "https://registry.npmjs.org", "npm"}},
		// The upstream URL's path is taken off: the backend sees the path below it.
		{"https://deb.debian.org/debian/dists/bookworm/InRelease", "/v1/apt/dists/bookworm/InRelease",
			Info{ModeNAT, "deb.debian.org", "https://deb.debian.org", "apt"}},
		// A link the proxy wrote earlier, followed on the host the client is on.
		{"https://pypi.org/_pullthrough/v1/pip/files.pythonhosted.org/packages/ab/six-1.16.0-py2.py3-none-any.whl",
			"/v1/pip/files.pythonhosted.org/packages/ab/six-1.16.0-py2.py3-none-any.whl",
			Info{ModeNAT, "pypi.org", "https://pypi.org", "pip"}},
		// Plain HTTP, routed by the Host header.
		{"http://deb.debian.org/debian/pool/main/h/hello/hello_2.10-3_amd64.deb", "/v1/apt/pool/main/h/hello/hello_2.10-3_amd64.deb",
			Info{ModeNAT, "deb.debian.org", "http://deb.debian.org", "apt"}},
	}
	for _, c := range cases {
		status, body := get(t, client, c.url)
		if status != http.StatusOK {
			t.Fatalf("GET %s: status %d (%s)", c.url, status, body)
		}
		got := d.last(t)
		if got.path != c.wantPath {
			t.Errorf("GET %s dispatched %q, want %q", c.url, got.path, c.wantPath)
		}
		if !got.hasInfo || got.info != c.want {
			t.Errorf("GET %s dispatched with info %+v (present %t), want %+v", c.url, got.info, got.hasInfo, c.want)
		}
		if got.host != c.want.Host {
			t.Errorf("GET %s dispatched with Host %q", c.url, got.host)
		}
	}

	stats := p.Stats()
	if stats.Requests[ModeNAT] != uint64(len(cases)) {
		t.Errorf("Requests[nat] = %d, want %d", stats.Requests[ModeNAT], len(cases))
	}
	if stats.Intercepted[ModeNAT] == 0 {
		t.Error("no intercepted NAT connection counted")
	}
}

func TestNATAnswersPathsNoUpstreamServes(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{"deb.debian.org/debian": "apt"})
	p, tlsAddr, httpAddr := natProxy(t, Options{Router: router, CA: ca}, d.handler())
	client := redirectedClient(t, tlsAddr, httpAddr, caPool(t, ca), nil)

	for _, url := range []string{
		"https://deb.debian.org/debian-security/dists/x",
		"https://deb.debian.org/",
		"https://deb.debian.org/_pullthrough/admin/api/config", // only /v1/ routes under the prefix
		"https://deb.debian.org/_pullthrough",
		"http://deb.debian.org/debian-ports/x",
	} {
		if status, _ := get(t, client, url); status != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", url, status)
		}
	}
	if n := d.count(); n != 0 {
		t.Errorf("%d request(s) dispatched for paths no upstream serves", n)
	}
	if got := p.Stats().Unrouted[ModeNAT]; got != 5 {
		t.Errorf("Unrouted[nat] = %d, want 5", got)
	}
}

func TestNATRefusesUnconfiguredHosts(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{"pypi.org": "pip"})
	p, tlsAddr, httpAddr := natProxy(t, Options{Router: router, CA: ca}, d.handler())
	client := redirectedClient(t, tlsAddr, httpAddr, caPool(t, ca), nil)

	// TLS: the handshake is refused with an alert naming the problem.
	_, err := client.Get("https://evil.example/payload")
	if err == nil || !strings.Contains(err.Error(), "unrecognized name") {
		t.Errorf("GET to an unconfigured TLS host: err = %v, want an unrecognized-name alert", err)
	}
	// No SNI at all (an IP literal): refused the same way.
	conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{RootCAs: caPool(t, ca), ServerName: ""})
	if err == nil {
		_ = conn.Close()
		t.Error("a TLS connection without a server name was accepted")
	}
	// Not TLS at all: closed.
	raw, err := net.Dial("tcp", tlsAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(raw, "GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n")
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, _ := io.ReadAll(raw)
	_ = raw.Close()
	if strings.Contains(string(reply), "HTTP/1.1 200") {
		t.Errorf("plain HTTP on the NAT TLS listener was served: %q", reply)
	}
	// Plain HTTP: 403.
	if status, _ := get(t, client, "http://evil.example/payload"); status != http.StatusForbidden {
		t.Errorf("GET to an unconfigured plain-HTTP host: status %d, want 403", status)
	}
	if n := d.count(); n != 0 {
		t.Errorf("%d request(s) dispatched for unconfigured hosts", n)
	}

	reasons := map[string]uint64{}
	for _, r := range p.Stats().Refused {
		if r.Mode == ModeNAT {
			reasons[r.Reason] = r.Count
		}
	}
	for _, want := range []string{refusedUnmatchedHost, refusedNoServerName, refusedNotTLS} {
		if reasons[want] == 0 {
			t.Errorf("no NAT refusal counted for reason %q (counted: %v)", want, reasons)
		}
	}
}

func TestNATPassthroughGoesToTheOriginalDestination(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "origin saw %s %s", r.Host, r.URL.Path)
	}))
	t.Cleanup(origin.Close)
	plainOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "plain origin saw %s %s", r.Host, r.URL.Path)
	}))
	t.Cleanup(plainOrigin.Close)

	d := &dispatched{}
	ca := newTestCA(t)
	opts := Options{Router: NewRouter(map[string]string{"pypi.org": "pip"}), CA: ca, PassthroughUnmatched: true}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	// What a NAT redirect would have recorded: the TLS listener's connections
	// were going to the TLS origin, the HTTP listener's to the plain one.
	tlsLn, _ := net.Listen("tcp", "127.0.0.1:0")
	httpLn, _ := net.Listen("tcp", "127.0.0.1:0")
	var dst sync.Map // local listener address -> original destination
	dst.Store(tlsLn.Addr().String(), origin.Listener.Addr())
	dst.Store(httpLn.Addr().String(), plainOrigin.Listener.Addr())
	p.originalDst = func(c net.Conn) (net.Addr, error) {
		v, ok := dst.Load(c.LocalAddr().String())
		if !ok {
			return nil, errors.New("not redirected")
		}
		return v.(net.Addr), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = p.ServeNAT(ctx, tlsLn, d.handler()) }()
	go func() { defer wg.Done(); _ = p.ServeNATHTTP(ctx, httpLn, d.handler()) }()
	t.Cleanup(func() { cancel(); wg.Wait() })

	// The client trusts the ORIGIN's certificate, not the interception CA: the
	// connection must reach the origin undecrypted.
	originPool := x509.NewCertPool()
	originPool.AddCert(origin.Certificate())
	client := redirectedClient(t, tlsLn.Addr().String(), httpLn.Addr().String(), originPool, nil)
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "example.com" // httptest's certificate names example.com
	if status, body := get(t, client, "https://example.com/elsewhere"); status != http.StatusOK || body != "origin saw example.com /elsewhere" {
		t.Errorf("TLS passthrough: %d %q", status, body)
	}
	if status, body := get(t, client, "http://other.example/x"); status != http.StatusOK || body != "plain origin saw other.example /x" {
		t.Errorf("plain-HTTP passthrough: %d %q", status, body)
	}
	if n := d.count(); n != 0 {
		t.Errorf("%d passthrough request(s) were dispatched into the pipeline", n)
	}
	if got := p.Stats().Passthrough[ModeNAT]; got != 2 {
		t.Errorf("Passthrough[nat] = %d, want 2", got)
	}

	// A connection that was not redirected — its "original destination" is the
	// proxy itself — has nowhere else to go: refused, never looped.
	dst.Store(tlsLn.Addr().String(), tlsLn.Addr())
	if _, err := client.Get("https://example.com/loop"); err == nil {
		t.Error("a connection whose original destination is the proxy itself was passed through")
	}
}

func TestNATKeepsTheClientAddress(t *testing.T) {
	const clientAddr = "127.0.43.9"
	if probe, err := net.Listen("tcp", net.JoinHostPort(clientAddr, "0")); err != nil {
		t.Skipf("cannot bind %s (needs a system where all of 127.0.0.0/8 is local): %v", clientAddr, err)
	} else {
		_ = probe.Close()
	}
	d := &dispatched{}
	ca := newTestCA(t)
	_, tlsAddr, httpAddr := natProxy(t, Options{Router: NewRouter(map[string]string{"index.crates.io": "cargo"}), CA: ca}, d.handler())
	client := redirectedClient(t, tlsAddr, httpAddr, caPool(t, ca), net.ParseIP(clientAddr))
	for _, url := range []string{"https://index.crates.io/cf/g-/cfg-if", "http://index.crates.io/config.json"} {
		if status, _ := get(t, client, url); status != http.StatusOK {
			t.Fatalf("GET %s: %d", url, status)
		}
		if host, _, _ := net.SplitHostPort(d.last(t).remote); host != clientAddr {
			t.Errorf("GET %s dispatched with remote address %q, want the client's %s", url, d.last(t).remote, clientAddr)
		}
	}
}

func TestInterceptedRequestsCarryProxyCredentialsOnly(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{"registry.npmjs.org": "npm"})
	addr, _ := startProxy(t, Options{Router: router, CA: ca, AllowPlainHTTP: true}, d.handler())

	// The client's own Authorization header was meant for the registry; the
	// credentials it gave the proxy (in the proxy URL) are what the pipeline
	// sees.
	proxyURL := "http://ci-runner:s3cret@" + addr
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustURL(t, proxyURL)),
			TLSClientConfig: &tls.Config{RootCAs: caPool(t, ca)},
		},
	}
	for _, target := range []string{"https://registry.npmjs.org/lodash", "http://registry.npmjs.org/lodash"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", "Bearer npm_registry_token")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		got := d.last(t)
		if got.auth != "Basic Y2ktcnVubmVyOnMzY3JldA==" {
			t.Errorf("GET %s: dispatched Authorization %q, want the proxy credentials", target, got.auth)
		}
		if got.proxyAuth != "" {
			t.Errorf("GET %s: Proxy-Authorization reached the pipeline", target)
		}
	}

	// Without proxy credentials the registry token is still not passed on.
	anon := clientThrough(t, addr, ca)
	req, _ := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/lodash", nil)
	req.Header.Set("Authorization", "Bearer npm_registry_token")
	resp, err := anon.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := d.last(t).auth; got != "" {
		t.Errorf("the client's registry credential reached the pipeline: %q", got)
	}
}

func TestRunStartsEveryListener(t *testing.T) {
	ports := make([]string, 3)
	for i := range ports {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = ln.Addr().String()
		_ = ln.Close()
	}
	d := &dispatched{}
	ca := newTestCA(t)
	p, err := New(Options{
		Router: NewRouter(map[string]string{"pypi.org": "pip"}), CA: ca, AllowPlainHTTP: true,
		ListenAddr: ports[0], NATListenAddr: ports[1], NATHTTPListenAddr: ports[2],
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx, d.handler()) }()

	waitListening := func(addr string) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if c, err := net.Dial("tcp", addr); err == nil {
				_ = c.Close()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%s is not listening", addr)
	}
	for _, a := range ports {
		waitListening(a)
	}
	forward := clientThrough(t, ports[0], ca)
	if status, _ := get(t, forward, "https://pypi.org/simple/six/"); status != http.StatusOK {
		t.Errorf("forward proxy: status %d", status)
	}
	nat := redirectedClient(t, ports[1], ports[2], caPool(t, ca), nil)
	if status, _ := get(t, nat, "https://pypi.org/simple/six/"); status != http.StatusOK {
		t.Errorf("NAT TLS: status %d", status)
	}
	if status, _ := get(t, nat, "http://pypi.org/simple/six/"); status != http.StatusOK {
		t.Errorf("NAT HTTP: status %d", status)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	none, _ := New(Options{Router: NewRouter(nil), CA: ca})
	if err := none.Run(context.Background(), d.handler()); err == nil {
		t.Error("Run without any listener address succeeded")
	}
}

func TestOriginalDestinationOfAnUnredirectedConnection(t *testing.T) {
	// No NAT rule is involved here: the call must either report the
	// connection's own address (connection tracking knows it) or fail — and
	// never be taken for somewhere to pass the connection on to.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dst, err := originalDestination(conn)
	if err == nil && !sameAddr(dst, conn.LocalAddr()) {
		t.Fatalf("original destination of a direct connection = %v, want %v", dst, conn.LocalAddr())
	}

	ca := newTestCA(t)
	p, _ := New(Options{Router: NewRouter(nil), CA: ca, PassthroughUnmatched: true})
	if target, ok := p.passthroughTarget(conn); ok {
		t.Fatalf("an unredirected connection would be passed through to %s", target)
	}
}

func mustURL(t *testing.T, raw string) *neturl.URL {
	t.Helper()
	u, err := neturl.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestInterceptedPathsWithDotSegmentsAreRefused(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{"deb.debian.org/debian": "apt", "pypi.org": "pip"})
	_, tlsAddr, httpAddr := natProxy(t, Options{Router: router, CA: ca}, d.handler())
	client := redirectedClient(t, tlsAddr, httpAddr, caPool(t, ca), nil)
	for _, target := range []string{
		"https://deb.debian.org/debian/%2e%2e/debian-security/dists/x",
		"https://pypi.org/_pullthrough/v1/pip/%2E%2E/%2E%2E/admin/api/config",
		"http://deb.debian.org/debian/pool/./x",
	} {
		if status, _ := get(t, client, target); status != http.StatusBadRequest {
			t.Errorf("GET %s: status %d, want 400", target, status)
		}
	}
	if n := d.count(); n != 0 {
		t.Errorf("%d request(s) with dot segments were dispatched", n)
	}
}

// A client may write its TLS ClientHello right behind the CONNECT, before it
// has read the proxy's answer. The handshake must still complete.
func TestConnectWithTheHandshakeRightBehind(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	addr, _ := startProxy(t, Options{Router: NewRouter(map[string]string{"pypi.org": "pip"}), CA: ca}, d.handler())

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// Capture the ClientHello a TLS client would send, then send it in the same
	// write as the CONNECT.
	helloConn := &captureConn{}
	go func() {
		_ = tls.Client(helloConn, &tls.Config{ServerName: "pypi.org", RootCAs: caPool(t, ca)}).Handshake()
	}()
	hello := helloConn.wait(t)
	if _, err := raw.Write(append([]byte("CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n"), hello...)); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(raw, br); err != nil || !strings.HasPrefix(string(br), "HTTP/1.1 200") {
		t.Fatalf("CONNECT answer %q: %v", br, err)
	}
	// The server's answer to the early ClientHello is a ServerHello record.
	rec := make([]byte, 5)
	if _, err := io.ReadFull(raw, rec); err != nil {
		t.Fatalf("no TLS answer to the ClientHello sent with the CONNECT: %v", err)
	}
	if rec[0] != 0x16 { // handshake record
		t.Fatalf("answer to the early ClientHello is record type %#x, want a handshake", rec[0])
	}
}

// captureConn records the first write of a TLS client (its ClientHello) and
// then fails, ending the client's handshake.
type captureConn struct {
	mu    sync.Mutex
	first []byte
	done  chan struct{}
	once  sync.Once
}

func (c *captureConn) init() {
	c.once.Do(func() { c.done = make(chan struct{}) })
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.init()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.first == nil {
		c.first = append([]byte(nil), p...)
		close(c.done)
	}
	return len(p), nil
}

func (c *captureConn) Read([]byte) (int, error) {
	c.init()
	<-c.done
	return 0, io.EOF
}

func (c *captureConn) wait(t *testing.T) []byte {
	t.Helper()
	c.init()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the TLS client wrote no ClientHello")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.first
}

func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// In FIPS mode the TLS the proxy terminates for intercepted clients is held to
// the approved floor: a client that offers only a non-approved cipher suite is
// refused.
func TestInterceptedTLSIsHardenedInFIPSMode(t *testing.T) {
	d := &dispatched{}
	ca := newTestCA(t)
	router := NewRouter(map[string]string{"pypi.org": "pip"})
	for _, fipsMode := range []bool{false, true} {
		_, tlsAddr, _ := natProxy(t, Options{Router: router, CA: ca, FIPS: fipsMode}, d.handler())
		conn, err := tls.Dial("tcp", tlsAddr, &tls.Config{
			ServerName: "pypi.org", RootCAs: caPool(t, ca), MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256},
		})
		if err == nil {
			_ = conn.Close()
		}
		if fipsMode && err == nil {
			t.Error("FIPS mode: a ChaCha20-only TLS 1.2 client was accepted")
		}
		// Under the Go FIPS module (GODEBUG=fips140=on) crypto/tls itself
		// refuses ChaCha20, whatever the proxy is configured with.
		if !fipsMode && err != nil && !fips140.Enabled() {
			t.Errorf("without FIPS mode a ChaCha20 TLS 1.2 client was refused: %v", err)
		}
	}
}
