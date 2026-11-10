package intercept

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// Options configures a Proxy.
type Options struct {
	// ListenAddr is the TCP address the forward-proxy listener binds, e.g.
	// ":3128". Required when Run is used.
	ListenAddr string
	// Router maps intercepted upstream hosts to backend names. Required.
	Router *Router
	// CA mints the leaf certificates presented to intercepted clients. Required.
	CA *CA
	// Logger is used for diagnostics. A nil logger discards output.
	Logger *slog.Logger
	// PassthroughUnmatched, when true, blindly tunnels CONNECT requests to hosts
	// that are not configured for interception (a transparent passthrough). When
	// false (the default, secure), such requests are refused with 403 so the proxy
	// only carries traffic to configured upstreams.
	PassthroughUnmatched bool
	// AllowPlainHTTP, when true, also intercepts absolute-form plain-HTTP proxy
	// requests (GET http://host/path) for configured hosts. HTTPS CONNECT
	// interception is always enabled. Default false.
	AllowPlainHTTP bool
	// DialTimeout bounds establishing a passthrough tunnel's upstream connection
	// (default 10s).
	DialTimeout time.Duration
	// HandshakeTimeout bounds the intercepted TLS handshake with the client
	// (default 10s).
	HandshakeTimeout time.Duration
	// ReadTimeout and WriteTimeout bound requests served over an intercepted
	// connection. Zero disables the respective timeout.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Proxy is the TLS-intercepting HTTP forward proxy. It accepts client proxy
// connections, maps upstream hostnames to configured backends, terminates TLS
// with a minted certificate, and dispatches the decrypted request into the
// serve handler supplied to Run (the gateway's /v1 pipeline).
type Proxy struct {
	router    *Router
	ca        *CA
	logger    *slog.Logger
	passthru  bool
	plainHTTP bool

	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	readTimeout      time.Duration
	writeTimeout     time.Duration

	mu       sync.RWMutex
	dispatch http.Handler
	baseCtx  context.Context
}

// New constructs a Proxy.
func New(opts Options) (*Proxy, error) {
	if opts.Router == nil {
		return nil, errors.New("intercept: router is required")
	}
	if opts.CA == nil {
		return nil, errors.New("intercept: CA is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	dial := opts.DialTimeout
	if dial <= 0 {
		dial = 10 * time.Second
	}
	hs := opts.HandshakeTimeout
	if hs <= 0 {
		hs = 10 * time.Second
	}
	return &Proxy{
		router:           opts.Router,
		ca:               opts.CA,
		logger:           logger,
		passthru:         opts.PassthroughUnmatched,
		plainHTTP:        opts.AllowPlainHTTP,
		dialTimeout:      dial,
		handshakeTimeout: hs,
		readTimeout:      opts.ReadTimeout,
		writeTimeout:     opts.WriteTimeout,
		baseCtx:          context.Background(),
	}, nil
}

// Run starts the forward-proxy listener and dispatches intercepted, host-routed
// requests into serve. It blocks until ctx is canceled, then stops accepting and
// closes active connections. serve receives requests whose URL path has been
// rewritten to the backend route space ("/v1/<backend>/<original-path>") so the
// existing gateway pipeline handles them unchanged.
func (p *Proxy) Run(ctx context.Context, listenAddr string, serve http.Handler) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("intercept: listening on %q: %w", listenAddr, err)
	}
	return p.Serve(ctx, ln, serve)
}

// Serve runs the forward proxy on an already-bound listener. It is used by Run
// and directly by tests that need the bound address. It blocks until ctx is
// canceled or a fatal serve error occurs.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener, serve http.Handler) error {
	if serve == nil {
		return errors.New("intercept: serve handler is required")
	}
	p.mu.Lock()
	p.dispatch = serve
	p.baseCtx = ctx
	p.mu.Unlock()

	listenAddr := ln.Addr().String()
	srv := &http.Server{
		Handler:     p,
		ReadTimeout: p.readTimeout,
		// WriteTimeout is intentionally left to the per-connection handler for
		// intercepted (hijacked) traffic; setting it here would also bound the
		// CONNECT response.
		ErrorLog: slog.NewLogLogger(p.logger.Handler(), slog.LevelError),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	errCh := make(chan error, 1)
	go func() {
		p.logger.Info("tls-intercept forward proxy listening",
			"addr", listenAddr,
			"hosts", p.router.Len(),
			"passthroughUnmatched", p.passthru,
			"ca", p.ca.Subject())
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	select {
	case <-ctx.Done():
		// Close (not Shutdown): intercepted connections are hijacked and not
		// tracked by the server's graceful-shutdown bookkeeping.
		_ = srv.Close()
		return nil
	case err := <-errCh:
		_ = srv.Close()
		return err
	}
}

// ServeHTTP implements the forward-proxy protocol. It is exported so the proxy
// can be driven directly in tests without binding a listener.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleAbsolute(w, r)
}

// handleConnect processes a CONNECT request. For a host configured for
// interception it hijacks the connection, completes a TLS handshake with a
// minted certificate, and serves decrypted requests. For an unconfigured host it
// either blind-tunnels (when PassthroughUnmatched) or refuses.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	backend, intercepted := p.router.Lookup(host)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "intercept: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		p.logger.Error("intercept: hijack failed", "host", host, "error", err)
		return
	}

	if !intercepted {
		if !p.passthru {
			_, _ = io.WriteString(clientConn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			_ = clientConn.Close()
			p.logger.Debug("intercept: refusing CONNECT to unconfigured host", "host", host)
			return
		}
		p.tunnel(clientConn, r.Host)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}
	p.interceptTLS(clientConn, backend, host)
}

// interceptTLS terminates TLS on an accepted client connection with a minted
// certificate, then serves the decrypted HTTP requests through the dispatch
// handler. It blocks until the client closes the connection.
func (p *Proxy) interceptTLS(clientConn net.Conn, backend, host string) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := normalizeHost(hello.ServerName)
			if name == "" {
				name = host // client omitted SNI; use the CONNECT target
			}
			return p.ca.LeafForHost(name)
		},
	}
	tlsConn := tls.Server(clientConn, tlsCfg)

	if p.handshakeTimeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(p.handshakeTimeout))
	}
	ctx := p.baseContext()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.logger.Debug("intercept: TLS handshake failed", "host", host, "error", err)
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{}) // clear the handshake deadline

	ln := newSingleConnListener(tlsConn)
	srv := &http.Server{
		Handler:      p.rewriteHandler(backend, host),
		ReadTimeout:  p.readTimeout,
		WriteTimeout: p.writeTimeout,
		ErrorLog:     slog.NewLogLogger(p.logger.Handler(), slog.LevelError),
		BaseContext:  func(net.Listener) context.Context { return ctx },
	}

	// Stop serving this connection when the base context is canceled.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = srv.Close()
		case <-done:
		}
	}()

	_ = srv.Serve(ln) // returns when the client closes the connection
}

// rewriteHandler maps a decrypted request onto the backend route space and
// dispatches it into the gateway pipeline. The original origin-form path is
// prefixed with "/v1/<backend>" so splitBackendPath in the gateway resolves the
// correct backend with the untouched upstream-relative path.
func (p *Proxy) rewriteHandler(backend, host string) http.Handler {
	prefix := "/v1/" + backend
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		if r.URL.Host == "" {
			r.URL.Host = host
		}
		if r.Host == "" {
			r.Host = host
		}
		r.URL.Path = prefix + r.URL.Path
		if r.URL.RawPath != "" {
			r.URL.RawPath = prefix + r.URL.RawPath
		}
		r.RequestURI = ""
		// Mark the request as intercepted so downstream logging/audit can tell it
		// apart from explicit /v1 traffic, and record the real upstream host.
		r.Header.Set("X-Pullthrough-Intercepted-Host", host)
		p.dispatchHandler().ServeHTTP(w, r)
	})
}

// handleAbsolute serves absolute-form plain-HTTP proxy requests
// (GET http://host/path). Only configured hosts are handled, and only when
// AllowPlainHTTP is set; everything else is refused.
func (p *Proxy) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "intercept: direct (non-proxy) requests are not served; configure this endpoint as an HTTP proxy", http.StatusBadRequest)
		return
	}
	if !p.plainHTTP {
		http.Error(w, "intercept: plain-HTTP proxying is disabled", http.StatusForbidden)
		return
	}
	host := normalizeHost(r.URL.Host)
	backend, ok := p.router.Lookup(host)
	if !ok {
		http.Error(w, fmt.Sprintf("intercept: host %q is not configured for interception", host), http.StatusForbidden)
		return
	}
	p.rewriteHandler(backend, host).ServeHTTP(w, r)
}

// tunnel blind-copies bytes between the client and the upstream host:port
// without decrypting (plain CONNECT passthrough for unconfigured hosts).
func (p *Proxy) tunnel(clientConn net.Conn, target string) {
	dialer := net.Dialer{Timeout: p.dialTimeout}
	upstream, err := dialer.DialContext(p.baseContext(), "tcp", target)
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = clientConn.Close()
		p.logger.Debug("intercept: passthrough dial failed", "target", target, "error", err)
		return
	}
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyAndCloseWrite(upstream, clientConn) }()
	go func() { defer wg.Done(); copyAndCloseWrite(clientConn, upstream) }()
	wg.Wait()
	_ = clientConn.Close()
	_ = upstream.Close()
}

func copyAndCloseWrite(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (p *Proxy) dispatchHandler() http.Handler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dispatch
}

func (p *Proxy) baseContext() context.Context {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.baseCtx != nil {
		return p.baseCtx
	}
	return context.Background()
}

// SetDispatch wires the serve handler without starting a listener. It exists so
// the proxy can be exercised directly (ServeHTTP) in tests.
func (p *Proxy) SetDispatch(serve http.Handler) {
	p.mu.Lock()
	p.dispatch = serve
	p.mu.Unlock()
}

// singleConnListener adapts a single accepted net.Conn into a net.Listener so a
// transient *http.Server can serve one hijacked connection (including HTTP
// keep-alive requests on it). The first Accept returns the connection; the
// second blocks until the connection is closed, then returns net.ErrClosed so
// http.Server.Serve returns.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	l := &singleConnListener{done: make(chan struct{})}
	l.conn = &notifyConn{Conn: conn, done: l.done}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() { c = l.conn })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return dummyAddr{}
}

// notifyConn closes the listener's done channel when the connection is closed,
// unblocking the second Accept so http.Server.Serve returns.
type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "intercept" }
