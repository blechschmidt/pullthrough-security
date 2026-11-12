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
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/fips"
)

// Options configures a Proxy.
type Options struct {
	// ListenAddr is the TCP address the forward-proxy listener binds, e.g.
	// ":3128": clients set HTTPS_PROXY/HTTP_PROXY to it. Empty runs no forward
	// proxy (NAT mode only).
	ListenAddr string
	// NATListenAddr is the TCP address that receives TLS connections the network
	// redirected to the proxy (NAT mode), e.g. ":8443" behind an iptables rule
	// that redirects outbound port 443, or ":443" on an address DNS hands out
	// for the upstream hosts. The connection is routed by the server name the
	// client asks for (SNI). Empty runs no NAT TLS listener.
	NATListenAddr string
	// NATHTTPListenAddr is the plain-HTTP counterpart of NATListenAddr (port 80
	// redirected): requests are routed by their Host header. Empty runs no NAT
	// HTTP listener.
	NATHTTPListenAddr string
	// Router maps intercepted upstream hosts to backend names. Required.
	Router *Router
	// CA mints the leaf certificates presented to intercepted clients. Required.
	CA *CA
	// Logger is used for diagnostics. A nil logger discards output.
	Logger *slog.Logger
	// PassthroughUnmatched, when true, passes connections to hosts that are not
	// configured for interception on to where they were going, undecrypted: a
	// CONNECT is blind-tunnelled to its target, and a NAT connection is relayed
	// to its original destination (which only a NAT redirect records; without
	// one the connection is refused). When false (the default, secure), such
	// connections are refused so the proxy only carries traffic to configured
	// upstreams.
	PassthroughUnmatched bool
	// AllowPlainHTTP, when true, also intercepts absolute-form plain-HTTP proxy
	// requests (GET http://host/path) for configured hosts on the forward-proxy
	// listener. HTTPS CONNECT interception is always enabled; the NAT HTTP
	// listener serves plain HTTP whenever it is configured. Default false.
	AllowPlainHTTP bool
	// DialTimeout bounds establishing a passthrough connection upstream (default
	// 10s).
	DialTimeout time.Duration
	// HandshakeTimeout bounds the intercepted TLS handshake with the client
	// (default 10s).
	HandshakeTimeout time.Duration
	// ReadTimeout and WriteTimeout bound requests served over an intercepted
	// connection. Zero disables the respective timeout.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// Metrics receives the interception counters. Nil keeps them only in the
	// proxy's own Stats.
	Metrics *Metrics
	// FIPS restricts the TLS the proxy terminates for intercepted clients to
	// the FIPS 140-3 approved floor (TLS 1.2 minimum, AES-GCM cipher suites),
	// as the gateway's own listener does in FIPS mode.
	FIPS bool
}

// Proxy is the TLS-intercepting proxy. It accepts client connections — as an
// HTTP forward proxy (CONNECT and absolute-form requests) and, in NAT mode, as
// the destination of connections the network redirected to it — maps the
// upstream host the client addressed to a configured backend, terminates TLS
// with a minted certificate, and dispatches the decrypted request into the
// serve handler supplied to Run (the gateway's /v1 pipeline).
type Proxy struct {
	router    *Router
	ca        *CA
	logger    *slog.Logger
	passthru  bool
	plainHTTP bool

	listenAddr, natAddr, natHTTPAddr string

	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	readTimeout      time.Duration
	writeTimeout     time.Duration

	metrics *Metrics
	fips    bool

	// originalDst returns the destination a NAT-redirected connection was
	// originally addressed to. It is replaced in tests.
	originalDst func(net.Conn) (net.Addr, error)

	mu       sync.RWMutex
	dispatch http.Handler
	baseCtx  context.Context
	// own lists the addresses the proxy's listeners are bound to: a NAT
	// connection whose original destination is one of them was not redirected
	// (or would loop), and is never passed through.
	own []net.Addr
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
	m := opts.Metrics
	if m == nil {
		m = &Metrics{}
	}
	return &Proxy{
		router:           opts.Router,
		ca:               opts.CA,
		logger:           logger,
		passthru:         opts.PassthroughUnmatched,
		plainHTTP:        opts.AllowPlainHTTP,
		listenAddr:       opts.ListenAddr,
		natAddr:          opts.NATListenAddr,
		natHTTPAddr:      opts.NATHTTPListenAddr,
		dialTimeout:      dial,
		handshakeTimeout: hs,
		readTimeout:      opts.ReadTimeout,
		writeTimeout:     opts.WriteTimeout,
		metrics:          m,
		fips:             opts.FIPS,
		originalDst:      originalDestination,
		baseCtx:          context.Background(),
	}, nil
}

// Router returns the proxy's routing table.
func (p *Proxy) Router() *Router { return p.router }

// CA returns the certificate authority the proxy mints leaf certificates with.
func (p *Proxy) CA() *CA { return p.ca }

// Run binds every configured listener — the forward proxy, the NAT TLS and the
// NAT HTTP listener — and dispatches intercepted, host-routed requests into
// serve. It blocks until ctx is canceled (then stops accepting and closes the
// active connections) or a listener fails. serve receives requests whose URL
// path has been rewritten into the backend route space
// ("/v1/<backend>/<upstream-relative path>"), with an Info in their context.
func (p *Proxy) Run(ctx context.Context, serve http.Handler) error {
	if serve == nil {
		return errors.New("intercept: serve handler is required")
	}
	type listener struct {
		addr  string
		serve func(context.Context, net.Listener, http.Handler) error
	}
	var wanted []listener
	if p.listenAddr != "" {
		wanted = append(wanted, listener{p.listenAddr, p.Serve})
	}
	if p.natAddr != "" {
		wanted = append(wanted, listener{p.natAddr, p.ServeNAT})
	}
	if p.natHTTPAddr != "" {
		wanted = append(wanted, listener{p.natHTTPAddr, p.ServeNATHTTP})
	}
	if len(wanted) == 0 {
		return errors.New("intercept: no listener configured (set a forward-proxy or a NAT listen address)")
	}

	listeners := make([]net.Listener, 0, len(wanted))
	for _, w := range wanted {
		ln, err := net.Listen("tcp", w.addr)
		if err != nil {
			for _, open := range listeners {
				_ = open.Close()
			}
			return fmt.Errorf("intercept: listening on %q: %w", w.addr, err)
		}
		listeners = append(listeners, ln)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, len(wanted))
	var wg sync.WaitGroup
	for i, w := range wanted {
		wg.Add(1)
		go func(serveFn func(context.Context, net.Listener, http.Handler) error, ln net.Listener) {
			defer wg.Done()
			if err := serveFn(ctx, ln, serve); err != nil {
				errCh <- err
				cancel()
			}
		}(w.serve, listeners[i])
	}
	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// Serve runs the forward proxy on an already-bound listener. It is used by Run
// and directly by tests that need the bound address. It blocks until ctx is
// canceled or a fatal serve error occurs.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener, serve http.Handler) error {
	if serve == nil {
		return errors.New("intercept: serve handler is required")
	}
	p.bind(ctx, ln, serve)

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
	p.logger.Info("tls-intercept forward proxy listening",
		"addr", ln.Addr().String(),
		"rules", p.router.Len(),
		"passthroughUnmatched", p.passthru,
		"ca", p.ca.Subject())
	return serveUntilDone(ctx, srv, ln)
}

// ServeNAT runs the NAT TLS listener on an already-bound listener: every
// connection is a TLS connection the network redirected here, routed by the
// server name its ClientHello asks for. It blocks until ctx is canceled or the
// listener fails.
func (p *Proxy) ServeNAT(ctx context.Context, ln net.Listener, serve http.Handler) error {
	if serve == nil {
		return errors.New("intercept: serve handler is required")
	}
	p.bind(ctx, ln, serve)
	p.logger.Info("tls-intercept NAT listener (TLS) listening",
		"addr", ln.Addr().String(),
		"rules", p.router.Len(),
		"passthroughUnmatched", p.passthru,
		"ca", p.ca.Subject())

	var wg sync.WaitGroup
	defer wg.Wait()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return fmt.Errorf("intercept: NAT listener: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handleNATConn(ctx, conn)
		}()
	}
}

// ServeNATHTTP runs the NAT plain-HTTP listener on an already-bound listener:
// requests are routed by their Host header. It blocks until ctx is canceled or
// the listener fails.
func (p *Proxy) ServeNATHTTP(ctx context.Context, ln net.Listener, serve http.Handler) error {
	if serve == nil {
		return errors.New("intercept: serve handler is required")
	}
	p.bind(ctx, ln, serve)
	srv := &http.Server{
		Handler:      http.HandlerFunc(p.serveNATHTTP),
		ReadTimeout:  p.readTimeout,
		WriteTimeout: p.writeTimeout,
		ErrorLog:     slog.NewLogLogger(p.logger.Handler(), slog.LevelError),
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			p.metrics.connection(ModeNAT)
			return context.WithValue(ctx, natConnKey{}, c)
		},
	}
	p.logger.Info("tls-intercept NAT listener (plain HTTP) listening",
		"addr", ln.Addr().String(),
		"rules", p.router.Len(),
		"passthroughUnmatched", p.passthru)
	return serveUntilDone(ctx, srv, ln)
}

// bind records the dispatch handler, the base context and a listener address.
func (p *Proxy) bind(ctx context.Context, ln net.Listener, serve http.Handler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dispatch = serve
	p.baseCtx = ctx
	p.own = append(p.own, ln.Addr())
}

// serveUntilDone serves srv on ln until ctx is canceled or serving fails.
func serveUntilDone(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case <-ctx.Done():
		// Close (not Shutdown): intercepted connections are hijacked and not
		// tracked by the server's graceful-shutdown bookkeeping.
		_ = srv.Close()
		<-errCh
		return nil
	case err, ok := <-errCh:
		_ = srv.Close()
		if !ok {
			return nil
		}
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
	p.metrics.connection(ModeForward)
	host := normalizeHost(r.Host)
	intercepted := p.router.Intercepts(host)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "intercept: connection hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		p.logger.Error("intercept: hijack failed", "host", host, "error", err)
		return
	}
	// A client may send the start of its TLS handshake right behind the
	// CONNECT, without waiting for the answer; whatever the server already
	// read of it is handed on first.
	var early []byte
	if brw != nil && brw.Reader.Buffered() > 0 {
		buffered, _ := brw.Reader.Peek(brw.Reader.Buffered())
		early = append([]byte(nil), buffered...)
	}

	if !intercepted {
		if !p.passthru {
			p.metrics.refused(ModeForward, refusedUnmatchedHost)
			_, _ = io.WriteString(clientConn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			_ = clientConn.Close()
			p.logger.Debug("intercept: refusing CONNECT to unconfigured host", "host", host)
			return
		}
		p.metrics.passthrough(ModeForward)
		p.tunnel(clientConn, early, r.Host)
		return
	}

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		return
	}
	// The credentials the client presented to the proxy, if any, identify it on
	// every request it sends through the tunnel.
	proxyAuth := r.Header.Get("Proxy-Authorization")
	p.interceptTLS(clientConn, early, ModeForward, host, proxyAuth)
}

// handleNATConn serves one connection the network redirected to the NAT TLS
// listener. It reads the ClientHello to learn which host the client is
// connecting to, then intercepts the connection (a configured host), passes it
// on to its original destination (an unconfigured host, with passthrough
// enabled and a NAT redirect to tell where that was), or refuses it.
func (p *Proxy) handleNATConn(ctx context.Context, conn net.Conn) {
	p.metrics.connection(ModeNAT)
	if p.handshakeTimeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(p.handshakeTimeout))
	}
	hello, recorded, err := peekClientHello(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		p.metrics.refused(ModeNAT, refusedNotTLS)
		p.logger.Debug("intercept: NAT connection did not start with a TLS ClientHello",
			"remote", conn.RemoteAddr().String(), "error", err)
		_ = conn.Close()
		return
	}
	host := normalizeHost(hello.ServerName)
	if host != "" && p.router.Intercepts(host) {
		p.interceptTLS(conn, recorded, ModeNAT, host, "")
		return
	}

	if p.passthru {
		if target, ok := p.passthroughTarget(conn); ok {
			p.metrics.passthrough(ModeNAT)
			p.relay(conn, recorded, target)
			return
		}
	}
	reason := refusedUnmatchedHost
	if host == "" {
		reason = refusedNoServerName
	}
	p.metrics.refused(ModeNAT, reason)
	p.logger.Debug("intercept: refusing NAT connection to unconfigured host",
		"host", host, "remote", conn.RemoteAddr().String())
	// A TLS alert names the problem in the client's error message: the proxy
	// does not serve that name.
	_, _ = conn.Write(tlsAlertUnrecognizedName)
	_ = conn.Close()
}

// tlsAlertUnrecognizedName is a fatal unrecognized_name (112) TLS alert record.
var tlsAlertUnrecognizedName = []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x70}

// interceptTLS terminates TLS on a client connection with a certificate minted
// for host, then serves the decrypted HTTP requests through the dispatch
// handler. recorded is what was already read from conn (a peeked ClientHello).
// It blocks until the client closes the connection.
func (p *Proxy) interceptTLS(clientConn net.Conn, recorded []byte, mode Mode, host, proxyAuth string) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The certificate is for the host the connection was routed by —
			// the CONNECT target or the server name of a NAT connection — and
			// for nothing else the client might ask for in its ClientHello.
			return p.ca.LeafForHost(host)
		},
	}
	if p.fips {
		tlsCfg = fips.HardenServerTLSConfig(tlsCfg)
	}
	var conn net.Conn = clientConn
	if len(recorded) > 0 {
		conn = &replayConn{Conn: clientConn, pending: recorded}
	}
	tlsConn := tls.Server(conn, tlsCfg)

	if p.handshakeTimeout > 0 {
		_ = tlsConn.SetDeadline(time.Now().Add(p.handshakeTimeout))
	}
	ctx := p.baseContext()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		p.metrics.refused(mode, refusedHandshake)
		p.logger.Debug("intercept: TLS handshake failed", "host", host, "mode", string(mode), "error", err)
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{}) // clear the handshake deadline
	p.metrics.intercepted(mode)

	ln := newSingleConnListener(tlsConn)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.serveIntercepted(w, r, mode, "https", host, proxyAuth)
		}),
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

// serveNATHTTP serves a request that arrived on the NAT plain-HTTP listener.
func (p *Proxy) serveNATHTTP(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.Host)
	if host != "" && p.router.Intercepts(host) {
		p.serveIntercepted(w, r, ModeNAT, "http", host, "")
		return
	}
	if p.passthru {
		if conn, ok := r.Context().Value(natConnKey{}).(net.Conn); ok {
			if target, ok := p.passthroughTarget(conn); ok {
				p.metrics.passthrough(ModeNAT)
				p.reverseProxy(w, r, target)
				return
			}
		}
	}
	p.metrics.refused(ModeNAT, refusedUnmatchedHost)
	http.Error(w, fmt.Sprintf("intercept: host %q is not configured for interception", host), http.StatusForbidden)
}

type natConnKey struct{}

// handleAbsolute serves absolute-form plain-HTTP proxy requests
// (GET http://host/path). Only configured hosts are handled, and only when
// AllowPlainHTTP is set; everything else is refused.
func (p *Proxy) handleAbsolute(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "intercept: direct (non-proxy) requests are not served; configure this endpoint as an HTTP proxy", http.StatusBadRequest)
		return
	}
	p.metrics.connection(ModeForward)
	if !p.plainHTTP {
		p.metrics.refused(ModeForward, refusedPlainHTTP)
		http.Error(w, "intercept: plain-HTTP proxying is disabled", http.StatusForbidden)
		return
	}
	host := normalizeHost(r.URL.Host)
	if !p.router.Intercepts(host) {
		p.metrics.refused(ModeForward, refusedUnmatchedHost)
		http.Error(w, fmt.Sprintf("intercept: host %q is not configured for interception", host), http.StatusForbidden)
		return
	}
	p.serveIntercepted(w, r, ModeForward, "http", host, r.Header.Get("Proxy-Authorization"))
}

// serveIntercepted maps a decrypted (or plain-HTTP) request for host onto the
// backend route space and dispatches it into the gateway pipeline:
//
//   - a request under RoutePrefix ("/_pullthrough/v1/<backend>/…") follows a
//     link the proxy itself wrote into an earlier response for this host; the
//     route is the rest of its path, taken as it is;
//   - any other request is routed by the host's rules: the rule's path prefix
//     is taken off and "/v1/<backend>" put in front, so the backend sees the
//     path relative to its upstream URL, exactly as in explicit mode.
//
// A request the rules do not cover is answered 404 here: it names a resource
// of an upstream host that no configured upstream serves.
func (p *Proxy) serveIntercepted(w http.ResponseWriter, r *http.Request, mode Mode, scheme, host, proxyAuth string) {
	path, rawPath := r.URL.Path, r.URL.RawPath
	// A "." or ".." segment would be resolved — by the gateway's router or by
	// the upstream — into a path other than the one routed here. No client
	// sends one; it arrives only in an encoded spelling, and is refused.
	if hasDotSegment(path) {
		p.metrics.unrouted(mode)
		http.Error(w, `intercept: invalid request path: "." and ".." segments are not accepted`, http.StatusBadRequest)
		return
	}
	var newPath, newRaw, backend string
	if rest, ok := cutRoutePrefix(path); ok {
		if !strings.HasPrefix(rest, "/v1/") {
			p.metrics.unrouted(mode)
			http.Error(w, "intercept: not found: "+RoutePrefix+" serves the proxy's own links (/v1/<upstream>/…) only", http.StatusNotFound)
			return
		}
		newPath = rest
		if raw, ok := strings.CutPrefix(rawPath, RoutePrefix); ok {
			newRaw = raw
		}
		backend, _, _ = strings.Cut(strings.TrimPrefix(rest, "/v1/"), "/")
	} else {
		route, ok := p.router.Route(host, path)
		if !ok {
			p.metrics.unrouted(mode)
			http.Error(w, fmt.Sprintf("intercept: no configured upstream serves %s%s", host, path), http.StatusNotFound)
			return
		}
		backend = route.Backend
		mount := "/v1/" + route.Backend
		newPath = mount + route.Path
		if rawPath != "" {
			if raw, ok := cutPathPrefix(rawPath, route.Prefix); ok {
				newRaw = mount + raw
			}
		}
	}

	origin := scheme + "://" + originHost(r.Host, host)
	r2 := r.Clone(WithInfo(r.Context(), Info{Mode: mode, Host: host, Origin: origin, Backend: backend}))
	r2.URL.Scheme = scheme
	r2.URL.Host = host
	r2.Host = host
	r2.URL.Path = newPath
	// The raw (escaped) path is kept only where it still spells the new path;
	// otherwise it is dropped and derived anew from the decoded one.
	r2.URL.RawPath = newRaw
	if newRaw != "" && r2.URL.EscapedPath() != newRaw {
		r2.URL.RawPath = ""
	}
	r2.RequestURI = ""

	// The client addressed its Authorization header to the upstream registry,
	// not to this proxy: it is not a credential the proxy accepts, and nothing
	// behind this point sends it on. What identifies the client to the proxy is
	// what it presented to the proxy itself (Proxy-Authorization on its CONNECT
	// or absolute-form request), if anything.
	r2.Header.Del("Authorization")
	r2.Header.Del("Proxy-Authorization")
	r2.Header.Del("Proxy-Connection")
	if proxyAuth != "" {
		r2.Header.Set("Authorization", proxyAuth)
	}
	p.metrics.request(mode)
	p.dispatchHandler().ServeHTTP(w, r2)
}

// originHost returns the host[:port] the client addressed, for links that have
// to lead back to the same place: the Host header when it names the routed host
// (keeping a non-default port), the routed host otherwise.
func originHost(hostHeader, routed string) string {
	if hostHeader != "" && normalizeHost(hostHeader) == routed {
		return strings.ToLower(strings.TrimSuffix(hostHeader, "."))
	}
	if strings.Contains(routed, ":") {
		return "[" + routed + "]"
	}
	return routed
}

// hasDotSegment reports whether a path has a "." or ".." segment.
func hasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// cutRoutePrefix reports whether path is under RoutePrefix and returns the rest.
func cutRoutePrefix(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, RoutePrefix)
	if !ok || (rest != "" && rest[0] != '/') {
		return "", false
	}
	return rest, true
}

// tunnel blind-copies bytes between the client and the upstream host:port
// without decrypting (plain CONNECT passthrough for unconfigured hosts). early
// is what the client sent behind its CONNECT before the answer.
func (p *Proxy) tunnel(clientConn net.Conn, early []byte, target string) {
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
	if len(early) > 0 {
		if _, err := upstream.Write(early); err != nil {
			_ = clientConn.Close()
			_ = upstream.Close()
			return
		}
	}
	pipe(clientConn, upstream)
}

// relay passes a NAT connection on to target, undecrypted: what was already
// read from the client (recorded) is sent first.
func (p *Proxy) relay(clientConn net.Conn, recorded []byte, target string) {
	dialer := net.Dialer{Timeout: p.dialTimeout}
	upstream, err := dialer.DialContext(p.baseContext(), "tcp", target)
	if err != nil {
		_ = clientConn.Close()
		p.logger.Debug("intercept: NAT passthrough dial failed", "target", target, "error", err)
		return
	}
	if len(recorded) > 0 {
		if _, err := upstream.Write(recorded); err != nil {
			_ = clientConn.Close()
			_ = upstream.Close()
			return
		}
	}
	pipe(clientConn, upstream)
}

// pipe copies both ways between a and b until both directions are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyAndCloseWrite(b, a) }()
	go func() { defer wg.Done(); copyAndCloseWrite(a, b) }()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func copyAndCloseWrite(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// passthroughTarget returns where a NAT connection to an unconfigured host was
// originally going, if a NAT redirect recorded that and it is somewhere other
// than this proxy. A connection that reached the proxy because DNS named it
// (no redirect) has no other destination to be passed on to.
func (p *Proxy) passthroughTarget(conn net.Conn) (string, bool) {
	if p.originalDst == nil {
		return "", false
	}
	dst, err := p.originalDst(conn)
	if err != nil || dst == nil {
		p.logger.Debug("intercept: no original destination for a NAT connection", "error", err)
		return "", false
	}
	if sameAddr(dst, conn.LocalAddr()) {
		return "", false
	}
	p.mu.RLock()
	own := append([]net.Addr(nil), p.own...)
	p.mu.RUnlock()
	for _, a := range own {
		if sameAddr(dst, a) {
			return "", false
		}
	}
	return dst.String(), true
}

// sameAddr reports whether two TCP addresses are the same endpoint. An
// unspecified listener address (":8443") matches any IP on its port.
func sameAddr(a, b net.Addr) bool {
	ta, okA := a.(*net.TCPAddr)
	tb, okB := b.(*net.TCPAddr)
	if !okA || !okB {
		return a.String() == b.String()
	}
	if ta.Port != tb.Port {
		return false
	}
	if ta.IP.IsUnspecified() || tb.IP.IsUnspecified() {
		return true
	}
	return ta.IP.Equal(tb.IP)
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
