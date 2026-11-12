package intercept

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// errHelloRead aborts the handshake peekClientHello runs once it has the
// ClientHello.
var errHelloRead = errors.New("intercept: client hello read")

// clientHello is what peekClientHello learns from a ClientHello.
type clientHello struct {
	// ServerName is the SNI the client sent ("" when it sent none).
	ServerName string
}

// peekClientHello reads a TLS ClientHello from conn without answering it and
// returns what it says together with every byte read from conn, so the
// connection can afterwards be handed — those bytes first — to a TLS server
// (interception) or to the original destination (passthrough). It needs no
// TLS parser of its own: crypto/tls reads the hello and the handshake is
// aborted from GetConfigForClient, before a byte is written.
func peekClientHello(conn net.Conn) (*clientHello, []byte, error) {
	var recorded bytes.Buffer
	var hello *clientHello
	ro := &recordingConn{r: io.TeeReader(conn, &recorded), local: conn.LocalAddr(), remote: conn.RemoteAddr()}
	err := tls.Server(ro, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = &clientHello{ServerName: info.ServerName}
			return nil, errHelloRead
		},
	}).Handshake()
	if hello == nil {
		if err == nil {
			err = errors.New("intercept: no client hello")
		}
		return nil, recorded.Bytes(), err
	}
	return hello, recorded.Bytes(), nil
}

// recordingConn is the read-only connection peekClientHello hands crypto/tls:
// reads come from the real connection (and are recorded), writes — the alert
// the aborted handshake sends — go nowhere.
type recordingConn struct {
	r             io.Reader
	local, remote net.Addr
}

func (c *recordingConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *recordingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return c.local }
func (c *recordingConn) RemoteAddr() net.Addr             { return c.remote }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

// replayConn is a connection whose first reads return bytes already read from
// it (a peeked ClientHello).
type replayConn struct {
	net.Conn
	pending []byte
}

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// reverseProxy passes a plain-HTTP request for an unconfigured host on to the
// address it was originally sent to, undecrypted and unexamined (NAT
// passthrough).
func (p *Proxy) reverseProxy(w http.ResponseWriter, r *http.Request, target string) {
	dialer := &net.Dialer{Timeout: p.dialTimeout}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = &url.URL{Scheme: "http", Host: pr.In.Host, Path: pr.In.URL.Path, RawPath: pr.In.URL.RawPath, RawQuery: pr.In.URL.RawQuery}
			pr.Out.Host = pr.In.Host
		},
		Transport: &http.Transport{
			// The request goes to where the client sent it, whatever its Host
			// header resolves to.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, target)
			},
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: p.handshakeTimeout,
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			p.logger.Debug("intercept: NAT HTTP passthrough failed", "target", target, "error", err)
			http.Error(w, "intercept: passthrough to the original destination failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}
