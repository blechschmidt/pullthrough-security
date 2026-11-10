package tlspin

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// startTLSServer starts an HTTPS test server presenting a freshly-minted,
// per-server self-signed certificate (unlike httptest's shared built-in cert, so
// distinct servers present genuinely different certificates — the "mismatched
// cert" scenario the pin must catch). It returns the server and its leaf cert.
func startTLSServer(t *testing.T, cn string) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost", cn},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, leaf
}

// capturingAudit records every audit event for assertions.
type capturingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *capturingAudit) Log(_ context.Context, ev audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *capturingAudit) all() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

// capturingNotifier records every emitted notification.
type capturingNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (c *capturingNotifier) Emit(_ context.Context, ev notify.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *capturingNotifier) all() []notify.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]notify.Event, len(c.events))
	copy(out, c.events)
	return out
}

// newPinnedClient builds an upstream.Client whose transport enforces ep's pins
// against g. InsecureSkipVerify isolates the pin decision from chain validation
// (the test servers are self-signed), modeling the MITM scenario where the pin
// is the sole trust anchor.
func newPinnedClient(t *testing.T, g *Guard, ep EndpointConfig) *upstream.Client {
	t.Helper()
	verify, err := g.VerifierFor(ep)
	if err != nil {
		t.Fatalf("VerifierFor: %v", err)
	}
	c, err := upstream.New(upstream.Options{
		TLS: upstream.TLSOptions{
			InsecureSkipVerify: true,
			VerifyConnection:   verify,
		},
	})
	if err != nil {
		t.Fatalf("upstream.New: %v", err)
	}
	return c
}

func get(c *upstream.Client, url string) error {
	resp, err := c.Do(context.Background(), upstream.Request{URL: url})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func TestVerifierForNoPins(t *testing.T) {
	g := New(Options{})
	verify, err := g.VerifierFor(EndpointConfig{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if verify != nil {
		t.Fatal("no pins should yield a nil verify hook")
	}
}

func TestVerifierForBadPin(t *testing.T) {
	g := New(Options{})
	if _, err := g.VerifierFor(EndpointConfig{Pins: []string{"garbage"}}); err == nil {
		t.Fatal("malformed pin should return an error")
	}
}

// TestPinEnforceMatchAndMismatch starts two self-signed TLS servers, pins
// server A's certificate, and verifies that a connection to A (matching) is
// allowed while a connection to B (a server presenting a mismatched cert) is
// refused fail-closed with a *PinError.
func TestPinEnforceMatchAndMismatch(t *testing.T) {
	srvA, certA := startTLSServer(t, "server-a")
	srvB, _ := startTLSServer(t, "server-b")

	auditLog := &capturingAudit{}
	notifier := &capturingNotifier{}
	g := New(Options{Audit: auditLog, Notifier: notifier})

	pinA := LeafSPKIPin(certA)
	client := newPinnedClient(t, g, EndpointConfig{Pins: []string{pinA}})

	// Matching server: allowed.
	if err := get(client, srvA.URL); err != nil {
		t.Fatalf("pinned fetch to matching server should succeed: %v", err)
	}

	// Mismatched server (presents cert B against pin A): refused.
	err := get(client, srvB.URL)
	if err == nil {
		t.Fatal("pinned fetch to mismatched server should fail")
	}
	var pe *PinError
	if !errors.As(err, &pe) {
		t.Fatalf("expected a *PinError, got %T: %v", err, err)
	}

	snap := g.Snapshot()
	if snap.Matches != 1 {
		t.Errorf("Matches = %d, want 1", snap.Matches)
	}
	if snap.ViolationsEnforced != 1 {
		t.Errorf("ViolationsEnforced = %d, want 1", snap.ViolationsEnforced)
	}
	if snap.ViolationsReport != 0 {
		t.Errorf("ViolationsReport = %d, want 0", snap.ViolationsReport)
	}
	if snap.Checks != 2 {
		t.Errorf("Checks = %d, want 2", snap.Checks)
	}

	// The violation produced an audit deny event and a notification.
	evs := auditLog.all()
	if len(evs) != 1 {
		t.Fatalf("audit events = %d, want 1", len(evs))
	}
	if evs[0].Type != audit.EventTLSPin || evs[0].Decision != audit.DecisionDeny {
		t.Errorf("audit event = %+v, want TLSPin/deny", evs[0])
	}
	if got := evs[0].Detail["mode"]; got != modeEnforce {
		t.Errorf("audit mode = %v, want %q", got, modeEnforce)
	}
	ntfs := notifier.all()
	if len(ntfs) != 1 {
		t.Fatalf("notifications = %d, want 1", len(ntfs))
	}
	if ntfs[0].Type != notify.EventTLSPinViolation || ntfs[0].Severity != notify.SeverityCritical {
		t.Errorf("notification = %+v, want TLSPinViolation/critical", ntfs[0])
	}
}

// TestPinReportOnly verifies that a mismatch in report-only mode is recorded
// (audit + notify + counters) but the connection is still allowed.
func TestPinReportOnly(t *testing.T) {
	_, certA := startTLSServer(t, "server-a")
	srvB, _ := startTLSServer(t, "server-b")

	auditLog := &capturingAudit{}
	notifier := &capturingNotifier{}
	g := New(Options{Audit: auditLog, Notifier: notifier})

	pinA := LeafSPKIPin(certA)
	client := newPinnedClient(t, g, EndpointConfig{Pins: []string{pinA}, ReportOnly: true})

	// Mismatched server under report-only: the fetch still succeeds.
	if err := get(client, srvB.URL); err != nil {
		t.Fatalf("report-only mismatch should still allow the fetch: %v", err)
	}

	snap := g.Snapshot()
	if snap.ViolationsReport != 1 {
		t.Errorf("ViolationsReport = %d, want 1", snap.ViolationsReport)
	}
	if snap.ViolationsEnforced != 0 {
		t.Errorf("ViolationsEnforced = %d, want 0", snap.ViolationsEnforced)
	}
	if len(snap.Recent) != 1 || !snap.Recent[0].ReportOnly {
		t.Errorf("recent ring should hold one report-only violation, got %+v", snap.Recent)
	}

	evs := auditLog.all()
	if len(evs) != 1 || evs[0].Detail["mode"] != modeReportOnly {
		t.Errorf("expected one report-only audit event, got %+v", evs)
	}
	ntfs := notifier.all()
	if len(ntfs) != 1 || ntfs[0].Severity != notify.SeverityHigh {
		t.Errorf("expected one high-severity report-only notification, got %+v", ntfs)
	}
}

func TestViolationsByHostAndEndpointCount(t *testing.T) {
	_, certA := startTLSServer(t, "server-a")
	srvB, _ := startTLSServer(t, "server-b")

	g := New(Options{})
	client := newPinnedClient(t, g, EndpointConfig{Pins: []string{LeafSPKIPin(certA)}})
	if g.PinnedEndpoints() != 1 {
		t.Errorf("PinnedEndpoints = %d, want 1", g.PinnedEndpoints())
	}

	_ = get(client, srvB.URL) // one enforced violation
	byHost := g.ViolationsByHost()
	var total float64
	for key, v := range byHost {
		if key[1] != modeEnforce {
			t.Errorf("unexpected mode %q", key[1])
		}
		total += v
	}
	if total != 1 {
		t.Errorf("by-host violation total = %v, want 1", total)
	}
}

func TestNilGuardStillEnforces(t *testing.T) {
	// A nil guard with pins configured must still fail closed (defensive path).
	var g *Guard
	_, certA := startTLSServer(t, "server-a")
	srvB, _ := startTLSServer(t, "server-b")

	client := newPinnedClient(t, g, EndpointConfig{Pins: []string{LeafSPKIPin(certA)}})
	if err := get(client, srvB.URL); err == nil {
		t.Fatal("nil guard should still enforce a configured pin")
	}
	// Snapshot/Totals are nil-safe.
	if snap := g.Snapshot(); snap.Checks != 0 {
		t.Errorf("nil guard snapshot should be zero, got %+v", snap)
	}
}
