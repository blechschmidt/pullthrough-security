package siem

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockSyslogTCP is a minimal TCP syslog receiver that records the newline-framed
// messages it receives.
type mockSyslogTCP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
}

func newMockSyslogTCP(t *testing.T) *mockSyslogTCP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mockSyslogTCP{ln: ln}
	go m.accept()
	return m
}

func (m *mockSyslogTCP) accept() {
	for {
		conn, err := m.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			sc := bufio.NewScanner(c)
			for sc.Scan() {
				m.mu.Lock()
				m.msgs = append(m.msgs, sc.Text())
				m.mu.Unlock()
			}
		}(conn)
	}
}

func (m *mockSyslogTCP) addr() string { return m.ln.Addr().String() }
func (m *mockSyslogTCP) close()       { _ = m.ln.Close() }

func (m *mockSyslogTCP) messages() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.msgs))
	copy(out, m.msgs)
	return out
}

func TestSyslogSinkCEFFormat(t *testing.T) {
	recv := newMockSyslogTCP(t)
	defer recv.close()

	sink, err := NewSyslogSink(SyslogOptions{
		Name:     "syslog",
		Network:  "tcp",
		Address:  recv.addr(),
		Hostname: "proxy1",
		AppName:  "pullthrough",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	ev := sampleEvent(SeverityHigh)
	ev.Fields = map[string]string{"coordinate": "npm/lodash@1.0.0", "ruleId": "CVE-2026-0001"}
	if err := sink.DeliverBatch(context.Background(), []Event{ev}); err != nil {
		t.Fatalf("DeliverBatch: %v", err)
	}

	waitFor(t, time.Second, func() bool { return len(recv.messages()) == 1 })
	msg := recv.messages()[0]

	// Syslog header: priority local0 (16*8) + error severity (3) = 131.
	if !strings.HasPrefix(msg, "<131>1 ") {
		t.Fatalf("missing/incorrect syslog PRI header: %q", msg)
	}
	if !strings.Contains(msg, "proxy1 pullthrough") {
		t.Fatalf("missing hostname/appname: %q", msg)
	}
	idx := strings.Index(msg, "CEF:0|")
	if idx < 0 {
		t.Fatalf("missing CEF prefix: %q", msg)
	}
	cef := msg[idx:]
	parts := strings.SplitN(cef, "|", 8)
	if len(parts) != 8 {
		t.Fatalf("CEF header does not have 7 pipes: %q", cef)
	}
	// parts: CEF:0 | vendor | product | version | sigID | name | severity | ext
	if parts[2] != "pullthrough-security" {
		t.Fatalf("CEF product = %q", parts[2])
	}
	if parts[6] != "8" { // high -> CEF severity 8
		t.Fatalf("CEF severity = %q, want 8", parts[6])
	}
	ext := parts[7]
	if !strings.Contains(ext, "ptsCoordinate=npm/lodash@1.0.0") {
		t.Fatalf("extension missing coordinate: %q", ext)
	}
	if !strings.Contains(ext, "outcome=error") {
		t.Fatalf("extension missing outcome: %q", ext)
	}
}

func TestSyslogSinkViaDialInjection(t *testing.T) {
	// Use a net.Pipe so the sink writes to an in-memory connection, verifying the
	// forwarder -> syslog path without a real listener.
	client, server := net.Pipe()
	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(server)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()

	sink, err := NewSyslogSink(SyslogOptions{
		Name: "syslog",
		Dial: func(ctx context.Context) (net.Conn, error) { return client, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	f := New(Options{Sinks: []Sink{sink}, BatchSize: 1, BatchTimeout: 10 * time.Millisecond})
	defer f.Close()

	f.Emit(sampleEvent(SeverityCritical))
	select {
	case line := <-lines:
		if !strings.Contains(line, "CEF:0|") {
			t.Fatalf("expected CEF line, got %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no syslog line received")
	}
}

func TestCEFEscaping(t *testing.T) {
	if got := cefEscapeHeader(`a|b\c`); got != `a\|b\\c` {
		t.Fatalf("header escape = %q", got)
	}
	if got := cefEscapeValue(`k=v\x` + "\n"); got != `k\=v\\x\n` {
		t.Fatalf("value escape = %q", got)
	}
}
