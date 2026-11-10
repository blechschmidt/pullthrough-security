package avscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClamd is an in-process clamd that speaks enough of the session protocol
// (zINSTREAM, zPING) to exercise the real ClamdEngine client end to end.
type fakeClamd struct {
	ln net.Listener
	wg sync.WaitGroup

	// matcher decides whether an accumulated INSTREAM payload is infected and,
	// if so, the signature name. nil => always clean.
	matcher func([]byte) (bool, string)
	// instreamReply, when set, overrides the computed reply (e.g. to inject an
	// ERROR). The "\x00" terminator is appended automatically.
	instreamReply string
	// abortAfter, when > 0, closes the connection after reading this many payload
	// bytes without sending a reply (simulates a dead daemon mid-stream).
	abortAfter int
}

func newFakeClamd(t *testing.T) *fakeClamd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeClamd{ln: ln}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeClamd) addr() string { return f.ln.Addr().String() }

func (f *fakeClamd) serve() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			f.handle(conn)
		}()
	}
}

func (f *fakeClamd) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	cmd, err := br.ReadString(0)
	if err != nil {
		return
	}
	cmd = strings.TrimRight(cmd, "\x00")
	switch cmd {
	case "zPING":
		_, _ = conn.Write([]byte("PONG\x00"))
	case "zINSTREAM":
		f.handleInstream(conn, br)
	default:
		_, _ = conn.Write([]byte("UNKNOWN COMMAND ERROR\x00"))
	}
}

func (f *fakeClamd) handleInstream(conn net.Conn, br *bufio.Reader) {
	var payload bytes.Buffer
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			break
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return
		}
		payload.Write(chunk)
		if f.abortAfter > 0 && payload.Len() >= f.abortAfter {
			// Simulate clamd closing the connection mid-stream without a reply.
			return
		}
	}
	if f.instreamReply != "" {
		_, _ = conn.Write([]byte(f.instreamReply + "\x00"))
		return
	}
	infected, sig := false, ""
	if f.matcher != nil {
		infected, sig = f.matcher(payload.Bytes())
	}
	if infected {
		_, _ = conn.Write([]byte("stream: " + sig + " FOUND\x00"))
	} else {
		_, _ = conn.Write([]byte("stream: OK\x00"))
	}
}

// eicar is the standard antivirus test string (not real malware).
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

func eicarMatcher(p []byte) (bool, string) {
	if bytes.Contains(p, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
		return true, "Eicar-Test-Signature"
	}
	return false, ""
}

func TestClamdEngineCleanAndInfected(t *testing.T) {
	f := newFakeClamd(t)
	f.matcher = eicarMatcher

	eng, err := newClamdEngine(f.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClamdEngine: %v", err)
	}

	// Clean payload.
	v, err := eng.Scan(context.Background(), strings.NewReader("hello world, perfectly benign"))
	if err != nil {
		t.Fatalf("scan clean: %v", err)
	}
	if v.Infected {
		t.Fatalf("expected clean, got infected %q", v.Signature)
	}
	if v.Bytes == 0 {
		t.Fatalf("expected non-zero scanned bytes")
	}

	// Infected payload (EICAR).
	v, err = eng.Scan(context.Background(), strings.NewReader(eicar))
	if err != nil {
		t.Fatalf("scan eicar: %v", err)
	}
	if !v.Infected {
		t.Fatalf("expected infected verdict for EICAR")
	}
	if v.Signature != "Eicar-Test-Signature" {
		t.Errorf("signature = %q, want Eicar-Test-Signature", v.Signature)
	}
}

func TestClamdEngineLargePayloadChunking(t *testing.T) {
	f := newFakeClamd(t)
	f.matcher = eicarMatcher
	eng, err := newClamdEngine(f.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClamdEngine: %v", err)
	}
	// A payload spanning several INSTREAM chunks with EICAR embedded past the
	// first chunk boundary.
	big := make([]byte, maxChunkSize*2+1234)
	copy(big[maxChunkSize+10:], eicar)
	v, err := eng.Scan(context.Background(), bytes.NewReader(big))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !v.Infected {
		t.Fatalf("expected infected across chunk boundary")
	}
	if v.Bytes != int64(len(big)) {
		t.Errorf("bytes = %d, want %d", v.Bytes, len(big))
	}
}

func TestClamdEnginePing(t *testing.T) {
	f := newFakeClamd(t)
	eng, err := newClamdEngine(f.addr(), 2*time.Second)
	if err != nil {
		t.Fatalf("newClamdEngine: %v", err)
	}
	if err := eng.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}

func TestClamdEngineUnreachable(t *testing.T) {
	// Point at a closed port; dial must fail as engine-unavailable.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	eng, err := newClamdEngine(addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("newClamdEngine: %v", err)
	}
	_, scanErr := eng.Scan(context.Background(), strings.NewReader("data"))
	if scanErr == nil {
		t.Fatalf("expected scan error for unreachable daemon")
	}
}

func TestClamdEngineErrorReply(t *testing.T) {
	f := newFakeClamd(t)
	f.instreamReply = "INSTREAM size limit exceeded ERROR"
	eng, err := newClamdEngine(f.addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("newClamdEngine: %v", err)
	}
	_, scanErr := eng.Scan(context.Background(), strings.NewReader("data"))
	if scanErr == nil {
		t.Fatalf("expected error for clamd ERROR reply")
	}
}

func TestParseClamdAddress(t *testing.T) {
	cases := []struct {
		in       string
		net, adr string
		wantErr  bool
	}{
		{"127.0.0.1:3310", "tcp", "127.0.0.1:3310", false},
		{"tcp://clamd:3310", "tcp", "clamd:3310", false},
		{"unix:///var/run/clamav/clamd.ctl", "unix", "/var/run/clamav/clamd.ctl", false},
		{"unix:/tmp/clamd.sock", "unix", "/tmp/clamd.sock", false},
		{"/var/run/clamd.sock", "unix", "/var/run/clamd.sock", false},
		{"", "", "", true},
		{"not-a-host-port", "", "", true},
	}
	for _, tc := range cases {
		n, a, err := parseClamdAddress(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseClamdAddress(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseClamdAddress(%q): %v", tc.in, err)
			continue
		}
		if n != tc.net || a != tc.adr {
			t.Errorf("parseClamdAddress(%q) = (%q,%q), want (%q,%q)", tc.in, n, a, tc.net, tc.adr)
		}
	}
}

func TestParseClamdReply(t *testing.T) {
	cases := []struct {
		reply     string
		infected  bool
		signature string
		wantErr   bool
	}{
		{"stream: OK", false, "", false},
		{"stream: Eicar-Test-Signature FOUND", true, "Eicar-Test-Signature", false},
		{"1: Win.Test.EICAR_HDB-1 FOUND", true, "Win.Test.EICAR_HDB-1", false},
		{"INSTREAM size limit exceeded ERROR", false, "", true},
		{"", false, "", true},
	}
	for _, tc := range cases {
		v, err := parseClamdReply(tc.reply)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseClamdReply(%q): expected error", tc.reply)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseClamdReply(%q): %v", tc.reply, err)
			continue
		}
		if v.Infected != tc.infected || v.Signature != tc.signature {
			t.Errorf("parseClamdReply(%q) = %+v, want infected=%v sig=%q", tc.reply, v, tc.infected, tc.signature)
		}
	}
}
