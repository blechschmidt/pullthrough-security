package avscan

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// clamdEngine speaks the ClamAV clamd session protocol over a TCP or UNIX
// socket. Scanning uses the INSTREAM command, which streams the payload to the
// daemon in length-prefixed chunks and never writes the artifact to a shared
// path — so the proxy can scan an in-flight, cache-staged blob without clamd
// needing filesystem access to it.
//
// The protocol framing (ClamAV docs): a session command is sent NUL-terminated
// when prefixed with 'z'; INSTREAM is then followed by a sequence of chunks,
// each a 4-byte big-endian length followed by that many bytes, terminated by a
// zero-length (four zero bytes) chunk. The daemon replies with a single
// NUL-terminated line: "stream: OK", "stream: <SIGNATURE> FOUND", or
// "<detail> ERROR".
type clamdEngine struct {
	network string // "tcp" | "unix"
	address string
	timeout time.Duration

	// dial is overridable in tests to supply an in-memory connection without a
	// real daemon; nil uses the real network dialer.
	dial func(ctx context.Context) (net.Conn, error)
}

// maxChunkSize bounds a single INSTREAM chunk. clamd caps a chunk at its
// StreamMaxLength; 64 KiB stays well under any realistic configuration while
// keeping the number of writes low.
const maxChunkSize = 64 * 1024

// newClamdEngine parses a clamd endpoint and constructs the engine. The address
// may be a "host:port" / "tcp://host:port" TCP socket or a "unix:///path" /
// filesystem-path UNIX socket.
func newClamdEngine(address string, timeout time.Duration) (*clamdEngine, error) {
	network, addr, err := parseClamdAddress(address)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &clamdEngine{network: network, address: addr, timeout: timeout}, nil
}

func (e *clamdEngine) Name() string { return EngineClamAV }

// parseClamdAddress classifies a clamd endpoint into a (network, address) pair.
func parseClamdAddress(address string) (network, addr string, err error) {
	a := strings.TrimSpace(address)
	if a == "" {
		return "", "", fmt.Errorf("avscan: empty clamd address")
	}
	switch {
	case strings.HasPrefix(a, "unix://"):
		return "unix", strings.TrimPrefix(a, "unix://"), nil
	case strings.HasPrefix(a, "unix:"):
		return "unix", strings.TrimPrefix(a, "unix:"), nil
	case strings.HasPrefix(a, "tcp://"):
		return "tcp", strings.TrimPrefix(a, "tcp://"), nil
	case strings.HasPrefix(a, "/"), strings.HasPrefix(a, "./"), strings.HasPrefix(a, "../"):
		// A bare filesystem path is a UNIX socket.
		return "unix", a, nil
	default:
		// Otherwise a TCP host:port.
		if _, _, splitErr := net.SplitHostPort(a); splitErr != nil {
			return "", "", fmt.Errorf("avscan: clamd address %q is neither a unix socket path nor a host:port: %w", address, splitErr)
		}
		return "tcp", a, nil
	}
}

// connect dials the daemon, honouring the per-scan timeout and the caller's
// context.
func (e *clamdEngine) connect(ctx context.Context) (net.Conn, error) {
	if e.dial != nil {
		return e.dial(ctx)
	}
	d := net.Dialer{Timeout: e.timeout}
	conn, err := d.DialContext(ctx, e.network, e.address)
	if err != nil {
		return nil, fmt.Errorf("%w: dialing %s %s: %v", ErrEngineUnavailable, e.network, e.address, err)
	}
	return conn, nil
}

// Scan streams r to clamd via INSTREAM and parses the verdict.
func (e *clamdEngine) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	conn, err := e.connect(ctx)
	if err != nil {
		return Verdict{}, err
	}
	defer conn.Close()

	e.applyDeadline(ctx, conn)
	// Cancel the blocking socket I/O promptly if the caller's context is done.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return Verdict{}, fmt.Errorf("%w: sending INSTREAM: %v", ErrEngineUnavailable, err)
	}

	bytes, writeErr := streamChunks(conn, r)
	// Even on a write failure (e.g. clamd aborted after hitting its stream size
	// limit and closed the connection) we still attempt to read the reply, which
	// usually carries the actionable "size limit exceeded" ERROR.
	reply, readErr := readClamdReply(conn)
	if readErr != nil {
		if writeErr != nil {
			return Verdict{}, fmt.Errorf("%w: streaming payload: %v", ErrEngineUnavailable, writeErr)
		}
		if err := ctx.Err(); err != nil {
			return Verdict{}, fmt.Errorf("%w: %v", ErrEngineUnavailable, err)
		}
		return Verdict{}, fmt.Errorf("%w: reading reply: %v", ErrEngineUnavailable, readErr)
	}

	verdict, perr := parseClamdReply(reply)
	if perr != nil {
		return Verdict{}, perr
	}
	verdict.Bytes = bytes
	return verdict, nil
}

// streamChunks writes r to conn as INSTREAM length-prefixed chunks, then the
// zero-length terminator. It returns the number of payload bytes sent.
func streamChunks(conn net.Conn, r io.Reader) (int64, error) {
	buf := make([]byte, maxChunkSize)
	var hdr [4]byte
	var total int64
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(hdr[:], uint32(n))
			if _, werr := conn.Write(hdr[:]); werr != nil {
				return total, werr
			}
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return total, rerr
		}
	}
	// Zero-length terminator chunk.
	binary.BigEndian.PutUint32(hdr[:], 0)
	if _, werr := conn.Write(hdr[:]); werr != nil {
		return total, werr
	}
	return total, nil
}

// readClamdReply reads a single NUL-terminated reply line (the 'z' command
// variant). A bare newline terminator is also tolerated for robustness.
func readClamdReply(conn net.Conn) (string, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString(0)
	if err != nil {
		if err == io.EOF && line != "" {
			return strings.TrimRight(line, "\n\x00"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\n\x00"), nil
}

// parseClamdReply turns a clamd reply line into a Verdict. "OK" is clean,
// "... FOUND" is infected (signature extracted), "... ERROR" is a daemon-side
// failure reported as engine-unavailable.
func parseClamdReply(reply string) (Verdict, error) {
	line := strings.TrimSpace(reply)
	switch {
	case strings.HasSuffix(line, "ERROR"):
		return Verdict{}, fmt.Errorf("%w: clamd error: %s", ErrEngineUnavailable, line)
	case strings.HasSuffix(line, "FOUND"):
		return Verdict{Infected: true, Signature: extractSignature(line)}, nil
	case strings.HasSuffix(line, "OK"):
		return Verdict{}, nil
	case line == "":
		return Verdict{}, fmt.Errorf("%w: empty clamd reply", ErrEngineUnavailable)
	default:
		return Verdict{}, fmt.Errorf("%w: unrecognized clamd reply %q", ErrEngineUnavailable, line)
	}
}

// extractSignature pulls the signature name out of a "stream: <SIG> FOUND" line.
func extractSignature(line string) string {
	s := strings.TrimSuffix(line, "FOUND")
	s = strings.TrimSpace(s)
	// Drop the leading "stream:" (or "<n>: " id prefix) if present.
	if i := strings.LastIndex(s, ": "); i >= 0 {
		s = s[i+2:]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}

// Ping issues a PING/PONG liveness check.
func (e *clamdEngine) Ping(ctx context.Context) error {
	conn, err := e.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	e.applyDeadline(ctx, conn)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("%w: sending PING: %v", ErrEngineUnavailable, err)
	}
	reply, err := readClamdReply(conn)
	if err != nil {
		return fmt.Errorf("%w: reading PONG: %v", ErrEngineUnavailable, err)
	}
	if strings.TrimSpace(reply) != "PONG" {
		return fmt.Errorf("%w: unexpected ping reply %q", ErrEngineUnavailable, reply)
	}
	return nil
}

// applyDeadline sets a socket deadline from the context deadline, falling back
// to the configured timeout.
func (e *clamdEngine) applyDeadline(ctx context.Context, conn net.Conn) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
		return
	}
	if e.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(e.timeout))
	}
}
