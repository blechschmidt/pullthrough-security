package git

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHServerOptions configures the inbound Git-over-SSH endpoint.
type SSHServerOptions struct {
	// Addr is the listen address, e.g. ":2222". Required.
	Addr string
	// HostKeyFile is a PEM-encoded private host key. When empty an ephemeral
	// ed25519 key is generated (clients will see a changing host key — set this in
	// production).
	HostKeyFile string
	// AuthorizedKeys is a list of OpenSSH-format public keys permitted to connect.
	AuthorizedKeys []string
	// AuthorizedKeysFile is an OpenSSH authorized_keys file whose entries are also
	// permitted. Optional.
	AuthorizedKeysFile string
	// NoClientAuth disables client authentication. Intended only for trusted
	// networks; the proxy is read-only regardless.
	NoClientAuth bool
	// Mirror serves git-upload-pack from local bare mirrors. Required (SSH serving
	// always uses mirror mode).
	Mirror *Mirror
	// Resolve maps an upstream name (the first repo path segment) to its Upstream.
	// Required.
	Resolve func(name string) (*Upstream, bool)
	Logger  *slog.Logger
}

// SSHServer is a read-only Git-over-SSH endpoint. It authenticates clients,
// accepts "git-upload-pack '<name>/<repo>'" exec requests, ensures the
// corresponding local mirror is fresh, and serves the pack negotiation from it.
type SSHServer struct {
	addr    string
	cfg     *ssh.ServerConfig
	mirror  *Mirror
	resolve func(name string) (*Upstream, bool)
	logger  *slog.Logger

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

// NewSSHServer validates opts and constructs an SSHServer.
func NewSSHServer(opts SSHServerOptions) (*SSHServer, error) {
	if opts.Addr == "" {
		return nil, errors.New("git ssh: listen address is required")
	}
	if opts.Mirror == nil {
		return nil, errors.New("git ssh: mirror is required (SSH serving requires mirror mode)")
	}
	if opts.Resolve == nil {
		return nil, errors.New("git ssh: upstream resolver is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	signer, err := loadOrGenerateHostKey(opts.HostKeyFile, logger)
	if err != nil {
		return nil, err
	}

	authorized, err := buildAuthorizedKeys(opts.AuthorizedKeys, opts.AuthorizedKeysFile)
	if err != nil {
		return nil, err
	}
	if !opts.NoClientAuth && len(authorized) == 0 {
		return nil, errors.New("git ssh: no authorized keys configured and client auth not disabled; refusing to start an open endpoint")
	}

	cfg := &ssh.ServerConfig{}
	if opts.NoClientAuth {
		cfg.NoClientAuth = true
	} else {
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorized[string(key.Marshal())] {
				return &ssh.Permissions{Extensions: map[string]string{"pubkey-fp": ssh.FingerprintSHA256(key)}}, nil
			}
			return nil, fmt.Errorf("git ssh: unauthorized public key")
		}
	}
	cfg.AddHostKey(signer)

	return &SSHServer{
		addr:    opts.Addr,
		cfg:     cfg,
		mirror:  opts.Mirror,
		resolve: opts.Resolve,
		logger:  logger,
	}, nil
}

// Run starts the SSH listener and blocks until ctx is canceled, then stops
// accepting and closes the listener. In-flight sessions are allowed to drain.
func (s *SSHServer) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("git ssh: listen %s: %w", s.addr, err)
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	s.logger.Info("git ssh gateway listening", "addr", s.addr)

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		_ = s.listener.Close()
		s.mu.Unlock()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				wg.Wait()
				return nil
			}
			// Transient accept error: back off briefly and continue.
			s.logger.Warn("git ssh accept failed", "error", err)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Addr returns the address the server is listening on, or nil before Run has
// bound the listener. It is primarily useful in tests that bind to ":0".
func (s *SSHServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *SSHServer) handleConn(ctx context.Context, nConn net.Conn) {
	defer nConn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, s.cfg)
	if err != nil {
		s.logger.Debug("git ssh handshake failed", "remote", nConn.RemoteAddr().String(), "error", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			s.logger.Debug("git ssh channel accept failed", "error", err)
			continue
		}
		go s.handleSession(ctx, sshConn, ch, chReqs)
	}
}

func (s *SSHServer) handleSession(ctx context.Context, conn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	// The client may set GIT_PROTOCOL (via an SSH "env" request) before "exec" to
	// negotiate the wire protocol version. We forward only that variable.
	var gitProtocol string
	for req := range reqs {
		switch req.Type {
		case "env":
			if name, value, ok := decodeEnvPayload(req.Payload); ok && name == "GIT_PROTOCOL" {
				gitProtocol = value
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			cmd := decodeExecPayload(req.Payload)
			status := s.runExec(ctx, ch, cmd, gitProtocol)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			sendExitStatus(ch, status)
			return
		case "shell":
			// Interactive shells are not offered by a git endpoint.
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			_, _ = io.WriteString(ch.Stderr(), "interactive shell access is not permitted\n")
			sendExitStatus(ch, 1)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// runExec parses and serves a git exec command, returning the exit status to
// report to the client.
func (s *SSHServer) runExec(ctx context.Context, ch ssh.Channel, rawCmd, protocol string) uint32 {
	service, repoArg, err := parseGitCommand(rawCmd)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "%v\n", err)
		return 1
	}
	if _, err := validateService(service); err != nil {
		fmt.Fprintf(ch.Stderr(), "%v\n", err)
		return 1
	}

	name, repoPath, ok := splitUpstreamRepo(repoArg)
	if !ok {
		fmt.Fprintln(ch.Stderr(), "git ssh: repository path must be '<upstream>/<repo>'")
		return 1
	}
	up, ok := s.resolve(name)
	if !ok {
		fmt.Fprintf(ch.Stderr(), "git ssh: unknown upstream %q\n", name)
		return 1
	}
	repo, err := sanitizeRepoPath(repoPath)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "%v\n", err)
		return 1
	}

	dir, err := s.mirror.Ensure(ctx, up, repo)
	if err != nil {
		s.logger.Error("git ssh mirror ensure failed", "upstream", name, "repo", repo, "error", err)
		fmt.Fprintln(ch.Stderr(), "git ssh: upstream unavailable")
		return 1
	}

	if err := s.mirror.UploadPackStateful(ctx, dir, ch, ch, ch.Stderr(), protocol); err != nil {
		s.logger.Warn("git ssh upload-pack failed", "upstream", name, "repo", repo, "error", err)
		return 1
	}
	return 0
}

// --- helpers -------------------------------------------------------------

func loadOrGenerateHostKey(path string, logger *slog.Logger) (ssh.Signer, error) {
	if path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("git ssh: reading host key %q: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("git ssh: parsing host key %q: %w", path, err)
		}
		return signer, nil
	}
	logger.Warn("git ssh: no host key configured; generating an ephemeral key (clients will see a changing host key)")
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("git ssh: generating host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("git ssh: building host signer: %w", err)
	}
	return signer, nil
}

func buildAuthorizedKeys(inline []string, file string) (map[string]bool, error) {
	out := make(map[string]bool)
	add := func(line string) error {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			return nil
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("git ssh: parsing authorized key: %w", err)
		}
		out[string(key.Marshal())] = true
		return nil
	}
	for _, line := range inline {
		if err := add(line); err != nil {
			return nil, err
		}
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("git ssh: reading authorized keys file %q: %w", file, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if err := add(line); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// decodeExecPayload extracts the command string from an SSH "exec" request
// payload (a single SSH string field).
func decodeExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload[:4])
	if int(n) > len(payload)-4 {
		return ""
	}
	return string(payload[4 : 4+n])
}

// decodeEnvPayload extracts the name and value from an SSH "env" request
// payload (two consecutive SSH string fields).
func decodeEnvPayload(payload []byte) (name, value string, ok bool) {
	name, rest, ok := readSSHString(payload)
	if !ok {
		return "", "", false
	}
	value, _, ok = readSSHString(rest)
	if !ok {
		return "", "", false
	}
	return name, value, true
}

// readSSHString reads a length-prefixed SSH string from the front of b,
// returning the string and the remaining bytes.
func readSSHString(b []byte) (string, []byte, bool) {
	if len(b) < 4 {
		return "", nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	if int(n) > len(b)-4 {
		return "", nil, false
	}
	return string(b[4 : 4+n]), b[4+n:], true
}

// parseGitCommand splits a git transport command such as
// "git-upload-pack 'github/owner/repo.git'" into its service and repository
// argument, handling single- and double-quoted arguments.
func parseGitCommand(cmd string) (service, repo string, err error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", "", errors.New("git ssh: empty command")
	}
	sp := strings.IndexByte(cmd, ' ')
	if sp < 0 {
		return "", "", fmt.Errorf("git ssh: malformed command %q", cmd)
	}
	service = cmd[:sp]
	arg := strings.TrimSpace(cmd[sp+1:])
	repo = unquote(arg)
	if repo == "" {
		return "", "", fmt.Errorf("git ssh: missing repository in command %q", cmd)
	}
	return service, repo, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitUpstreamRepo splits "/github/owner/repo.git" (or without the leading
// slash) into the upstream name and the repository path.
func splitUpstreamRepo(p string) (name, repo string, ok bool) {
	p = strings.TrimPrefix(strings.TrimSpace(p), "/")
	name, repo, found := strings.Cut(p, "/")
	if name == "" || !found || repo == "" {
		return "", "", false
	}
	return name, repo, true
}

// sendExitStatus sends the SSH "exit-status" request closing out a session.
func sendExitStatus(ch ssh.Channel, status uint32) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], status)
	_, _ = ch.SendRequest("exit-status", false, payload[:])
}
