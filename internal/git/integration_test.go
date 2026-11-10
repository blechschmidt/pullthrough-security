//go:build integration
// +build integration

package git

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// requireGit skips the test when the git binary is unavailable.
func requireGit(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not available; skipping integration test")
	}
	return bin
}

// isolatedGitEnv returns an environment that isolates git from the host user's
// global/system configuration, for deterministic tests.
func isolatedGitEnv(home string) []string {
	return append(os.Environ(),
		"HOME="+home,
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
}

func runGitT(t *testing.T, env []string, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// createOriginRepo builds a bare "upstream" repository with one commit on the
// default branch and returns (originRoot, repoName, headSHA). The repo is at
// <originRoot>/<repoName>.
func createOriginRepo(t *testing.T) (originRoot, repoName, head string) {
	t.Helper()
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	env := isolatedGitEnv(home)

	work := filepath.Join(tmp, "work")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	runGitT(t, env, work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello pullthrough\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitT(t, env, work, "add", "-A")
	runGitT(t, env, work, "commit", "-q", "-m", "initial commit")

	out, err := exec.Command("git", "-C", work, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	head = strings.TrimSpace(string(out))

	originRoot = filepath.Join(tmp, "origin")
	repoName = "team/project.git"
	target := filepath.Join(originRoot, filepath.FromSlash(repoName))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	runGitT(t, env, tmp, "clone", "-q", "--bare", work, target)
	return originRoot, repoName, head
}

// fileUpstream constructs a mirror-mode HTTPS-transport upstream that clones from
// a local file:// origin (white-box: the production constructor only accepts
// http(s)/ssh URLs, but the mirror is transport-agnostic for file://).
func fileUpstream(t *testing.T, name, originRoot string) *Upstream {
	t.Helper()
	base, err := url.Parse("file://" + originRoot)
	if err != nil {
		t.Fatal(err)
	}
	return &Upstream{Name: name, Transport: TransportHTTPS, base: base}
}

func newMirror(t *testing.T) *Mirror {
	t.Helper()
	m, err := NewMirror(MirrorOptions{
		Root:            filepath.Join(t.TempDir(), "mirrors"),
		RefreshInterval: time.Hour,
		Logger:          discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewMirror: %v", err)
	}
	return m
}

// TestMirrorCloneOverHTTP exercises the full smart-HTTP mirror path with a real
// git client: the proxy clones the upstream into a local bare mirror and serves
// info/refs + git-upload-pack from it.
func TestMirrorCloneOverHTTP(t *testing.T) {
	requireGit(t)
	originRoot, repoName, head := createOriginRepo(t)

	mirror := newMirror(t)
	up := fileUpstream(t, "gh", originRoot)
	backend, err := NewBackend(BackendOptions{Upstream: up, Mirror: mirror, Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/gh")
		backend.ServeBackendHTTP(w, r, rest)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	env := isolatedGitEnv(home)
	out := filepath.Join(tmp, "clone")

	cloneURL := srv.URL + "/gh/" + repoName
	cmd := exec.Command("git", "clone", "-q", cloneURL, out)
	cmd.Env = env
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone over proxy failed: %v\n%s", err, combined)
	}

	// The cloned working tree must contain the upstream content...
	data, err := os.ReadFile(filepath.Join(out, "README.md"))
	if err != nil {
		t.Fatalf("cloned README missing: %v", err)
	}
	if string(data) != "hello pullthrough\n" {
		t.Errorf("cloned content = %q", string(data))
	}
	// ...and the same HEAD commit.
	rev, err := exec.Command("git", "-C", out, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(rev)); got != head {
		t.Errorf("cloned HEAD = %s, want %s", got, head)
	}
}

// TestMirrorRejectsPushOverHTTP verifies the read-only proxy refuses receive-pack
// even in mirror mode.
func TestMirrorRejectsPushOverHTTP(t *testing.T) {
	requireGit(t)
	originRoot, repoName, _ := createOriginRepo(t)
	mirror := newMirror(t)
	up := fileUpstream(t, "gh", originRoot)
	backend, _ := NewBackend(BackendOptions{Upstream: up, Mirror: mirror, Logger: discardLogger()})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/"+repoName+"/git-receive-pack", strings.NewReader(""))
	backend.ServeBackendHTTP(rr, req, "/"+repoName+"/git-receive-pack")
	if rr.Code != http.StatusForbidden {
		t.Errorf("receive-pack status = %d, want 403", rr.Code)
	}
}

// TestSSHCloneOverSSH performs a full "git clone" over the SSH endpoint with a
// real OpenSSH client, exercising auth, host-key verification, command parsing,
// the mirror, and the stateful upload-pack negotiation end to end.
func TestSSHCloneOverSSH(t *testing.T) {
	requireGit(t)
	requireSSH(t)
	originRoot, repoName, head := createOriginRepo(t)
	mirror := newMirror(t)
	up := fileUpstream(t, "gh", originRoot)

	keyDir := t.TempDir()
	hostKey := sshKeygen(t, filepath.Join(keyDir, "host"))
	clientKey := sshKeygen(t, filepath.Join(keyDir, "client"))
	clientPub := readFile(t, clientKey+".pub")

	srv, err := NewSSHServer(SSHServerOptions{
		Addr:           "127.0.0.1:0",
		HostKeyFile:    hostKey,
		AuthorizedKeys: []string{clientPub},
		Mirror:         mirror,
		Resolve:        func(name string) (*Upstream, bool) { return up, name == "gh" },
		Logger:         discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	addr := waitForAddr(t, srv)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	// Build a known_hosts entry pinning the server host key on this host:port.
	hostPub := readFile(t, hostKey+".pub")
	knownHosts := filepath.Join(keyDir, "known_hosts")
	khLine := "[" + host + "]:" + port + " " + hostPub + "\n"
	if err := os.WriteFile(knownHosts, []byte(khLine), 0o644); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	env := isolatedGitEnv(home)
	env = append(env, "GIT_SSH_COMMAND=ssh -i "+clientKey+
		" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+knownHosts)

	out := filepath.Join(tmp, "clone")
	cloneURL := "ssh://git@" + host + ":" + port + "/gh/" + repoName
	cmd := exec.Command("git", "clone", "-q", cloneURL, out)
	cmd.Env = env
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git clone over ssh failed: %v\n%s", err, combined)
	}

	rev, err := exec.Command("git", "-C", out, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(rev)); got != head {
		t.Errorf("cloned HEAD = %s, want %s", got, head)
	}
	if data := readFile(t, filepath.Join(out, "README.md")); !strings.Contains(data, "hello pullthrough") {
		t.Errorf("cloned content = %q", data)
	}
}

// TestSSHRejectsPushOverSSH verifies the SSH endpoint refuses git-receive-pack.
func TestSSHRejectsPushOverSSH(t *testing.T) {
	requireGit(t)
	requireSSH(t)
	originRoot, repoName, _ := createOriginRepo(t)
	mirror := newMirror(t)
	up := fileUpstream(t, "gh", originRoot)

	keyDir := t.TempDir()
	hostKey := sshKeygen(t, filepath.Join(keyDir, "host"))
	clientKey := sshKeygen(t, filepath.Join(keyDir, "client"))
	clientPub := readFile(t, clientKey+".pub")

	srv, _ := NewSSHServer(SSHServerOptions{
		Addr:           "127.0.0.1:0",
		HostKeyFile:    hostKey,
		AuthorizedKeys: []string{clientPub},
		Mirror:         mirror,
		Resolve:        func(name string) (*Upstream, bool) { return up, name == "gh" },
		Logger:         discardLogger(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	addr := waitForAddr(t, srv)
	host, port, _ := net.SplitHostPort(addr)

	signer, err := ssh.ParsePrivateKey(readFileBytes(t, clientKey))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer conn.Close()
	_ = host
	_ = port

	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	err = sess.Run("git-receive-pack 'gh/" + repoName + "'")
	if err == nil {
		t.Error("expected non-zero exit for receive-pack over ssh")
	}
}

// TestSSHRejectsUnauthorizedKey verifies an unauthorized client key is denied.
func TestSSHRejectsUnauthorizedKey(t *testing.T) {
	mirror := &Mirror{} // not used before auth fails
	srv, err := NewSSHServer(SSHServerOptions{
		Addr:           "127.0.0.1:0",
		AuthorizedKeys: []string{mustAuthLine(t)},
		Mirror:         mirror,
		Resolve:        func(string) (*Upstream, bool) { return nil, false },
		Logger:         discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	addr := waitForAddr(t, srv)

	// A different (unauthorized) key.
	otherSigner, _ := genKeyPair(t)
	cfg := &ssh.ClientConfig{
		User:            "git",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(otherSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if _, err := ssh.Dial("tcp", addr, cfg); err == nil {
		t.Error("expected dial to fail for unauthorized key")
	}
}

func TestNewSSHServerRefusesOpenEndpoint(t *testing.T) {
	_, err := NewSSHServer(SSHServerOptions{
		Addr:    "127.0.0.1:0",
		Mirror:  &Mirror{},
		Resolve: func(string) (*Upstream, bool) { return nil, false },
		Logger:  discardLogger(),
	})
	if err == nil {
		t.Error("expected error: no authorized keys and client auth not disabled")
	}
}

// --- test key helpers ----------------------------------------------------

// requireSSH skips the test when the OpenSSH client tooling needed to drive a
// real git-over-ssh clone is unavailable.
func requireSSH(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client not available; skipping ssh integration test")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available; skipping ssh integration test")
	}
}

// sshKeygen generates an ed25519 OpenSSH key pair at path (private) and
// path+".pub" (public), returning the private key path. The OpenSSH private-key
// format it emits is parseable by both the git/ssh client and
// golang.org/x/crypto/ssh.ParsePrivateKey.
func sshKeygen(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "pullthrough-test", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen %s: %v\n%s", path, err, out)
	}
	return path
}

// readFile reads a file and returns its contents as a trimmed string. It is used
// for single-line artifacts (public keys) and small text payloads where trailing
// whitespace is noise.
func readFile(t *testing.T, path string) string {
	t.Helper()
	return strings.TrimSpace(string(readFileBytes(t, path)))
}

// readFileBytes reads a file and returns its raw bytes (e.g. a PEM private key,
// which must not be trimmed).
func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func genKeyPair(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return signer, authLine
}

func mustAuthLine(t *testing.T) string {
	t.Helper()
	_, line := genKeyPair(t)
	return line
}

func waitForAddr(t *testing.T, srv *SSHServer) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a := srv.Addr(); a != nil {
			return a.String()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("ssh server did not bind in time")
	return ""
}

// writeTestHostKey writes an ephemeral PEM host key to a temp file (kept for
// completeness; the SSH tests use ephemeral in-memory keys).
func writeTestHostKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "hostkey")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var _ = writeTestHostKey
var _ = io.Discard
