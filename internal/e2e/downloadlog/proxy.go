//go:build integration
// +build integration

package downloadlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	dl "github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// Environment variables that tune a run. All are optional.
const (
	// envProxyBin points at a prebuilt `pullthrough` binary. Without it the suite
	// builds one from the source tree, once per run.
	envProxyBin = "PT_DOWNLOADLOG_PROXY_BIN"
	// envClients selects the package managers that drive the suite: "auto" (the
	// default) uses the real cargo and go where installed and a scripted
	// stand-in otherwise; "real" makes a missing package manager a failure (CI
	// sets this, so the suite cannot quietly degrade); "scripted" forces the
	// stand-ins.
	envClients = "PT_DOWNLOADLOG_CLIENTS"
	// envWorkDir is where the proxy's state, its log and the clients' scratch
	// directories are created. Default: a temporary directory.
	envWorkDir = "PT_DOWNLOADLOG_WORKDIR"
	// envKeep keeps the work directory of a passing run too (a failing run's is
	// always kept, and its path logged).
	envKeep = "PT_DOWNLOADLOG_KEEP"
	// envReportDir receives the matrix. It is shared with the other integration
	// suites so one CI step publishes them all.
	envReportDir = "PT_TEST_REPORT_DIR"
	// envAttachments is the task runner's attachment directory, used when
	// envReportDir is unset.
	envAttachments = "CLOOP_TASK_ATTACHMENTS"
)

const (
	// adminToken guards the admin API of every proxy the suite starts.
	adminToken = "downloadlog-e2e-admin-token"
	// publicHost is the name clients know the proxy by. It does not resolve: a
	// client can only reach it through its egress, which is what gives each
	// client machine an address of its own.
	publicHost = "pullthrough.test"
	// trustedProxyAddr is the one address listed in server.trustedProxies — the
	// suite's "load balancer".
	trustedProxyAddr = "127.0.99.1"
)

var (
	proxyBinOnce sync.Once
	proxyBinPath string
	proxyBinErr  error
)

// proxyBinary returns the path of the `pullthrough` binary under test, building
// it on first use unless envProxyBin names one.
func proxyBinary(t *testing.T) string {
	t.Helper()
	proxyBinOnce.Do(func() {
		if bin := os.Getenv(envProxyBin); bin != "" {
			abs, err := filepath.Abs(bin)
			if err == nil {
				_, err = os.Stat(abs)
			}
			if err != nil {
				proxyBinErr = fmt.Errorf("%s: %w", envProxyBin, err)
				return
			}
			proxyBinPath = abs
			return
		}
		dir, err := os.MkdirTemp("", "downloadlog-proxy-bin-")
		if err != nil {
			proxyBinErr = err
			return
		}
		proxyBinPath = filepath.Join(dir, "pullthrough")
		// The tests run in the package directory; the command is three levels up.
		build := exec.Command("go", "build", "-o", proxyBinPath, "../../../cmd/pullthrough")
		if out, err := build.CombinedOutput(); err != nil {
			proxyBinErr = fmt.Errorf("building the proxy (set %s to a prebuilt binary to skip this): %v\n%s", envProxyBin, err, out)
		}
	})
	if proxyBinErr != nil {
		// A tagged run was asked for explicitly: a missing prerequisite is a
		// failure, never a skip — a skipped suite would look green.
		t.Fatalf("the proxy binary is unavailable: %v", proxyBinErr)
	}
	return proxyBinPath
}

// proxyProc is a running proxy process.
type proxyProc struct {
	bin      string
	stateDir string
	cfgPath  string
	logPath  string
	// listen is the loopback address the process listens on; publicURL the base
	// URL clients are configured with (the unresolvable public host, same port).
	listen    string
	publicURL string

	cmd    *exec.Cmd
	exited chan error
	client *http.Client
}

// renderConfig renders the configuration of the proxy under test. It is what an
// operator would write: two upstreams, a cache directory, the admin API behind a
// token, a dependency-firewall denylist, the load balancer as a trusted proxy,
// and a file for the download log. The download log itself is not switched on
// anywhere — it is on by default, which is part of what the suite verifies.
func renderConfig(s *stub, stateDir, listen, publicURL string) ([]byte, error) {
	cfg := map[string]any{
		"server": map[string]any{
			"httpAddr":       listen,
			"publicUrl":      publicURL,
			"trustedProxies": []any{trustedProxyAddr},
		},
		"logging": map[string]any{"level": "info", "format": "json"},
		"cache":   map[string]any{"backend": "filesystem", "dir": filepath.Join(stateDir, "cache")},
		// Loopback, and nothing else: the stub registries are reachable, and a
		// request to anywhere on the network is refused by the proxy itself. The
		// suite is hermetic by enforcement, not by good behaviour.
		"egress": map[string]any{
			"enabled":                 true,
			"allowedSchemes":          []any{"http"},
			"allowlist":               []any{"127.0.0.1"},
			"allowedDestinationCidrs": []any{"127.0.0.1/32"},
		},
		"upstreams": map[string]any{
			"cargo": map[string]any{
				"type": "cargo", "url": s.cratesURL(),
				// The stub plays the download host as well as the index.
				"settings": map[string]any{"downloadUrl": s.cratesURL()},
			},
			"go": map[string]any{
				"type": "go", "url": s.goproxyURL(),
				// The fixture modules are in no checksum database; the clients run
				// with GOSUMDB=off and the proxy does not offer one.
				"settings": map[string]any{"sumdb": "off"},
			},
		},
		"observability": map[string]any{"metrics": true, "admin": true, "adminToken": adminToken},
		"depfirewall": map[string]any{
			"enabled": true,
			"rules": []any{
				map[string]any{"ecosystem": "cargo", "name": s.crates[roleDenied].Name, "denied": []any{s.crates[roleDenied].Version}},
				map[string]any{"ecosystem": "go", "name": s.modules[roleDenied].Name, "denied": []any{s.modules[roleDenied].Version}},
			},
		},
		"downloadLog": map[string]any{
			"path": filepath.Join(stateDir, "downloads.jsonl"),
		},
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by internal/e2e/downloadlog. Do not edit.\n"), out...), nil
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

// startProxy writes the proxy's configuration into stateDir and starts it,
// returning once it answers /readyz. With listen empty a free port is chosen —
// and, because another process can take a port between choosing and binding it,
// a start that fails is retried on a new one. A restart passes the address the
// first start settled on, so the clients' configuration stays valid.
func startProxy(bin, stateDir, logPath string, s *stub, listen string) (*proxyProc, error) {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		addr := listen
		if addr == "" {
			var err error
			if addr, err = freeAddr(); err != nil {
				return nil, err
			}
		}
		_, port, _ := net.SplitHostPort(addr)
		p := &proxyProc{
			bin:       bin,
			stateDir:  stateDir,
			cfgPath:   filepath.Join(stateDir, "config.yaml"),
			logPath:   logPath,
			listen:    addr,
			publicURL: "http://" + net.JoinHostPort(publicHost, port),
			client:    &http.Client{Timeout: 30 * time.Second},
		}
		cfg, err := renderConfig(s, stateDir, p.listen, p.publicURL)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p.cfgPath, cfg, 0o644); err != nil {
			return nil, err
		}
		if lastErr = p.start(); lastErr == nil {
			return p, nil
		}
		if listen != "" {
			break // a restart must come back on the same address
		}
	}
	return nil, lastErr
}

func (p *proxyProc) start() error {
	logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(p.bin, "-config", p.cfgPath)
	cmd.Dir = p.stateDir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("starting the proxy: %w", err)
	}
	_ = logFile.Close() // the child holds its own descriptor
	p.cmd = cmd
	p.exited = make(chan error, 1)
	go func() { p.exited <- cmd.Wait() }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			p.cmd = nil
			return fmt.Errorf("the proxy exited during startup: %v\n%s", err, tailFile(p.logPath, 30))
		default:
		}
		resp, err := p.client.Get("http://" + p.listen + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.stop()
	return fmt.Errorf("the proxy did not become ready within 60s\n%s", tailFile(p.logPath, 30))
}

// stop shuts the proxy down the way a deployment does (SIGTERM), which is when
// it writes what the download log still holds in memory, and waits for it.
func (p *proxyProc) stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
	p.cmd = nil
}

// adminGet performs an admin API request with the given bearer token ("" for
// none) and returns the status and body.
func (p *proxyProc) adminGet(pathAndQuery, token string) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+p.listen+pathAndQuery, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return resp.StatusCode, resp.Header, body, err
}

// logPage is the admin API's download-log response.
type logPage struct {
	Enabled    bool       `json:"enabled"`
	Total      int        `json:"total"`
	Returned   int        `json:"returned"`
	NextBefore uint64     `json:"nextBefore"`
	Entries    []dl.Entry `json:"entries"`
	Log        dl.Stats   `json:"log"`
}

// logSummary is the admin API's download-log summary response.
type logSummary struct {
	Enabled bool `json:"enabled"`
	dl.Summary
}

// downloads queries the download log through the admin API — the endpoint the
// console's Downloads tab reads. The query is given as URL parameters.
func (p *proxyProc) downloads(query url.Values) (logPage, error) {
	if query == nil {
		query = url.Values{}
	}
	if query.Get("limit") == "" {
		query.Set("limit", "1000")
	}
	var page logPage
	status, _, body, err := p.adminGet("/admin/api/downloads?"+query.Encode(), adminToken)
	if err != nil {
		return page, err
	}
	if status != http.StatusOK {
		return page, fmt.Errorf("GET /admin/api/downloads?%s: status %d: %s", query.Encode(), status, firstLine(body))
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return page, fmt.Errorf("decoding the download log: %w", err)
	}
	return page, nil
}

// summary queries the download-log aggregates through the admin API.
func (p *proxyProc) summary(query url.Values) (logSummary, error) {
	if query == nil {
		query = url.Values{}
	}
	if query.Get("top") == "" {
		query.Set("top", "100")
	}
	var sum logSummary
	status, _, body, err := p.adminGet("/admin/api/downloads/summary?"+query.Encode(), adminToken)
	if err != nil {
		return sum, err
	}
	if status != http.StatusOK {
		return sum, fmt.Errorf("GET /admin/api/downloads/summary?%s: status %d: %s", query.Encode(), status, firstLine(body))
	}
	if err := json.Unmarshal(body, &sum); err != nil {
		return sum, fmt.Errorf("decoding the download-log summary: %w", err)
	}
	return sum, nil
}

// awaitEntries polls the download log until the query returns at least want
// entries, and returns them. An entry is recorded when the proxy's handler
// returns, which is a moment after the client has received the last byte — so
// "the client is done" and "the entry is there" are not the same instant.
func (p *proxyProc) awaitEntries(query url.Values, want int) ([]dl.Entry, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		page, err := p.downloads(cloneValues(query))
		if err != nil {
			return nil, err
		}
		if len(page.Entries) >= want || time.Now().After(deadline) {
			return page.Entries, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// tailFile returns the last n lines of a file, for failure messages.
func tailFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// errNotLinux explains the one platform assumption of the suite.
var errNotLinux = errors.New("the suite gives every client machine its own loopback source address (127.0.10.1, …), " +
	"which needs a system where all of 127.0.0.0/8 is local — Linux. On macOS, add the aliases first " +
	"(sudo ifconfig lo0 alias 127.0.10.1, …)")
