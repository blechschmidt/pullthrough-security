//go:build integration
// +build integration

package pkgscan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment variables that tune a run. All are optional.
const (
	// envProxyBin points at a prebuilt `pullthrough` binary. Without it the
	// suite builds one from the source tree, once per run (which needs the Go
	// toolchain — the same one running the tests).
	envProxyBin = "PT_PKGSCAN_PROXY_BIN"
	// envEcosystems restricts the run to a space- or comma-separated list of
	// ecosystem IDs. The coverage gate then checks only those, and the matrix is
	// marked partial.
	envEcosystems = "PT_PKGSCAN_ECOSYSTEMS"
	// envWorkDir is where the per-ecosystem workspaces (proxy configuration,
	// state and log) are created. Default: a temporary directory.
	envWorkDir = "PT_PKGSCAN_WORKDIR"
	// envKeep keeps the workspaces of passing ecosystems too. A failing
	// ecosystem's workspace is always kept, and its path logged.
	envKeep = "PT_PKGSCAN_KEEP"
	// envReportDir receives the matrix (shared with the other integration
	// suites, so one CI step publishes them all).
	envReportDir = "PT_TEST_REPORT_DIR"
	// envAttachments is the task runner's attachment directory, used when
	// envReportDir is unset.
	envAttachments = "CLOOP_TASK_ATTACHMENTS"
)

// scanTimeout is llmPackageScan.timeout in every proxy the suite starts. It is
// how long a timeout scenario takes, so it is short; it is also the bound on
// every ordinary scan, which against the mock takes milliseconds.
const scanTimeout = 3 * time.Second

// auditKey is the audit log's HMAC key in every proxy the suite starts.
const auditKey = "pkgscan-e2e-audit-key"

var (
	proxyBinOnce sync.Once
	proxyBinPath string
	proxyBinErr  error
	// proxyBinDir is the directory the suite built the binary into, removed when
	// the test binary exits (see TestMain); empty for a prebuilt binary.
	proxyBinDir string
)

// proxyBinary returns the path of the `pullthrough` binary under test,
// building it on first use unless envProxyBin names one.
func proxyBinary(t *testing.T) string {
	t.Helper()
	proxyBinOnce.Do(func() {
		if bin := os.Getenv(envProxyBin); bin != "" {
			abs, err := filepath.Abs(bin)
			if err != nil {
				proxyBinErr = err
				return
			}
			if _, err := os.Stat(abs); err != nil {
				proxyBinErr = fmt.Errorf("%s: %w", envProxyBin, err)
				return
			}
			proxyBinPath = abs
			return
		}
		dir, err := os.MkdirTemp("", "pkgscan-proxy-bin-")
		if err != nil {
			proxyBinErr = err
			return
		}
		proxyBinDir = dir
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

// gateConfig is the llmPackageScan posture of one proxy process.
type gateConfig struct {
	// Provider selects the wire format spoken to the mock: "claude" or "openai".
	Provider string
	// Action and FailMode are written to the configuration only when set, so
	// that an empty value tests the shipped default.
	Action   string
	FailMode string
}

// procConfig describes one proxy process.
type procConfig struct {
	// Role names the process within its ecosystem's run ("strict", "control").
	Role string
	// Eco is the ecosystem whose upstream the process fronts.
	Eco eco
	// StubURL is the stub registry's base URL.
	StubURL string
	// StateDir holds everything the process persists: content cache, verdicts,
	// audit log, approvals. Two processes given the same directory are one
	// deployment restarted.
	StateDir string
	// Gate enables llmPackageScan; nil leaves the gate off.
	Gate *gateConfig
	// LLM is the mock provider endpoint the gate talks to.
	LLM *mockLLM
}

// renderConfig renders the proxy configuration of a process. It is what an
// operator would write: an upstream, a cache directory, the audit log, the
// approval workflow, and the llmPackageScan block. Everything else is the
// shipped default — which is the point: the default-on gates (install hooks,
// content scan, risk score, …) all run, and the package scan is exercised in
// the place it really has among them.
func renderConfig(pc procConfig, listen string) ([]byte, error) {
	e := pc.Eco
	up := map[string]any{"type": e.Type, "url": pc.StubURL + e.UpstreamPath}
	if e.Settings != nil {
		if s := e.Settings(pc.StubURL); len(s) > 0 {
			settings := map[string]any{}
			for k, v := range s {
				settings[k] = v
			}
			up["settings"] = settings
		}
	}
	if e.Generic != nil {
		up["generic"] = e.Generic
	}

	cfg := map[string]any{
		"server":  map[string]any{"httpAddr": listen, "publicUrl": "http://" + listen},
		"logging": map[string]any{"level": "debug", "format": "json"},
		"cache":   map[string]any{"backend": "filesystem", "dir": filepath.Join(pc.StateDir, "cache")},
		// The admin API is how the suite observes the proxy from outside: cache
		// entries, verdicts, findings, reviews.
		"observability": map[string]any{"metrics": true, "admin": true},
		"audit": map[string]any{
			"enabled": true,
			"file":    auditLogPath(pc.StateDir),
			"hmacKey": auditKey,
		},
		// Loopback, and nothing else: the stub registry is reachable, and a
		// request to anywhere on the network is refused by the proxy itself. The
		// suite is hermetic by enforcement, not by good behaviour.
		"egress": map[string]any{
			"enabled":                 true,
			"allowedSchemes":          []any{"http"},
			"allowlist":               []any{"127.0.0.1"},
			"allowedDestinationCidrs": []any{"127.0.0.1/32"},
		},
		"upstreams": map[string]any{e.ID: up},
		// A refusal opens a review (the break-glass workflow): that a review is
		// open for exactly the refused bytes is part of "quarantined".
		"approvals": map[string]any{
			"enabled":   true,
			"storePath": filepath.Join(pc.StateDir, "approvals.json"),
		},
	}

	env := configEnv{StateDir: pc.StateDir, StubURL: pc.StubURL, GateEnabled: pc.Gate != nil}
	if pc.Gate != nil {
		if pc.LLM == nil {
			return nil, errors.New("a process with the gate enabled needs a mock LLM")
		}
		env.LLMProvider, env.LLMBaseURL = pc.Gate.Provider, pc.LLM.BaseURL(pc.Gate.Provider)
		gate := map[string]any{
			"enabled":  true,
			"provider": pc.Gate.Provider,
			"baseUrl":  env.LLMBaseURL,
			"apiKey":   mockAPIKey,
			"model":    "mock-model",
			"timeout":  scanTimeout.String(),
			// One attempt: the error scenarios are about what the gate does with a
			// failed scan, not about how long the provider client keeps trying.
			"maxRetries": -1,
			"storeDir":   filepath.Join(pc.StateDir, "llm-verdicts"),
		}
		if pc.Gate.Action != "" {
			gate["action"] = pc.Gate.Action
		}
		if pc.Gate.FailMode != "" {
			gate["failMode"] = pc.Gate.FailMode
		}
		cfg["llmPackageScan"] = gate
	} else if pc.LLM != nil {
		env.LLMProvider, env.LLMBaseURL = "claude", pc.LLM.BaseURL("claude")
	}
	if e.Configure != nil {
		e.Configure(cfg, env)
	}

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("rendering the %s/%s configuration: %w", e.ID, pc.Role, err)
	}
	header := fmt.Sprintf("# Generated by internal/e2e/pkgscan for the %q ecosystem (%s process). Do not edit.\n", e.ID, pc.Role)
	return append([]byte(header), out...), nil
}

// auditLogPath is where a process writes its audit log.
func auditLogPath(stateDir string) string { return filepath.Join(stateDir, "audit", "audit.log") }

// proxyProc is a running proxy process.
type proxyProc struct {
	pc      procConfig
	bin     string
	base    string // http://127.0.0.1:<port>
	logPath string
	cfgPath string
	cmd     *exec.Cmd
	exited  chan error
	client  *http.Client
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

// startProxy writes the configuration of a process into dir and starts it,
// returning once the proxy answers /readyz. The port is picked by asking the
// kernel for a free one and releasing it, so another process can take it in
// between; a start that fails on the listener is retried on a new port.
func startProxy(bin, dir string, pc procConfig) (*proxyProc, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(pc.StateDir, 0o755); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		p, err := startProxyOnce(bin, dir, pc)
		if err == nil {
			return p, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "address already in use") {
			break
		}
	}
	return nil, lastErr
}

func startProxyOnce(bin, dir string, pc procConfig) (*proxyProc, error) {
	listen, err := freeAddr()
	if err != nil {
		return nil, err
	}
	cfg, err := renderConfig(pc, listen)
	if err != nil {
		return nil, err
	}
	p := &proxyProc{
		pc:      pc,
		bin:     bin,
		base:    "http://" + listen,
		logPath: filepath.Join(dir, "proxy-"+pc.Role+".log"),
		cfgPath: filepath.Join(dir, "config-"+pc.Role+".yaml"),
		client: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				// The bytes on the wire are the bytes asserted on.
				DisableCompression: true,
				MaxIdleConns:       4,
				IdleConnTimeout:    10 * time.Second,
			},
			// The proxy must answer itself. A redirect would send a package
			// manager somewhere the gate is not; the suite treats one as the
			// response it is instead of following it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if err := os.WriteFile(p.cfgPath, cfg, 0o600); err != nil {
		return nil, err
	}
	// Append: a restarted process continues the log of the one before it.
	logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-config", p.cfgPath)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Keep the developer's git configuration (signing, hooks, URL rewrites) out
	// of anything the proxy shells out to git for.
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
	setParentDeathSignal(cmd)
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("starting the proxy: %w", err)
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
			return nil, fmt.Errorf("the proxy exited during startup (%v):\n%s", err, tailFile(p.logPath, 15))
		default:
		}
		resp, err := p.client.Get(p.base + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return p, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.stop()
	return nil, fmt.Errorf("the proxy did not become ready within 60s:\n%s", tailFile(p.logPath, 15))
}

// stop shuts the process down: gracefully first — the proxy seals its audit
// log and flushes its stores on SIGTERM — then firmly.
func (p *proxyProc) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.exited:
	case <-time.After(20 * time.Second):
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
	p.cmd = nil
	p.client.CloseIdleConnections()
}

// mount is the URL of the upstream's mount on this proxy.
func (p *proxyProc) mount() string { return p.mountOf(p.pc.Eco.ID) }

// mountOf is the URL of a named upstream's mount on this proxy. A row whose
// configuration has more than one upstream (Git: the repository and the
// packages built from it) reaches the others through it.
func (p *proxyProc) mountOf(upstream string) string { return p.base + "/v1/" + upstream }

// response is a proxy response, read to its end.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// get performs one client request below the upstream's mount: a GET, unless
// the step names another method.
func (p *proxyProc) get(st step) (*response, error) { return p.getFrom(p.mount(), st) }

// getFrom performs one client request below the given mount.
func (p *proxyProc) getFrom(mount string, st step) (*response, error) {
	method := st.Method
	if method == "" {
		method = http.MethodGet
	}
	var reqBody io.Reader
	if st.Body != nil {
		reqBody = bytes.NewReader(st.Body)
	}
	req, err := http.NewRequest(method, mount+st.Path, reqBody)
	if err != nil {
		return nil, err
	}
	for k, vs := range st.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("reading the response of %s: %w", st.Path, err)
	}
	return &response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// adminJSON fetches a document of the admin API.
func (p *proxyProc) adminJSON(path string, v any) error {
	resp, err := p.client.Get(p.base + "/admin/api/" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /admin/api/%s: status %d: %s", path, resp.StatusCode, firstLine(body))
	}
	return json.Unmarshal(body, v)
}

// cacheEntry is one entry of the content cache, as the admin API lists it.
type cacheEntry struct {
	Key      string            `json:"key"`
	Size     int64             `json:"size"`
	Metadata map[string]string `json:"metadata"`
}

// cacheEntries lists the content cache.
func (p *proxyProc) cacheEntries() ([]cacheEntry, error) {
	var resp struct {
		Items []cacheEntry `json:"items"`
	}
	if err := p.adminJSON("cache?limit=100000", &resp); err != nil {
		return nil, fmt.Errorf("listing the cache: %w", err)
	}
	return resp.Items, nil
}

// cached reports whether the content cache holds bytes with the given digest.
func (p *proxyProc) cached(digest string) (bool, error) {
	entries, err := p.cacheEntries()
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Metadata["digest"] == digest {
			return true, nil
		}
	}
	return false, nil
}

// review is one request of the break-glass approval workflow.
type review struct {
	ID         string `json:"id"`
	Ecosystem  string `json:"ecosystem"`
	Coordinate string `json:"coordinate"`
	Gate       string `json:"gate"`
	Reason     string `json:"reason"`
	Status     string `json:"status"`
}

// reviews lists the approval workflow's requests.
func (p *proxyProc) reviews() ([]review, error) {
	var resp struct {
		Enabled bool     `json:"enabled"`
		Items   []review `json:"items"`
	}
	if err := p.adminJSON("approvals", &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, errors.New("the approval workflow is not enabled in the proxy")
	}
	return resp.Items, nil
}

// finding is one finding of an artifact's findings document.
type finding struct {
	RuleID   string `json:"ruleId"`
	Gate     string `json:"gate"`
	Severity string `json:"severity"`
	Location struct {
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"location"`
}

// findingsDoc is the findings recorded for one artifact.
type findingsDoc struct {
	Artifact struct {
		Ecosystem  string `json:"ecosystem"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		Coordinate string `json:"coordinate"`
	} `json:"artifact"`
	Findings []finding `json:"findings"`
}

// findings lists the findings documents the proxy holds.
func (p *proxyProc) findings() ([]findingsDoc, error) {
	var resp struct {
		Enabled bool          `json:"enabled"`
		Items   []findingsDoc `json:"items"`
	}
	if err := p.adminJSON("findings?limit=100000", &resp); err != nil {
		return nil, err
	}
	if !resp.Enabled {
		return nil, errors.New("the findings store is not enabled in the proxy")
	}
	return resp.Items, nil
}

// storedVerdict is a verdict of the LLM package scan, as the admin API lists it.
type storedVerdict struct {
	Digest     string  `json:"digest"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Provider   string  `json:"provider"`
	Model      string  `json:"model"`
	Mode       string  `json:"mode"`
	Format     string  `json:"format"`
	Kind       string  `json:"kind"`
	Files      int     `json:"files"`
	Truncated  bool    `json:"truncated"`
	Ecosystem  string  `json:"ecosystem"`
	Name       string  `json:"name"`
	Version    string  `json:"version"`
	Evidence   []struct {
		Path     string `json:"path"`
		Line     int    `json:"line"`
		Verified bool   `json:"verified"`
	} `json:"evidence"`
	Injection []struct {
		Rule   string `json:"rule"`
		Strong bool   `json:"strong"`
		Path   string `json:"path"`
	} `json:"injection"`
	Standing struct {
		Disposition string `json:"disposition"`
		Refused     bool   `json:"refused"`
	} `json:"standing"`
}

// verdictFor returns the stored verdict on the bytes with the given digest.
func (p *proxyProc) verdictFor(digest string) (*storedVerdict, error) {
	var resp struct {
		Verdicts []storedVerdict `json:"verdicts"`
	}
	if err := p.adminJSON("llmpkgscan/verdicts?limit=1000", &resp); err != nil {
		return nil, err
	}
	for i := range resp.Verdicts {
		if resp.Verdicts[i].Digest == digest {
			return &resp.Verdicts[i], nil
		}
	}
	return nil, fmt.Errorf("the proxy holds no LLM package-scan verdict for %s (%d verdicts on record)", digest, len(resp.Verdicts))
}

// gateStatus is the gate's own account of its configuration and tallies.
type gateStatus struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Action   string `json:"action"`
	FailMode string `json:"failMode"`
	Scans    int    `json:"scans"`
}

// status returns the LLM package-scan gate's status.
func (p *proxyProc) status() (*gateStatus, error) {
	var st gateStatus
	if err := p.adminJSON("llmpkgscan", &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// auditEvent is one record of the tamper-evident audit log.
type auditEvent struct {
	Type     string         `json:"type"`
	Resource string         `json:"resource"`
	Decision string         `json:"decision"`
	Reason   string         `json:"reason"`
	Status   int            `json:"status"`
	Detail   map[string]any `json:"detail"`
}

// auditEvents reads the audit log of a state directory.
func auditEvents(stateDir string) ([]auditEvent, error) {
	f, err := os.Open(auditLogPath(stateDir))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []auditEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		var rec struct {
			Event auditEvent `json:"event"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || rec.Event.Type == "" {
			continue
		}
		out = append(out, rec.Event)
	}
	return out, sc.Err()
}

// verifyAudit runs the proxy's own verifier over an audit log: the hash chain
// and its keyed MACs must be intact from the first record to the last.
func verifyAudit(bin, stateDir string) error {
	cmd := exec.Command(bin, "-verify-audit", auditLogPath(stateDir), "-audit-key", auditKey)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("the audit log does not verify: %v: %s", err, firstLine(out))
	}
	return nil
}

// tailFile returns the last n lines of a file, for diagnosis.
func tailFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for i, l := range lines {
		if len(l) > 600 {
			lines[i] = l[:600] + "…"
		}
	}
	return strings.Join(lines, "\n")
}

// firstLine returns the first line of b, bounded.
func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
