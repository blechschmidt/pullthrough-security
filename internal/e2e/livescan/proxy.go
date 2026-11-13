//go:build integration || livellm

package livescan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// Environment variables that tune a run. All are optional.
const (
	// envProxyBin points at a prebuilt `pullthrough` binary; without it the
	// suite builds one from the source tree.
	envProxyBin = "PT_LIVESCAN_PROXY_BIN"
	// envSamples restricts a run to a space- or comma-separated list of sample
	// IDs (the file names under testdata/corpus, without ".txtar").
	envSamples = "PT_LIVESCAN_SAMPLES"
	// envWorkDir is where the run's proxy state, logs and fixtures go
	// (default: a temporary directory, removed after a passing run).
	envWorkDir = "PT_LIVESCAN_WORKDIR"
	// envParallel is how many pulls run at once (default 3).
	envParallel = "PT_LIVESCAN_PARALLEL"
	// envReportDir receives the report (shared with the other suites).
	envReportDir = "PT_TEST_REPORT_DIR"
)

// Model is how a run reaches a model.
type Model struct {
	// Label names the model and the route to it in reports.
	Label string
	// BaseURL and APIKey configure the gates' provider ("claude"). An empty
	// BaseURL is the Anthropic API itself; APIKey may be a secret reference
	// (env://NAME).
	BaseURL, APIKey string
	// Mode is the package scan's llmPackageScan.mode ("bundle" through the
	// Claude Code bridge, "auto" against the API).
	Mode string
	// PackageModel is the package scan's model; TriageModel and DeepModel the
	// commit scan's. Empty means the proxy's defaults.
	PackageModel, TriageModel, DeepModel string
	// Timeout is llmPackageScan.timeout and the commit scan's timeout.
	Timeout time.Duration
	// ProxyEnv is added to the proxy's environment (the API key in API mode).
	ProxyEnv []string
	// Bridge is the Claude Code bridge the gates talk to, when they do.
	Bridge *Bridge
}

// proxyProc is a running proxy.
type proxyProc struct {
	base    string
	logPath string
	cfgPath string
	cmd     *exec.Cmd
	exited  chan error
	client  *http.Client
}

// runConfig is what one proxy process is configured with.
type runConfig struct {
	StateDir string
	Model    Model
	// Upstreams maps upstream name to the stub's base URL.
	Upstreams map[string]string
	// Repos are the repositories the commit scanner watches.
	Repos []*commitRepo
}

// renderConfig writes the proxy configuration of a run. The package scan is
// the only content gate: every deterministic gate in front of it is switched
// off, so each artifact reaches the model and a refusal can only be the
// model's verdict. (What those gates would have done is a different question,
// which this suite does not ask.)
func renderConfig(rc runConfig, listen string) ([]byte, error) {
	upstreams := map[string]any{}
	for name, url := range rc.Upstreams {
		up := map[string]any{"type": upstreamType(name), "url": url}
		switch name {
		case "pypi":
			// The stub plays the file host too.
			up["settings"] = map[string]any{"filesUrl": url}
		case "generic":
			up["generic"] = genericRoutes()
		}
		upstreams[name] = up
	}
	off := map[string]any{"enabled": false}
	timeout := rc.Model.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	gate := map[string]any{
		"enabled":  true,
		"provider": "claude",
		"apiKey":   rc.Model.APIKey,
		"action":   "block",
		"failMode": "closed",
		"timeout":  timeout.String(),
		"storeDir": filepath.Join(rc.StateDir, "llm-verdicts"),
		// Scans run one after another per pull worker; two at a time per
		// proxy keeps a subscription's rate limit comfortable.
		"maxConcurrent": 2,
	}
	if rc.Model.BaseURL != "" {
		gate["baseUrl"] = rc.Model.BaseURL
	}
	if rc.Model.Mode != "" {
		gate["mode"] = rc.Model.Mode
	}
	if rc.Model.PackageModel != "" {
		gate["model"] = rc.Model.PackageModel
	}
	cfg := map[string]any{
		"server": map[string]any{
			"httpAddr": listen, "publicUrl": "http://" + listen,
			// A scan holds the response until the verdict exists.
			"writeTimeout": (timeout + 2*time.Minute).String(),
		},
		"logging":       map[string]any{"level": "info", "format": "json"},
		"cache":         map[string]any{"backend": "filesystem", "dir": filepath.Join(rc.StateDir, "cache")},
		"observability": map[string]any{"metrics": true, "admin": true},
		// Loopback and nothing else for upstream fetches: the stubs are
		// reachable, no registry on the network is. (The LLM provider's own
		// client is not an upstream fetch.)
		"egress": map[string]any{
			"enabled":                 true,
			"allowedSchemes":          []any{"http"},
			"allowlist":               []any{"127.0.0.1"},
			"allowedDestinationCidrs": []any{"127.0.0.1/32"},
		},
		"upstreams":       upstreams,
		"llmPackageScan":  gate,
		"installHooks":    off,
		"contentScan":     off,
		"mlGuard":         off,
		"maturity":        off,
		"malfeed":         off,
		"continuity":      off,
		"sbomDiff":        off,
		"rebuildVerify":   off,
		"buildProv":       off,
		"pypiAttestation": off,
	}
	if len(rc.Repos) > 0 {
		var repos []any
		for _, r := range rc.Repos {
			repos = append(repos, map[string]any{"name": r.Sample.ID, "url": r.Bare, "branches": []any{"main"}})
		}
		commitCfg := map[string]any{"storeDir": filepath.Join(rc.StateDir, "commit-verdicts")}
		if rc.Model.TriageModel != "" {
			commitCfg["triageModel"] = rc.Model.TriageModel
		}
		if rc.Model.DeepModel != "" {
			commitCfg["deepModel"] = rc.Model.DeepModel
		}
		scanning := map[string]any{
			"enabled":  true,
			"provider": "claude",
			"apiKey":   rc.Model.APIKey,
			"failOn":   "high",
			"timeout":  timeout.String(),
			"commit":   commitCfg,
			"watch": map[string]any{
				"enabled":   true,
				"mirrorDir": filepath.Join(rc.StateDir, "commit-mirrors"),
				"stateDir":  filepath.Join(rc.StateDir, "commit-cursors"),
				// Scan the existing history on first sight.
				"backfill":     true,
				"pollInterval": "5s",
				"repos":        repos,
			},
		}
		if rc.Model.BaseURL != "" {
			scanning["baseUrl"] = rc.Model.BaseURL
		}
		cfg["scanning"] = scanning
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by internal/e2e/livescan. Do not edit.\n"), out...), nil
}

// upstreamType is the upstream type of each stub the suite starts.
func upstreamType(name string) string {
	if name == "pypi" {
		return "pip"
	}
	return name
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

// startProxy starts a proxy for rc and waits until it answers /readyz.
func startProxy(bin, dir string, rc runConfig) (*proxyProc, error) {
	if err := os.MkdirAll(rc.StateDir, 0o700); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		p, err := startProxyOnce(bin, dir, rc)
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

func startProxyOnce(bin, dir string, rc runConfig) (*proxyProc, error) {
	listen, err := freeAddr()
	if err != nil {
		return nil, err
	}
	cfg, err := renderConfig(rc, listen)
	if err != nil {
		return nil, err
	}
	p := &proxyProc{
		base:    "http://" + listen,
		logPath: filepath.Join(dir, "proxy.log"),
		cfgPath: filepath.Join(dir, "config.yaml"),
		client: &http.Client{
			// A pull of an unscanned artifact waits for the verdict.
			Timeout:       rc.Model.Timeout + 5*time.Minute,
			Transport:     &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	if err := os.WriteFile(p.cfgPath, cfg, 0o600); err != nil {
		return nil, err
	}
	logFile, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-config", p.cfgPath)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = logFile, logFile
	// The proxy gets the environment it needs and no credential it does not:
	// in particular never a Claude Code token, which only the bridge's CLI uses.
	cmd.Env = append(proxyEnv(), rc.Model.ProxyEnv...)
	setParentDeathSignal(cmd)
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("starting the proxy: %w", err)
	}
	_ = logFile.Close()
	p.cmd = cmd
	p.exited = make(chan error, 1)
	go func() { p.exited <- cmd.Wait() }()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.exited:
			p.cmd = nil
			return nil, fmt.Errorf("the proxy exited during start-up (%v); log %s:\n%s", err, p.logPath, tail(p.logPath, 4000))
		default:
		}
		res, err := p.client.Get(p.base + "/readyz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return p, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.stop()
	return nil, fmt.Errorf("the proxy did not become ready; log %s:\n%s", p.logPath, tail(p.logPath, 4000))
}

// envAllow are the variables a child process of the suite inherits from the
// test process: what it needs to run and reach a network, nothing that carries
// a credential and nothing that redirects a client (ANTHROPIC_BASE_URL would
// send the API key to whatever gateway a developer's shell names).
var envAllow = map[string]bool{
	"PATH": true, "HOME": true, "TMPDIR": true, "TEMP": true, "TMP": true, "USER": true, "LOGNAME": true,
	"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true, "SYSTEMROOT": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true, "https_proxy": true, "http_proxy": true, "no_proxy": true,
}

// minimalEnv is the test process's environment reduced to envAllow.
func minimalEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); envAllow[k] {
			env = append(env, kv)
		}
	}
	return env
}

// withoutCredentials is env minus anything that looks like a credential or
// belongs to a CI or model client: for a tool that needs the toolchain's own
// variables (go build) but no secret.
func withoutCredentials(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(k)
		drop := strings.HasPrefix(up, "ANTHROPIC_") || strings.HasPrefix(up, "CLAUDE") || strings.HasPrefix(up, "OPENAI_") ||
			strings.HasPrefix(up, "ACTIONS_") || strings.HasPrefix(up, "GITHUB_")
		for _, word := range []string{"TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "API_KEY", "APIKEY", "PRIVATE_KEY"} {
			drop = drop || strings.Contains(up, word)
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

// proxyEnv is the proxy's environment: the allow-listed variables of the test
// process, git kept away from the machine's configuration. A credential the
// proxy needs (the API key of the direct route) is added by the caller, and
// only that one.
func proxyEnv() []string {
	return append(minimalEnv(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
}

// tail returns the last n bytes of a file.
func tail(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(" + err.Error() + ")"
	}
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

func (p *proxyProc) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
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
	p.client.CloseIdleConnections()
}

// response is a proxy response, read to its end.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// get performs one client request below an upstream's mount.
func (p *proxyProc) get(upstream string, st step) (*response, error) {
	req, err := http.NewRequest(http.MethodGet, p.base+"/v1/"+upstream+st.Path, nil)
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

// adminJSON reads an admin API document.
func (p *proxyProc) adminJSON(path string, v any) (int, error) {
	resp, err := p.client.Get(p.base + "/admin/api/" + path)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("GET /admin/api/%s: status %d: %s", path, resp.StatusCode, firstLine(body))
	}
	return resp.StatusCode, json.Unmarshal(body, v)
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
