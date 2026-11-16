//go:build integration
// +build integration

package fullmirror

import (
	"bytes"
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

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	fm "github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
)

// Environment variables that tune a run. All are optional.
const (
	// envProxyBin points at a prebuilt `pullthrough` binary. Without it the
	// suite builds one from the source tree, once per run.
	envProxyBin = "PT_FULLMIRROR_PROXY_BIN"
	// envTypes restricts the run to a space- or comma-separated list of
	// upstream types. The coverage gate then checks only those, and the matrix
	// is written as a partial one.
	envTypes = "PT_FULLMIRROR_TYPES"
	// envWorkDir is where the per-type workspaces (proxy configuration, state,
	// log, the feeds' Git repositories) are created. Default: a temporary
	// directory, removed after a passing run.
	envWorkDir = "PT_FULLMIRROR_WORKDIR"
	// envKeep keeps the workspaces of passing rows too. A failing row's
	// workspace is always kept, and its path logged.
	envKeep = "PT_FULLMIRROR_KEEP"
	// envReportDir receives the matrix — the directory every integration suite
	// writes its report to, so that one CI step publishes them. Without it the
	// matrix is written to the work directory.
	envReportDir = "PT_TEST_REPORT_DIR"
)

// Timing of every proxy the suite starts.
const (
	// pollInterval is fullMirror.pollInterval: the shortest the configuration
	// accepts. A package published after the enumeration is found by the next
	// poll, so it is also how long a row waits for the follow-up poll.
	pollInterval = fm.MinPollInterval
	// requestsPerSecond is fullMirror.requestsPerSecond: the stub needs no
	// pacing.
	requestsPerSecond = 1000
	// byteBudget is fullMirror.byteBudget: far above what a row fetches.
	byteBudget = 1 << 30
)

// Waits. Each returns as soon as what it waits for holds; the bounds only
// keep a broken row from hanging the run. They leave room above the engines'
// own retry delays (the mirror retries a failed fetch after 2 s, doubling; a
// failed poll backs the upstream off for a minute) so that one transient
// failure on a loaded runner costs time, not the row.
const (
	waitBootstrap = 3 * time.Minute
	waitFollow    = 3 * time.Minute
	waitRestart   = 3 * time.Minute
)

// auditKey is the audit log's HMAC key in every proxy the suite starts.
const auditKey = "fullmirror-e2e-audit-key"

var (
	proxyBinOnce sync.Once
	proxyBinPath string
	proxyBinErr  error
	// proxyBinDir is the directory the suite built the binary into, removed
	// when the test binary exits (TestMain); empty for a prebuilt binary.
	proxyBinDir string
)

// proxyBinary returns the `pullthrough` binary under test, building it on
// first use unless envProxyBin names one.
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
		dir, err := os.MkdirTemp("", "fullmirror-proxy-bin-")
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

// upstreamName is the name of the one upstream every row configures, and so
// its mount: /v1/mirrored/.
const upstreamName = "mirrored"

// procConfig describes one proxy process.
type procConfig struct {
	// Type is the upstream's type; URL its `url:`.
	Type string
	URL  string
	// Settings is the upstream's `settings:` block; Generic its `generic:`.
	Settings map[string]string
	Generic  map[string]any
	// Feed is fullMirror.feed: the adapter's options. Mirror false leaves the
	// upstream's fullMirror block out.
	Feed   map[string]string
	Mirror bool
	// StateDir holds everything the process persists. Two processes given the
	// same directory are one deployment restarted.
	StateDir string
	// LLMBaseURL and LLMAPIKey are the mock LLM the gate talks to.
	LLMBaseURL string
	LLMAPIKey  string
}

// renderConfig renders the proxy configuration of a process: what an operator
// would write to mirror one upstream in full with every file judged by the LLM
// package scan — the upstream with its fullMirror block (fullScan on), the
// engine's state directory, the full scan's cost budget and the llmPackageScan
// block — plus what the suite observes the proxy through (the admin API, the
// audit log). Everything else is the shipped default: the download log, the
// default-on admission gates and the gate's default action (block) all run as
// in production.
func renderConfig(pc procConfig, listen string) ([]byte, error) {
	up := map[string]any{"type": pc.Type, "url": pc.URL}
	if len(pc.Settings) > 0 {
		settings := map[string]any{}
		for k, v := range pc.Settings {
			settings[k] = v
		}
		up["settings"] = settings
	}
	if pc.Generic != nil {
		up["generic"] = pc.Generic
	}
	if pc.Mirror {
		mirror := map[string]any{
			"enabled":           true,
			"fullScan":          true,
			"byteBudget":        byteBudget,
			"requestsPerSecond": requestsPerSecond,
			"pollInterval":      pollInterval.String(),
		}
		if len(pc.Feed) > 0 {
			feed := map[string]any{}
			for k, v := range pc.Feed {
				feed[k] = v
			}
			mirror["feed"] = feed
		}
		up["fullMirror"] = mirror
	}

	cfg := map[string]any{
		"server":        map[string]any{"httpAddr": listen, "publicUrl": "http://" + listen},
		"logging":       map[string]any{"level": "debug", "format": "json"},
		"cache":         map[string]any{"backend": "filesystem", "dir": filepath.Join(pc.StateDir, "cache")},
		"observability": map[string]any{"metrics": true, "admin": true},
		"audit": map[string]any{
			"enabled": true,
			"file":    auditLogPath(pc.StateDir),
			"hmacKey": auditKey,
		},
		// Loopback, and nothing else: the stub registry is reachable, and a
		// request to anywhere else is refused by the proxy itself.
		"egress": map[string]any{
			"enabled":                 true,
			"allowedSchemes":          []any{"http"},
			"allowlist":               []any{"127.0.0.1"},
			"allowedDestinationCidrs": []any{"127.0.0.1/32"},
		},
		"upstreams":  map[string]any{upstreamName: up},
		"fullMirror": map[string]any{"stateDir": filepath.Join(pc.StateDir, "fullmirror")},
	}
	if pc.Mirror {
		cfg["fullScan"] = map[string]any{"budget": map[string]any{"dailyUsd": 100}}
		cfg["llmPackageScan"] = map[string]any{
			"enabled":  true,
			"provider": "claude",
			"baseUrl":  pc.LLMBaseURL,
			"apiKey":   pc.LLMAPIKey,
			"model":    "mock-model",
			"storeDir": filepath.Join(pc.StateDir, "llm-verdicts"),
		}
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("rendering the %s configuration: %w", pc.Type, err)
	}
	header := fmt.Sprintf("# Generated by internal/e2e/fullmirror for upstream type %q. Do not edit.\n", pc.Type)
	return append([]byte(header), out...), nil
}

// auditLogPath is where a process writes its audit log.
func auditLogPath(stateDir string) string { return filepath.Join(stateDir, "audit", "audit.log") }

// proxyProc is a running proxy process.
type proxyProc struct {
	pc      procConfig
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

// startProxy writes the configuration into dir and starts the proxy,
// returning once it answers /readyz. A start that fails on the listener (the
// port picked was taken in between) is retried on another port.
func startProxy(bin, dir, role string, pc procConfig) (*proxyProc, error) {
	if err := os.MkdirAll(pc.StateDir, 0o755); err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		p, err := startProxyOnce(bin, dir, role, pc)
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

func startProxyOnce(bin, dir, role string, pc procConfig) (*proxyProc, error) {
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
		base:    "http://" + listen,
		logPath: filepath.Join(dir, "proxy-"+role+".log"),
		cfgPath: filepath.Join(dir, "config-"+role+".yaml"),
		client: &http.Client{
			Timeout: 2 * time.Minute,
			Transport: &http.Transport{
				DisableCompression: true,
				MaxIdleConns:       4,
				IdleConnTimeout:    10 * time.Second,
			},
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
	fmt.Fprintf(logFile, "\n===== %s: starting the proxy (%s) =====\n", time.Now().UTC().Format(time.RFC3339Nano), role)
	cmd := exec.Command(bin, "-config", p.cfgPath)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_TERMINAL_PROMPT=0")
	setParentDeathSignal(cmd)
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("starting the proxy: %w", err)
	}
	_ = logFile.Close()
	p.cmd = cmd
	p.exited = make(chan error, 1)
	go func() { p.exited <- cmd.Wait() }()

	deadline := time.Now().Add(90 * time.Second)
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
				// The port was free when it was picked, not necessarily when
				// the proxy bound it: another row's proxy may have taken it
				// and answered. A mirroring proxy names its state directory.
				if err := p.isOurs(); err != nil {
					p.stop()
					return nil, fmt.Errorf("address already in use: %v", err)
				}
				return p, nil
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.stop()
	return nil, fmt.Errorf("the proxy did not become ready within 90s:\n%s", tailFile(p.logPath, 15))
}

// isOurs checks that the proxy answering on the address is this process: it
// has not exited, and — when it mirrors — its full mirror keeps its state in
// this process's state directory.
func (p *proxyProc) isOurs() error {
	select {
	case err := <-p.exited:
		p.exited <- err
		return fmt.Errorf("the proxy exited (%v), and another process answers on %s", err, p.base)
	default:
	}
	if !p.pc.Mirror {
		return nil
	}
	var st fm.Status
	if err := p.adminJSON("fullmirror/status", &st); err != nil {
		return err
	}
	if want := filepath.Join(p.pc.StateDir, "fullmirror"); st.StateDir != want {
		return fmt.Errorf("the proxy on %s keeps its state in %q, not %q: another row's", p.base, st.StateDir, want)
	}
	return nil
}

// stop shuts the process down: gracefully first (the proxy writes its state
// and seals its audit log on SIGTERM), then firmly.
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

// mount is the URL of the upstream's mount on this proxy.
func (p *proxyProc) mount() string { return p.base + "/v1/" + upstreamName }

// response is a proxy response, read to its end.
type response struct {
	Status int
	Header http.Header
	Body   []byte
}

// get performs a client request below the upstream's mount.
func (p *proxyProc) get(path string, header http.Header) (*response, error) {
	req, err := http.NewRequest(http.MethodGet, p.mount()+path, nil)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
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
		return nil, fmt.Errorf("reading the response of %s: %w", path, err)
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

// mirrorStatus returns the full mirror's state of the row's upstream.
func (p *proxyProc) mirrorStatus() (fm.UpstreamStatus, error) {
	var st fm.Status
	if err := p.adminJSON("fullmirror/status", &st); err != nil {
		return fm.UpstreamStatus{}, err
	}
	for _, u := range st.Upstreams {
		if u.Upstream == upstreamName {
			return u, nil
		}
	}
	return fm.UpstreamStatus{}, fmt.Errorf("the full mirror's status lists no upstream %q (enabled %v, %d upstreams)", upstreamName, st.Enabled, len(st.Upstreams))
}

// scanStatus returns the full scan's state of the row's upstream.
func (p *proxyProc) scanStatus() (fullscan.UpstreamStatus, error) {
	var st fullscan.Status
	if err := p.adminJSON("fullscan/status", &st); err != nil {
		return fullscan.UpstreamStatus{}, err
	}
	for _, u := range st.Upstreams {
		if u.Upstream == upstreamName {
			return u, nil
		}
	}
	return fullscan.UpstreamStatus{}, fmt.Errorf("the full scan's status lists no upstream %q (enabled %v, state %s)", upstreamName, st.Enabled, st.State)
}

// downloads returns the download log, oldest first.
func (p *proxyProc) downloads() ([]downloadlog.Entry, error) {
	var out []downloadlog.Entry
	before := uint64(0)
	for page := 0; page < 100; page++ {
		q := url.Values{"limit": {"1000"}}
		if before > 0 {
			q.Set("before", fmt.Sprint(before))
		}
		var res downloadlog.Result
		if err := p.adminJSON("downloads?"+q.Encode(), &res); err != nil {
			return nil, err
		}
		out = append(out, res.Entries...)
		if res.NextBefore == 0 || len(res.Entries) == 0 {
			break
		}
		before = res.NextBefore
	}
	// The log lists newest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// storedVerdict is a verdict of the LLM package scan, as the admin API lists
// it.
type storedVerdict struct {
	Digest   string `json:"digest"`
	Verdict  string `json:"verdict"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Standing struct {
		Disposition string `json:"disposition"`
		Refused     bool   `json:"refused"`
	} `json:"standing"`
}

// verdicts returns the stored verdicts by digest.
func (p *proxyProc) verdicts() (map[string]storedVerdict, error) {
	var resp struct {
		Verdicts []storedVerdict `json:"verdicts"`
	}
	if err := p.adminJSON("llmpkgscan/verdicts?limit=1000", &resp); err != nil {
		return nil, err
	}
	out := map[string]storedVerdict{}
	for _, v := range resp.Verdicts {
		out[v.Digest] = v
	}
	return out, nil
}

// cacheEntry is one entry of the content cache, as the admin API lists it.
type cacheEntry struct {
	Key      string            `json:"key"`
	Metadata map[string]string `json:"metadata"`
}

// The cache metadata of a fill's provenance (cache.MetaFillUpstream and
// cache.MetaFillPath): the upstream and the escaped request path below its
// mount that filled the entry.
const (
	cacheFillUpstream = "fill-upstream"
	cacheFillPath     = "fill-path"
)

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

// cachedDigests returns the digests of the content cache's entries.
func (p *proxyProc) cachedDigests() (map[string]bool, error) {
	entries, err := p.cacheEntries()
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range entries {
		if d := e.Metadata["digest"]; d != "" {
			out[d] = true
		}
	}
	return out, nil
}

// auditEvent is one record of the audit log.
type auditEvent struct {
	Type     string         `json:"type"`
	Backend  string         `json:"backend"`
	Resource string         `json:"resource"`
	Decision string         `json:"decision"`
	Reason   string         `json:"reason"`
	Detail   map[string]any `json:"detail"`
}

// auditEvents reads the audit log of a state directory.
func auditEvents(stateDir string) ([]auditEvent, error) {
	data, err := os.ReadFile(auditLogPath(stateDir))
	if err != nil {
		return nil, err
	}
	var out []auditEvent
	for _, line := range bytes.Split(data, []byte("\n")) {
		var rec struct {
			Event auditEvent `json:"event"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.Event.Type == "" {
			continue
		}
		out = append(out, rec.Event)
	}
	return out, nil
}

// verifyAudit runs the proxy's own verifier over an audit log.
func verifyAudit(bin, stateDir string) error {
	out, err := exec.Command(bin, "-verify-audit", auditLogPath(stateDir), "-audit-key", auditKey).CombinedOutput()
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

// errTimeout is what waitFor returns when the condition never held.
var errTimeout = errors.New("timed out")

// waitFor polls cond until it holds or the bound passes. cond returns why it
// does not hold yet, which the error carries.
func waitFor(bound time.Duration, cond func() (bool, string)) error {
	deadline := time.Now().Add(bound)
	why := ""
	for {
		ok, w := cond()
		if ok {
			return nil
		}
		why = w
		if time.Now().After(deadline) {
			return fmt.Errorf("%w after %s: %s", errTimeout, bound, why)
		}
		time.Sleep(150 * time.Millisecond)
	}
}
