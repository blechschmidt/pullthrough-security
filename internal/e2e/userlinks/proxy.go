//go:build integration
// +build integration

package userlinks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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
	"github.com/blechschmidt/pullthrough-security/internal/userlinks/oidctest"
)

// Environment variables that tune a run. All are optional.
const (
	// envProxyBin points at a prebuilt `pullthrough` binary. Without it the suite
	// builds one from the source tree, once per run.
	envProxyBin = "PT_USERLINKS_PROXY_BIN"
	// envClients selects how a missing package manager is treated: "auto" (the
	// default) skips its ecosystem; "real" makes it a failure (CI sets this, so
	// the suite cannot quietly shrink).
	envClients = "PT_USERLINKS_CLIENTS"
	// envWorkDir is where the proxies' state, their logs and the clients'
	// scratch directories are created. Default: a temporary directory.
	envWorkDir = "PT_USERLINKS_WORKDIR"
	// envKeep keeps the work directory of a passing run too (a failing run's is
	// always kept, and its path logged).
	envKeep = "PT_USERLINKS_KEEP"
	// envReportDir receives the matrix. It is shared with the other integration
	// suites so one CI step publishes them all.
	envReportDir = "PT_TEST_REPORT_DIR"
	// envAttachments is the task runner's attachment directory, used when
	// envReportDir is unset.
	envAttachments = "CLOOP_TASK_ATTACHMENTS"
)

const (
	adminToken   = "userlinks-e2e-admin-token"
	sessionKey   = "userlinks-e2e-session-key-0123456789abcdef"
	auditKey     = "userlinks-e2e-audit-key-0123456789abcdef"
	oidcClientID = "pullthrough-cache"
	oidcSecret   = "userlinks-e2e-client-secret"
)

var (
	proxyBinOnce sync.Once
	proxyBinPath string
	proxyBinErr  error
	// proxyBinTemp is the directory of a binary the suite built itself, removed
	// when the run ends (see TestMain).
	proxyBinTemp string
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
		dir, err := os.MkdirTemp("", "userlinks-proxy-bin-")
		if err != nil {
			proxyBinErr = err
			return
		}
		proxyBinTemp = dir
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

// proxyOptions is what differs between the proxies the suite starts.
type proxyOptions struct {
	// name labels the proxy in messages and names its state directory.
	name string
	// registryDir is the directory of the link registry. Two proxies given the
	// same one are two replicas of one deployment.
	registryDir string
	// auth switches client authentication on: nobody pulls without a credential,
	// and a personal link is one.
	auth bool
}

// proxyProc is a running proxy process.
type proxyProc struct {
	opts     proxyOptions
	bin      string
	stateDir string
	cfgPath  string
	logPath  string
	// listen is the loopback address the process listens on, and — as a URL —
	// what clients and browsers know it by.
	listen string
	url    string

	cmd    *exec.Cmd
	exited chan error
	client *http.Client
}

// renderConfig renders the configuration of a proxy under test. It is what an
// operator would write: six upstreams, a cache directory, the admin API behind
// a token, an audit log, a file for the download log — and personal links, with
// the identity provider users sign in at.
func renderConfig(s *stub, idp *oidctest.Provider, o proxyOptions, stateDir, listen, publicURL string) ([]byte, error) {
	links := map[string]any{
		"enabled":    true,
		"sessionKey": sessionKey,
		// The suite speaks plain HTTP on loopback; a browser would not send a
		// Secure cookie over it.
		"insecureCookies": true,
		// How long a revocation performed on one replica takes to reach another.
		"syncInterval": "1s",
		"store":        map[string]any{"backend": "filesystem", "dir": o.registryDir},
		"oidc": map[string]any{
			"enabled":      true,
			"issuer":       idp.Issuer(),
			"clientId":     oidcClientID,
			"clientSecret": oidcSecret,
		},
	}
	cfg := map[string]any{
		"server": map[string]any{"httpAddr": listen, "publicUrl": publicURL},
		// Debug logging: the request log is on, so that if a link's token could
		// reach the log, it would.
		"logging": map[string]any{"level": "debug", "format": "json"},
		"cache":   map[string]any{"backend": "filesystem", "dir": filepath.Join(stateDir, "cache")},
		// Loopback, and nothing else: the stub registries are reachable, and a
		// request to anywhere on the network is refused by the proxy itself.
		"egress": map[string]any{
			"enabled":                 true,
			"allowedSchemes":          []any{"http"},
			"allowlist":               []any{"127.0.0.1"},
			"allowedDestinationCidrs": []any{"127.0.0.1/32"},
		},
		"upstreams": map[string]any{
			"npm": map[string]any{"type": "npm", "url": s.url(npmPrefix)},
			"pypi": map[string]any{
				"type": "pip", "url": s.url(pypiPrefix),
				// The stub plays the index's file host as well.
				"settings": map[string]any{"filesUrl": s.url(pypiPrefix), "fileHosts": s.host()},
			},
			"cargo": map[string]any{
				"type": "cargo", "url": s.url(cratesPrefix),
				"settings": map[string]any{"downloadUrl": s.url(cratesPrefix)},
			},
			"go": map[string]any{
				"type": "go", "url": s.url(goproxyPrefix),
				// The fixture module is in no checksum database.
				"settings": map[string]any{"sumdb": "off"},
			},
			"dockerhub": map[string]any{"type": "docker", "url": s.registry.URL},
		},
		"observability": map[string]any{"metrics": true, "admin": true, "adminToken": adminToken},
		"audit":         map[string]any{"enabled": true, "file": filepath.Join(stateDir, "audit.log"), "hmacKey": auditKey},
		"downloadLog":   map[string]any{"path": filepath.Join(stateDir, "downloads.jsonl")},
		"userLinks":     links,
	}
	if s.gitSrv != nil {
		cfg["upstreams"].(map[string]any)["git"] = map[string]any{"type": "git", "url": s.gitSrv.URL}
	}
	if o.auth {
		// Access control on, nothing anonymous: a personal link is the only way
		// in, and what its user may pull follows from their groups at the
		// identity provider.
		cfg["auth"] = map[string]any{
			"enabled": true,
			"roles": []any{
				map[string]any{"name": "reader", "ecosystems": []any{"*"}, "upstreams": []any{"*"}},
				map[string]any{"name": "npm-only", "ecosystems": []any{"npm"}, "upstreams": []any{"*"}},
			},
		}
		links["roleMap"] = map[string]any{"cache-readers": "reader", "npm-team": "npm-only"}
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Generated by internal/e2e/userlinks. Do not edit.\n"), out...), nil
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

// startProxy writes a proxy's configuration into its state directory and starts
// it, returning once it answers /readyz. With listen empty a free port is
// chosen — and, because another process can take a port between choosing and
// binding it, a start that fails is retried on a new one. A restart passes the
// address the first start settled on, so that the links users hold stay valid.
func startProxy(bin, work string, s *stub, idp *oidctest.Provider, o proxyOptions, listen string) (*proxyProc, error) {
	stateDir := filepath.Join(work, o.name)
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
		p := &proxyProc{
			opts:     o,
			bin:      bin,
			stateDir: stateDir,
			cfgPath:  filepath.Join(stateDir, "config.yaml"),
			logPath:  filepath.Join(work, o.name+".log"),
			listen:   addr,
			url:      "http://" + addr,
			client:   &http.Client{Timeout: 30 * time.Second},
		}
		cfg, err := renderConfig(s, idp, o, stateDir, p.listen, p.url)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(p.cfgPath, cfg, 0o644); err != nil {
			return nil, err
		}
		if lastErr = p.start(); lastErr == nil {
			// The identity provider only sends browsers back to a callback that
			// was registered with it.
			idp.AllowRedirect(p.url + "/links/callback")
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
		resp, err := p.client.Get(p.url + "/readyz")
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
// it writes what it still holds only in memory, and waits for it.
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

// --- the operator: the admin API ------------------------------------------------

// admin performs an admin API request with the admin token and decodes the JSON
// answer into out (when non-nil). It returns the status.
func (p *proxyProc) admin(method, pathAndQuery string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, p.url+"/admin/api/"+pathAndQuery, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding the answer of %s %s: %w: %s", method, pathAndQuery, err, firstLine(data))
		}
	}
	return resp.StatusCode, nil
}

// logPage is the admin API's download-log response.
type logPage struct {
	Enabled bool       `json:"enabled"`
	Total   int        `json:"total"`
	Entries []dl.Entry `json:"entries"`
}

// logSummary is the admin API's download-log summary response.
type logSummary struct {
	Enabled bool `json:"enabled"`
	dl.Summary
}

// downloads queries the download log through the admin API — the endpoint the
// console's Downloads tab reads.
func (p *proxyProc) downloads(query url.Values) ([]dl.Entry, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("limit", "1000")
	var page logPage
	status, err := p.admin(http.MethodGet, "downloads?"+query.Encode(), nil, &page)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("GET downloads?%s: status %d", query.Encode(), status)
	}
	return page.Entries, nil
}

// awaitDownloads polls the download log until the query returns at least want
// entries. An entry is recorded when the proxy's handler returns, a moment
// after the client has received the last byte.
func (p *proxyProc) awaitDownloads(query url.Values, want int) ([]dl.Entry, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, err := p.downloads(cloneValues(query))
		if err != nil {
			return nil, err
		}
		if len(entries) >= want || time.Now().After(deadline) {
			return entries, nil
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

// --- the user: the links page ---------------------------------------------------

// user is a person at a browser: an identity at the identity provider, and the
// cookies their browser holds for one proxy.
type user struct {
	t       *testing.T
	proxy   *proxyProc
	idp     *oidctest.Provider
	who     oidctest.User
	browser *http.Client
}

// newUser gives a person a browser for one proxy. It does not sign them in.
func newUser(t *testing.T, p *proxyProc, idp *oidctest.Provider, who oidctest.User) *user {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &user{t: t, proxy: p, idp: idp, who: who, browser: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
}

// signIn opens the links page's sign-in in the browser and follows it through
// the identity provider and back. It returns the final status and page.
func (u *user) signIn() (int, string) {
	u.t.Helper()
	u.idp.SignInAs(u.who)
	resp, err := u.browser.Get(u.proxy.url + "/links/login")
	if err != nil {
		u.t.Fatalf("signing in as %s: %v", u.who.Email, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(body)
}

// page calls the links page's API the way its script does.
func (u *user) page(method, path string, body any) (int, map[string]any) {
	u.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u.proxy.url+"/links/"+path, reader)
	if err != nil {
		u.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("X-Pullthrough-Links", "1")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", u.proxy.url)
	}
	resp, err := u.browser.Do(req)
	if err != nil {
		u.t.Fatalf("%s /links/%s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var out map[string]any
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			u.t.Fatalf("%s /links/%s answered %d with a body that is not JSON: %s", method, path, resp.StatusCode, firstLine(data))
		}
	}
	return resp.StatusCode, out
}

// link is a personal link as its user holds it: what the page showed, once.
type link struct {
	// Token is the secret; Base what stands before "/v1/<upstream>".
	Token string
	Base  string
	ID    string
	// snippets holds, per upstream, the client configuration the page handed
	// out: for the link as part of the address, and for the link as a credential.
	snippets      map[string]string
	tokenSnippets map[string]string
}

// mount returns the user's personal address of an upstream.
func (l link) mount(upstream string) string { return l.Base + "/v1/" + upstream }

// createLink has the signed-in user create a link on the page.
func (u *user) createLink(label string) link {
	u.t.Helper()
	status, resp := u.page(http.MethodPost, "api/links", map[string]any{"label": label})
	if status != http.StatusCreated {
		u.t.Fatalf("%s creating a link: status %d: %v", u.who.Email, status, resp)
	}
	l := link{snippets: map[string]string{}, tokenSnippets: map[string]string{}}
	l.Token, _ = resp["token"].(string)
	l.Base, _ = resp["baseUrl"].(string)
	if info, _ := resp["link"].(map[string]any); info != nil {
		l.ID, _ = info["id"].(string)
	}
	ups, _ := resp["upstreams"].([]any)
	for _, raw := range ups {
		up, _ := raw.(map[string]any)
		name, _ := up["name"].(string)
		for field, into := range map[string]map[string]string{"snippets": l.snippets, "tokenSnippets": l.tokenSnippets} {
			if list, _ := up[field].([]any); len(list) > 0 {
				if first, _ := list[0].(map[string]any); first != nil {
					into[name], _ = first["body"].(string)
				}
			}
		}
	}
	if l.Token == "" || l.Base == "" || l.ID == "" {
		u.t.Fatalf("the page's answer to a new link lacks the link: %v", resp)
	}
	return l
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
