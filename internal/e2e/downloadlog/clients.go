//go:build integration
// +build integration

package downloadlog

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// egress is the network path of one client machine: a small HTTP forwarding
// proxy that the package manager is pointed at, and that reaches the
// pull-through proxy from a source address of its own. It is what makes "which
// address did this download come from" a fact the proxy observes on the wire.
type egress struct {
	// name labels the machine in messages ("cargo-a").
	name string
	// addr is the source address the pull-through proxy sees for this machine.
	addr string
	// forwardFor, when set, is the X-Forwarded-For header the egress adds to
	// every request: the egress then plays a reverse proxy (or a client forging
	// its address) rather than a plain client machine.
	forwardFor string

	// url is what a package manager is given as its HTTP proxy.
	url string
	srv *http.Server
	ln  net.Listener

	mu       sync.Mutex
	requests int
	// strays are requests for anything but the pull-through proxy. There must
	// be none: the suite is hermetic, and a client that talks to anything else
	// would be reporting a download the proxy never saw.
	strays []string
}

// newEgress starts an egress whose connections to the proxy at target come from
// addr. public is the host:port clients know the proxy by.
func newEgress(name, addr, forwardFor, target, public string) (*egress, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("egress %s: %q is not an IP address", name, addr)
	}
	// Fail early, with an explanation, where the address is not local.
	probe, err := net.Listen("tcp", net.JoinHostPort(addr, "0"))
	if err != nil {
		return nil, fmt.Errorf("egress %s: cannot use %s as a source address (%v): %w", name, addr, err, errNotLinux)
	}
	_ = probe.Close()

	e := &egress{name: name, addr: addr, forwardFor: forwardFor}
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}, Timeout: 10 * time.Second}
	rp := &httputil.ReverseProxy{
		Transport: &http.Transport{DialContext: dialer.DialContext, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = target
			pr.Out.Host = pr.In.Host
			// Rewrite strips forwarding headers from the outbound request; an
			// ordinary client machine sends none. Only the egresses that play a
			// reverse proxy add one.
			if e.forwardFor != "" {
				pr.Out.Header.Set("X-Forwarded-For", e.forwardFor)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "egress "+name+": "+err.Error(), http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		e.requests++
		stray := r.Method == http.MethodConnect || !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host != public
		if stray {
			e.strays = append(e.strays, r.Method+" "+r.URL.String())
		}
		e.mu.Unlock()
		if stray {
			http.Error(w, "this egress reaches the pull-through proxy only", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	e.ln = ln
	e.url = "http://" + ln.Addr().String()
	e.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = e.srv.Serve(ln) }()
	return e, nil
}

func (e *egress) close() {
	if e.srv != nil {
		_ = e.srv.Close()
	}
}

// strayRequests returns the requests the machine made for anything but the
// pull-through proxy.
func (e *egress) strayRequests() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.strays...)
}

// installer installs a package through the proxy, as one ecosystem's package
// manager does.
type installer interface {
	// describe names the client for the report ("cargo 1.84.0").
	describe() string
	// real reports whether this is the ecosystem's actual package manager.
	real() bool
	// userAgent is a prefix of the User-Agent the client sends, which the
	// download log records.
	userAgent() string
	// install fetches p through the proxy mount, over the given egress, using
	// dir as its scratch space (a fresh, empty directory: every install starts
	// with cold caches, so the package really is downloaded). It reports whether
	// the client considers the package installed, with its output.
	install(ctx context.Context, mount string, eg *egress, p pkg, dir string) (ok bool, output string)
}

// proxyEnvVars are the variables that would route a client's traffic somewhere
// the suite did not choose.
var proxyEnvVars = []string{
	"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
}

// baseEnv returns the process environment without the variables in drop (by
// exact name) or with a prefix in dropPrefixes.
func baseEnv(drop []string, dropPrefixes ...string) []string {
	skip := map[string]bool{}
	for _, name := range drop {
		skip[name] = true
	}
	var out []string
next:
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if skip[name] {
			continue
		}
		for _, prefix := range dropPrefixes {
			if strings.HasPrefix(name, prefix) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

func writeFiles(files map[string]string) error {
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// --- cargo ------------------------------------------------------------------

// realCargo drives the real cargo.
type realCargo struct{ bin, version string }

// findCargo locates the cargo binary. Under rustup, `cargo` on PATH is a shim;
// the toolchain's own binary is used instead so the client under test is cargo
// itself.
func findCargo() (installer, error) {
	bin, err := exec.LookPath("cargo")
	if err != nil {
		return nil, err
	}
	if rustup, err := exec.LookPath("rustup"); err == nil {
		if out, err := exec.Command(rustup, "which", "cargo").Output(); err == nil {
			if real := strings.TrimSpace(string(out)); real != "" {
				bin = real
			}
		}
	}
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("%s --version: %w", bin, err)
	}
	fields := strings.Fields(string(out)) // "cargo 1.84.0 (66221abde 2024-11-19)"
	if len(fields) < 2 {
		return nil, fmt.Errorf("unexpected `cargo --version` output %q", out)
	}
	return realCargo{bin: bin, version: fields[1]}, nil
}

func (c realCargo) describe() string  { return "cargo " + c.version }
func (c realCargo) real() bool        { return true }
func (c realCargo) userAgent() string { return "cargo" }

func (c realCargo) install(ctx context.Context, mount string, eg *egress, p pkg, dir string) (bool, string) {
	home := filepath.Join(dir, "cargo-home")
	app := filepath.Join(dir, "app")
	err := writeFiles(map[string]string{
		// Source replacement sends every crates.io dependency to the proxy's
		// sparse registry (the trailing slash is required); the egress is the
		// machine's way out.
		filepath.Join(home, "config.toml"): "[source.crates-io]\nreplace-with = \"pullthrough\"\n\n" +
			"[source.pullthrough]\nregistry = \"sparse+" + mount + "/\"\n\n" +
			"[http]\nproxy = \"" + eg.url + "\"\n\n" +
			"[net]\nretry = 0\n",
		filepath.Join(app, "Cargo.toml"): "[package]\nname = \"ptdl-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n" +
			"[dependencies]\n" + p.Name + " = \"=" + p.Version + "\"\n",
		filepath.Join(app, "src", "main.rs"): "fn main() {}\n",
	})
	if err != nil {
		return false, err.Error()
	}
	cmd := exec.CommandContext(ctx, c.bin, "fetch")
	cmd.Dir = app
	cmd.Env = append(baseEnv(proxyEnvVars, "CARGO_"),
		"CARGO_HOME="+home,
		"CARGO_TERM_COLOR=never",
	)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// scriptedCargo speaks the sparse-registry protocol the way cargo does: read
// config.json for the download location, read the crate's index file for the
// version's checksum, download the crate, verify the checksum.
type scriptedCargo struct{}

func (scriptedCargo) describe() string  { return "scripted cargo sparse-registry client" }
func (scriptedCargo) real() bool        { return false }
func (scriptedCargo) userAgent() string { return "cargo" }

func (scriptedCargo) install(ctx context.Context, mount string, eg *egress, p pkg, _ string) (bool, string) {
	get := scriptedGetter(ctx, eg, "cargo/0.0.0 (pullthrough download-log suite)")

	body, err := get(mount + "/config.json")
	if err != nil {
		return false, err.Error()
	}
	var cfg struct {
		DL string `json:"dl"`
	}
	if err := json.Unmarshal(body, &cfg); err != nil || cfg.DL == "" {
		return false, fmt.Sprintf("config.json names no download location: %v: %s", err, body)
	}

	index, err := get(mount + "/" + crateIndexPath(p.Name))
	if err != nil {
		return false, err.Error()
	}
	var cksum string
	for _, line := range bytes.Split(index, []byte("\n")) {
		var v struct {
			Vers  string `json:"vers"`
			Cksum string `json:"cksum"`
		}
		if json.Unmarshal(line, &v) == nil && v.Vers == p.Version {
			cksum = v.Cksum
		}
	}
	if cksum == "" {
		return false, fmt.Sprintf("the index lists no version %s of %s", p.Version, p.Name)
	}

	crate, err := get(cfg.DL + "/" + p.Name + "/" + p.Version + "/download")
	if err != nil {
		return false, err.Error()
	}
	if got := sha256Hex(crate); got != cksum {
		return false, fmt.Sprintf("checksum mismatch for %s: index says %s, downloaded %s", p, cksum, got)
	}
	return true, fmt.Sprintf("downloaded %s (%d bytes, checksum verified)", p, len(crate))
}

// --- go ---------------------------------------------------------------------

// realGo drives the real go command.
type realGo struct{ bin, version string }

func findGo() (installer, error) {
	bin, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(bin, "env", "GOVERSION").Output()
	if err != nil {
		return nil, fmt.Errorf("%s env GOVERSION: %w", bin, err)
	}
	return realGo{bin: bin, version: strings.TrimPrefix(strings.TrimSpace(string(out)), "go")}, nil
}

func (g realGo) describe() string  { return "go " + g.version }
func (g realGo) real() bool        { return true }
func (g realGo) userAgent() string { return "Go-http-client" }

func (g realGo) install(ctx context.Context, mount string, eg *egress, p pkg, dir string) (bool, string) {
	app := filepath.Join(dir, "app")
	if err := writeFiles(map[string]string{
		filepath.Join(app, "go.mod"): "module example.com/ptdl-app\n\ngo 1.21\n",
	}); err != nil {
		return false, err.Error()
	}
	cmd := exec.CommandContext(ctx, g.bin, "get", p.Name+"@"+p.Version)
	cmd.Dir = app
	// GOPROXY without ",direct": every module comes from the proxy, and one it
	// refuses is not fetched from anywhere else. The fixture modules are in no
	// checksum database, hence GOSUMDB=off.
	cmd.Env = append(baseEnv(append([]string{"GOPROXY", "GOSUMDB", "GOFLAGS", "GOPATH", "GOMODCACHE", "GOCACHE",
		"GOENV", "GOTOOLCHAIN", "GOWORK", "GONOSUMDB", "GONOSUMCHECK", "GONOPROXY", "GOPRIVATE", "GOINSECURE", "GOVCS"}, proxyEnvVars...)),
		"GOPROXY="+mount,
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
		"GOPATH="+filepath.Join(dir, "gopath"),
		"GOMODCACHE="+filepath.Join(dir, "gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(dir, "gocache"),
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOVCS=*:off",
		"HTTP_PROXY="+eg.url,
		"http_proxy="+eg.url,
	)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// scriptedGo speaks the GOPROXY protocol the way `go get` does for one module
// version: the version list, the .info, the .mod, and the zip.
type scriptedGo struct{}

func (scriptedGo) describe() string  { return "scripted GOPROXY client" }
func (scriptedGo) real() bool        { return false }
func (scriptedGo) userAgent() string { return "Go-http-client" }

func (scriptedGo) install(ctx context.Context, mount string, eg *egress, p pkg, _ string) (bool, string) {
	get := scriptedGetter(ctx, eg, "Go-http-client/1.1")
	base := mount + "/" + p.Name + "/@v/"

	list, err := get(base + "list")
	if err != nil {
		return false, err.Error()
	}
	if !strings.Contains("\n"+string(list), "\n"+p.Version+"\n") {
		return false, fmt.Sprintf("the version list of %s does not offer %s: %q", p.Name, p.Version, list)
	}
	for _, ext := range []string{".info", ".mod"} {
		if _, err := get(base + p.Version + ext); err != nil {
			return false, err.Error()
		}
	}
	body, err := get(base + p.Version + ".zip")
	if err != nil {
		return false, err.Error()
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return false, fmt.Sprintf("the module zip of %s is not a zip: %v", p, err)
	}
	return true, fmt.Sprintf("downloaded %s (%d bytes, %d files)", p, len(body), len(zr.File))
}

// scriptedGetter returns a GET function that goes out through eg and fails on
// any status but 200, as a package manager does.
func scriptedGetter(ctx context.Context, eg *egress, userAgent string) func(string) ([]byte, error) {
	proxyURL, _ := url.Parse(eg.url)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true},
		Timeout:   30 * time.Second,
	}
	return func(target string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: status %d: %s", target, resp.StatusCode, firstLine(body))
		}
		return body, nil
	}
}

// pickInstaller chooses the client for an ecosystem according to envClients.
func pickInstaller(mode string, find func() (installer, error), scripted installer, what string) (installer, error) {
	switch mode {
	case "scripted":
		return scripted, nil
	case "real":
		inst, err := find()
		if err != nil {
			return nil, fmt.Errorf("%s=real but %s is not usable: %w", envClients, what, err)
		}
		return inst, nil
	case "", "auto":
		if inst, err := find(); err == nil {
			return inst, nil
		}
		return scripted, nil
	default:
		return nil, errors.New(envClients + " must be auto, real or scripted")
	}
}
