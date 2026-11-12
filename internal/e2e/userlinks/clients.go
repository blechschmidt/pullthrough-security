//go:build integration
// +build integration

package userlinks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// installer installs a package through a user's personal link, as one
// ecosystem's package manager does — configured with the snippet the links page
// handed the user.
type installer interface {
	// describe names the client for the report ("npm 10.9.2").
	describe() string
	// userAgent is a prefix of the User-Agent the client sends, which the
	// download log records.
	userAgent() string
	// install fetches p using the client configuration in snippet, with dir as
	// its scratch space (a fresh, empty directory: every install starts with
	// cold caches, so the package really is downloaded). It reports whether the
	// client considers the package installed, and its output.
	install(ctx context.Context, snippet string, p pkg, dir string) (ok bool, output string)
	// written lists the files under dir the client wrote that people commit: a
	// lock file, a manifest. The link must not be in them.
	written(dir string) []string
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

func versionOf(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// --- npm ----------------------------------------------------------------------

type realNpm struct{ bin, version string }

func findNpm() (installer, error) {
	bin, err := exec.LookPath("npm")
	if err != nil {
		return nil, err
	}
	version, err := versionOf(bin, "--version")
	if err != nil {
		return nil, err
	}
	return realNpm{bin: bin, version: version}, nil
}

func (n realNpm) describe() string  { return "npm " + n.version }
func (n realNpm) userAgent() string { return "npm/" }

func (n realNpm) install(ctx context.Context, snippet string, p pkg, dir string) (bool, string) {
	home := filepath.Join(dir, "home")
	app := filepath.Join(dir, "app")
	err := writeFiles(map[string]string{
		// The page says: your user-level ~/.npmrc. That is where it goes.
		filepath.Join(home, ".npmrc"):      snippet,
		filepath.Join(app, "package.json"): `{"name":"ptul-app","version":"1.0.0","private":true}` + "\n",
	})
	if err != nil {
		return false, err.Error()
	}
	cmd := exec.CommandContext(ctx, n.bin, "install", p.Name+"@"+p.Version, "--no-audit", "--no-fund", "--loglevel=error")
	cmd.Dir = app
	cmd.Env = append(baseEnv(proxyEnvVars, "npm_config_", "NPM_CONFIG_"),
		"HOME="+home,
		"npm_config_cache="+filepath.Join(dir, "npm-cache"),
		"npm_config_update_notifier=false",
		"npm_config_fetch_retries=0",
		"NO_COLOR=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, string(out)
	}
	// Installed means the package's files are where npm puts them.
	if _, err := os.Stat(filepath.Join(app, "node_modules", p.Name, "index.js")); err != nil {
		return false, string(out) + "\nnpm reported success, but the package is not in node_modules: " + err.Error()
	}
	return true, string(out)
}

func (realNpm) written(dir string) []string {
	return []string{filepath.Join(dir, "app", "package-lock.json"), filepath.Join(dir, "app", "package.json")}
}

// --- pip ----------------------------------------------------------------------

type realPip struct{ python, version string }

func findPip() (installer, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		return nil, err
	}
	out, err := versionOf(python, "-m", "pip", "--version") // "pip 24.0 from … (python 3.12)"
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return nil, fmt.Errorf("unexpected `pip --version` output %q", out)
	}
	return realPip{python: python, version: fields[1]}, nil
}

func (p realPip) describe() string { return "pip " + p.version }
func (realPip) userAgent() string  { return "pip/" }

func (p realPip) install(ctx context.Context, snippet string, pk pkg, dir string) (bool, string) {
	conf := filepath.Join(dir, "pip.conf")
	dest := filepath.Join(dir, "downloads")
	if err := writeFiles(map[string]string{conf: snippet}); err != nil {
		return false, err.Error()
	}
	cmd := exec.CommandContext(ctx, p.python, "-m", "pip", "download", "--no-deps", "--no-cache-dir",
		"--disable-pip-version-check", "--no-input", "--retries", "0", "--dest", dest, pk.Name+"=="+pk.Version)
	cmd.Dir = dir
	cmd.Env = append(baseEnv(proxyEnvVars, "PIP_"),
		"HOME="+filepath.Join(dir, "home"),
		// The page's pip.conf, as the only configuration pip reads.
		"PIP_CONFIG_FILE="+conf,
		// The suite's proxy speaks plain HTTP on loopback.
		"PIP_TRUSTED_HOST=127.0.0.1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, string(out)
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".whl") {
		return false, string(out) + "\npip reported success, but the wheel is not in the download directory"
	}
	return true, string(out)
}

// pip writes nothing a project commits.
func (realPip) written(string) []string { return nil }

// --- cargo --------------------------------------------------------------------

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
	out, err := versionOf(bin, "--version") // "cargo 1.84.0 (66221abde 2024-11-19)"
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(out)
	if len(fields) < 2 {
		return nil, fmt.Errorf("unexpected `cargo --version` output %q", out)
	}
	return realCargo{bin: bin, version: fields[1]}, nil
}

func (c realCargo) describe() string { return "cargo " + c.version }
func (realCargo) userAgent() string  { return "cargo" }

func (c realCargo) install(ctx context.Context, snippet string, p pkg, dir string) (bool, string) {
	home := filepath.Join(dir, "cargo-home")
	app := filepath.Join(dir, "app")
	err := writeFiles(map[string]string{
		// The page's config.toml, plus one line of the suite's own: do not retry.
		filepath.Join(home, "config.toml"): snippet + "\n[net]\nretry = 0\n",
		filepath.Join(app, "Cargo.toml"): "[package]\nname = \"ptul-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n" +
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

func (realCargo) written(dir string) []string {
	return []string{filepath.Join(dir, "app", "Cargo.lock"), filepath.Join(dir, "app", "Cargo.toml")}
}

// --- go -----------------------------------------------------------------------

type realGo struct{ bin, version string }

func findGo() (installer, error) {
	bin, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	version, err := versionOf(bin, "env", "GOVERSION")
	if err != nil {
		return nil, err
	}
	return realGo{bin: bin, version: strings.TrimPrefix(version, "go")}, nil
}

func (g realGo) describe() string { return "go " + g.version }
func (realGo) userAgent() string  { return "Go-http-client" }

// goproxyInSnippet finds the GOPROXY value in the page's `go env -w` line.
var goproxyInSnippet = regexp.MustCompile(`GOPROXY=(\S+)`)

func (g realGo) install(ctx context.Context, snippet string, p pkg, dir string) (bool, string) {
	m := goproxyInSnippet.FindStringSubmatch(snippet)
	if m == nil {
		return false, "the page's go snippet names no GOPROXY:\n" + snippet
	}
	// The page offers "<mount>,direct". The suite drops the fall-back: a module
	// the proxy refuses must not be fetched from anywhere else — and could not
	// be, the fixture exists nowhere else.
	goproxy := strings.TrimSuffix(m[1], ",direct")

	app := filepath.Join(dir, "app")
	if err := writeFiles(map[string]string{
		filepath.Join(app, "go.mod"): "module example.com/ptul-app\n\ngo 1.21\n",
	}); err != nil {
		return false, err.Error()
	}
	cmd := exec.CommandContext(ctx, g.bin, "get", p.Name+"@"+p.Version)
	cmd.Dir = app
	// The fixture module is in no checksum database, hence GOSUMDB=off.
	cmd.Env = append(baseEnv(append([]string{"GOPROXY", "GOSUMDB", "GOFLAGS", "GOPATH", "GOMODCACHE", "GOCACHE",
		"GOENV", "GOTOOLCHAIN", "GOWORK", "GONOSUMDB", "GONOSUMCHECK", "GONOPROXY", "GOPRIVATE", "GOINSECURE", "GOVCS"}, proxyEnvVars...)),
		"GOPROXY="+goproxy,
		"GOSUMDB=off",
		"GOFLAGS=-mod=mod",
		"GOPATH="+filepath.Join(dir, "gopath"),
		"GOMODCACHE="+filepath.Join(dir, "gopath", "pkg", "mod"),
		"GOCACHE="+filepath.Join(dir, "gocache"),
		"GOENV=off",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOVCS=*:off",
	)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

func (realGo) written(dir string) []string {
	return []string{filepath.Join(dir, "app", "go.mod"), filepath.Join(dir, "app", "go.sum")}
}

// --- docker -------------------------------------------------------------------

// realDocker is the Docker Engine: the daemon pulls, the CLI asks it to. The
// daemon treats a registry on loopback as one it may speak plain HTTP to, which
// is what lets it pull from the suite's proxy without any configuration.
type realDocker struct{ bin, version string }

func findDocker() (installer, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, err
	}
	version, err := versionOf(bin, "version", "--format", "{{.Server.Version}}")
	if err != nil {
		return nil, fmt.Errorf("the Docker daemon cannot be reached: %w", err)
	}
	return realDocker{bin: bin, version: version}, nil
}

func (d realDocker) describe() string { return "Docker Engine " + d.version }

// The daemon's User-Agent depends on which image store it was set up with
// ("docker/…" or "containerd/…"); the log is not held to either.
func (realDocker) userAgent() string { return "" }

// dockerPullInSnippet finds the page's example pull, which names the user's
// personal address of the upstream followed by an example repository.
var dockerPullInSnippet = regexp.MustCompile(`(?m)^docker pull (\S+)/library/alpine:latest$`)

func (d realDocker) install(ctx context.Context, snippet string, p pkg, dir string) (bool, string) {
	m := dockerPullInSnippet.FindStringSubmatch(snippet)
	if m == nil {
		return false, "the page's Docker snippet shows no `docker pull <address>/library/alpine:latest`:\n" + snippet
	}
	return d.pull(ctx, m[1]+"/"+p.Name+":"+p.Version, dir)
}

// run runs the docker CLI with a configuration directory of its own, so that
// nothing the machine's user is logged in to takes part.
func (d realDocker) run(ctx context.Context, dir string, args ...string) (string, error) {
	return d.runWithInput(ctx, dir, "", args...)
}

// runWithInput is run with text on the CLI's standard input, which is how a
// password is handed to `docker login` without putting it on a command line.
func (d realDocker) runWithInput(ctx context.Context, dir, input string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, d.bin, args...)
	cmd.Dir = dir
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	cmd.Env = append(baseEnv(append([]string{"DOCKER_CONFIG", "DOCKER_CONTENT_TRUST"}, proxyEnvVars...)),
		"DOCKER_CONFIG="+filepath.Join(dir, "docker-config"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// pull pulls an image and removes it again. Removing it is what makes the next
// pull download the layer again — and takes the image's name, which contains
// the link, out of the daemon's image list.
func (d realDocker) pull(ctx context.Context, ref, dir string) (bool, string) {
	if err := os.MkdirAll(filepath.Join(dir, "docker-config"), 0o700); err != nil {
		return false, err.Error()
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = d.run(cleanup, dir, "image", "rm", "--force", ref)
	}()
	out, err := d.run(ctx, dir, "pull", ref)
	if err != nil {
		return false, out
	}
	// Pulled means the daemon holds the image, its layer included.
	layers, err := d.run(ctx, dir, "image", "inspect", "--format", "{{len .RootFS.Layers}}", ref)
	if err != nil || strings.TrimSpace(layers) != "1" {
		return false, out + "\ndocker reported success, but the image is not in the daemon's store: " + layers
	}
	return true, out
}

// docker writes nothing a project commits. (The image's name does contain the
// link — the page says so.)
func (realDocker) written(string) []string { return nil }

// --- git ----------------------------------------------------------------------

// realGit clones over HTTP. upstream is the forge's own address, which is what
// the clone names: the page's insteadOf rule sends it through the user's link.
type realGit struct{ bin, version, upstream string }

func findGit(s *stub) (installer, error) {
	if s.gitErr != nil {
		return nil, s.gitErr
	}
	bin, err := exec.LookPath("git")
	if err != nil {
		return nil, err
	}
	out, err := versionOf(bin, "version") // "git version 2.43.0"
	if err != nil {
		return nil, err
	}
	return realGit{bin: bin, version: strings.TrimPrefix(out, "git version "), upstream: s.gitSrv.URL}, nil
}

func (g realGit) describe() string { return "git " + g.version }
func (realGit) userAgent() string  { return "git/" }

// insteadOfInSnippet finds the page's `git config --global url."…".insteadOf "…"`.
var insteadOfInSnippet = regexp.MustCompile(`(?m)^git config --global url\."([^"]+)"\.insteadOf "([^"]+)"$`)

func (g realGit) install(ctx context.Context, snippet string, p pkg, dir string) (bool, string) {
	m := insteadOfInSnippet.FindStringSubmatch(snippet)
	if m == nil {
		return false, "the page's Git snippet has no insteadOf rule:\n" + snippet
	}
	var output strings.Builder
	for _, args := range [][]string{
		// The page's rule, in the user's global configuration.
		{"config", "--global", "url." + m[1] + ".insteadOf", m[2]},
		// The clone names the forge, as a README or a submodule would.
		{"clone", "--quiet", g.upstream + "/" + p.Name, filepath.Join(dir, "app")},
	} {
		out, err := g.run(ctx, dir, args...)
		output.WriteString(out)
		if err != nil {
			return false, output.String()
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "app", "README.md")); err != nil {
		return false, output.String() + "\ngit reported success, but the work tree is empty: " + err.Error()
	}
	return true, output.String()
}

// run runs git with dir/home as the user's home. The user's own configuration
// is the only one read, and nobody is asked for a password: a refused clone
// must fail, not wait at a prompt.
func (g realGit) run(ctx context.Context, dir string, args ...string) (string, error) {
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, g.bin, args...)
	cmd.Dir = dir
	cmd.Env = append(baseEnv(proxyEnvVars, "GIT_"),
		"HOME="+home,
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// The clone's own configuration records where it was cloned from.
func (realGit) written(dir string) []string {
	return []string{filepath.Join(dir, "app", ".git", "config")}
}
