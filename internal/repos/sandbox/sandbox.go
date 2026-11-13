// Package sandbox runs a package manager in a network-less container whose
// only registry is the proxy (Task 182).
//
// The repository maintenance updater rewrites most lock files itself. When an
// update needs the dependency graph resolved again — the new version declares
// other dependencies — it hands the lock file to the ecosystem's real package
// manager instead, and this package runs that tool:
//
//   - in a throwaway container of the tool's official image, with no network
//     at all (--network none), a read-only root file system, every capability
//     dropped, no new privileges, and memory, process and time limits;
//   - with the project's files in /work, and nothing of the host besides;
//   - reaching the proxy — and nothing else — through a unix socket mounted
//     into the container. Inside, this very binary listens on the loopback
//     address the tool is configured with and relays each request over the
//     socket, adding the session's short-lived token. The handler behind the
//     socket is the updater's: it serves registry metadata through the
//     admission gates, and package content only when the LLM package-content
//     scan judged those exact bytes benign (the "scanned-benign-only" policy).
//
// This is the client lab's and the ecosystem tests' arrangement
// (scripts/client-lab, internal/ecotest), made a production component: the same
// official images, the same "the proxy is the only thing reachable" network
// model, the same in-container forwarder.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TokenHeader carries the session token from the in-container forwarder to the
// session's handler.
const TokenHeader = "X-Pullthrough-Sandbox-Token"

// ListenAddr is where the forwarder listens inside the container; tools are
// configured with http://ListenAddr/v1/<upstream>/….
const ListenAddr = "127.0.0.1:8080"

// BaseURL is the proxy's address as the sandboxed tool sees it.
const BaseURL = "http://" + ListenAddr

// Paths inside the container.
const (
	toolDir   = "/pt"
	workDir   = "/work"
	specFile  = toolDir + "/spec.json"
	sockFile  = toolDir + "/proxy.sock"
	forwarder = toolDir + "/pullthrough"
)

// Config configures the runner.
type Config struct {
	// Runtime is the container runtime binary: "docker" or "podman".
	Runtime string
	// Images maps a tool ("npm", "cargo", "go", "uv") to its image.
	Images map[string]string
	// Forwarder is the static binary run inside the container as the
	// forwarder (default: this executable). It must be statically linked:
	// the tools' images share no libraries with the host.
	Forwarder string
	// Timeout bounds one job (default 10m); Memory ("2g") and PIDs bound its
	// container.
	Timeout time.Duration
	Memory  string
	PIDs    int
	// User is the "uid:gid" the tool runs as (default 65534:65534, nobody:
	// never the proxy's own user, which may be root).
	User string
	// TempDir holds each job's files; it must be a directory the runtime can
	// bind-mount (default the system's temporary directory).
	TempDir string
	// MaxCollectBytes bounds a file collected back (default 64 MiB).
	MaxCollectBytes int64
	// MaxWorkBytes and MaxWorkFiles bound what the tool may leave in its work
	// directory, a host directory: a job past either is stopped (defaults
	// 1 GiB, 100000 files).
	MaxWorkBytes int64
	MaxWorkFiles int
	// Logger reports what the runner could not clean up (default
	// slog.Default()).
	Logger *slog.Logger
}

// maxFileBytes is the largest file a job's commands may write.
const maxFileBytes = 512 << 20

// DefaultImages are the tools' images: those of the client lab and the
// ecosystem tests (internal/ecotest catalog), pinned by tag.
var DefaultImages = map[string]string{
	"npm":   "node:22-slim",
	"cargo": "rust:1-slim",
	"go":    "golang:1.24-alpine",
	"uv":    "ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
}

// Job is one run of a tool.
type Job struct {
	// Tool names the tool ("npm"); its image comes from Config.Images.
	Tool string
	// Files are the project's files, by slash-separated path below /work.
	Files map[string][]byte
	// Dir is the directory below /work the commands run in.
	Dir string
	// Commands are run in order, each an argument vector — never a shell
	// line: package names and versions come from registries and must not be
	// read as shell syntax. The first that fails ends the job.
	Commands [][]string
	// Env is the commands' environment ("KEY=value").
	Env []string
	// Collect are the files read back once the commands succeeded, by path
	// below /work; a file the commands removed is reported absent.
	Collect []string
	// Handler serves the requests the tool makes of the proxy. Every request
	// carries the session token in TokenHeader; requests without it never
	// reach the handler.
	Handler http.Handler
}

// Result is what a job produced.
type Result struct {
	// Files are the collected files' contents; an absent one was removed.
	Files map[string][]byte
	// Output is the commands' combined output, bounded.
	Output string
	// ExitCode is the failing command's exit status (0 when every one ran).
	ExitCode int
	// Duration is how long the container ran.
	Duration time.Duration
}

// Runner runs jobs in containers.
type Runner struct {
	cfg Config
}

// New returns a runner, checking that the runtime and the forwarder are usable.
func New(cfg Config) (*Runner, error) {
	if cfg.Runtime == "" {
		return nil, errors.New("sandbox: no container runtime is configured")
	}
	if _, err := exec.LookPath(cfg.Runtime); err != nil {
		return nil, fmt.Errorf("sandbox: container runtime %q: %w", cfg.Runtime, err)
	}
	if cfg.Forwarder == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("sandbox: locating the forwarder: %w", err)
		}
		cfg.Forwarder = exe
	}
	if dyn, err := dynamicallyLinked(cfg.Forwarder); err != nil {
		return nil, fmt.Errorf("sandbox: inspecting the forwarder %s: %w", cfg.Forwarder, err)
	} else if dyn {
		return nil, fmt.Errorf("sandbox: the forwarder %s is dynamically linked; build it with CGO_ENABLED=0 (the release binaries are)", cfg.Forwarder)
	}
	if cfg.Images == nil {
		cfg.Images = map[string]string{}
	}
	for tool, img := range DefaultImages {
		if _, ok := cfg.Images[tool]; !ok {
			cfg.Images[tool] = img
		}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	if cfg.Memory == "" {
		cfg.Memory = "2g"
	}
	if cfg.PIDs <= 0 {
		cfg.PIDs = 1024
	}
	if cfg.User == "" {
		cfg.User = "65534:65534"
	}
	if cfg.MaxCollectBytes <= 0 {
		cfg.MaxCollectBytes = 64 << 20
	}
	if cfg.MaxWorkBytes <= 0 {
		cfg.MaxWorkBytes = 1 << 30
	}
	if cfg.MaxWorkFiles <= 0 {
		cfg.MaxWorkFiles = 100_000
	}
	return &Runner{cfg: cfg}, nil
}

// watchWork stops the job's container when its work directory grows past the
// bounds; it returns when ctx ends. It reports, through exceeded, why it
// stopped the job.
func (r *Runner) watchWork(ctx context.Context, dir, container string, exceeded *string, mu *sync.Mutex) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var bytes int64
		files := 0
		hidden := ""
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				// What an unprivileged proxy cannot read, it cannot
				// measure: a directory the tool keeps to itself stops
				// the job. (Entries removed meanwhile are not counted.)
				if errors.Is(err, fs.ErrPermission) {
					hidden = p
					return filepath.SkipAll
				}
				return nil
			}
			files++
			if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
				bytes += info.Size()
			}
			if files > r.cfg.MaxWorkFiles || bytes > r.cfg.MaxWorkBytes {
				return filepath.SkipAll
			}
			return nil
		})
		why := ""
		switch {
		case files > r.cfg.MaxWorkFiles || bytes > r.cfg.MaxWorkBytes:
			why = fmt.Sprintf("the job's work directory grew past %d files or %d bytes", r.cfg.MaxWorkFiles, r.cfg.MaxWorkBytes)
		case hidden != "":
			rel, err := filepath.Rel(dir, hidden)
			if err != nil {
				rel = hidden
			}
			why = fmt.Sprintf("the job made %s unreadable, so its size cannot be bounded", filepath.ToSlash(rel))
		}
		if why != "" {
			mu.Lock()
			*exceeded = why
			mu.Unlock()
			_ = exec.Command(r.cfg.Runtime, "kill", container).Run()
			return
		}
	}
}

// Tool reports whether the runner has an image for the tool.
func (r *Runner) Tool(tool string) (bool, string) {
	if r == nil {
		return false, "no sandbox is configured (repositories.updates.sandbox)"
	}
	if strings.TrimSpace(r.cfg.Images[tool]) == "" {
		return false, "the sandbox has no image for " + tool
	}
	return true, ""
}

// dynamicallyLinked reports whether an ELF executable asks for an interpreter.
func dynamicallyLinked(p string) (bool, error) {
	f, err := elf.Open(p)
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

// spec is what the forwarder reads inside the container.
type spec struct {
	Listen   string     `json:"listen"`
	Socket   string     `json:"socket"`
	Token    string     `json:"token"`
	Dir      string     `json:"dir"`
	Commands [][]string `json:"commands"`
	Env      []string   `json:"env"`
	// Release is the directory opened up to every user once the commands
	// are done (see release); a spec without commands only does that.
	Release string `json:"release,omitempty"`
}

// maxOutput bounds the output kept of a job.
const maxOutput = 256 << 10

// Run runs a job.
func (r *Runner) Run(ctx context.Context, job Job) (*Result, error) {
	image := r.cfg.Images[job.Tool]
	if image == "" {
		return nil, fmt.Errorf("sandbox: no image for %s", job.Tool)
	}
	if job.Handler == nil || len(job.Commands) == 0 {
		return nil, errors.New("sandbox: a job needs a handler and commands")
	}
	dir, err := cleanDir(job.Dir)
	if err != nil {
		return nil, err
	}
	// A unix socket path is limited to about 100 bytes: the job's directory
	// lives directly under the temporary directory.
	base, err := os.MkdirTemp(r.cfg.TempDir, "ptsb-")
	if err != nil {
		return nil, err
	}
	tools := filepath.Join(base, "pt")
	work := filepath.Join(base, "work")
	defer r.removeJob(image, base, tools, work)
	for _, d := range []string{tools, work} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := writeFiles(work, job.Files); err != nil {
		return nil, err
	}
	// The container's user owns nothing on the host: the work tree is made
	// writable for it, and only it is mounted writable.
	if err := openUp(work); err != nil {
		return nil, err
	}
	if err := copyFile(r.cfg.Forwarder, filepath.Join(tools, "pullthrough"), 0o755); err != nil {
		return nil, fmt.Errorf("sandbox: installing the forwarder: %w", err)
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	sp := spec{Listen: ListenAddr, Socket: sockFile, Token: token, Dir: path.Join(workDir, dir), Commands: job.Commands, Env: job.Env,
		Release: workDir}
	data, err := json.Marshal(sp)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(tools, "spec.json"), data, 0o644); err != nil {
		return nil, err
	}

	// The session: only requests carrying the token reach the handler, and
	// the socket only exists while the job runs.
	ln, err := net.Listen("unix", filepath.Join(tools, "proxy.sock"))
	if err != nil {
		return nil, fmt.Errorf("sandbox: opening the proxy socket: %w", err)
	}
	if err := os.Chmod(filepath.Join(tools, "proxy.sock"), 0o666); err != nil {
		_ = ln.Close()
		return nil, err
	}
	srv := &http.Server{Handler: tokenGuard(token, job.Handler), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	// The session ends with the job: its handlers have returned before the
	// caller reads what they recorded.
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			_ = srv.Close()
		}
	}()

	jctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
	defer cancel()
	name := "ptsb-" + token[:12]
	var exceeded string
	var exceededMu sync.Mutex
	wctx, stopWatch := context.WithCancel(jctx)
	defer stopWatch()
	go r.watchWork(wctx, work, name, &exceeded, &exceededMu)
	args := []string{"run", "--rm", "--name", name,
		"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(r.cfg.PIDs), "--memory", r.cfg.Memory,
		"--tmpfs", "/tmp:rw,exec,size=2g", "--user", r.cfg.User,
		"-v", tools + ":" + toolDir + ":ro", "-v", work + ":" + workDir,
		"-e", "HOME=/tmp/home", "--entrypoint", forwarder, image, "sandbox-exec", specFile}
	start := time.Now()
	cmd := exec.CommandContext(jctx, r.cfg.Runtime, args...)
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, max: maxOutput}
	cmd.Stderr = cmd.Stdout
	runErr := cmd.Run()
	stopWatch()
	res := &Result{Output: out.String(), Duration: time.Since(start)}
	if jctx.Err() != nil {
		_ = exec.Command(r.cfg.Runtime, "rm", "-f", name).Run()
		return res, fmt.Errorf("sandbox: %s did not finish within %s", job.Tool, r.cfg.Timeout)
	}
	exceededMu.Lock()
	why := exceeded
	exceededMu.Unlock()
	if why != "" {
		_ = exec.Command(r.cfg.Runtime, "rm", "-f", name).Run()
		return res, fmt.Errorf("sandbox: %s was stopped: %s", job.Tool, why)
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			res.ExitCode = exit.ExitCode()
			return res, fmt.Errorf("sandbox: %s failed (exit status %d)", job.Tool, res.ExitCode)
		}
		return res, fmt.Errorf("sandbox: running the container: %w", runErr)
	}
	res.Files = map[string][]byte{}
	for _, p := range job.Collect {
		clean, err := cleanDir(p)
		if err != nil || clean == "" {
			return res, fmt.Errorf("sandbox: %q is not a path to collect", p)
		}
		data, err := readBounded(filepath.Join(work, filepath.FromSlash(clean)), r.cfg.MaxCollectBytes)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return res, fmt.Errorf("sandbox: collecting %s: %w", clean, err)
		}
		res.Files[clean] = data
	}
	return res, nil
}

// removeJob removes a job's directory. What the tool left in its work tree
// belongs to the container's user, not to this process's: a job that ended
// normally opened it up on its way out (ExecMain), but one that was stopped did
// not, and an unprivileged proxy cannot remove a directory another user made.
// A short container of the same image, as the same user, opens it up then.
func (r *Runner) removeJob(image, base, tools, work string) {
	err := os.RemoveAll(work)
	if err != nil {
		if rerr := r.releaseWork(image, tools, work); rerr != nil {
			err = fmt.Errorf("%w (opening it up: %v)", err, rerr)
		} else {
			err = os.RemoveAll(work)
		}
	}
	if err == nil {
		err = os.RemoveAll(base)
	}
	if err != nil {
		r.logger().Warn("sandbox: a job's directory is left behind", "dir", base, "error", err)
	}
}

// releaseWork runs the forwarder in release-only mode over a job's work tree,
// with the job's isolation.
func (r *Runner) releaseWork(image, tools, work string) error {
	data, err := json.Marshal(spec{Release: workDir})
	if err != nil {
		return err
	}
	const releaseSpec = toolDir + "/release.json"
	if err := os.WriteFile(filepath.Join(tools, path.Base(releaseSpec)), data, 0o644); err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	name := "ptsb-release-" + token[:12]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"run", "--rm", "--name", name,
		"--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "16", "--memory", r.cfg.Memory, "--user", r.cfg.User,
		"-v", tools + ":" + toolDir + ":ro", "-v", work + ":" + workDir,
		"--entrypoint", forwarder, image, "sandbox-exec", releaseSpec}
	out, err := exec.CommandContext(ctx, r.cfg.Runtime, args...).CombinedOutput()
	if ctx.Err() != nil {
		_ = exec.Command(r.cfg.Runtime, "rm", "-f", name).Run()
	}
	if err != nil {
		if len(out) > 2048 {
			out = out[:2048]
		}
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (r *Runner) logger() *slog.Logger {
	if r.cfg.Logger != nil {
		return r.cfg.Logger
	}
	return slog.Default()
}

// tokenGuard admits a request only with the session's token.
func tokenGuard(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get(TokenHeader))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			http.Error(w, "the sandbox session token is missing or wrong", http.StatusUnauthorized)
			return
		}
		r.Header.Del(TokenHeader)
		next.ServeHTTP(w, r)
	})
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// cleanDir validates a relative slash-separated path and returns it cleaned
// ("" for the work directory itself).
func cleanDir(p string) (string, error) {
	if p == "" || p == "." {
		return "", nil
	}
	if strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00") {
		return "", fmt.Errorf("sandbox: %q is not a relative path", p)
	}
	c := path.Clean(p)
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("sandbox: %q leaves the work directory", p)
	}
	return c, nil
}

// writeFiles materializes the job's files below dir.
func writeFiles(dir string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		clean, err := cleanDir(n)
		if err != nil || clean == "" {
			return fmt.Errorf("sandbox: %q is not a file path", n)
		}
		p := filepath.Join(dir, filepath.FromSlash(clean))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, files[n], 0o644); err != nil {
			return err
		}
	}
	return nil
}

// openUp makes the work tree writable by the container's user, whoever it is.
func openUp(dir string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.Chmod(p, 0o777)
		}
		return os.Chmod(p, 0o666)
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// readBounded reads a regular file of at most max bytes (a symbolic link the
// tool left is not followed).
func readBounded(p string, max int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("larger than %d bytes", max)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}

// limitedWriter keeps the first max bytes written to it.
type limitedWriter struct {
	mu  sync.Mutex
	w   *bytes.Buffer
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := l.max - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}
