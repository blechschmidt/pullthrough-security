package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

// lockfilesToken is spelled like a personal link token but fails the
// checksum.
const lockfilesToken = "ptl1abcdefghijklmnopqrstuvwxyz234567qwertyz"

// lockfilesRepo builds a repository whose lock files were resolved through a
// proxy at https://proxy.example.com, by way of a personal link.
func lockfilesRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	dir := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("web/package-lock.json", `{"lockfileVersion": 3, "packages": {
  "": {"name": "web"},
  "node_modules/lodash": {
    "version": "4.17.21",
    "resolved": "https://proxy.example.com/u/`+lockfilesToken+`/v1/npm/lodash/-/lodash-4.17.21.tgz",
    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
  }
}}
`)
	write("api/requirements.txt", "--index-url https://ci:hunter2@pypi.example.com/simple\nrequests==2.32.3\nflask>=2\n")
	write("node_modules/x/package-lock.json", `{"lockfileVersion": 3, "packages": {"node_modules/y": {"version": "1.0.0"}}}`)
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "--quiet", "--initial-branch=main")
	run("config", "uploadpack.allowFilter", "true")
	run("add", "-A")
	run("-c", "user.email=t@example.com", "-c", "user.name=T", "commit", "--quiet", "-m", "c")
	return dir
}

func scanOutput(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	err := lockfilesScan(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func TestLockfilesScanTable(t *testing.T) {
	repo := lockfilesRepo(t)
	out, _, err := scanOutput(t, repo, "--public-url", "https://proxy.example.com", "--url", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"web/package-lock.json:3", "lodash", "4.17.21", "proxy upstream npm: https://proxy.example.com/v1/npm", "sha512:",
		"api/requirements.txt:2", "requests", "https://pypi.example.com/simple",
		"2 dependencies in 2 lock files",
		"flask is not pinned",
		"node_modules/: matches a skip glob",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, secret := range []string{lockfilesToken, "ptl1", "hunter2", "ci:"} {
		if strings.Contains(out, secret) {
			t.Errorf("output contains %q:\n%s", secret, out)
		}
	}
}

func TestLockfilesScanJSONAndSubdirectory(t *testing.T) {
	repo := lockfilesRepo(t)
	// A directory inside the working tree scans that directory; flags may
	// follow the repository argument.
	out, _, err := scanOutput(t, filepath.Join(repo, "web"), "--json", "--url", "")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Repository string            `json:"repository"`
		Commit     string            `json:"commit"`
		Root       string            `json:"root"`
		Files      []*lockfiles.File `json:"files"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Root != "web" || len(got.Files) != 1 || got.Files[0].Path != "web/package-lock.json" || len(got.Commit) != 40 {
		t.Fatalf("report %+v", got)
	}
	d := got.Files[0].Dependencies[0]
	// Without the proxy's address the personal link is still recognised, and
	// its token removed.
	if d.Upstream != "npm" || d.URL != "https://proxy.example.com/v1/npm/lodash/-/lodash-4.17.21.tgz" || len(d.Digests) != 1 {
		t.Errorf("dependency %+v", d)
	}
	if strings.Contains(out, "ptl1") {
		t.Errorf("the JSON contains the token:\n%s", out)
	}
}

func TestLockfilesScanWithProxyConfig(t *testing.T) {
	repo := lockfilesRepo(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	cfg := `server:
  httpAddr: ":8080"
  publicUrl: https://proxy.example.com
upstreams:
  npm: {type: npm, url: "https://registry.npmjs.org"}
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := scanOutput(t, repo, "--config", cfgPath, "--json", "--url", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"registry": "https://registry.npmjs.org"`) || !strings.Contains(out, `"upstream": "npm"`) {
		t.Errorf("the upstream's own registry is missing:\n%s", out)
	}
	if _, _, err := scanOutput(t, repo, "--config", filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing config file was accepted")
	}
}

func TestLockfilesScanDiscoversUpstreams(t *testing.T) {
	repo := lockfilesRepo(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/api/overview" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"info":{"upstreams":[{"name":"npm","type":"npm","url":"https://registry.npmjs.org"}]}}`))
	}))
	defer srv.Close()
	out, _, err := scanOutput(t, repo, "--url", srv.URL, "--public-url", "https://proxy.example.com", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"registry": "https://registry.npmjs.org"`) {
		t.Errorf("the discovered upstream was not used:\n%s", out)
	}
	// A proxy that does not answer is a note, not a failure.
	_, stderr, err := scanOutput(t, repo, "--url", "http://127.0.0.1:1", "--timeout", "1s")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "could not list the proxy's upstreams") {
		t.Errorf("stderr %q", stderr)
	}
}

func TestLockfilesScanRemote(t *testing.T) {
	repo := lockfilesRepo(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp) // where the temporary clone goes
	out, stderr, err := scanOutput(t, "file://"+repo, "--rev", "main", "--url", "")
	if err != nil {
		t.Fatalf("%v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "fetching file://") || !strings.Contains(out, "2 dependencies in 2 lock files") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out, stderr)
	}
	// A failed fetch cleans up too.
	if _, _, err := scanOutput(t, "file://"+repo, "--rev", "no-such-branch", "--url", ""); err == nil {
		t.Error("an unknown revision was scanned")
	}
	if entries, _ := os.ReadDir(tmp); len(entries) > 0 {
		t.Errorf("temporary clones left behind: %v", entries)
	}
}

// TestLockfilesScanCleansUpBeforePrinting: the clone is gone by the time the
// report is written, so a reader that stops early (SIGPIPE) leaves nothing.
func TestLockfilesScanCleansUpBeforePrinting(t *testing.T) {
	repo := lockfilesRepo(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	w := &checkingWriter{check: func() {
		if entries, _ := os.ReadDir(tmp); len(entries) > 0 {
			t.Errorf("the clone still exists while the report is written: %v", entries)
		}
	}}
	if err := lockfilesScan([]string{"file://" + repo, "--url", ""}, w, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !w.wrote {
		t.Fatal("nothing was written")
	}
}

// checkingWriter runs check before its first write.
type checkingWriter struct {
	check func()
	wrote bool
}

func (w *checkingWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.check()
		w.wrote = true
	}
	return len(p), nil
}

func TestLockfilesArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}, {"--bogus-flag", "x"}} {
		if _, _, err := scanOutput(t, args...); err == nil {
			t.Errorf("args %q accepted", args)
		}
	}
	if err := runLockfiles([]string{"nope"}); err == nil {
		t.Error("unknown action accepted")
	}
	if _, _, err := scanOutput(t, "ext::sh -c id", "--url", ""); err == nil {
		t.Error("a remote-helper URL was accepted")
	}
}

func TestLockfilesFormats(t *testing.T) {
	var out bytes.Buffer
	if err := lockfilesFormats(nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"npm", "package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml", "apt", "no lock-file format"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("formats lack %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := lockfilesFormats([]string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var table []lockfiles.Coverage
	if err := json.Unmarshal(out.Bytes(), &table); err != nil || len(table) < 30 {
		t.Fatalf("JSON table: %v (%d entries)", err, len(table))
	}
}

func TestLockfilesTableEscapesRepositoryText(t *testing.T) {
	r := &lockfiles.Report{
		Commit: strings.Repeat("a", 40),
		Files: []*lockfiles.File{{
			Path: "evil\x1b[2Jdir/package-lock.json",
			Dependencies: []lockfiles.Dependency{{
				Type: "npm", Name: "a\u202eb", Version: "1.0.0\r", File: "evil\x1b[2Jdir/package-lock.json", Line: 1,
			}},
			Warnings: []string{"tab\there"},
		}},
		Skipped:    []lockfiles.Skipped{{Path: "x\ny/", Reason: "matches a skip glob"}},
		Submodules: []lockfiles.Submodule{{Path: "sub\x07", Commit: strings.Repeat("b", 40)}},
	}
	var out bytes.Buffer
	printLockfilesReport(&out, "repo", r)
	for _, c := range []string{"\x1b", "\u202e", "\r", "\x07", "x\ny"} {
		if strings.Contains(out.String(), c) {
			t.Errorf("the table prints %q raw:\n%s", c, out.String())
		}
	}
	if !strings.Contains(out.String(), `evil\u001b[2Jdir/package-lock.json`) {
		t.Errorf("escaped path missing:\n%s", out.String())
	}
}
