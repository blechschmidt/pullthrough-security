package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenGuard(t *testing.T) {
	var sawToken string
	h := tokenGuard("s3cret", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawToken = r.Header.Get(TokenHeader)
		w.WriteHeader(http.StatusNoContent)
	}))
	for token, want := range map[string]int{"": 401, "wrong": 401, "s3cret": 204} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/npm/x", nil)
		if token != "" {
			req.Header.Set(TokenHeader, token)
		}
		h.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Errorf("token %q: %d, want %d", token, rr.Code, want)
		}
	}
	if sawToken != "" {
		t.Error("the token must not reach the session's handler")
	}
}

func TestPaths(t *testing.T) {
	for p, want := range map[string]string{"": "", ".": "", "a/b": "a/b", "a/./b/../c": "a/c"} {
		if got, err := cleanDir(p); err != nil || got != want {
			t.Errorf("%q: %q %v", p, got, err)
		}
	}
	for _, bad := range []string{"/etc", "../x", "a/../../x", "a\\b", "a\x00b"} {
		if _, err := cleanDir(bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	dir := t.TempDir()
	if err := writeFiles(dir, map[string][]byte{"../escape": []byte("x")}); err == nil {
		t.Error("a file outside the work directory must be refused")
	}
	if err := writeFiles(dir, map[string][]byte{"sub/dir/f.txt": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(filepath.Join(dir, "link"), 1<<20); err == nil {
		t.Error("a symbolic link the tool left must not be followed")
	}
	if _, err := readBounded(filepath.Join(dir, "sub/dir/f.txt"), 0); err == nil {
		t.Error("a file over the bound must be refused")
	}
}

func TestNewRefusesADynamicForwarder(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	real, _ := filepath.EvalSymlinks(sh)
	if dyn, err := dynamicallyLinked(real); err != nil || !dyn {
		t.Skipf("%s is not a dynamically linked ELF here", real)
	}
	if _, err := New(Config{Runtime: "docker", Forwarder: real}); err == nil || !strings.Contains(err.Error(), "dynamically linked") {
		t.Fatalf("a dynamically linked forwarder must be refused: %v", err)
	}
}

// staticForwarder builds the test forwarder without cgo.
func staticForwarder(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "forwarder")
	cmd := exec.Command("go", "build", "-o", out, "./testdata/forwarder")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the forwarder: %v\n%s", err, b)
	}
	return out
}

func dockerImage(t *testing.T, image string) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: no containers")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		if out, err := exec.Command("docker", "pull", "--quiet", image).CombinedOutput(); err != nil {
			t.Skipf("image %s is not available: %v\n%s", image, err, out)
		}
	}
}

// TestRunReachesOnlyTheSession runs a job in a real container: it reaches the
// session's handler through the forwarder, with the token added on the way,
// and nothing else — the container has no network.
func TestRunReachesOnlyTheSession(t *testing.T) {
	const image = "alpine:3.20"
	dockerImage(t, image)
	r, err := New(Config{Runtime: "docker", Forwarder: staticForwarder(t), Images: map[string]string{"probe": image}, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/v1/up/hello" {
			_, _ = w.Write([]byte("hello from the proxy"))
			return
		}
		http.NotFound(w, req)
	})
	res, err := r.Run(context.Background(), Job{
		Tool: "probe", Handler: handler, Dir: "proj",
		Files:    map[string][]byte{"proj/in.txt": []byte("input\n")},
		Commands: [][]string{{"sh", "-c", "wget -q -O out.txt http://127.0.0.1:8080/v1/up/hello && cat in.txt >> out.txt && id -u > uid.txt"}},
		Collect:  []string{"proj/out.txt", "proj/uid.txt", "proj/absent.txt"},
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, res.Output)
	}
	if got := string(res.Files["proj/out.txt"]); got != "hello from the proxyinput\n" {
		t.Fatalf("out.txt: %q\n%s", got, res.Output)
	}
	if got := strings.TrimSpace(string(res.Files["proj/uid.txt"])); got != "65534" {
		t.Errorf("the tool ran as uid %q, want 65534", got)
	}
	if _, ok := res.Files["proj/absent.txt"]; ok {
		t.Error("a file the job did not write was collected")
	}

	// No network: an address other than the forwarder's is unreachable.
	res, err = r.Run(context.Background(), Job{Tool: "probe", Handler: handler,
		Commands: [][]string{{"sh", "-c", "wget -q -T 3 -O - http://1.1.1.1/ || exit 7"}}})
	if err == nil || res.ExitCode != 7 {
		t.Fatalf("the container reached the network: %v (exit %d)\n%s", err, res.ExitCode, res.Output)
	}
}

// TestRunStopsAJobThatFillsItsWorkDirectory: the work directory is a host
// directory; a job that writes past the bound is stopped.
func TestRunStopsAJobThatFillsItsWorkDirectory(t *testing.T) {
	const image = "alpine:3.20"
	dockerImage(t, image)
	r, err := New(Config{Runtime: "docker", Forwarder: staticForwarder(t), Images: map[string]string{"probe": image},
		Timeout: 2 * time.Minute, MaxWorkBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(context.Background(), Job{Tool: "probe", Handler: http.NotFoundHandler(),
		Commands: [][]string{{"sh", "-c", "i=0; while [ $i -lt 400 ]; do head -c 1048576 /dev/zero > f$i; i=$((i+1)); sleep 0.05; done"}}})
	if err == nil || !strings.Contains(err.Error(), "was stopped") {
		t.Fatalf("a job filling its work directory ran on: %v\n%s", err, res.Output)
	}

	// Writing below a directory the proxy's user cannot read does not hide
	// the bytes: a privileged proxy counts them, an unprivileged one stops
	// the job for the directory.
	res, err = r.Run(context.Background(), Job{Tool: "probe", Handler: http.NotFoundHandler(),
		Commands: [][]string{{"sh", "-c", "mkdir -m 0700 private && i=0; while [ $i -lt 400 ]; do head -c 1048576 /dev/zero > private/f$i; i=$((i+1)); sleep 0.05; done"}}})
	if err == nil || !strings.Contains(err.Error(), "was stopped") {
		t.Fatalf("a job filling a private directory ran on: %v\n%s", err, res.Output)
	}
}

// TestReleaseOpensUpTheTree: what the container's user made is opened up to
// the proxy's user on the way out — without following links.
func TestReleaseOpensUpTheTree(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "b", "lock"), []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "a", "link")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(dir, "a", "b"), filepath.Join(dir, "a")} {
		if err := os.Chmod(d, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	release(dir)
	for p, want := range map[string]os.FileMode{
		dir: 0o777, filepath.Join(dir, "a"): 0o777, filepath.Join(dir, "a", "b"): 0o777,
		filepath.Join(dir, "a", "b", "lock"): 0o666, outside: 0o600,
	} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %v, want %v", p, got, want)
		}
	}
}

// TestRunLeavesNothingBehind: the job's directory is removed whether the job
// ended or was stopped, even when the tool made it unwritable — the container's
// user is not the proxy's, so an unprivileged proxy could not otherwise remove
// what the tool left (CI runs this as such a user).
func TestRunLeavesNothingBehind(t *testing.T) {
	const image = "alpine:3.20"
	dockerImage(t, image)
	tmp, err := os.MkdirTemp("", "ptsbt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	r, err := New(Config{Runtime: "docker", Forwarder: staticForwarder(t), Images: map[string]string{"probe": image},
		Timeout: 2 * time.Minute, TempDir: tmp, MaxWorkBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// Readable — the watchdog measures it — but not writable: only the
	// container's user could remove what is inside.
	const lockUp = "mkdir -p d/e && echo x > d/e/f && chmod 0400 d/e/f && chmod 0555 d/e d"
	empty := func(what string) {
		t.Helper()
		entries, err := os.ReadDir(tmp)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			t.Errorf("%s: %s is left behind", what, e.Name())
		}
	}

	res, err := r.Run(context.Background(), Job{Tool: "probe", Handler: http.NotFoundHandler(), Dir: "proj",
		Files: map[string][]byte{"proj/lock": []byte("old\n")},
		// Replaced as tools replace a lock file, by a private file of the
		// container's user.
		Commands: [][]string{{"sh", "-c", lockUp + " && echo new > lock.new && chmod 0600 lock.new && mv lock.new lock"}},
		Collect:  []string{"proj/lock"}})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, res.Output)
	}
	if got := string(res.Files["proj/lock"]); got != "new\n" {
		t.Fatalf("collected %q, want the tool's private result", got)
	}
	empty("a job that ended")

	// Stopped mid-way (by the watchdog, here), the job never opens its tree
	// up itself.
	res, err = r.Run(context.Background(), Job{Tool: "probe", Handler: http.NotFoundHandler(),
		Commands: [][]string{{"sh", "-c", lockUp + " && head -c 2097152 /dev/zero > big && sleep 600"}}})
	if err == nil || !strings.Contains(err.Error(), "was stopped") {
		t.Fatalf("a job past its bounds: %v\n%s", err, res.Output)
	}
	empty("a job that was stopped")
}
