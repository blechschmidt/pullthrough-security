//go:build integration
// +build integration

package git

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// These tests drive the download-log hooks with a real git client, because what
// they have to get right is what a real client sends: which of its requests is
// the fetch, in which protocol version, compressed or not.

// describedServer serves a mirror-mode backend the way the gateway does —
// DescribeDownload first, then ServeBackendHTTP — and records what was
// described as a download.
type describedServer struct {
	*httptest.Server
	mu        sync.Mutex
	requests  int
	downloads []backends.Download
}

func newDescribedServer(t *testing.T, backend *Backend) *describedServer {
	t.Helper()
	s := &describedServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/gh")
		d, ok := backend.DescribeDownload(r, rest)
		s.mu.Lock()
		s.requests++
		if ok {
			s.downloads = append(s.downloads, d)
		}
		s.mu.Unlock()
		backend.ServeBackendHTTP(w, r, rest)
	}))
	t.Cleanup(s.Close)
	return s
}

// take returns what was recorded since the last call.
func (s *describedServer) take() (requests int, downloads []backends.Download) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests, downloads = s.requests, s.downloads
	s.requests, s.downloads = 0, nil
	return requests, downloads
}

func gitClient(t *testing.T, env []string, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// A clone is one download, in either protocol version; listing refs is none;
// and examining the request must not break the clone.
func TestDescribeDownloadWithRealGitClient(t *testing.T) {
	requireGit(t)
	originRoot, repoName, head := createOriginRepo(t)
	backend, err := NewBackend(BackendOptions{Upstream: fileUpstream(t, "gh", originRoot), Mirror: newMirror(t), Logger: discardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	srv := newDescribedServer(t, backend)
	cloneURL := srv.URL + "/gh/" + repoName

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	env := isolatedGitEnv(home)
	want := backends.Download{Name: "team/project.git"}

	for _, version := range []string{"2", "0"} {
		t.Run("clone/protocol-v"+version, func(t *testing.T) {
			out := filepath.Join(tmp, "clone-v"+version)
			gitClient(t, env, tmp, "-c", "protocol.version="+version, "clone", "-q", cloneURL, out)

			rev, err := exec.Command("git", "-C", out, "rev-parse", "HEAD").Output()
			if err != nil || strings.TrimSpace(string(rev)) != head {
				t.Fatalf("cloned HEAD = %q (%v), want %s: the clone must be unaffected by the inspection", rev, err, head)
			}
			requests, downloads := srv.take()
			if len(downloads) != 1 || downloads[0] != want {
				t.Fatalf("a clone made %d requests of which %d were described as downloads (%+v); want exactly one, of %+v",
					requests, len(downloads), downloads, want)
			}
			if requests < 2 {
				t.Fatalf("a clone made %d requests; expected the advertisement plus the fetch", requests)
			}
		})
	}

	t.Run("ls-remote", func(t *testing.T) {
		for _, version := range []string{"2", "0"} {
			gitClient(t, env, tmp, "-c", "protocol.version="+version, "ls-remote", cloneURL)
			requests, downloads := srv.take()
			if requests == 0 {
				t.Fatalf("ls-remote (v%s) made no request", version)
			}
			if len(downloads) != 0 {
				t.Fatalf("ls-remote (v%s) transfers no objects but was described as a download: %+v", version, downloads)
			}
		}
	})

	t.Run("fetch with nothing new", func(t *testing.T) {
		gitClient(t, env, filepath.Join(tmp, "clone-v2"), "fetch", "-q", "origin")
		if _, downloads := srv.take(); len(downloads) != 0 {
			t.Fatalf("an up-to-date fetch was described as a download: %+v", downloads)
		}
	})
}

// Over SSH the server reports a fetch session itself: once per clone, with the
// client's address and key, and not for a bare ref listing.
func TestSSHFetchIsReported(t *testing.T) {
	requireGit(t)
	requireSSH(t)
	originRoot, repoName, head := createOriginRepo(t)
	up := fileUpstream(t, "gh", originRoot)

	keyDir := t.TempDir()
	hostKey := sshKeygen(t, filepath.Join(keyDir, "host"))
	clientKey := sshKeygen(t, filepath.Join(keyDir, "client"))
	clientPub := readFile(t, clientKey+".pub")

	var mu sync.Mutex
	var events []FetchEvent
	srv, err := NewSSHServer(SSHServerOptions{
		Addr:           "127.0.0.1:0",
		HostKeyFile:    hostKey,
		AuthorizedKeys: []string{clientPub},
		Mirror:         newMirror(t),
		Resolve:        func(name string) (*Upstream, bool) { return up, name == "gh" },
		OnFetch: func(ev FetchEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewSSHServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	addr := waitForAddr(t, srv)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(keyDir, "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("["+host+"]:"+port+" "+readFile(t, hostKey+".pub")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(isolatedGitEnv(home), "GIT_SSH_COMMAND=ssh -i "+clientKey+
		" -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+knownHosts)
	cloneURL := "ssh://git@" + host + ":" + port + "/gh/" + repoName

	taken := func() []FetchEvent {
		// The event is reported when the session ends, which the client does not
		// wait for: give the server a moment.
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			got := events
			mu.Unlock()
			if len(got) > 0 || time.Now().After(deadline) {
				mu.Lock()
				events = nil
				mu.Unlock()
				return got
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	for _, version := range []string{"2", "0"} {
		out := filepath.Join(tmp, "clone-v"+version)
		gitClient(t, env, tmp, "-c", "protocol.version="+version, "clone", "-q", cloneURL, out)
		rev, err := exec.Command("git", "-C", out, "rev-parse", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(rev)) != head {
			t.Fatalf("v%s: cloned HEAD = %q (%v), want %s", version, rev, err, head)
		}
		got := taken()
		if len(got) != 1 {
			t.Fatalf("v%s: a clone reported %d fetch events, want 1: %+v", version, len(got), got)
		}
		ev := got[0]
		if ev.Upstream != "gh" || ev.Repo != "team/project.git" {
			t.Errorf("v%s: event names %s/%s, want gh/team/project.git", version, ev.Upstream, ev.Repo)
		}
		if peer, _, err := net.SplitHostPort(ev.RemoteAddr); err != nil || peer != "127.0.0.1" {
			t.Errorf("v%s: RemoteAddr = %q, want the client's 127.0.0.1:<port>", version, ev.RemoteAddr)
		}
		if !strings.HasPrefix(ev.KeyFingerprint, "SHA256:") {
			t.Errorf("v%s: KeyFingerprint = %q, want the client key's SHA256 fingerprint", version, ev.KeyFingerprint)
		}
		if ev.Bytes <= 0 || ev.Err != nil || ev.Duration <= 0 {
			t.Errorf("v%s: bytes %d, err %v, duration %s; want a successful, non-empty transfer", version, ev.Bytes, ev.Err, ev.Duration)
		}
	}

	// Listing refs opens the same kind of session but asks for no objects.
	gitClient(t, env, tmp, "ls-remote", cloneURL)
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	leftover := events
	mu.Unlock()
	if len(leftover) != 0 {
		t.Fatalf("ls-remote reported a fetch: %+v", leftover)
	}
}

// runGitServer runs a git server-side command on a request body and returns
// what it answered. A command that fails (git refuses the request) simply
// answers without a pack.
func runGitServer(t *testing.T, dir string, env []string, stdin []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	_ = cmd.Run()
	return out.Bytes()
}

// The rule the classification must keep: whatever request the real git answers
// with a pack is recorded. The cases are phrasings of a fetch that a reading of
// only the first pkt-line, or only the first kilobyte, took for something else
// — each is fed to the real `git upload-pack` (and, for the compressed ones, to
// the real `git http-backend`, which is what decodes Content-Encoding on a Git
// server) to see whether it is served, and to DescribeDownload to see whether
// it is recorded.
func TestFetchesGitServesAreAllRecorded(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o755); err != nil {
		t.Fatal(err)
	}
	env := []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	}
	full := append(os.Environ(), env...)
	gitClient(t, full, work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "file.txt"), []byte("the repository content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitClient(t, full, work, "add", ".")
	gitClient(t, full, work, "commit", "-q", "-m", "c1")
	oid := strings.TrimSpace(string(runGitServer(t, work, env, nil, "rev-parse", "HEAD")))
	if len(oid) != 40 {
		t.Fatalf("rev-parse HEAD: %q", oid)
	}
	bare := filepath.Join(root, "repo.git")
	gitClient(t, full, root, "clone", "-q", "--bare", work, bare)

	b := newPassthroughBackend(t, "https://git.example.invalid", upstream.Credentials{}, nil, 0)
	recorded := func(body []byte, encoding string) bool {
		r := uploadPackRequest(body, false)
		if encoding != "" {
			r.Header.Set("Content-Encoding", encoding)
		}
		_, ok := b.DescribeDownload(r, "/o/r.git/git-upload-pack")
		return ok
	}
	// uploadPack feeds a stateless-rpc request to the real git upload-pack.
	uploadPack := func(body []byte, protocol string) []byte {
		e := env
		if protocol != "" {
			e = append(append([]string{}, env...), "GIT_PROTOCOL="+protocol)
		}
		return runGitServer(t, root, e, body, "upload-pack", "--stateless-rpc", bare)
	}
	// httpBackend feeds the request to the real git http-backend (CGI).
	httpBackend := func(body []byte, encoding string) []byte {
		e := append(append([]string{}, env...),
			"GIT_PROJECT_ROOT="+root, "GIT_HTTP_EXPORT_ALL=1", "REQUEST_METHOD=POST",
			"PATH_INFO=/repo.git/git-upload-pack", "CONTENT_TYPE=application/x-git-upload-pack-request",
			"CONTENT_LENGTH="+strconv.Itoa(len(body)), "HTTP_GIT_PROTOCOL=version=2", "GIT_PROTOCOL=version=2",
			"REMOTE_ADDR=127.0.0.1", "REMOTE_USER=", "QUERY_STRING=")
		if encoding != "" {
			e = append(e, "HTTP_CONTENT_ENCODING="+encoding)
		}
		return runGitServer(t, root, e, body, "http-backend")
	}
	hasPack := func(out []byte) bool { return bytes.Contains(out, []byte("PACK")) }

	want := "want " + oid + "\n"
	fetchV2 := pktLine("command=fetch\n") + pktLine("agent=git/2.43.0\n") + "0001" + pktLine(want) + pktLine("done\n") + "0000"
	fetchV0 := pktLine("want "+oid+" side-band-64k shallow agent=git/2.43.0\n") + "0000" + pktLine("done\n")
	capabilityFirst := pktLine("agent=git/2.43.0\n") + pktLine("command=fetch\n") + "0001" + pktLine(want) + pktLine("done\n") + "0000"
	deepenFirst := pktLine("deepen 1\n") + pktLine("want "+oid+" side-band-64k shallow agent=git/2.43.0\n") + "0000" + pktLine("done\n")
	listing := pktLine("command=ls-refs\n") + pktLine("agent=git/2.43.0\n") + "0001" + pktLine("peel\n") + "0000"
	listingCapabilityFirst := pktLine("agent=git/2.43.0\n") + pktLine("command=ls-refs\n") + "0001" + pktLine("peel\n") + "0000"

	cases := []struct {
		name     string
		served   bool // the real git answered with a pack
		recorded bool // DescribeDownload calls it a download
		// mustServe marks what git itself sends: the fixture is broken if git
		// does not serve it.
		mustServe bool
	}{
		{"v2, as git sends it", hasPack(uploadPack([]byte(fetchV2), "version=2")), recorded([]byte(fetchV2), ""), true},
		{"v0, as git sends it", hasPack(uploadPack([]byte(fetchV0), "")), recorded([]byte(fetchV0), ""), true},
		{"v2, a capability line before command=fetch", hasPack(uploadPack([]byte(capabilityFirst), "version=2")), recorded([]byte(capabilityFirst), ""), false},
		{"v0, a deepen line before the first want", hasPack(uploadPack([]byte(deepenFirst), "")), recorded([]byte(deepenFirst), ""), false},
		{"v2 gzip, as git sends it", hasPack(httpBackend(gzipped(t, fetchV2), "gzip")), recorded(gzipped(t, fetchV2), "gzip"), true},
		{"v2 x-gzip", hasPack(httpBackend(gzipped(t, fetchV2), "x-gzip")), recorded(gzipped(t, fetchV2), "x-gzip"), false},
		{"v2 gzip with a 2000-byte header extra field", hasPack(httpBackend(gzipWithExtra(t, fetchV2, 2000), "gzip")), recorded(gzipWithExtra(t, fetchV2, 2000), "gzip"), false},
		{"v2 gzip with a 60000-byte header extra field", hasPack(httpBackend(gzipWithExtra(t, fetchV2, 60000), "gzip")), recorded(gzipWithExtra(t, fetchV2, 60000), "gzip"), false},
		{"v2 gzip opening with 300 empty stored blocks", hasPack(httpBackend(gzipWithEmptyBlocks(t, fetchV2, 300), "gzip")), recorded(gzipWithEmptyBlocks(t, fetchV2, 300), "gzip"), false},
		{"v2 gzip opening with 5000 empty stored blocks", hasPack(httpBackend(gzipWithEmptyBlocks(t, fetchV2, 5000), "gzip")), recorded(gzipWithEmptyBlocks(t, fetchV2, 5000), "gzip"), false},
	}
	servedOddly := 0
	for _, c := range cases {
		t.Logf("%-48s git served a pack: %-5v  recorded: %v", c.name, c.served, c.recorded)
		if c.mustServe && !c.served {
			t.Errorf("%s: git did not serve what git sends — the fixture is broken", c.name)
		}
		if c.served && !c.recorded {
			t.Errorf("%s: git answers with a pack, and the download log would not record it", c.name)
		}
		if c.served && !c.mustServe {
			servedOddly++
		}
	}
	if servedOddly == 0 {
		t.Log("this git serves none of the unusual phrasings; the cases above assert nothing here")
	}

	// The other direction: what the log leaves out, git must not answer with a
	// pack — in either reading of the command section's order.
	for name, body := range map[string]string{"a ref listing": listing, "a ref listing, capability first": listingCapabilityFirst} {
		if recorded([]byte(body), "") {
			t.Errorf("%s is recorded as a download", name)
		}
		if hasPack(uploadPack([]byte(body), "version=2")) {
			t.Errorf("%s: git answered with a pack", name)
		}
	}
}
