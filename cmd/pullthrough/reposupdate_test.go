package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/scan/watch"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// This file holds the end-to-end test of the maintenance updater (Task 182)
// over the real wiring: a bare Git repository on disk with npm, pip, Cargo and
// Go lock files; the real npm, pip, cargo and go backends in front of a stub
// registry that offers, for each package, a safe compatible newer version, a
// malicious one (newer still, and compatible), and an incompatible major
// release; the real cache, gateway and LLM package-content scan gate (with a
// mock model); the registry's Git mirror. It shows the task's acceptance list:
//
//   - only the safe compatible versions land on the maintenance branch, and
//     each skipped candidate is reported with its reason;
//   - the rewritten lock files install with the real npm, pip, cargo and go
//     through the proxy;
//   - a second run is a no-op: nothing is pushed;
//   - a default branch that moves while a run computes is handled: the run
//     starts over on the new head;
//   - a branch someone else pushed to is not overwritten.

// updStub is the stub registry of every ecosystem of the test.
type updStub struct {
	srv   *http.Server
	url   string
	mu    sync.Mutex
	files map[string][]byte
	types map[string]string
}

func newUpdStub(t *testing.T) *updStub {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &updStub{url: "http://" + ln.Addr().String(), files: map[string][]byte{}, types: map[string]string{}}
	s.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.files[r.URL.Path]
		ct := s.types[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		_, _ = w.Write(body)
	})}
	go func() { _ = s.srv.Serve(ln) }()
	t.Cleanup(func() { _ = s.srv.Close() })
	return s
}

func (s *updStub) put(path, contentType string, body []byte) {
	s.mu.Lock()
	s.files[path], s.types[path] = body, contentType
	s.mu.Unlock()
}

// The test's packages: for each ecosystem the pinned version, a safe update, a
// malicious newer one, and a major release.
const (
	pinnedV    = "1.0.0"
	safeV      = "1.0.1"
	maliciousV = "1.1.0"
	majorV     = "2.0.0"
)

var updVersions = []string{pinnedV, safeV, maliciousV, majorV}

// pkgContent returns a version's file content: the malicious one carries the
// marker the mock model keys on.
func pkgContent(version string) string {
	if version == maliciousV {
		return "// " + pkgscantest.MaliciousMarker + "\n// exfiltrates credentials on import\n"
	}
	return "// version " + version + "\n"
}

// --- npm ---------------------------------------------------------------------

func npmUpdTarball(version string) []byte {
	return pkgscantest.NpmTarball("left-pad", version, nil, map[string]string{
		"index.js": pkgContent(version) + "module.exports = (s, n) => String(s).padStart(n);\n",
	})
}

func (s *updStub) publishNPM() map[string][]byte {
	tarballs := map[string][]byte{}
	versions := map[string]any{}
	times := map[string]string{}
	for i, v := range updVersions {
		tb := npmUpdTarball(v)
		tarballs[v] = tb
		sum := sha512.Sum512(tb)
		sha1sum := sha1Hex(tb)
		versions[v] = map[string]any{
			"name": "left-pad", "version": v, "license": "MIT",
			"dist": map[string]any{
				"tarball":   s.url + "/left-pad/-/left-pad-" + v + ".tgz",
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:]),
				"shasum":    sha1sum,
			},
		}
		times[v] = time.Date(2025, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		s.put("/left-pad/-/left-pad-"+v+".tgz", "application/octet-stream", tb)
	}
	doc, _ := json.Marshal(map[string]any{"name": "left-pad", "versions": versions, "time": times,
		"dist-tags": map[string]string{"latest": majorV}})
	s.put("/left-pad", "application/json", doc)
	return tarballs
}

// --- pip ---------------------------------------------------------------------

func pipUpdWheel(version string) []byte {
	di := "tinyutil-" + version + ".dist-info/"
	files := map[string]string{
		"tinyutil/__init__.py": strings.ReplaceAll(pkgContent(version), "//", "#") + "VERSION = '" + version + "'\n",
		di + "METADATA":        "Metadata-Version: 2.1\nName: tinyutil\nVersion: " + version + "\n",
		di + "WHEEL":           "Wheel-Version: 1.0\nGenerator: pullthrough-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
	}
	var record strings.Builder
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sum := sha256.Sum256([]byte(files[n]))
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", n, base64.RawURLEncoding.EncodeToString(sum[:]), len(files[n]))
	}
	record.WriteString(di + "RECORD,,\n")
	files[di+"RECORD"] = record.String()
	return pkgscantest.Zip(files)
}

func (s *updStub) publishPip() map[string][]byte {
	wheels := map[string][]byte{}
	var page strings.Builder
	page.WriteString("<!DOCTYPE html><html><body>\n")
	for _, v := range updVersions {
		whl := pipUpdWheel(v)
		wheels[v] = whl
		file := "tinyutil-" + v + "-py3-none-any.whl"
		sum := sha256.Sum256(whl)
		s.put("/packages/"+file, "application/octet-stream", whl)
		fmt.Fprintf(&page, "<a href=\"%s/packages/%s#sha256=%s\">%s</a><br/>\n", s.url, file, hex.EncodeToString(sum[:]), file)
		meta, _ := json.Marshal(map[string]any{"info": map[string]any{"name": "tinyutil", "version": v, "requires_dist": nil}})
		s.put("/pypi/tinyutil/"+v+"/json", "application/json", meta)
	}
	page.WriteString("</body></html>\n")
	s.put("/simple/tinyutil/", "text/html", []byte(page.String()))
	return wheels
}

// --- cargo -------------------------------------------------------------------

func cargoUpdCrate(version string) []byte {
	return pkgscantest.TarGz(map[string]string{
		"tinycrate-" + version + "/Cargo.toml": "[package]\nname = \"tinycrate\"\nversion = \"" + version + "\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
		"tinycrate-" + version + "/src/lib.rs": pkgContent(version) + "pub fn tiny() -> u32 { 1 }\n",
	})
}

func (s *updStub) publishCargo() map[string][]byte {
	crates := map[string][]byte{}
	var index strings.Builder
	for _, v := range updVersions {
		c := cargoUpdCrate(v)
		crates[v] = c
		sum := sha256.Sum256(c)
		line, _ := json.Marshal(map[string]any{"name": "tinycrate", "vers": v, "deps": []any{}, "cksum": hex.EncodeToString(sum[:]),
			"features": map[string]any{}, "yanked": false})
		index.Write(line)
		index.WriteByte('\n')
		s.put("/api/v1/crates/tinycrate/"+v+"/download", "application/octet-stream", c)
	}
	s.put("/ti/ny/tinycrate", "text/plain", []byte(index.String()))
	cfg, _ := json.Marshal(map[string]string{"dl": s.url + "/api/v1/crates"})
	s.put("/config.json", "application/json", cfg)
	return crates
}

// --- go ----------------------------------------------------------------------

const tinyMod = "example.com/tinymod"

func goUpdMod() []byte { return []byte("module " + tinyMod + "\n\ngo 1.21\n") }

func goUpdZip(version string) []byte {
	prefix := tinyMod + "@v" + version + "/"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{prefix + "go.mod", string(goUpdMod())},
		{prefix + "tiny.go", "package tinymod\n\n" + pkgContent(version) + "// Tiny returns one.\nfunc Tiny() int { return 1 }\n"},
	} {
		w, _ := zw.Create(f.name)
		_, _ = w.Write([]byte(f.body))
	}
	_ = zw.Close()
	return buf.Bytes()
}

func (s *updStub) publishGo() map[string][]byte {
	zips := map[string][]byte{}
	var list strings.Builder
	for i, v := range updVersions {
		gv := "v" + v
		if v == majorV {
			gv = "v" + v + "+incompatible"
			list.WriteString(gv + "\n")
			continue
		}
		list.WriteString(gv + "\n")
		z := goUpdZip(v)
		zips[v] = z
		base := "/" + tinyMod + "/@v/" + gv
		info, _ := json.Marshal(map[string]string{"Version": gv, "Time": time.Date(2025, 1, 1+i, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)})
		s.put(base+".info", "application/json", info)
		s.put(base+".mod", "text/plain", goUpdMod())
		s.put(base+".zip", "application/zip", z)
	}
	s.put("/"+tinyMod+"/@v/list", "text/plain", []byte(list.String()))
	return zips
}

// goH1 is the Go module hash of a module zip (dirhash.HashZip).
func goH1Zip(t *testing.T, z []byte) string {
	zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	files := append([]*zip.File(nil), zr.File...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	h := sha256.New()
	for _, f := range files {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()
		sum := sha256.Sum256(data)
		fmt.Fprintf(h, "%x  %s\n", sum, f.Name)
	}
	return "h1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func goH1Mod(mod []byte) string {
	sum := sha256.Sum256(mod)
	h := sha256.Sum256([]byte(fmt.Sprintf("%x  go.mod\n", sum)))
	return "h1:" + base64.StdEncoding.EncodeToString(h[:])
}

// sha1Hex is npm's shasum: SHA-1, hex.
func sha1Hex(b []byte) string {
	sum := sha1.Sum(b)
	return hex.EncodeToString(sum[:])
}

// --- the project -------------------------------------------------------------

// updProject writes the project's files: manifests and lock files pinning the
// 1.0.0 version of each package, resolved through the proxy at proxyURL.
func updProject(t *testing.T, proxyURL string, npmTB, wheels, crates, zips map[string][]byte) map[string]string {
	sum512 := sha512.Sum512(npmTB[pinnedV])
	lock := map[string]any{
		"name": "widgets", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"": map[string]any{"name": "widgets", "version": "1.0.0", "dependencies": map[string]string{"left-pad": "^1.0.0"}},
			"node_modules/left-pad": map[string]any{
				"version":   pinnedV,
				"resolved":  proxyURL + "/v1/npm/left-pad/-/left-pad-" + pinnedV + ".tgz",
				"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum512[:]),
				"license":   "MIT",
			},
		},
	}
	lockJSON, _ := json.MarshalIndent(lock, "", "  ")
	whlSum := sha256.Sum256(wheels[pinnedV])
	crateSum := sha256.Sum256(crates[pinnedV])
	return map[string]string{
		"package.json":      "{\n  \"name\": \"widgets\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n",
		"package-lock.json": string(lockJSON) + "\n",
		"requirements.txt":  "#\n# This file is autogenerated by pip-compile\n#\ntinyutil==" + pinnedV + " \\\n    --hash=sha256:" + hex.EncodeToString(whlSum[:]) + "\n    # via -r requirements.in\n",
		"Cargo.toml":        "[package]\nname = \"widgets\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntinycrate = \"1.0.0\"\n",
		"Cargo.lock": "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n" +
			"[[package]]\nname = \"tinycrate\"\nversion = \"" + pinnedV + "\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + hex.EncodeToString(crateSum[:]) + "\"\n\n" +
			"[[package]]\nname = \"widgets\"\nversion = \"0.1.0\"\ndependencies = [\n \"tinycrate\",\n]\n",
		"src/main.rs": "fn main() { println!(\"{}\", tinycrate::tiny()); }\n",
		"go.mod":      "module example.com/widgets\n\ngo 1.21\n\nrequire " + tinyMod + " v" + pinnedV + "\n",
		"go.sum":      tinyMod + " v" + pinnedV + " " + goH1Zip(t, zips[pinnedV]) + "\n" + tinyMod + " v" + pinnedV + "/go.mod " + goH1Mod(goUpdMod()) + "\n",
		"main.go":     "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + tinyMod + "\"\n)\n\nfunc main() { fmt.Println(tinymod.Tiny()) }\n",
		"README.md":   "widgets\n",
	}
}

// bareRepo is a bare repository standing in for the Git host, and a working
// clone that pushes to it.
type bareRepo struct {
	t    *testing.T
	bare string
	work *gitRepo
}

func newBareRepo(t *testing.T, files map[string]string) *bareRepo {
	t.Helper()
	work := newGitRepo(t)
	work.commit("initial", files)
	bare := filepath.Join(t.TempDir(), "widgets.git")
	work.git("init", "--quiet", "--bare", "--initial-branch=main", bare)
	work.git("remote", "add", "origin", bare)
	work.git("push", "--quiet", "origin", "main")
	return &bareRepo{t: t, bare: bare, work: work}
}

// commitMain commits to main and pushes it.
func (b *bareRepo) commitMain(msg string, files map[string]string) string {
	b.t.Helper()
	sha := b.work.commit(msg, files)
	b.work.git("push", "--quiet", "origin", "main")
	return sha
}

// ref returns a ref's commit in the bare repository ("" when absent).
func (b *bareRepo) ref(name string) string {
	cmd := exec.Command("git", "-C", b.bare, "rev-parse", "--verify", "--quiet", name)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// show returns a file of a revision of the bare repository.
func (b *bareRepo) show(rev, path string) string {
	b.t.Helper()
	out, err := exec.Command("git", "-C", b.bare, "show", rev+":"+path).Output()
	if err != nil {
		b.t.Fatalf("git show %s:%s: %v", rev, path, err)
	}
	return string(out)
}

// updStack is the proxy as main wires it, without client authentication (the
// real clients pull anonymously), serving on a real listener.
type updStack struct {
	cfg     *config.Config
	svc     *repos.Service
	cache   cache.Cache
	gateway *proxy.Gateway
	url     string
	notes   *recordingNotifier
}

func startUpdStack(t *testing.T, cfg *config.Config, ln net.Listener, stub *updStub, gate *llmpkgscan.Service) *updStack {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	svc, err := buildRepos(context.Background(), cfg, logger)
	if err != nil {
		t.Fatalf("buildRepos: %v", err)
	}
	cacheImpl, err := buildCache(cfg, logger, pinChecker(svc))
	if err != nil {
		t.Fatalf("buildCache: %v", err)
	}
	registry := backends.NewRegistry()
	client := upstream.NewWithHTTPClient(&http.Client{Timeout: 30 * time.Second}, "test/1")
	for name, up := range cfg.Upstreams {
		b, err := buildBackend(cfg, name, up, client, upstream.Credentials{})
		if err != nil {
			t.Fatalf("buildBackend %s: %v", name, err)
		}
		if err := registry.Register(b); err != nil {
			t.Fatal(err)
		}
	}
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cacheImpl, Backends: registry, Pins: pinChecker(svc),
		DownloadLog: dl, Ecosystems: ecosystemMap(cfg), LLMPkgScan: gate,
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	secretsResolver, err := config.NewSecretsResolver(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	notes := &recordingNotifier{}
	if err := wireRepos(ctx, svc, cfg, gw, reposDeps{cache: cacheImpl, logger: logger, llmScan: gate, secrets: secretsResolver, notify: notes}); err != nil {
		t.Fatalf("wireRepos: %v", err)
	}
	srv := &http.Server{Handler: gw.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = srv.Close()
		cancel()
		_ = svc.Close()
		_ = cacheImpl.Close()
	})
	return &updStack{cfg: cfg, svc: svc, cache: cacheImpl, gateway: gw, url: "http://" + ln.Addr().String(), notes: notes}
}

// fakeGitHub answers the pull-request calls of the GitHub REST API for one
// repository, acme/widgets, and records them.
type fakeGitHub struct {
	*httptest.Server
	mu      sync.Mutex
	open    map[string]any // the open pull request, or nil
	calls   []string
	created map[string]any // the body of the last POST /pulls
	auth    []string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/widgets/pulls":
			if f.open == nil {
				_, _ = w.Write([]byte("[]"))
				return
			}
			_ = json.NewEncoder(w).Encode([]any{f.open})
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/pulls":
			f.created = body
			f.open = map[string]any{"number": 7, "html_url": "https://github.example/acme/widgets/pull/7", "state": "open",
				"title": body["title"], "body": body["body"],
				"head": map[string]any{"ref": body["head"], "repo": map[string]any{"full_name": "acme/widgets"}},
				"base": map[string]any{"ref": body["base"]}}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(f.open)
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/widgets/pulls/7":
			f.open["title"], f.open["body"] = body["title"], body["body"]
			_ = json.NewEncoder(w).Encode(f.open)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/widgets/issues/7/labels":
			f.open["labels"] = []any{map[string]any{"name": "dependencies"}}
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeGitHub) record() ([]string, map[string]any, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...), f.created, append([]string(nil), f.auth...)
}

// movingBranches moves the default branch of the remote the first time a
// commit is built: a push that lands while the run computes.
type movingBranches struct {
	repos.BranchSource
	once sync.Once
	move func()
}

func (m *movingBranches) BuildCommit(ctx context.Context, r repos.Repo, spec repos.CommitSpec) (string, string, error) {
	m.once.Do(m.move)
	return m.BranchSource.BuildCommit(ctx, r, spec)
}

func TestMaintenanceUpdaterEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	stub := newUpdStub(t)
	npmTB := stub.publishNPM()
	wheels := stub.publishPip()
	crates := stub.publishCargo()
	zips := stub.publishGo()

	github := newFakeGitHub(t)
	t.Setenv("PT_E2E_FORGE_TOKEN", "ghp_e2e_forge_token")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://" + ln.Addr().String()
	remote := newBareRepo(t, updProject(t, proxyURL, npmTB, wheels, crates, zips))
	head := remote.ref("refs/heads/main")

	base := t.TempDir()
	zero := time.Duration(0)
	cfg := config.Default()
	cfg.Server.PublicURL = proxyURL
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"npm":   {Type: "npm", URL: stub.url},
		"pip":   {Type: "pip", URL: stub.url, Settings: map[string]string{"filesUrl": stub.url}},
		"cargo": {Type: "cargo", URL: stub.url, Settings: map[string]string{"downloadUrl": stub.url}},
		"go":    {Type: "go", URL: stub.url},
	}
	cfg.LLMPackageScan.Enabled = true
	cfg.LLMPackageScan.Provider = "claude"
	cfg.LLMPackageScan.APIKey = "unused: the test builds the gate with a mock model"
	never := -time.Hour
	cfg.Repositories = config.RepositoriesConfig{
		Enabled: true, StateDir: filepath.Join(base, "state"), PollInterval: &zero, AllowedSchemes: []string{"file"},
		Scan: config.RepositoryScanConfig{Interval: never},
		Updates: config.RepositoryUpdatesConfig{Enabled: true, Interval: never,
			PullRequests: config.RepositoryPullRequestsConfig{Enabled: true, Labels: []string{"dependencies"}}},
		Repos: []config.RepositoryConfig{{Name: "widgets", URL: "file://" + remote.bare, Tenant: "team-a",
			Upstreams: map[string]string{"cargo": "cargo"},
			Updates: &config.RepositoryUpdateConfig{Forge: "github", ForgeAPI: github.URL, ForgeRepo: "acme/widgets",
				ForgeTokenRef: "env://PT_E2E_FORGE_TOKEN"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	model := &pkgscantest.Provider{}
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled: true, Provider: model, Model: "mock-model-1", Action: llmpkgscan.ActionBlock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	st := startUpdStack(t, &cfg, ln, stub, gate)
	ctx := context.Background()

	// The first run: only the safe compatible versions land.
	run, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("run %s: %s %s\n%s", run.ID, run.Status, run.Reason, run.Message)
	if run.Status != repos.UpdatePushed || !run.Pushed || run.Base != head {
		t.Fatalf("first run: %s (%s) base %s", run.Status, run.Reason, run.Base)
	}
	want := map[string]string{
		"npm/left-pad":    pinnedV + "->" + safeV,
		"pip/tinyutil":    pinnedV + "->" + safeV,
		"cargo/tinycrate": pinnedV + "->" + safeV,
		"go/" + tinyMod:   "v" + pinnedV + "->v" + safeV,
	}
	got := map[string]string{}
	for _, u := range run.Updates {
		got[u.Type+"/"+u.Name] = u.From + "->" + u.To
		if u.Verdict != repos.VerdictBenign || len(u.ScanIDs) == 0 || u.ScanIDs[0] == "" || u.Method != "native" {
			t.Errorf("%s/%s: verdict %s scans %v method %s", u.Type, u.Name, u.Verdict, u.ScanIDs, u.Method)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("updates: got %v, want %v", got, want)
	}
	// Each malicious candidate and each major release is skipped, with its
	// reason.
	skipped := map[string]string{}
	for _, sk := range run.Skipped {
		skipped[sk.Type+"/"+sk.Name+"@"+sk.To] = sk.Code
	}
	for _, eco := range []string{"npm/left-pad", "pip/tinyutil", "cargo/tinycrate"} {
		if skipped[eco+"@"+maliciousV] != repos.SkipMalicious {
			t.Errorf("%s %s: skipped as %q, want malicious (%v)", eco, maliciousV, skipped[eco+"@"+maliciousV], skipped)
		}
		if skipped[eco+"@"+majorV] != repos.SkipIncompatible {
			t.Errorf("%s %s: skipped as %q, want incompatible", eco, majorV, skipped[eco+"@"+majorV])
		}
	}
	if skipped["go/"+tinyMod+"@v"+maliciousV] != repos.SkipMalicious || skipped["go/"+tinyMod+"@v"+majorV+"+incompatible"] != repos.SkipIncompatible {
		t.Errorf("go skips: %v", skipped)
	}
	branch := remote.ref("refs/heads/pullthrough/maintenance")
	if branch == "" || branch != run.Commit {
		t.Fatalf("maintenance branch at %q, run says %q", branch, run.Commit)
	}
	if parent := remote.ref(branch + "^"); parent != head {
		t.Fatalf("the maintenance commit's parent is %s, want the default branch's head %s", parent, head)
	}
	// The pull request: opened from the branch to the default branch, with the
	// token, the title and the updates.
	calls, created, auths := github.record()
	if run.PullRequest == nil || !run.PullRequest.Created || run.PullRequest.Number != 7 || run.PullRequestError != "" {
		t.Fatalf("pull request: %+v %q (calls %v)", run.PullRequest, run.PullRequestError, calls)
	}
	if created["head"] != "pullthrough/maintenance" || created["base"] != "main" || created["title"] != "Update 4 dependencies" ||
		!strings.Contains(fmt.Sprint(created["body"]), "| `npm/left-pad` | `1.0.0` | `1.0.1` |") {
		t.Fatalf("the pull request opened: %v", created)
	}
	for _, a := range auths {
		if a != "Bearer ghp_e2e_forge_token" {
			t.Fatalf("the forge API was called with %q", a)
		}
	}
	msg := remote.work.git("--git-dir", remote.bare, "log", "-1", "--format=%B", branch)
	for _, needle := range []string{"npm/left-pad 1.0.0 -> 1.0.1", "verdict benign", "scan ", "left-pad 1.0.0 -> 1.1.0: malicious", "2.0.0: incompatible"} {
		if !strings.Contains(msg, needle) {
			t.Errorf("the commit message lacks %q:\n%s", needle, msg)
		}
	}

	// The rewritten lock files hold the safe versions with the digests of
	// their bytes.
	checkLock := func(path string, wantDigest string) {
		t.Helper()
		if body := remote.show(branch, path); !strings.Contains(body, wantDigest) {
			t.Errorf("%s on the branch lacks %s:\n%s", path, wantDigest, body)
		}
	}
	s512 := sha512.Sum512(npmTB[safeV])
	checkLock("package-lock.json", "sha512-"+base64.StdEncoding.EncodeToString(s512[:]))
	checkLock("package-lock.json", proxyURL+"/v1/npm/left-pad/-/left-pad-"+safeV+".tgz")
	ws := sha256.Sum256(wheels[safeV])
	checkLock("requirements.txt", "tinyutil=="+safeV)
	checkLock("requirements.txt", "--hash=sha256:"+hex.EncodeToString(ws[:]))
	cs := sha256.Sum256(crates[safeV])
	checkLock("Cargo.lock", hex.EncodeToString(cs[:]))
	checkLock("go.mod", "require "+tinyMod+" v"+safeV)
	checkLock("go.sum", tinyMod+" v"+safeV+" "+goH1Zip(t, zips[safeV]))
	checkLock("go.sum", tinyMod+" v"+safeV+"/go.mod "+goH1Mod(goUpdMod()))
	if pj := remote.show(branch, "package.json"); pj != remote.show("main", "package.json") {
		t.Errorf("package.json changed:\n%s", pj)
	}
	// Re-parsed, each lock file pins the safe versions and nothing else.
	for _, path := range []string{"package-lock.json", "requirements.txt", "Cargo.lock"} {
		f := lockfiles.ParseFile(nil, nil, path, []byte(remote.show(branch, path)))
		if f == nil || f.Error != "" {
			t.Fatalf("%s does not parse: %+v", path, f)
		}
		for _, d := range f.Dependencies {
			if d.Version == maliciousV || d.Version == majorV {
				t.Errorf("%s pins %s %s", path, d.Name, d.Version)
			}
		}
	}

	// The real clients install the branch through the proxy.
	checkout := t.TempDir()
	remote.work.git("clone", "--quiet", "--branch", "pullthrough/maintenance", remote.bare, checkout)
	installWithRealClients(t, checkout, proxyURL)

	// A second run changes nothing and pushes nothing.
	again, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again.Status != repos.UpdateUnchanged || again.Pushed || remote.ref("refs/heads/pullthrough/maintenance") != branch {
		t.Fatalf("second run: %s (%s), pushed %v", again.Status, again.Reason, again.Pushed)
	}

	// The default branch moves while a run computes: the run starts over on
	// the new head, and the branch is rebuilt on top of it.
	gs, err := watch.NewGitSource(watch.GitSourceOptions{Root: cfg.RepositoriesMirrorDir(),
		Refspecs: []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}, AllowedProtocols: []string{"file"}})
	if err != nil {
		t.Fatal(err)
	}
	var moved string
	st.svc.Attach(repos.Options{Branches: &movingBranches{BranchSource: mirrorBranches{gs: gs}, move: func() {
		moved = remote.commitMain("docs", map[string]string{"README.md": "widgets, moved\n"})
	}}})
	third, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("third run: %v", err)
	}
	if third.Status != repos.UpdatePushed || third.Attempts != 2 || third.Base != moved {
		t.Fatalf("third run: %s (%s), %d attempts, base %s, moved %s", third.Status, third.Reason, third.Attempts, third.Base, moved)
	}
	if third.PullRequest == nil || third.PullRequest.Created || !third.PullRequest.Updated || third.PullRequest.Number != 7 {
		t.Fatalf("the open pull request was not updated: %+v %q", third.PullRequest, third.PullRequestError)
	}
	newBranch := remote.ref("refs/heads/pullthrough/maintenance")
	if parent := remote.ref(newBranch + "^"); parent != moved {
		t.Fatalf("the rebuilt branch's parent is %s, want %s", parent, moved)
	}
	if !strings.Contains(remote.show(newBranch, "README.md"), "moved") || !strings.Contains(remote.show(newBranch, "go.mod"), "v"+safeV) {
		t.Fatalf("the rebuilt branch lacks the new head's change or the update")
	}

	// Someone else pushes to the maintenance branch: it is not overwritten.
	other := remote.work.commit("a human's fix", map[string]string{"NOTES.md": "hand-edited\n"})
	remote.work.git("push", "--quiet", "--force", "origin", other+":refs/heads/pullthrough/maintenance")
	remote.commitMain("more docs", map[string]string{"README.md": "widgets, moved again\n"})
	fourth, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("fourth run: %v", err)
	}
	if fourth.Status != repos.UpdateConflict || fourth.Pushed || remote.ref("refs/heads/pullthrough/maintenance") != other {
		t.Fatalf("fourth run: %s (%s), pushed %v", fourth.Status, fourth.Reason, fourth.Pushed)
	}
	if evs := st.notes.of(notify.EventRepositoryUpdate); len(evs) != 1 || !strings.Contains(evs[0].Summary, "is not overwritten") ||
		strings.Contains(evs[0].Summary, "_is_") {
		t.Fatalf("conflict notifications: %+v", evs)
	}

	// The overview reports the state and the runs.
	ov, err := st.svc.UpdateOverview(ctx, "team-a", "widgets")
	if err != nil || ov.State.LastPushed != newBranch || ov.State.Conflict == "" || len(ov.Runs) != 4 {
		t.Fatalf("overview: %v %+v (%d runs)", err, ov.State, len(ov.Runs))
	}

	// A dry run on request (the API's way: in the background, read back by
	// its ID) computes the commit and pushes nothing; another tenant cannot
	// start one.
	if _, err := st.svc.StartUpdate(ctx, "team-b", "widgets", repos.UpdateOptions{DryRun: true}); err == nil {
		t.Fatal("another tenant started a run")
	}
	started, err := st.svc.StartUpdate(ctx, "team-a", "widgets", repos.UpdateOptions{DryRun: true, By: "test"})
	if err != nil || started.Status != repos.UpdateRunning {
		t.Fatalf("start: %v %+v", err, started)
	}
	deadline := time.Now().Add(time.Minute)
	var dry *repos.UpdateRun
	for {
		dry, err = st.svc.UpdateReport(ctx, "team-a", "widgets", started.ID)
		if err == nil && dry.Status != repos.UpdateRunning {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the dry run did not finish: %v %+v", err, dry)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if dry.Status != repos.UpdateDryRun || dry.Pushed || dry.Commit == "" || remote.ref("refs/heads/pullthrough/maintenance") != other {
		t.Fatalf("dry run: %s (%s) pushed %v", dry.Status, dry.Reason, dry.Pushed)
	}
	if after, _ := st.svc.UpdateOverview(ctx, "team-a", "widgets"); after.State.LastRun != fourth.ID {
		t.Errorf("a dry run moved the schedule's last run to %s", after.State.LastRun)
	}

	// The human's branch is deleted; the next run creates the branch again.
	remote.work.git("push", "--quiet", "origin", "--delete", "pullthrough/maintenance")
	fifth, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil || fifth.Status != repos.UpdatePushed || fifth.Previous != "" {
		t.Fatalf("fifth run: %v %s (%s) previous %q", err, fifth.Status, fifth.Reason, fifth.Previous)
	}
	// The branch is merged: the default branch now pins the safe versions,
	// nothing is left to propose, and the next run deletes the branch.
	merged := remote.ref("refs/heads/pullthrough/maintenance")
	remote.work.git("fetch", "--quiet", "origin")
	remote.work.git("push", "--quiet", "origin", merged+":refs/heads/main")
	sixth, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil || sixth.Status != repos.UpdateRetired || len(sixth.Updates) != 0 || remote.ref("refs/heads/pullthrough/maintenance") != "" {
		t.Fatalf("sixth run: %v %s (%s), branch at %q", err, sixth.Status, sixth.Reason, remote.ref("refs/heads/pullthrough/maintenance"))
	}
	if ov, _ := st.svc.UpdateOverview(ctx, "team-a", "widgets"); ov.State.LastPushed != "" {
		t.Errorf("a retired branch is still the lease: %q", ov.State.LastPushed)
	}
	// And then there is nothing to do: no branch, no push.
	seventh, err := st.svc.RunUpdate(ctx, "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil || seventh.Status != repos.UpdateNone || remote.ref("refs/heads/pullthrough/maintenance") != "" {
		t.Fatalf("seventh run: %v %s (%s)", err, seventh.Status, seventh.Reason)
	}
}

// installWithRealClients installs the checked-out maintenance branch with the
// real npm, pip, cargo and go through the proxy. A client that is not installed
// is skipped, with a note.
func installWithRealClients(t *testing.T, dir, proxyURL string) {
	t.Helper()
	home := t.TempDir()
	env := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "XDG_CACHE_HOME="+filepath.Join(home, ".cache"))
	run := func(name string, extraEnv []string, args ...string) {
		t.Helper()
		if _, err := exec.LookPath(args[0]); err != nil {
			t.Logf("%s is not installed: the %s install is not checked", args[0], name)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(append([]string(nil), env...), extraEnv...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v failed: %v\n%s", name, args, err, out)
		}
		t.Logf("%s: %v ok", name, args)
	}
	run("npm", []string{"npm_config_cache=" + filepath.Join(home, "npm-cache"), "npm_config_update_notifier=false"},
		"npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry="+proxyURL+"/v1/npm/")
	if data, err := os.ReadFile(filepath.Join(dir, "node_modules/left-pad/package.json")); err == nil && !strings.Contains(string(data), `"version":"`+safeV+`"`) && !strings.Contains(string(data), `"version": "`+safeV+`"`) {
		t.Errorf("npm installed another version of left-pad:\n%s", data)
	}
	run("pip", nil, "python3", "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "--require-hashes",
		"--target", filepath.Join(home, "site"), "--index-url", proxyURL+"/v1/pip/simple/", "-r", "requirements.txt")
	if _, err := os.Stat(filepath.Join(home, "site", "tinyutil-"+safeV+".dist-info")); err != nil && fileExists(filepath.Join(home, "site")) {
		t.Errorf("pip did not install tinyutil %s: %v", safeV, err)
	}
	cargoHome := filepath.Join(home, "cargo")
	if err := os.MkdirAll(cargoHome, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte("[source.crates-io]\nreplace-with = \"pt\"\n\n[source.pt]\nregistry = \"sparse+"+proxyURL+"/v1/cargo/\"\n"), 0o644)
	// rustup finds its toolchains under the real home unless told.
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		if h, err := os.UserHomeDir(); err == nil {
			rustupHome = filepath.Join(h, ".rustup")
		}
	}
	run("cargo", []string{"CARGO_HOME=" + cargoHome, "CARGO_TARGET_DIR=" + filepath.Join(home, "target"), "RUSTUP_HOME=" + rustupHome},
		"cargo", "build", "--locked", "--quiet")
	// -modcacherw: the module cache lives in the test's temporary directory,
	// which an unprivileged user (CI) could not remove were it read-only.
	gopath := filepath.Join(home, "go")
	run("go", []string{"GOPROXY=" + proxyURL + "/v1/go", "GOSUMDB=off", "GOFLAGS=-mod=readonly -modcacherw", "GOTOOLCHAIN=local",
		"GOPATH=" + gopath, "GOMODCACHE=" + filepath.Join(gopath, "pkg", "mod"), "GOCACHE=" + filepath.Join(home, "gocache"), "GONOSUMDB=", "GOPRIVATE="},
		"go", "build", "-o", filepath.Join(home, "widgets"), ".")
}

// staticPullthrough builds this binary without cgo, for the sandbox to run as
// its in-container relay.
func staticPullthrough(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "pullthrough")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building a static pullthrough: %v\n%s", err, b)
	}
	return out
}

// TestMaintenanceUpdaterSandboxedResolution updates a dependency whose new
// version declares a new dependency: the lock file cannot be rewritten in
// place, so the real npm re-resolves it in a network-less container whose only
// registry is the proxy's scanned-benign-only session — and the dependency the
// resolution brings in is vetted before anything is pushed. A second package
// whose update would bring in a malicious dependency is not updated.
func TestMaintenanceUpdaterSandboxedResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: no containers")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	const image = "node:22-bookworm-slim"
	if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
		if out, err := exec.Command("docker", "pull", "--quiet", image).CombinedOutput(); err != nil {
			t.Skipf("image %s is not available: %v\n%s", image, err, out)
		}
	}
	stub := newUpdStub(t)
	type pv struct {
		name, version string
		deps          map[string]string
		content       string
	}
	tarballs := map[string][]byte{}
	publish := func(name string, vs []pv) {
		versions := map[string]any{}
		for _, v := range vs {
			tb := pkgscantest.NpmTarball(name, v.version, nil, map[string]string{"index.js": v.content + "module.exports = 1;\n"})
			tarballs[name+"@"+v.version] = tb
			sum := sha512.Sum512(tb)
			entry := map[string]any{"name": name, "version": v.version,
				"dist": map[string]any{"tarball": stub.url + "/" + name + "/-/" + name + "-" + v.version + ".tgz",
					"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}}
			if len(v.deps) > 0 {
				entry["dependencies"] = v.deps
			}
			versions[v.version] = entry
			stub.put("/"+name+"/-/"+name+"-"+v.version+".tgz", "application/octet-stream", tb)
		}
		doc, _ := json.Marshal(map[string]any{"name": name, "versions": versions})
		stub.put("/"+name, "application/json", doc)
	}
	publish("dep-host", []pv{{"dep-host", "1.0.0", nil, "// a\n"}, {"dep-host", "1.0.1", map[string]string{"helper": "^1.0.0"}, "// b\n"}})
	publish("helper", []pv{{"helper", "1.0.0", nil, "// helper\n"}})
	publish("other-host", []pv{{"other-host", "1.0.0", nil, "// c\n"}, {"other-host", "1.0.1", map[string]string{"evil-helper": "^1.0.0"}, "// d\n"}})
	publish("evil-helper", []pv{{"evil-helper", "1.0.0", nil, "// " + pkgscantest.MaliciousMarker + "\n"}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://" + ln.Addr().String()
	entry := func(name, version string) map[string]any {
		sum := sha512.Sum512(tarballs[name+"@"+version])
		return map[string]any{"version": version, "resolved": proxyURL + "/v1/npm/" + name + "/-/" + name + "-" + version + ".tgz",
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(sum[:])}
	}
	deps := map[string]string{"dep-host": "^1.0.0", "other-host": "^1.0.0"}
	lock, _ := json.MarshalIndent(map[string]any{"name": "widgets", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
		"packages": map[string]any{
			"":                        map[string]any{"name": "widgets", "version": "1.0.0", "dependencies": deps},
			"node_modules/dep-host":   entry("dep-host", "1.0.0"),
			"node_modules/other-host": entry("other-host", "1.0.0"),
		}}, "", "  ")
	pj, _ := json.MarshalIndent(map[string]any{"name": "widgets", "version": "1.0.0", "private": true, "dependencies": deps}, "", "  ")
	remote := newBareRepo(t, map[string]string{"package.json": string(pj) + "\n", "package-lock.json": string(lock) + "\n"})
	head := remote.ref("refs/heads/main")

	base := t.TempDir()
	zero := time.Duration(0)
	never := -time.Hour
	cfg := config.Default()
	cfg.Server.PublicURL = proxyURL
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{"npm": {Type: "npm", URL: stub.url}}
	cfg.LLMPackageScan.Enabled = true
	cfg.LLMPackageScan.Provider = "claude"
	cfg.LLMPackageScan.APIKey = "unused"
	cfg.Repositories = config.RepositoriesConfig{
		Enabled: true, StateDir: filepath.Join(base, "state"), PollInterval: &zero, AllowedSchemes: []string{"file"},
		Scan: config.RepositoryScanConfig{Interval: never},
		Updates: config.RepositoryUpdatesConfig{Enabled: true, Interval: never, Sandbox: config.RepositoryUpdateSandboxConfig{
			Runtime: "docker", Forwarder: staticPullthrough(t), Images: map[string]string{"npm": image}, Timeout: 5 * time.Minute}},
		Repos: []config.RepositoryConfig{{Name: "widgets", URL: "file://" + remote.bare, Tenant: "team-a"}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "mock-model-1",
		Action: llmpkgscan.ActionBlock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	st := startUpdStack(t, &cfg, ln, stub, gate)

	run, err := st.svc.RunUpdate(context.Background(), "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("run %s: %s %s\n%s", run.ID, run.Status, run.Reason, run.Message)
	if run.Status != repos.UpdatePushed || len(run.Updates) != 1 || run.Updates[0].Name != "dep-host" || run.Updates[0].Method != "sandbox" {
		t.Fatalf("run: %s (%s) updates %+v skipped %+v lockfiles %+v", run.Status, run.Reason, run.Updates, run.Skipped, run.LockFiles)
	}
	var sawEvil bool
	for _, sk := range run.Skipped {
		if sk.Name == "other-host" && sk.Code == repos.SkipResolution && strings.Contains(sk.Reason, "evil-helper") {
			sawEvil = true
		}
	}
	if !sawEvil {
		t.Fatalf("other-host's update, which brings in a malicious dependency, was not skipped for it: %+v", run.Skipped)
	}
	branch := remote.ref("refs/heads/pullthrough/maintenance")
	if parent := remote.ref(branch + "^"); parent != head {
		t.Fatalf("parent %s, want %s", parent, head)
	}
	got := remote.show(branch, "package-lock.json")
	f := lockfiles.ParseFile(nil, nil, "package-lock.json", []byte(got))
	pins := map[string]string{}
	for _, d := range f.Dependencies {
		pins[d.Name] = d.Version
	}
	if pins["dep-host"] != "1.0.1" || pins["helper"] != "1.0.0" || pins["other-host"] != "1.0.0" || pins["evil-helper"] != "" {
		t.Fatalf("the re-resolved lock pins %v:\n%s", pins, got)
	}
	if strings.Contains(got, "127.0.0.1:8080") || !strings.Contains(got, proxyURL+"/v1/npm/helper/-/helper-1.0.0.tgz") {
		t.Fatalf("the resolved URLs do not point at the registry the lock file used:\n%s", got)
	}
	// The real npm installs it through the proxy.
	checkout := t.TempDir()
	remote.work.git("clone", "--quiet", "--branch", "pullthrough/maintenance", remote.bare, checkout)
	home := t.TempDir()
	cmd := exec.Command("npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--registry="+proxyURL+"/v1/npm/")
	cmd.Dir = checkout
	cmd.Env = append(os.Environ(), "HOME="+home, "npm_config_cache="+filepath.Join(home, "cache"))
	if _, err := exec.LookPath("npm"); err == nil {
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("npm ci: %v\n%s", err, out)
		}
	}
}

// TestMaintenanceUpdaterSandboxedCargoAndGo re-resolves a Cargo.lock and a
// go.mod/go.sum in the sandbox with the real cargo and go: each update's new
// version requires a crate or module the lock file does not pin yet.
func TestMaintenanceUpdaterSandboxedCargoAndGo(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: no containers")
	}
	for _, tool := range []string{"docker", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	images := map[string]string{"cargo": "rust:1-slim", "go": "golang:1.24-alpine"}
	for _, image := range images {
		if err := exec.Command("docker", "image", "inspect", image).Run(); err != nil {
			if out, err := exec.Command("docker", "pull", "--quiet", image).CombinedOutput(); err != nil {
				t.Skipf("image %s is not available: %v\n%s", image, err, out)
			}
		}
	}
	stub := newUpdStub(t)

	// Cargo: host-crate 1.0.1 adds a dependency on helper-crate.
	crates := map[string][]byte{}
	crateIndex := map[string]*strings.Builder{}
	publishCrate := func(name, version string, deps []map[string]any) {
		c := pkgscantest.TarGz(map[string]string{
			name + "-" + version + "/Cargo.toml": "[package]\nname = \"" + name + "\"\nversion = \"" + version + "\"\nedition = \"2021\"\n",
			name + "-" + version + "/src/lib.rs": "pub fn f() {}\n",
		})
		crates[name+"@"+version] = c
		sum := sha256.Sum256(c)
		if deps == nil {
			deps = []map[string]any{}
		}
		line, _ := json.Marshal(map[string]any{"name": name, "vers": version, "deps": deps, "cksum": hex.EncodeToString(sum[:]), "features": map[string]any{}, "yanked": false})
		if crateIndex[name] == nil {
			crateIndex[name] = &strings.Builder{}
		}
		crateIndex[name].Write(line)
		crateIndex[name].WriteByte('\n')
		stub.put("/api/v1/crates/"+name+"/"+version+"/download", "application/octet-stream", c)
	}
	publishCrate("host-crate", "1.0.0", nil)
	publishCrate("host-crate", "1.0.1", []map[string]any{{"name": "helper-crate", "req": "^1", "features": []string{}, "optional": false,
		"default_features": true, "target": nil, "kind": "normal"}})
	publishCrate("helper-crate", "1.0.0", nil)
	stub.put("/ho/st/host-crate", "text/plain", []byte(crateIndex["host-crate"].String()))
	stub.put("/he/lp/helper-crate", "text/plain", []byte(crateIndex["helper-crate"].String()))
	cfgJSON, _ := json.Marshal(map[string]string{"dl": stub.url + "/api/v1/crates"})
	stub.put("/config.json", "application/json", cfgJSON)

	// Go: example.com/hostmod v1.0.1 requires example.com/helpermod.
	goMods := map[string][]byte{}
	goZips := map[string][]byte{}
	publishMod := func(mod, version, gomod string) {
		zipBuf := &bytes.Buffer{}
		zw := zip.NewWriter(zipBuf)
		for name, body := range map[string]string{"go.mod": gomod, "x.go": "package " + mod[strings.LastIndex(mod, "/")+1:] + "\n\nfunc F() {}\n"} {
			w, _ := zw.Create(mod + "@" + version + "/" + name)
			_, _ = w.Write([]byte(body))
		}
		_ = zw.Close()
		goMods[mod+"@"+version], goZips[mod+"@"+version] = []byte(gomod), zipBuf.Bytes()
		base := "/" + mod + "/@v/" + version
		stub.put(base+".info", "application/json", []byte(`{"Version":"`+version+`","Time":"2025-01-01T00:00:00Z"}`))
		stub.put(base+".mod", "text/plain", []byte(gomod))
		stub.put(base+".zip", "application/zip", zipBuf.Bytes())
	}
	publishMod("example.com/hostmod", "v1.0.0", "module example.com/hostmod\n\ngo 1.21\n")
	publishMod("example.com/hostmod", "v1.0.1", "module example.com/hostmod\n\ngo 1.21\n\nrequire example.com/helpermod v1.0.0\n")
	publishMod("example.com/helpermod", "v1.0.0", "module example.com/helpermod\n\ngo 1.21\n")
	stub.put("/example.com/hostmod/@v/list", "text/plain", []byte("v1.0.0\nv1.0.1\n"))
	stub.put("/example.com/helpermod/@v/list", "text/plain", []byte("v1.0.0\n"))

	crateSum := sha256.Sum256(crates["host-crate@1.0.0"])
	project := map[string]string{
		"rust/Cargo.toml": "[package]\nname = \"widgets\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhost-crate = \"1.0.0\"\n",
		"rust/Cargo.lock": "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n" +
			"[[package]]\nname = \"host-crate\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"" + hex.EncodeToString(crateSum[:]) + "\"\n\n" +
			"[[package]]\nname = \"widgets\"\nversion = \"0.1.0\"\ndependencies = [\n \"host-crate\",\n]\n",
		"rust/src/main.rs":        "fn main() { host_crate::f(); }\n",
		"rust/.cargo/config.toml": "[net]\noffline = true\n", // never given to the sandbox
		"golang/go.mod":           "module example.com/widgets\n\ngo 1.21\n\nrequire example.com/hostmod v1.0.0\n",
		"golang/go.sum": "example.com/hostmod v1.0.0 " + goH1Zip(t, goZips["example.com/hostmod@v1.0.0"]) + "\nexample.com/hostmod v1.0.0/go.mod " +
			goH1Mod(goMods["example.com/hostmod@v1.0.0"]) + "\n",
		"golang/main.go": "package main\n\nimport \"example.com/hostmod\"\n\nfunc main() { hostmod.F() }\n",
	}
	remote := newBareRepo(t, project)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := "http://" + ln.Addr().String()
	base := t.TempDir()
	zero := time.Duration(0)
	never := -time.Hour
	cfg := config.Default()
	cfg.Server.PublicURL = proxyURL
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"cargo": {Type: "cargo", URL: stub.url, Settings: map[string]string{"downloadUrl": stub.url}},
		"go":    {Type: "go", URL: stub.url},
	}
	cfg.LLMPackageScan.Enabled = true
	cfg.LLMPackageScan.Provider = "claude"
	cfg.LLMPackageScan.APIKey = "unused"
	cfg.Repositories = config.RepositoriesConfig{
		Enabled: true, StateDir: filepath.Join(base, "state"), PollInterval: &zero, AllowedSchemes: []string{"file"},
		Scan: config.RepositoryScanConfig{Interval: never},
		Updates: config.RepositoryUpdatesConfig{Enabled: true, Interval: never, Sandbox: config.RepositoryUpdateSandboxConfig{
			Runtime: "docker", Forwarder: staticPullthrough(t), Images: images, Timeout: 5 * time.Minute}},
		Repos: []config.RepositoryConfig{{Name: "widgets", URL: "file://" + remote.bare, Tenant: "team-a",
			Upstreams: map[string]string{"cargo": "cargo"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "mock-model-1",
		Action: llmpkgscan.ActionBlock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	st := startUpdStack(t, &cfg, ln, stub, gate)

	run, err := st.svc.RunUpdate(context.Background(), "", "widgets", repos.UpdateOptions{By: "test"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	t.Logf("run %s: %s %s\n%s", run.ID, run.Status, run.Reason, run.Message)
	methods := map[string]string{}
	for _, u := range run.Updates {
		methods[u.Type+"/"+u.Name+"@"+u.To] = u.Method
	}
	if run.Status != repos.UpdatePushed || methods["cargo/host-crate@1.0.1"] != "sandbox" || methods["go/example.com/hostmod@v1.0.1"] != "sandbox" {
		t.Fatalf("run: %s (%s) updates %v skipped %+v lockfiles %+v", run.Status, run.Reason, methods, run.Skipped, run.LockFiles)
	}
	branch := remote.ref("refs/heads/pullthrough/maintenance")
	lock := remote.show(branch, "rust/Cargo.lock")
	helperSum := sha256.Sum256(crates["helper-crate@1.0.0"])
	if !strings.Contains(lock, "name = \"host-crate\"\nversion = \"1.0.1\"") || !strings.Contains(lock, hex.EncodeToString(helperSum[:])) {
		t.Fatalf("Cargo.lock after the sandboxed cargo:\n%s", lock)
	}
	gomod, gosum := remote.show(branch, "golang/go.mod"), remote.show(branch, "golang/go.sum")
	if !strings.Contains(gomod, "example.com/hostmod v1.0.1") || !strings.Contains(gosum, "example.com/hostmod v1.0.1 "+goH1Zip(t, goZips["example.com/hostmod@v1.0.1"])) {
		t.Fatalf("go.mod/go.sum after the sandboxed go:\n%s\n%s", gomod, gosum)
	}
	if remote.show(branch, "rust/.cargo/config.toml") != project["rust/.cargo/config.toml"] {
		t.Fatal("the repository's own cargo configuration changed")
	}

	// What the tools resolved builds with the real cargo and go, through the
	// proxy, without changing the lock files.
	checkout := t.TempDir()
	remote.work.git("clone", "--quiet", "--branch", "pullthrough/maintenance", remote.bare, checkout)
	home := t.TempDir()
	build := func(name, dir string, env []string, args ...string) {
		t.Helper()
		if _, err := exec.LookPath(args[0]); err != nil {
			t.Logf("%s is not installed: the build is not checked", args[0])
			return
		}
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = filepath.Join(checkout, dir)
		cmd.Env = append(append(os.Environ(), "HOME="+home), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
	}
	cargoHome := filepath.Join(home, "cargo")
	_ = os.MkdirAll(cargoHome, 0o755)
	_ = os.WriteFile(filepath.Join(cargoHome, "config.toml"), []byte("[source.crates-io]\nreplace-with = \"pt\"\n\n[source.pt]\nregistry = \"sparse+"+proxyURL+"/v1/cargo/\"\n"), 0o644)
	// The repository's own .cargo/config.toml (offline) is in the checkout;
	// cargo build is told to fetch anyway.
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		if h, err := os.UserHomeDir(); err == nil {
			rustupHome = filepath.Join(h, ".rustup")
		}
	}
	build("cargo", "rust", []string{"CARGO_HOME=" + cargoHome, "CARGO_NET_OFFLINE=false", "RUSTUP_HOME=" + rustupHome,
		"CARGO_TARGET_DIR=" + filepath.Join(home, "target")}, "cargo", "build", "--locked", "--quiet")
	// -modcacherw: the module cache lives in the test's temporary directory,
	// which an unprivileged user (CI) could not remove were it read-only.
	gopath := filepath.Join(home, "go")
	build("go", "golang", []string{"GOPROXY=" + proxyURL + "/v1/go", "GOSUMDB=off", "GOFLAGS=-mod=readonly -modcacherw", "GOTOOLCHAIN=local",
		"GOPATH=" + gopath, "GOMODCACHE=" + filepath.Join(gopath, "pkg", "mod"), "GOCACHE=" + filepath.Join(home, "gocache"), "GONOSUMDB=", "GOPRIVATE="},
		"go", "build", "-o", filepath.Join(home, "widgets"), ".")
}

// fixedPublished dates every version as published at one instant.
type fixedPublished time.Time

func (f fixedPublished) PublishedAt(context.Context, maturity.Coordinate) (time.Time, bool, error) {
	return time.Time(f), true, nil
}

// TestCandidatePolicyHonoursTheFirewallAndTheCooldown: a maintenance candidate
// is held to the dependency firewall and the maturity cooldown before it is
// fetched; with neither configured, everything is admitted.
func TestCandidatePolicyHonoursTheFirewallAndTheCooldown(t *testing.T) {
	fw, err := depfirewall.NewService(depfirewall.Config{Rules: []depfirewall.Rule{{Ecosystem: "npm", Name: "left-pad", Denied: []string{"1.0.2"}}}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	mat := maturity.NewService(maturity.Config{DefaultCooldown: 72 * time.Hour, Resolver: fixedPublished(now.Add(-time.Hour)),
		Allowlist: []string{"npm:trusted"}, Now: func() time.Time { return now }})
	p := candidatePolicy{firewall: fw, maturity: mat}
	if ok, code, _ := p.CheckCandidate("team-a", "npm", "left-pad", "1.0.2"); ok || code != repos.SkipFirewall {
		t.Errorf("a denied version: ok %v code %q", ok, code)
	}
	if ok, code, why := p.CheckCandidate("team-a", "npm", "left-pad", "1.0.3"); ok || code != repos.SkipCooldown || !strings.Contains(why, "cooldown") {
		t.Errorf("a version published an hour ago: ok %v code %q (%s)", ok, code, why)
	}
	if ok, _, why := p.CheckCandidate("team-a", "npm", "trusted", "9.9.9"); !ok {
		t.Errorf("an allowlisted coordinate: %s", why)
	}
	if ok, _, _ := (candidatePolicy{}).CheckCandidate("team-a", "npm", "left-pad", "1.0.2"); !ok {
		t.Error("with neither service, a candidate must pass")
	}
}
