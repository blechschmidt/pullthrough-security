package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/cache"
	"github.com/blechschmidt/pullthrough-security/internal/cachegc"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/repos"
	"github.com/blechschmidt/pullthrough-security/internal/repos/locate"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// This file holds the end-to-end test of release pinning (Task 180) over the
// real wiring: a Git repository on disk with real lock files, the real npm and
// cargo backends in front of a stub registry, the real filesystem cache, the
// gateway's gated serve pipeline, and the registry's Git mirror and lock-file
// scanner. What it shows is the task's acceptance list:
//
//   - moving a tag keeps both commits' artifacts pinned and resolvable — served
//     from the cache with the upstream gone;
//   - a GC pass after the move deletes nothing pinned (while it does delete what
//     is not), and neither does LRU eviction for size;
//   - everything survives a restart: history, manifests, pins;
//   - tenants are isolated: each sees its own releases, and each tenant's
//     dependencies are fetched — and cached, and pinned — under its own
//     namespace.

// teamAToken is the API token of team-a's client.
const teamAToken = "team-a-ci-token-0123456789abcdef"

// stubRegistry serves npm tarballs and cargo crates.
type stubRegistry struct {
	*httptest.Server
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
}

func newStubRegistry(t *testing.T) *stubRegistry {
	s := &stubRegistry{files: map[string][]byte{}, hits: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		body, ok := s.files[r.URL.Path]
		s.hits[r.URL.Path]++
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stubRegistry) publish(path string, body []byte) {
	s.mu.Lock()
	s.files[path] = body
	s.mu.Unlock()
}

// gitRepo is a repository on disk the test commits lock files to.
type gitRepo struct {
	t   *testing.T
	dir string
}

func newGitRepo(t *testing.T) *gitRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	g := &gitRepo{t: t, dir: t.TempDir()}
	g.git("init", "--quiet", "--initial-branch=main")
	return g
}

func (g *gitRepo) git(args ...string) string {
	g.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = g.dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_NOSYSTEM=1", "HOME="+g.dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		g.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// commit writes files and commits them, returning the commit ID.
func (g *gitRepo) commit(msg string, files map[string]string) string {
	g.t.Helper()
	for name, content := range files {
		p := filepath.Join(g.dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			g.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			g.t.Fatal(err)
		}
	}
	g.git("add", "-A")
	g.git("commit", "--quiet", "-m", msg)
	return g.git("rev-parse", "HEAD")
}

func npmLock(registry string, pkgs map[string][]byte) string {
	var b strings.Builder
	b.WriteString(`{"name":"widgets","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"widgets","version":"1.0.0"}`)
	for nv, body := range pkgs {
		name, version, _ := strings.Cut(nv, "@")
		sum := sha512.Sum512(body)
		fmt.Fprintf(&b, `,"node_modules/%s":{"version":%q,"resolved":"%s/%s/-/%s-%s.tgz","integrity":"sha512-%s"}`,
			name, version, registry, name, name, version, base64.StdEncoding.EncodeToString(sum[:]))
	}
	b.WriteString(`}}`)
	return b.String()
}

func cargoLock(name, version string, body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("version = 4\n\n[[package]]\nname = \"widgets\"\nversion = \"0.1.0\"\ndependencies = [\"%s\"]\n\n"+
		"[[package]]\nname = %q\nversion = %q\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = %q\n",
		name, name, version, hex.EncodeToString(sum[:]))
}

// releaseStack is the proxy as main wires it, cut down to what pinning needs.
type releaseStack struct {
	cfg     *config.Config
	svc     *repos.Service
	cache   cache.Cache
	gateway *proxy.Gateway
	log     *downloadlog.Log
	handler http.Handler
}

func startReleaseStack(t *testing.T, cfg *config.Config, stub *stubRegistry) *releaseStack {
	t.Helper()
	return startReleaseStackWith(t, cfg, stub, stackExtras{})
}

// stackExtras are the collaborators a test adds to the release stack: the LLM
// package-content scan gate and the findings layer (Task 181).
type stackExtras struct {
	llm      *llmpkgscan.Service
	findings *findings.Store
	ledger   *findings.SuppressionLedger
	notify   notify.Emitter
	policy   *policyengine.Engine
}

func startReleaseStackWith(t *testing.T, cfg *config.Config, stub *stubRegistry, extra stackExtras) *releaseStack {
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
	for name, up := range cfg.Upstreams {
		b, err := buildBackend(cfg, name, up, upstream.NewWithHTTPClient(stub.Client(), "test/1"), upstream.Credentials{})
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
	// Clients authenticate with a token of their tenant: team-a's client
	// reads team-a's cache namespace.
	az, err := auth.NewAuthorizer([]auth.Role{{Name: "reader", Ecosystems: []string{"*"}, Upstreams: []string{"*"}}})
	if err != nil {
		t.Fatal(err)
	}
	ta, err := auth.NewTokenAuthenticator([]auth.TokenEntry{
		{Name: "ci-a", Team: "team-a", Roles: []string{"reader"}, Secret: teamAToken},
	})
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := auth.NewEnforcer(auth.EnforcerOptions{Authenticator: ta, Authorizer: az, Quota: auth.NewQuotaManager(auth.QuotaOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cacheImpl, Backends: registry, Pins: pinChecker(svc),
		DownloadLog: dl, Ecosystems: ecosystemMap(cfg), Enforcer: enforcer,
		LLMPkgScan: extra.llm, Findings: extra.findings, Suppressions: extra.ledger, Notify: extra.notify,
		PolicyEngine: extra.policy,
	}, proxy.Options{HTTPAddr: ":0", CacheNamespacing: true})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if err := wireRepos(ctx, svc, cfg, gw, reposDeps{cache: cacheImpl, logger: logger, notify: extra.notify,
		llmScan: extra.llm, findings: extra.findings, suppressions: extra.ledger}); err != nil {
		t.Fatalf("wireRepos: %v", err)
	}
	st := &releaseStack{cfg: cfg, svc: svc, cache: cacheImpl, gateway: gw, log: dl, handler: gw.Handler()}
	t.Cleanup(func() {
		cancel()
		_ = svc.Close()
		_ = cacheImpl.Close()
	})
	return st
}

func (s *releaseStack) stop() {
	_ = s.svc.Close()
	_ = s.cache.Close()
}

// waitPinned waits until the release of commit has been through a pinning
// attempt.
func waitPinned(t *testing.T, svc *repos.Service, repo, commit string) repos.ReleaseView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		rel, err := svc.Releases(context.Background(), "", repos.ReleaseQuery{Repo: repo, Commit: commit, Full: true})
		if err == nil && len(rel) == 1 && rel[0].Status != repos.ReleasePending {
			return rel[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("release %s@%s not pinned in time: %v %+v", repo, commit, err, rel)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func pinnedKeys(v repos.ReleaseView) []string {
	var keys []string
	for _, d := range v.Manifest.Dependencies {
		for _, o := range d.Objects {
			if o.Status == repos.StatusPinned {
				keys = append(keys, o.CacheKey)
			}
		}
	}
	return keys
}

func TestReleasePinningEndToEnd(t *testing.T) {
	stub := newStubRegistry(t)
	leftPad100 := []byte("left-pad 1.0.0 tarball")
	leftPad110 := []byte("left-pad 1.1.0 tarball")
	itoa := []byte("itoa 1.0.11 crate")
	stub.publish("/left-pad/-/left-pad-1.0.0.tgz", leftPad100)
	stub.publish("/left-pad/-/left-pad-1.1.0.tgz", leftPad110)
	stub.publish("/api/v1/crates/itoa/1.0.11/download", itoa)

	repo := newGitRepo(t)
	// The npm lock file was resolved against the registry the proxy's npm
	// upstream fronts; Cargo.lock names crates.io, which the repository is
	// configured to fetch through the cargo upstream.
	commitA := repo.commit("release 1.0", map[string]string{
		"package-lock.json": npmLock(stub.URL, map[string][]byte{"left-pad@1.0.0": leftPad100}),
		"Cargo.lock":        cargoLock("itoa", "1.0.11", itoa),
	})
	repo.git("tag", "v1.0")
	commitB := repo.commit("release 1.0, again", map[string]string{
		"package-lock.json": npmLock(stub.URL, map[string][]byte{"left-pad@1.1.0": leftPad110}),
	})

	base := t.TempDir()
	zero := time.Duration(0)
	cfg := config.Default()
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"npm":   {Type: "npm", URL: stub.URL},
		"cargo": {Type: "cargo", URL: stub.URL, Settings: map[string]string{"downloadUrl": stub.URL}},
	}
	cfg.Repositories = config.RepositoriesConfig{
		Enabled: true, StateDir: filepath.Join(base, "state"), PollInterval: &zero, AllowedSchemes: []string{"file"},
		// The release pinner fetches with the role team-a's clients hold.
		Roles: []string{"reader"},
		Repos: []config.RepositoryConfig{{Name: "widgets", URL: "file://" + repo.dir, Tenant: "team-a", Upstreams: map[string]string{"cargo": "cargo"}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	st := startReleaseStack(t, &cfg, stub)
	ctx := context.Background()

	// v1.0 at A: pinned.
	if res, err := st.svc.Sync(ctx, "widgets", "manual"); err != nil || res.Created != 1 {
		t.Fatalf("sync: %+v %v", res, err)
	}
	relA := waitPinned(t, st.svc, "widgets", commitA)
	if !relA.FullyPinned || relA.Summary.Dependencies != 2 || relA.Summary.PinnedObjects != 2 {
		t.Fatalf("release A: %s %q %+v", relA.Status, relA.Reason, relA.Summary)
	}
	for _, d := range relA.Manifest.Dependencies {
		o := d.Objects[0]
		if o.Check == nil || o.Check.Status != "verified" {
			t.Fatalf("%s was not verified against the lock file: %+v", d.Coordinate(), o.Check)
		}
		if !strings.HasPrefix(o.CacheKey, "team-a/") {
			t.Fatalf("%s is not in team-a's cache namespace: %s", d.Coordinate(), o.CacheKey)
		}
	}

	// Force-move v1.0 to B.
	repo.git("tag", "-f", "v1.0", commitB)
	if res, err := st.svc.Sync(ctx, "widgets", "manual"); err != nil || res.Moved != 1 {
		t.Fatalf("sync after the move: %+v %v", res, err)
	}
	relB := waitPinned(t, st.svc, "widgets", commitB)
	if !relB.FullyPinned {
		t.Fatalf("release B: %s %q", relB.Status, relB.Reason)
	}
	rel, err := st.svc.Releases(ctx, "", repos.ReleaseQuery{Repo: "widgets", Tag: "v1.0"})
	if err != nil || len(rel) != 2 {
		t.Fatalf("releases of v1.0: %v %+v", err, rel)
	}
	for _, r := range rel {
		want := repos.ReleaseHistorical
		if r.Commit == commitB {
			want = repos.ReleaseCurrent
		}
		if r.State != want || !r.FullyPinned {
			t.Fatalf("%s: state %s pinned %v", r.Commit, r.State, r.FullyPinned)
		}
	}
	keys := append(pinnedKeys(relA), pinnedKeys(relB)...)
	for _, k := range keys {
		if !st.svc.IsPinned(k) {
			t.Fatalf("%s is not pinned", k)
		}
	}

	// A GC pass with everything over the watermark and past its TTL deletes
	// what is not pinned and nothing that is.
	if _, err := st.cache.Put(ctx, "scratch/filler", bytes.NewReader(bytes.Repeat([]byte{'f'}, 4096)), nil); err != nil {
		t.Fatal(err)
	}
	gcCache, ok := st.cache.(cachegc.Cache)
	if !ok {
		t.Fatal("the cache does not support lifecycle management")
	}
	engine, err := cachegc.New(cachegc.Config{Enabled: true, CapacityBytes: 1, DefaultTTL: time.Nanosecond},
		gcCache, cachegc.Options{Sources: []cachegc.ReferenceSource{releaseGCSource(st.svc)}})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	rep, err := engine.Run(ctx, false)
	if err != nil {
		t.Fatalf("gc: %v", err)
	}
	if rep.EvictedCount == 0 || rep.Errors != 0 {
		t.Fatalf("gc evicted %d with %d errors: %+v", rep.EvictedCount, rep.Errors, rep.Evicted)
	}
	for _, e := range rep.Evicted {
		if st.svc.IsPinned(e.Key) {
			t.Fatalf("gc evicted pinned %s", e.Key)
		}
	}
	for _, k := range keys {
		if _, err := st.cache.Stat(ctx, k); err != nil {
			t.Fatalf("pinned %s is gone after gc: %v", k, err)
		}
	}
	if _, err := st.cache.Stat(ctx, "scratch/filler"); err == nil {
		t.Fatal("gc should have reclaimed the unpinned filler")
	}

	// Both releases resolve from the cache with the upstream gone.
	stub.Close()
	for _, p := range []string{"/v1/npm/left-pad/-/left-pad-1.0.0.tgz", "/v1/npm/left-pad/-/left-pad-1.1.0.tgz", "/v1/cargo/api/v1/crates/itoa/1.0.11/download"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+teamAToken)
		rr := httptest.NewRecorder()
		st.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "HIT" {
			t.Fatalf("%s: %d %s %q", p, rr.Code, rr.Header().Get("X-Cache"), rr.Body.String())
		}
	}

	// The system fetches are in the download log.
	res, err := st.log.Query(downloadlog.Query{Via: downloadlog.ViaSystem, Limit: -1})
	if err != nil || res.Total < 3 {
		t.Fatalf("download log: %v %d", err, res.Total)
	}
	for _, e := range res.Entries {
		if e.Subject != "system:release-pinner" || e.Tenant != "team-a" {
			t.Fatalf("entry %+v", e)
		}
	}

	// Restart: everything is read back from disk.
	st.stop()
	stub2 := newStubRegistry(t) // the upstream stays gone: nothing is re-fetched
	cfg2 := cfg
	cfg2.Upstreams = map[string]config.UpstreamConfig{
		"npm":   {Type: "npm", URL: stub2.URL},
		"cargo": {Type: "cargo", URL: stub2.URL, Settings: map[string]string{"downloadUrl": stub2.URL}},
	}
	st2 := startReleaseStack(t, &cfg2, stub2)
	for _, k := range keys {
		if !st2.svc.IsPinned(k) {
			t.Fatalf("%s lost its pin across the restart", k)
		}
		if _, err := st2.cache.Stat(ctx, k); err != nil {
			t.Fatalf("%s is not in the cache after the restart: %v", k, err)
		}
	}
	assoc, err := st2.svc.TagHistory(ctx, "", "widgets", "v1.0")
	if err != nil || len(assoc) != 2 || assoc[0].Commit != commitB || assoc[1].Commit != commitA {
		t.Fatalf("history after the restart: %v %+v", err, assoc)
	}
	if res, err := st2.svc.Sync(ctx, "widgets", "manual"); err != nil || res.Created+res.Moved+res.Deleted != 0 {
		t.Fatalf("a restart must not re-record tags: %+v %v", res, err)
	}
	if n := len(stub2.hits); n != 0 {
		t.Fatalf("the restart fetched from upstream: %v", stub2.hits)
	}

	// Tenant isolation: team-b registers its own repository pinning the same
	// package; each tenant sees its own release, under its own cache key.
	stub2.publish("/left-pad/-/left-pad-1.0.0.tgz", leftPad100)
	other := newGitRepo(t)
	commitC := other.commit("gadgets 9", map[string]string{
		"package-lock.json": npmLock(stub2.URL, map[string][]byte{"left-pad@1.0.0": leftPad100}),
	})
	other.git("tag", "v9")
	if _, err := st2.svc.Add(ctx, repos.Repo{Name: "gadgets", URL: "file://" + other.dir, Tenant: "team-b"}, "test"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := st2.svc.Sync(ctx, "gadgets", "manual"); err != nil {
		t.Fatal(err)
	}
	relC := waitPinned(t, st2.svc, "gadgets", commitC)
	if !relC.FullyPinned {
		t.Fatalf("release C: %s %q", relC.Status, relC.Reason)
	}
	keyC := pinnedKeys(relC)[0]
	if !strings.HasPrefix(keyC, "team-b/") {
		t.Fatalf("team-b's dependency is not in its namespace: %s", keyC)
	}
	for tenant, want := range map[string]string{"team-a": "widgets", "team-b": "gadgets"} {
		hits, err := st2.svc.Lookup(ctx, tenant, repos.LookupQuery{Type: "npm", Name: "left-pad", Version: "1.0.0"})
		if err != nil || len(hits) != 1 || hits[0].Repo != want {
			t.Fatalf("%s: %v %+v", tenant, err, hits)
		}
		list, _ := st2.svc.List(ctx, tenant)
		if len(list) != 1 || list[0].Name != want {
			t.Fatalf("%s lists %+v", tenant, list)
		}
	}
	if _, err := st2.svc.Releases(ctx, "team-b", repos.ReleaseQuery{Repo: "widgets"}); err == nil {
		t.Fatal("team-b reads team-a's releases")
	}
}

// Backups include the registry's registrations, histories and manifests (the
// pins) — and not the volatile tracking state or the mirrors, which change at
// every poll and are rebuilt.
func TestRepositoryStateIsABackupSource(t *testing.T) {
	cfg := config.Default()
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = "/var/lib/pt/cache"
	cfg.Repositories.Enabled = true
	got := map[string]string{}
	for _, src := range backupMetadataSources(&cfg) {
		got[src.name] = src.path
	}
	state := cfg.RepositoriesStateDir()
	for name, sub := range map[string]string{"repos-registry": "repos", "repos-history": "history", "repos-manifests": "manifests", "repos-scans": "scans",
		"repos-updates": "updatestate", "repos-update-runs": "updates", "repos-update-dry-runs": "updatedry"} {
		if got[name] != filepath.Join(state, sub) {
			t.Errorf("%s = %q, want %q", name, got[name], filepath.Join(state, sub))
		}
	}
	for _, p := range got {
		if strings.HasPrefix(p, filepath.Join(state, "live")) || strings.HasPrefix(p, filepath.Join(state, "mirrors")) || p == state {
			t.Errorf("volatile state is a backup source: %s", p)
		}
	}
	cfg.Repositories.Enabled = false
	for _, src := range backupMetadataSources(&cfg) {
		if strings.HasPrefix(src.name, "repos-") {
			t.Errorf("a disabled registry is a backup source: %+v", src)
		}
	}
}

// Restoring the tag histories drops the trackers' saved state, which would
// otherwise anchor the head the history had before the restore and read an
// older history as a truncated one.
func TestRestoreResetsTheRepositoryTrackers(t *testing.T) {
	cfg := config.Default()
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = t.TempDir()
	cfg.Repositories.Enabled = true
	live := filepath.Join(cfg.RepositoriesStateDir(), "live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "widgets"), []byte(`{"headSeq":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := resetRepositoryTrackers(&cfg, map[string]string{"cache-index": "/x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(live, "widgets")); err != nil {
		t.Fatal("a restore without the histories dropped the trackers' state")
	}
	if err := resetRepositoryTrackers(&cfg, restoreTargets(backupMetadataSources(&cfg))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatalf("the trackers' state survived the restore of the histories: %v", err)
	}
}

// Every locator (Task 180) builds paths the backend the server builds for the
// type serves as a cacheable object — the payload, or for the documents a
// build also reads (a POM, an image manifest, a go.mod), a cacheable document —
// and, for the payload, parses back into the dependency's coordinate. A path a
// backend does not cache could not be pinned, and one it parses differently
// would pin another package.
func TestReleaseLocatorsMatchTheBackends(t *testing.T) {
	stub := newStubRegistry(t)
	docs := fakeLocateDocs{}
	type tc struct {
		up       config.UpstreamConfig
		dep      lockfiles.Dependency
		wantName string
	}
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	cases := map[string]tc{
		"npm":       {config.UpstreamConfig{Type: "npm", URL: stub.URL}, lockfiles.Dependency{Type: "npm", Name: "@types/node", Version: "20.14.10"}, "@types/node"},
		"cargo":     {config.UpstreamConfig{Type: "cargo", URL: stub.URL}, lockfiles.Dependency{Type: "cargo", Name: "itoa", Version: "1.0.11"}, "itoa"},
		"go":        {config.UpstreamConfig{Type: "go", URL: stub.URL}, lockfiles.Dependency{Type: "go", Name: "github.com/Azure/go-x", Version: "v1.2.0", Digests: []lockfiles.Digest{{Algorithm: "h1", Value: "x"}}}, "github.com/!azure/go-x"},
		"rubygems":  {config.UpstreamConfig{Type: "rubygems", URL: stub.URL}, lockfiles.Dependency{Type: "rubygems", Name: "nokogiri", Version: "1.16.7-aarch64-linux"}, "nokogiri"},
		"dart":      {config.UpstreamConfig{Type: "dart", URL: stub.URL}, lockfiles.Dependency{Type: "dart", Name: "collection", Version: "1.18.0"}, "collection"},
		"hex":       {config.UpstreamConfig{Type: "hex", URL: stub.URL}, lockfiles.Dependency{Type: "hex", Name: "jason", Version: "1.4.4"}, "jason"},
		"hackage":   {config.UpstreamConfig{Type: "hackage", URL: stub.URL}, lockfiles.Dependency{Type: "hackage", Name: "aeson", Version: "2.2.3.0"}, "aeson"},
		"puppet":    {config.UpstreamConfig{Type: "puppet", URL: stub.URL}, lockfiles.Dependency{Type: "puppet", Name: "puppetlabs/stdlib", Version: "9.6.0"}, ""},
		"ansible":   {config.UpstreamConfig{Type: "ansible", URL: stub.URL}, lockfiles.Dependency{Type: "ansible", Name: "community.general", Version: "9.0.0"}, ""},
		"swift":     {config.UpstreamConfig{Type: "swift", URL: stub.URL}, lockfiles.Dependency{Type: "swift", Name: "mona.LinkedList", Version: "1.1.0"}, ""},
		"cran":      {config.UpstreamConfig{Type: "cran", URL: stub.URL}, lockfiles.Dependency{Type: "cran", Name: "jsonlite", Version: "1.8.8"}, "jsonlite"},
		"cpan":      {config.UpstreamConfig{Type: "cpan", URL: stub.URL}, lockfiles.Dependency{Type: "cpan", Name: "Try-Tiny", Version: "0.31", ID: "E/ET/ETHER/Try-Tiny-0.31.tar.gz"}, ""},
		"julia":     {config.UpstreamConfig{Type: "julia", URL: stub.URL}, lockfiles.Dependency{Type: "julia", Name: "Example", Version: "0.5.3", ID: "7876af07-990d-54b4-ab0e-23690620f79a", Digests: []lockfiles.Digest{{Algorithm: "sha1", Value: strings.Repeat("a", 40), Of: "git-tree"}}}, ""},
		"bazel":     {config.UpstreamConfig{Type: "bazel", URL: stub.URL}, lockfiles.Dependency{Type: "bazel", Name: "rules_cc", Version: "0.0.9"}, "rules_cc"},
		"helm":      {config.UpstreamConfig{Type: "helm", URL: stub.URL}, lockfiles.Dependency{Type: "helm", Name: "nginx", Version: "15.0.0"}, "nginx"},
		"terraform": {config.UpstreamConfig{Type: "terraform", URL: stub.URL}, lockfiles.Dependency{Type: "terraform", Name: "registry.terraform.io/hashicorp/aws", Version: "5.0.0"}, ""},
		"conda":     {config.UpstreamConfig{Type: "conda", URL: stub.URL + "/conda-forge"}, lockfiles.Dependency{Type: "conda", Name: "zlib", Version: "1.3.1", URL: stub.URL + "/conda-forge/linux-64/zlib-1.3.1-hb9d3cd8_2.conda"}, "zlib"},
		"homebrew":  {config.UpstreamConfig{Type: "homebrew", URL: stub.URL, Settings: map[string]string{"bottleRegistryUrl": "https://ghcr.io"}}, lockfiles.Dependency{Type: "homebrew", Name: "wget", Version: "1.24.5", URL: "https://ghcr.io/v2/homebrew/core/wget/blobs/" + d("a")}, ""},
		"pip":       {config.UpstreamConfig{Type: "pip", URL: stub.URL}, lockfiles.Dependency{Type: "pip", Name: "certifi", Version: "2026.10.23", Digests: []lockfiles.Digest{{Algorithm: "sha256", Value: "e9", Of: "certifi-2026.10.23-py3-none-any.whl"}}}, "certifi"},
		"nuget":     {config.UpstreamConfig{Type: "nuget", URL: stub.URL + "/v3/index.json"}, lockfiles.Dependency{Type: "nuget", Name: "newtonsoft.json", Version: "13.0.3"}, ""},
		"maven":     {config.UpstreamConfig{Type: "maven", URL: stub.URL + "/maven2"}, lockfiles.Dependency{Type: "maven", Name: "com.google.guava:guava", Version: "31.1-jre"}, ""},
		"docker":    {config.UpstreamConfig{Type: "docker", URL: stub.URL}, lockfiles.Dependency{Type: "docker", Name: "library/alpine", Version: d("0")}, ""},
	}
	docs["pip/simple/certifi/"] = locate.Document{Status: 200, ContentType: "application/vnd.pypi.simple.v1+json",
		Body: []byte(`{"files":[{"filename":"certifi-2026.10.23-py3-none-any.whl","url":"/v1/pip/files/https/files.pythonhosted.org/packages/aa/bb/certifi-2026.10.23-py3-none-any.whl","hashes":{"sha256":"e9"}}]}`)}
	docs["nuget/v3/index.json"] = locate.Document{Status: 200, Body: []byte(`{"resources":[{"@id":"/v1/nuget/v3-flatcontainer/","@type":"PackageBaseAddress/3.0.0"}]}`)}
	docs["maven/com/google/guava/guava/31.1-jre/guava-31.1-jre.pom"] = locate.Document{Status: 200, Body: []byte(`<project><packaging>bundle</packaging></project>`)}
	docs["docker/v2/library/alpine/manifests/"+d("0")] = locate.Document{Status: 200,
		Body: []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":%q},"layers":[{"digest":%q}]}`, d("1"), d("2")))}

	for name, c := range cases {
		cfg := config.Default()
		b, err := buildBackend(&cfg, name, c.up, upstream.NewWithHTTPClient(stub.Client(), "test/1"), upstream.Credentials{})
		if err != nil {
			t.Errorf("%s: building the backend: %v", name, err)
			continue
		}
		env := locate.Env{Upstreams: []locate.Upstream{{Name: name, Type: c.up.Type, URLs: []string{c.up.URL}, Settings: c.up.Settings}}, Fetch: docs}
		plan, err := locate.Locate(context.Background(), env, c.dep)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, a := range plan.Artifacts {
			if a.Error != "" {
				t.Errorf("%s: %s: %s", name, a.Path, a.Error)
				continue
			}
			header := http.Header{}
			if a.Accept != "" {
				header.Set("Accept", a.Accept)
			}
			res, err := b.Resolve(context.Background(), &backends.Request{Method: http.MethodGet, Path: a.Path, Header: header})
			if err != nil {
				t.Errorf("%s: %s does not resolve: %v", name, a.Path, err)
				continue
			}
			if !res.Cacheable && !a.Optional {
				t.Errorf("%s: %s (%s) is not cached by the backend: it could not be pinned", name, a.Path, a.Role)
			}
			if a.Role == "package" || a.Role == "file" {
				if res.Artifact.Class != backends.ArtifactPayload {
					t.Errorf("%s: %s is not classified as the payload (%v)", name, a.Path, res.Artifact.Class)
				}
				if c.wantName != "" && res.Coordinate.Name != c.wantName {
					t.Errorf("%s: %s parses as %q, want %q", name, a.Path, res.Coordinate.Name, c.wantName)
				}
			}
		}
	}
}

// fakeLocateDocs serves index documents to the locators.
type fakeLocateDocs map[string]locate.Document

func (f fakeLocateDocs) FetchDocument(_ context.Context, upstream, path, _ string) (locate.Document, error) {
	if d, ok := f[upstream+path]; ok {
		return d, nil
	}
	return locate.Document{Status: http.StatusNotFound}, nil
}
