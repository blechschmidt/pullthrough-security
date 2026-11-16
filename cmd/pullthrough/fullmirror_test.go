package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// crateFeed stands in for the cargo feed adapter (the real one follows the
// crates.io Git index): a registry of three crates, enumerated in one batch.
type crateFeed struct {
	mu      sync.Mutex
	changes []string
}

func (f *crateFeed) Bootstrap(_ context.Context, cursor string) (fullmirror.Batch, error) {
	return fullmirror.Batch{
		Items: []fullmirror.Coordinate{{Name: "good"}, {Name: "evil"}, {Name: "huge"}},
		Next:  "index:1", Head: "index:1", Lag: 0, LagKnown: true,
	}, nil
}

func (f *crateFeed) Changes(_ context.Context, cursor string) (fullmirror.Batch, error) {
	f.mu.Lock()
	f.changes = append(f.changes, cursor)
	f.mu.Unlock()
	return fullmirror.Batch{Next: cursor}, nil
}

func crateArtifact(name, version string) fullmirror.Artifact {
	return fullmirror.Artifact{Path: "/api/v1/crates/" + name + "/" + version + "/download"}
}

func (f *crateFeed) Releases(_ context.Context, name string) ([]fullmirror.Release, error) {
	switch name {
	case "good":
		return []fullmirror.Release{
			{Version: "1.0.0", Artifacts: []fullmirror.Artifact{crateArtifact("good", "1.0.0")}},
			{Version: "1.1.0", Artifacts: []fullmirror.Artifact{crateArtifact("good", "1.1.0")}},
		}, nil
	case "evil":
		return []fullmirror.Release{{Version: "0.1.0", Artifacts: []fullmirror.Artifact{crateArtifact("evil", "0.1.0")}}}, nil
	case "huge":
		return []fullmirror.Release{{Version: "1.0.0", Artifacts: []fullmirror.Artifact{crateArtifact("huge", "1.0.0")}}}, nil
	}
	return nil, fullmirror.Permanent(io.EOF)
}

// The full mirror over the real wiring: config validation with a registered
// adapter, the real cargo backend in front of a stub registry, the real cache
// and gated serve pipeline with a known-malicious crate, the download log.
// Every mirrored file goes through the gateway as system:full-mirror; a gate's
// refusal is counted as refused; a file over maxArtifactBytes is never cached;
// a client then gets the mirrored crates from the cache; a restart resumes from
// the stored cursor; the state is a backup source.
func TestFullMirrorEndToEnd(t *testing.T) {
	feed := &crateFeed{}
	var env fullmirror.Env
	restore := fullmirror.ReplaceAdapter("cargo", func(e fullmirror.Env) (fullmirror.Feed, error) {
		env = e
		return feed, nil
	})
	defer restore()

	stub := newStubRegistry(t)
	good100, good110 := []byte("good 1.0.0 crate"), []byte("good 1.1.0 crate")
	stub.publish("/api/v1/crates/good/1.0.0/download", good100)
	stub.publish("/api/v1/crates/good/1.1.0/download", good110)
	stub.publish("/api/v1/crates/evil/0.1.0/download", []byte("evil 0.1.0 crate"))
	stub.publish("/api/v1/crates/huge/1.0.0/download", []byte(strings.Repeat("x", 500)))

	base := t.TempDir()
	cfg := config.Default()
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"cargo": {Type: "cargo", URL: stub.URL, Settings: map[string]string{"downloadUrl": stub.URL},
			FullMirror: &config.UpstreamFullMirrorConfig{
				Enabled: true, ByteBudget: 1 << 20, MaxArtifactBytes: 100, RequestsPerSecond: 1000, PollInterval: time.Hour,
			}},
	}
	cfg.FullMirror.Tenant = "mirror"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cacheImpl, err := buildCache(&cfg, logger, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cacheImpl.Close()
	registry := backends.NewRegistry()
	b, err := buildBackend(&cfg, "cargo", cfg.Upstreams["cargo"], upstream.NewWithHTTPClient(stub.Client(), "test/1"), upstream.Credentials{})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(b); err != nil {
		t.Fatal(err)
	}
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	mal := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-2026-1", Ecosystem: "cargo", Name: "evil", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cacheImpl, Backends: registry, DownloadLog: dl, Ecosystems: ecosystemMap(&cfg), Malfeed: mal,
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}

	start := func() *fullmirror.Engine {
		t.Helper()
		e, err := buildFullMirror(&cfg, nil, nil, nil, nil, logger)
		if err != nil || e == nil {
			t.Fatalf("buildFullMirror: %v %v", e, err)
		}
		wireFullMirror(context.Background(), e, &cfg, gw, nil, nil, nil, nil)
		return e
	}
	e := start()
	waitFor(t, func() bool { us := e.Status().Upstreams[0]; return us.Phase == "follow" && !us.LastCommit.IsZero() })

	if env.Upstream != "cargo" || env.URL != stub.URL || env.HTTP == nil || env.Dir != filepath.Join(cfg.Cache.Dir, "fullmirror", "upstreams", "cargo", "feed") {
		t.Errorf("adapter env %+v", env)
	}
	us := e.Status().Upstreams[0]
	c := us.Counters
	if c.Fetched != 2 || c.Refused != 1 || c.RefusedBy["malfeed"] != 1 || c.Skipped[fullmirror.SkipTooLarge] != 1 || c.Failed != 0 {
		t.Fatalf("counters %+v", c)
	}
	if us.Cursor != "index:1" || us.Budget.Used != int64(len(good100)+len(good110)) {
		t.Errorf("cursor %q budget %+v", us.Cursor, us.Budget)
	}

	// Every file went through the gateway as the mirror's system principal.
	res, err := dl.Query(downloadlog.Query{Limit: -1})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]downloadlog.Entry{}
	for _, en := range res.Entries {
		seen[en.Package+"@"+en.Version] = en
		if en.Via != downloadlog.ViaSystem || en.Subject != fullmirror.Subject || en.UserAgent != fullMirrorUserAgent || en.Tenant != "mirror" {
			t.Errorf("download-log entry %+v", en)
		}
	}
	if seen["good@1.0.0"].Outcome != downloadlog.OutcomeServed || seen["good@1.1.0"].Cache != "MISS" {
		t.Errorf("good crates: %+v %+v", seen["good@1.0.0"], seen["good@1.1.0"])
	}
	if ev := seen["evil@0.1.0"]; ev.Outcome != downloadlog.OutcomeBlocked || ev.Gate != "malfeed" {
		t.Errorf("evil crate: %+v", ev)
	}

	// The cache holds what was admitted, nothing else.
	for path, want := range map[string]bool{
		"/api/v1/crates/good/1.0.0/download": true, "/api/v1/crates/good/1.1.0/download": true,
		"/api/v1/crates/evil/0.1.0/download": false, "/api/v1/crates/huge/1.0.0/download": false,
	} {
		lk, err := gw.SystemLookup(context.Background(), proxy.SystemFetchRequest{Backend: "cargo", Path: path, Tenant: "mirror"})
		if err != nil || lk.Cached != want {
			t.Errorf("%s cached=%v, want %v (%v)", path, lk.Cached, want, err)
		}
	}
	// A client gets the mirrored crate from the cache.
	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cargo/api/v1/crates/good/1.0.0/download", nil))
	stub.mu.Lock()
	hits := stub.hits["/api/v1/crates/good/1.0.0/download"]
	stub.mu.Unlock()
	if rr.Code != http.StatusOK || rr.Header().Get("X-Cache") != "HIT" || hits != 1 {
		t.Errorf("client pull: %d %s, upstream hits %d", rr.Code, rr.Header().Get("X-Cache"), hits)
	}

	reg := metrics.New()
	fullmirror.BindMetrics(reg, e)
	var sb strings.Builder
	if err := reg.WritePrometheus(&sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), `pullthrough_fullmirror_artifacts_total{upstream="cargo",outcome="fetched"} 2`) {
		t.Errorf("metrics:\n%s", sb.String())
	}

	// A restart resumes from the stored cursor: no new enumeration.
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := start()
	defer e2.Close()
	waitFor(t, func() bool {
		feed.mu.Lock()
		defer feed.mu.Unlock()
		return len(feed.changes) > 0
	})
	if feed.changes[0] != "index:1" {
		t.Errorf("the restarted mirror polled from %q, want the stored cursor", feed.changes[0])
	}
	if got := e2.Status().Upstreams[0].Counters.Fetched; got != 2 {
		t.Errorf("counters did not survive the restart: fetched %d", got)
	}

	// The state is a backup source, captured once per file.
	var found bool
	for _, s := range backupMetadataSources(&cfg) {
		if s.name == "full-mirror" {
			found = s.volatile && s.path == cfg.FullMirrorStateDir()
		}
	}
	if !found {
		t.Errorf("the full mirror's state is not a volatile backup source: %+v", backupMetadataSources(&cfg))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNoFullMirrorWithoutAnUpstream(t *testing.T) {
	cfg := config.Default()
	e, err := buildFullMirror(&cfg, nil, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || e != nil {
		t.Fatalf("buildFullMirror without upstreams: %v %v", e, err)
	}
	for _, s := range backupMetadataSources(&cfg) {
		if s.name == "full-mirror" {
			t.Errorf("a backup source without full mirroring: %+v", s)
		}
	}
}
