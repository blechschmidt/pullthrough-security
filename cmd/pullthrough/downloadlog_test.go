package main

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
	"github.com/blechschmidt/pullthrough-security/internal/git"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
)

func downloadLogTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func downloadLogConfig(mutate func(*config.Config)) *config.Config {
	cfg := config.Default()
	if mutate != nil {
		mutate(&cfg)
	}
	return &cfg
}

// The shipped defaults yield a working, bounded, in-memory log: an operator who
// configures nothing still sees which address pulled what.
func TestBuildDownloadLogDefaults(t *testing.T) {
	log, err := buildDownloadLog(downloadLogConfig(nil), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	st := log.Stats()
	if !st.Enabled || st.Persistent || st.IncludeMetadata {
		t.Fatalf("default log = %+v, want enabled, in memory, packages only", st)
	}
	if st.Capacity != downloadlog.DefaultMaxEntries {
		t.Errorf("capacity = %d, want %d", st.Capacity, downloadlog.DefaultMaxEntries)
	}
	if want := int64(30 * 24 * time.Hour / time.Second); st.RetentionSeconds != want {
		t.Errorf("retention = %ds, want %ds (30 days)", st.RetentionSeconds, want)
	}
}

func TestBuildDownloadLogFromConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "downloads.jsonl")
	log, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) {
		c.DownloadLog.MaxEntries = 1234
		c.DownloadLog.Retention = 48 * time.Hour
		c.DownloadLog.Path = path
		c.DownloadLog.IncludeMetadata = true
	}), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	st := log.Stats()
	if st.Capacity != 1234 || st.RetentionSeconds != 48*3600 || !st.Persistent || !st.IncludeMetadata {
		t.Fatalf("log = %+v", st)
	}
	log.Record(downloadlog.Entry{ClientIP: "10.0.0.5", Ecosystem: "cargo", Package: "cfg-if", Version: "1.0.0",
		Kind: downloadlog.KindPackage, Outcome: downloadlog.OutcomeServed, Status: http.StatusOK})
	// Closing — what the binary does on shutdown — writes the pending entry.
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"clientIp":"10.0.0.5"`) || !strings.Contains(string(data), `"package":"cfg-if"`) {
		t.Fatalf("the on-disk log does not hold the entry: %q", data)
	}

	// The next start restores it.
	again, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) { c.DownloadLog.Path = path }), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	res, err := again.Query(downloadlog.Query{})
	if err != nil || res.Total != 1 || res.Entries[0].Package != "cfg-if" {
		t.Fatalf("after a restart: %+v, %v", res, err)
	}
}

// In the configuration "0s" means "no time limit"; the log must not read that
// as "use the default".
func TestBuildDownloadLogUnlimitedRetention(t *testing.T) {
	log, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) { c.DownloadLog.Retention = 0 }), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	if got := log.Stats().RetentionSeconds; got != 0 {
		t.Fatalf("retention = %ds, want 0 (no time limit)", got)
	}
}

func TestBuildDownloadLogDisabled(t *testing.T) {
	// A disabled log is still a log — the gateway, the admin API and the metrics
	// binder all take it — and it never touches its path.
	log, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) {
		c.DownloadLog.Enabled = false
		c.DownloadLog.Path = "/nonexistent-dir-for-test/downloads.jsonl"
	}), downloadLogTestLogger())
	if err != nil || log == nil {
		t.Fatalf("disabled log: %v, %v", log, err)
	}
	if log.Enabled() {
		t.Fatal("the log is enabled")
	}
	bindDownloadLogMetrics(metrics.NewCollector(), log)
	bindDownloadLogMetrics(metrics.NewCollector(), nil)
	if sshFetchRecorder(log, nil) != nil {
		t.Fatal("a disabled log still installs an SSH fetch callback")
	}
}

// An operator who asked for a log that survives restarts must learn at startup
// that it cannot be written — not after the restart that lost it.
func TestBuildDownloadLogFailsOnUnusablePath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) {
		c.DownloadLog.Path = filepath.Join(file, "downloads.jsonl")
	}), downloadLogTestLogger())
	if err == nil || !strings.Contains(err.Error(), "downloadLog.path") {
		t.Fatalf("err = %v, want a startup error naming downloadLog.path", err)
	}
}

func TestBuildClientIPResolver(t *testing.T) {
	none, err := buildClientIPResolver(downloadLogConfig(nil), downloadLogTestLogger())
	if err != nil || none.TrustsAny() {
		t.Fatalf("default resolver: trusts %v, err %v; want it to trust no proxy", none.TrustsAny(), err)
	}

	resolver, err := buildClientIPResolver(downloadLogConfig(func(c *config.Config) {
		c.Server.TrustedProxies = []string{"10.255.0.0/24"}
	}), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://proxy/v1/cargo/x", nil)
	req.RemoteAddr = "10.255.0.7:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := resolver.Resolve(req); got.Client != "203.0.113.9" || got.Peer != "10.255.0.7" || !got.Forwarded {
		t.Fatalf("resolved %+v", got)
	}

	if _, err := buildClientIPResolver(downloadLogConfig(func(c *config.Config) {
		c.Server.TrustedProxies = []string{"not-an-address"}
	}), downloadLogTestLogger()); err == nil || !strings.Contains(err.Error(), "server.trustedProxies") {
		t.Fatalf("err = %v, want an error naming server.trustedProxies", err)
	}
}

// A clone over SSH is logged like any other download: the repository, the
// client's address, and the key it authenticated with.
func TestSSHFetchRecorder(t *testing.T) {
	log, err := buildDownloadLog(downloadLogConfig(nil), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	record := sshFetchRecorder(log, map[string]string{"github": "git"})
	if record == nil {
		t.Fatal("no callback for an enabled log")
	}

	record(git.FetchEvent{
		Upstream: "github", Repo: "octocat/Hello-World.git",
		RemoteAddr: "[2001:db8::7]:51022", KeyFingerprint: "SHA256:abcDEF",
		Bytes: 4096, Duration: 150 * time.Millisecond,
	})
	record(git.FetchEvent{
		Upstream: "unmapped", Repo: "team/project.git",
		RemoteAddr: "10.0.0.9:40000", Bytes: 512, Err: errors.New("broken pipe"),
	})

	res, err := log.Query(downloadlog.Query{})
	if err != nil || res.Total != 2 {
		t.Fatalf("log = %+v, %v", res, err)
	}
	failed, served := res.Entries[0], res.Entries[1]

	want := downloadlog.Entry{
		ID: 1, Time: served.Time,
		ClientIP: "2001:db8::7", Ecosystem: "git", Upstream: "github", Package: "octocat/Hello-World.git",
		Kind: downloadlog.KindPackage, Method: "SSH", Path: "github/octocat/Hello-World.git",
		Outcome: downloadlog.OutcomeServed, Bytes: 4096, DurationMs: 150,
		Subject: "SHA256:abcDEF", AuthMethod: "ssh-key",
	}
	if served != want {
		t.Fatalf("served entry\n %+v\nwant\n %+v", served, want)
	}
	if failed.Outcome != downloadlog.OutcomeError || failed.Bytes != 0 || failed.Reason == "" ||
		failed.ClientIP != "10.0.0.9" || failed.Ecosystem != "git" || failed.Subject != "" || failed.AuthMethod != "" {
		t.Fatalf("failed entry = %+v", failed)
	}

	// "Who cloned this repository?" works across transports.
	sum, err := log.Summarize(downloadlog.Query{Ecosystem: "git", Package: "octocat/*"}, 0)
	if err != nil || sum.Total != 1 || sum.ByClient[0].ClientIP != "2001:db8::7" {
		t.Fatalf("summary = %+v, %v", sum, err)
	}
}

// The metrics the log exports follow what it records.
func TestDownloadLogMetrics(t *testing.T) {
	log, err := buildDownloadLog(downloadLogConfig(func(c *config.Config) { c.DownloadLog.MaxEntries = 2 }), downloadLogTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	collector := metrics.NewCollector()
	bindDownloadLogMetrics(collector, log)

	for i, outcome := range []downloadlog.Outcome{downloadlog.OutcomeServed, downloadlog.OutcomeServed, downloadlog.OutcomeBlocked} {
		log.Record(downloadlog.Entry{ClientIP: "10.0.0.1", Ecosystem: "go", Package: "example.com/m", Version: "v1.0.0",
			Kind: downloadlog.KindPackage, Outcome: outcome, Status: 200 + i})
	}

	rec := newMetricsScrape(t, collector)
	for _, want := range []string{
		`pullthrough_downloadlog_entries_total{outcome="served"} 2`,
		`pullthrough_downloadlog_entries_total{outcome="blocked"} 1`,
		`pullthrough_downloadlog_entries_total{outcome="not_found"} 0`,
		`pullthrough_downloadlog_retained_entries 2`,
		`pullthrough_downloadlog_capacity_entries 2`,
		`pullthrough_downloadlog_evicted_total 1`,
		`pullthrough_downloadlog_expired_total 0`,
		`pullthrough_downloadlog_persisted_total 0`,
		`pullthrough_downloadlog_persist_errors_total 0`,
		`pullthrough_downloadlog_persist_lost_total 0`,
	} {
		if !strings.Contains(rec, want+"\n") {
			t.Errorf("the metrics exposition lacks %q", want)
		}
	}
}

// newMetricsScrape returns the Prometheus exposition of a collector.
func newMetricsScrape(t *testing.T, c *metrics.Collector) string {
	t.Helper()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scraping metrics: status %d", rec.Code)
	}
	return rec.Body.String()
}

// A backup snapshot re-reads every metadata file after it has streamed the
// cache, and fails if the file changed in between. The download log's file is
// appended to within a second of every download and replaced when it is
// compacted: as a backup source it would fail every backup taken while the
// proxy serves traffic. It is therefore not one (docs/download-log.md says how
// to copy it instead).
func TestDownloadLogIsNotABackupSource(t *testing.T) {
	cfg := config.Default()
	cfg.DownloadLog.Path = "/var/lib/pt/downloads.jsonl"
	for _, src := range backupMetadataSources(&cfg) {
		if src.path == cfg.DownloadLog.Path || strings.Contains(src.name, "download") {
			t.Errorf("the download log is a backup source (%+v): a file that changes during the snapshot fails the backup", src)
		}
	}
}
