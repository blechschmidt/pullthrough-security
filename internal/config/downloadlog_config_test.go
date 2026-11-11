package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/downloadlog"
)

// loadDownloadLogYAML writes a config document to a temp file and loads it
// through the production loader (defaults, env expansion, validation).
func loadDownloadLogYAML(t *testing.T, doc string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

const downloadLogBaseYAML = `
server:
  httpAddr: ":8080"
upstreams:
  cargo: {type: cargo, url: "https://index.crates.io"}
`

// The log is on without any configuration: an operator who opens the admin UI
// sees which address pulled what, with bounds already in place.
func TestDownloadLogDefaults(t *testing.T) {
	def := Default().DownloadLog
	if !def.Enabled {
		t.Error("the download log must be enabled by default")
	}
	if def.MaxEntries != downloadlog.DefaultMaxEntries {
		t.Errorf("default maxEntries = %d, want %d", def.MaxEntries, downloadlog.DefaultMaxEntries)
	}
	if def.Retention != 30*24*time.Hour {
		t.Errorf("default retention = %s, want 720h", def.Retention)
	}
	if def.Path != "" || def.IncludeMetadata {
		t.Errorf("defaults must be in-memory and packages-only: %+v", def)
	}

	// A document that does not mention the section keeps the defaults.
	cfg, err := loadDownloadLogYAML(t, downloadLogBaseYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DownloadLog != def {
		t.Errorf("a config without a downloadLog section = %+v, want the defaults %+v", cfg.DownloadLog, def)
	}
	if len(cfg.Server.TrustedProxies) != 0 {
		t.Errorf("trustedProxies must default to empty, got %v", cfg.Server.TrustedProxies)
	}
}

func TestDownloadLogYAML(t *testing.T) {
	cfg, err := loadDownloadLogYAML(t, downloadLogBaseYAML+`
downloadLog:
  maxEntries: 250000
  retention: 2160h
  path: /var/lib/pullthrough/downloads.jsonl
  includeMetadata: true
`)
	if err != nil {
		t.Fatal(err)
	}
	want := DownloadLogConfig{
		Enabled:         true, // untouched keys keep their default
		MaxEntries:      250000,
		Retention:       90 * 24 * time.Hour,
		Path:            "/var/lib/pullthrough/downloads.jsonl",
		IncludeMetadata: true,
	}
	if cfg.DownloadLog != want {
		t.Errorf("parsed %+v, want %+v", cfg.DownloadLog, want)
	}

	cfg, err = loadDownloadLogYAML(t, downloadLogBaseYAML+"\ndownloadLog:\n  enabled: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DownloadLog.Enabled {
		t.Error("enabled: false did not disable the log")
	}

	// retention: 0s is an explicit "no time limit", distinct from the default.
	cfg, err = loadDownloadLogYAML(t, downloadLogBaseYAML+"\ndownloadLog:\n  retention: 0s\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DownloadLog.Retention != 0 {
		t.Errorf("retention: 0s parsed as %s", cfg.DownloadLog.Retention)
	}
}

func TestDownloadLogMaxEntriesOrDefault(t *testing.T) {
	if got := (DownloadLogConfig{}).MaxEntriesOrDefault(); got != downloadlog.DefaultMaxEntries {
		t.Errorf("zero maxEntries = %d, want the default", got)
	}
	if got := (DownloadLogConfig{MaxEntries: 7}).MaxEntriesOrDefault(); got != 7 {
		t.Errorf("maxEntries 7 = %d", got)
	}
}

func TestValidateDownloadLog(t *testing.T) {
	ok := map[string]func(*Config){
		"defaults":           func(*Config) {},
		"zero capacity":      func(c *Config) { c.DownloadLog.MaxEntries = 0 },
		"largest capacity":   func(c *Config) { c.DownloadLog.MaxEntries = downloadlog.MaxMaxEntries },
		"no time limit":      func(c *Config) { c.DownloadLog.Retention = 0 },
		"disabled":           func(c *Config) { c.DownloadLog.Enabled = false },
		"hand-built literal": func(c *Config) { c.DownloadLog = DownloadLogConfig{} },
	}
	for name, mutate := range ok {
		t.Run("ok/"+name, func(t *testing.T) {
			c := Default()
			mutate(&c)
			if err := c.Validate(); err != nil {
				t.Fatalf("expected a valid config, got %v", err)
			}
		})
	}

	bad := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"negative capacity":  {func(c *Config) { c.DownloadLog.MaxEntries = -1 }, "downloadLog.maxEntries"},
		"oversized capacity": {func(c *Config) { c.DownloadLog.MaxEntries = downloadlog.MaxMaxEntries + 1 }, "downloadLog.maxEntries"},
		"negative retention": {func(c *Config) { c.DownloadLog.Retention = -time.Hour }, "downloadLog.retention"},
		// The bounds are checked even while the log is switched off: a value that
		// would be rejected the day the log is enabled is rejected today.
		"negative capacity while disabled": {func(c *Config) {
			c.DownloadLog.Enabled = false
			c.DownloadLog.MaxEntries = -1
		}, "downloadLog.maxEntries"},
	}
	for name, tc := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	c := Default()
	c.Server.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.10", "fd00::/8", "::1", " 172.16.0.0/12 "}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid trusted proxies rejected: %v", err)
	}

	// A typo must fail the load: an entry that was silently dropped would leave
	// every download attributed to the load balancer.
	for _, bad := range []string{"10.0.0.0/33", "loadbalancer.internal", "10.0.0.1:8080", "10.0.0", "", "  "} {
		c := Default()
		c.Server.TrustedProxies = []string{"10.0.0.0/8", bad}
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "server.trustedProxies[1]") {
			t.Errorf("trustedProxies entry %q: Validate() = %v, want an error naming server.trustedProxies[1]", bad, err)
		}
	}

	cfg, err := loadDownloadLogYAML(t, `
server:
  httpAddr: ":8080"
  trustedProxies: ["10.0.0.0/8", "192.168.1.10"]
upstreams:
  cargo: {type: cargo, url: "https://index.crates.io"}
`)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.TrustedProxies; len(got) != 2 || got[0] != "10.0.0.0/8" || got[1] != "192.168.1.10" {
		t.Fatalf("parsed trustedProxies = %v", got)
	}
}

// Trusting every address makes the forwarding header authoritative from any
// client. It loads (a lab may want it) but preflight must say so.
func TestCheckWarnsOnTrustEverything(t *testing.T) {
	warningsFor := func(proxies ...string) []Issue {
		c := Default()
		c.Upstreams = map[string]UpstreamConfig{"cargo": {Type: "cargo", URL: "https://index.crates.io"}}
		c.Server.TrustedProxies = proxies
		var out []Issue
		for _, is := range c.Check().Issues {
			if strings.HasPrefix(is.Path, "server.trustedProxies") {
				out = append(out, is)
			}
		}
		return out
	}

	if got := warningsFor("10.0.0.0/8", "192.168.1.10"); len(got) != 0 {
		t.Errorf("ordinary trusted proxies produced issues: %+v", got)
	}
	for _, all := range []string{"0.0.0.0/0", "::/0"} {
		got := warningsFor("10.0.0.0/8", all)
		if len(got) != 1 || got[0].Severity != SeverityWarning || got[0].Path != "server.trustedProxies[1]" {
			t.Errorf("%s: issues = %+v, want one warning at server.trustedProxies[1]", all, got)
		}
	}
}

// The reference documentation and the unknown-key detection are driven by the
// schema; both new settings must be part of it.
func TestDownloadLogSchemaPaths(t *testing.T) {
	for _, path := range []string{
		"server.trustedProxies",
		"downloadLog.enabled", "downloadLog.maxEntries", "downloadLog.retention",
		"downloadLog.path", "downloadLog.includeMetadata",
	} {
		if !YAMLPathExists(path) {
			t.Errorf("config path %s is not part of the schema", path)
		}
	}

	// A misspelled key is reported, not ignored.
	report := CheckBytes([]byte(downloadLogBaseYAML + "\ndownloadLog:\n  maxEntrys: 5\n"))
	found := false
	for _, is := range report.Issues {
		if strings.Contains(is.Path+" "+is.Message, "maxEntrys") {
			found = true
		}
	}
	if !found {
		t.Errorf("a misspelled downloadLog key went unreported: %+v", report.Issues)
	}
}
