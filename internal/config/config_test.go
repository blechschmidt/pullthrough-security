package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") returned error: %v", err)
	}
	if cfg.Server.HTTPAddr != ":8080" {
		t.Errorf("default HTTPAddr = %q, want :8080", cfg.Server.HTTPAddr)
	}
	if cfg.Cache.Backend != "memory" {
		t.Errorf("default cache backend = %q, want memory", cfg.Cache.Backend)
	}
}

func TestLoadFileWithSecretExpansion(t *testing.T) {
	t.Setenv("TEST_NPM_TOKEN", "s3cret")

	yaml := `
server:
  httpAddr: ":9090"
cache:
  backend: filesystem
  dir: /tmp/cache
upstreams:
  npm:
    type: npm
    url: https://registry.npmjs.org
    credentials:
      token: ${TEST_NPM_TOKEN}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr = %q, want :9090", cfg.Server.HTTPAddr)
	}
	if got := cfg.Upstreams["npm"].Credentials.Token; got != "s3cret" {
		t.Errorf("npm token = %q, want s3cret (env expansion failed)", got)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("PTS_HTTP_ADDR", ":1234")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Server.HTTPAddr != ":1234" {
		t.Errorf("HTTPAddr = %q, want :1234 from env override", cfg.Server.HTTPAddr)
	}
}

func TestValidateNotifications(t *testing.T) {
	valid := func() *Config {
		c := Default()
		c.Notifications = NotifyConfig{
			Enabled:     true,
			MinSeverity: "high",
			Sinks: []NotifySinkConfig{
				{Name: "slack", Kind: "slack", URL: "https://hooks.slack.com/services/x"},
				{Name: "hook", Kind: "webhook", URL: "https://example.com/hook"},
			},
			Routes: []NotifyRouteConfig{
				{Sinks: []string{"slack"}, EventTypes: []string{"policy_block", "quarantine"}, MinSeverity: "high"},
			},
		}
		return &c
	}

	if err := valid().Validate(); err != nil {
		t.Fatalf("valid notifications config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no sinks", func(c *Config) { c.Notifications.Sinks = nil }, "at least one sink"},
		{"dup name", func(c *Config) {
			c.Notifications.Sinks[1].Name = "slack"
		}, "duplicate sink name"},
		{"bad kind", func(c *Config) { c.Notifications.Sinks[0].Kind = "pigeon" }, "unknown kind"},
		{"non-http url", func(c *Config) { c.Notifications.Sinks[0].URL = "ftp://x" }, "http(s)"},
		{"bad min severity", func(c *Config) { c.Notifications.MinSeverity = "nope" }, "minSeverity"},
		{"route undefined sink", func(c *Config) {
			c.Notifications.Routes = []NotifyRouteConfig{{Sinks: []string{"ghost"}}}
		}, "undefined sink"},
		{"route bad event type", func(c *Config) {
			c.Notifications.Routes = []NotifyRouteConfig{{Sinks: []string{"slack"}, EventTypes: []string{"nope"}}}
		}, "unknown event type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}

	// Disabled notifications must skip validation entirely.
	c := Default()
	c.Notifications = NotifyConfig{Enabled: false, Sinks: nil}
	if err := c.Validate(); err != nil {
		t.Errorf("disabled notifications should not be validated: %v", err)
	}
}

func TestValidateRejectsUnknownUpstreamType(t *testing.T) {
	cfg := Default()
	cfg.Upstreams = map[string]UpstreamConfig{
		"bad": {Type: "ftp", URL: "https://example.com"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for unknown upstream type, got nil")
	}
}

func TestValidateRejectsNonHTTPUpstreamURL(t *testing.T) {
	cfg := Default()
	cfg.Upstreams = map[string]UpstreamConfig{
		"bad": {Type: "npm", URL: "ftp://example.com"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for non-http upstream url, got nil")
	}
}

func TestValidateMirrors(t *testing.T) {
	t.Run("accepts valid mirrors", func(t *testing.T) {
		cfg := Default()
		cfg.Upstreams = map[string]UpstreamConfig{
			"npm": {Type: "npm", URL: "https://registry.npmjs.org", Mirrors: []MirrorConfig{
				{ID: "eu", URL: "https://npm-eu.example.com"},
				{URL: "https://npm-2.example.com"},
			}},
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid mirrors rejected: %v", err)
		}
	})
	t.Run("rejects mirrors on git", func(t *testing.T) {
		cfg := Default()
		cfg.Upstreams = map[string]UpstreamConfig{
			"gh": {Type: "git", URL: "https://github.com", Mirrors: []MirrorConfig{{URL: "https://ghmirror.example.com"}}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for mirrors on git upstream")
		}
	})
	t.Run("rejects bad mirror url", func(t *testing.T) {
		cfg := Default()
		cfg.Upstreams = map[string]UpstreamConfig{
			"npm": {Type: "npm", URL: "https://registry.npmjs.org", Mirrors: []MirrorConfig{{URL: "ftp://bad"}}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for non-http mirror url")
		}
	})
	t.Run("rejects duplicate mirror ids", func(t *testing.T) {
		cfg := Default()
		cfg.Upstreams = map[string]UpstreamConfig{
			"npm": {Type: "npm", URL: "https://registry.npmjs.org", Mirrors: []MirrorConfig{
				{ID: "dup", URL: "https://a.example.com"},
				{ID: "dup", URL: "https://b.example.com"},
			}},
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for duplicate mirror ids")
		}
	})
}

func TestValidateRejectsBadOutboundTLSVersion(t *testing.T) {
	cfg := Default()
	cfg.Outbound.TLS.MinVersion = "2.0"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for bad outbound tls minVersion, got nil")
	}
}

func TestValidateRejectsBadUpstreamTLSVersion(t *testing.T) {
	cfg := Default()
	cfg.Upstreams = map[string]UpstreamConfig{
		"x": {Type: "npm", URL: "https://example.com", TLS: &TLSConfig{MinVersion: "junk"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for bad upstream tls minVersion, got nil")
	}
}

func TestLoadParsesOutboundAndUpstreamTLS(t *testing.T) {
	yaml := `
cache:
  backend: memory
outbound:
  userAgent: my-proxy/2
  maxIdleConnsPerHost: 32
  tls:
    minVersion: "1.3"
upstreams:
  internal:
    type: npm
    url: https://npm.internal.example.com
    tls:
      caCertFile: /etc/ssl/internal-ca.pem
      minVersion: "1.2"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Outbound.UserAgent != "my-proxy/2" {
		t.Errorf("outbound.userAgent = %q", cfg.Outbound.UserAgent)
	}
	if cfg.Outbound.MaxIdleConnsPerHost != 32 {
		t.Errorf("outbound.maxIdleConnsPerHost = %d, want 32", cfg.Outbound.MaxIdleConnsPerHost)
	}
	if cfg.Outbound.TLS.MinVersion != "1.3" {
		t.Errorf("outbound.tls.minVersion = %q", cfg.Outbound.TLS.MinVersion)
	}
	up := cfg.Upstreams["internal"]
	if up.TLS == nil || up.TLS.CACertFile != "/etc/ssl/internal-ca.pem" {
		t.Errorf("upstream tls override not parsed: %+v", up.TLS)
	}
}

func TestValidateRejectsScanWithoutProvider(t *testing.T) {
	cfg := Default()
	cfg.Scanning.Enabled = true
	cfg.Scanning.Provider = "none"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for enabled scanning without provider, got nil")
	}
}

func TestValidateVulnerabilities(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.Vulnerabilities = VulnConfig{Enabled: true, Scanner: "osv", FailSeverity: "high", Action: "block"}
		return &c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid vuln config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*VulnConfig)
	}{
		{"unknown scanner", func(v *VulnConfig) { v.Scanner = "snyk" }},
		{"reserved scanner", func(v *VulnConfig) { v.Scanner = "trivy" }},
		{"bad action", func(v *VulnConfig) { v.Action = "explode" }},
		{"bad failSeverity", func(v *VulnConfig) { v.FailSeverity = "spicy" }},
		{"bad warnSeverity", func(v *VulnConfig) { v.WarnSeverity = "spicy" }},
		{"cvss out of range", func(v *VulnConfig) { v.FailCVSS = 11 }},
		{"no threshold", func(v *VulnConfig) { v.FailSeverity = ""; v.FailCVSS = 0; v.WarnSeverity = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mutate(&cfg.Vulnerabilities)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", c.name)
			}
		})
	}
}

func TestValidateVulnerabilitiesDisabledSkips(t *testing.T) {
	c := Default()
	// Garbage values are tolerated while the subsystem is disabled.
	c.Vulnerabilities = VulnConfig{Enabled: false, Scanner: "nonsense", Action: "explode"}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled vuln config should not be validated: %v", err)
	}
}

func TestValidateNameguard(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.Nameguard = NameguardConfig{Enabled: true, Action: "block", FailSeverity: "high", WarnSeverity: "medium"}
		return &c
	}

	if err := base().Validate(); err != nil {
		t.Fatalf("valid nameguard config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*NameguardConfig)
	}{
		{"bad action", func(n *NameguardConfig) { n.Action = "explode" }},
		{"bad failSeverity", func(n *NameguardConfig) { n.FailSeverity = "spicy" }},
		{"bad warnSeverity", func(n *NameguardConfig) { n.WarnSeverity = "spicy" }},
		{"negative distance", func(n *NameguardConfig) { n.DistanceThreshold = -1 }},
		{"negative minNameLength", func(n *NameguardConfig) { n.MinNameLength = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base()
			c.mutate(&cfg.Nameguard)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", c.name)
			}
		})
	}
}

func TestValidateNameguardDisabledSkips(t *testing.T) {
	c := Default()
	c.Nameguard = NameguardConfig{Enabled: false, Action: "explode", FailSeverity: "spicy"}
	if err := c.Validate(); err != nil {
		t.Fatalf("disabled nameguard config should not be validated: %v", err)
	}
}

func TestValidateS3CacheRequiresBucketAndCredentials(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*S3CacheConfig)
	}{
		{"no bucket", func(s *S3CacheConfig) { s.Bucket = "" }},
		{"no access key", func(s *S3CacheConfig) { s.AccessKeyID = "" }},
		{"no secret key", func(s *S3CacheConfig) { s.SecretAccessKey = "" }},
		{"negative retries", func(s *S3CacheConfig) { s.MaxRetries = -1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			cfg.Cache.Backend = "s3"
			cfg.Cache.S3 = S3CacheConfig{Bucket: "b", AccessKeyID: "ak", SecretAccessKey: "sk"}
			c.mutate(&cfg.Cache.S3)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", c.name)
			}
		})
	}
}

func TestValidateS3CacheValid(t *testing.T) {
	cfg := Default()
	cfg.Cache.Backend = "s3"
	cfg.Cache.S3 = S3CacheConfig{
		Endpoint:        "http://minio:9000",
		Bucket:          "pts-cache",
		AccessKeyID:     "ak",
		SecretAccessKey: "sk",
		UsePathStyle:    true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid s3 config rejected: %v", err)
	}
	if !cfg.Cache.S3.IsSharedMode() {
		t.Fatalf("s3 shared mode should default to true")
	}
	off := false
	cfg.Cache.S3.SharedMode = &off
	if cfg.Cache.S3.IsSharedMode() {
		t.Fatalf("shared mode should honor explicit false")
	}
}

func TestS3CacheSecretsEnvExpansionAndEnvOverride(t *testing.T) {
	t.Setenv("MY_S3_SECRET", "super-secret")
	t.Setenv("PTS_CACHE_S3_ACCESS_KEY_ID", "env-access-key")
	yaml := `
cache:
  backend: s3
  s3:
    bucket: pts-cache
    accessKeyId: placeholder
    secretAccessKey: ${MY_S3_SECRET}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cache.S3.SecretAccessKey != "super-secret" {
		t.Fatalf("secretAccessKey = %q, want expanded value", cfg.Cache.S3.SecretAccessKey)
	}
	if cfg.Cache.S3.AccessKeyID != "env-access-key" {
		t.Fatalf("accessKeyId = %q, want env override", cfg.Cache.S3.AccessKeyID)
	}
}

func TestLoadLicenseConfig(t *testing.T) {
	yaml := `
server:
  httpAddr: ":9090"
cache:
  backend: memory
license:
  enabled: true
  action: block
  allow: [MIT, Apache-2.0]
  deny: ["@strong-copyleft", "GPL-*"]
  review: [MPL-2.0]
  unknown: review
  driftDetection: true
  tenants:
    proprietary:
      deny: ["@network-copyleft"]
      action: quarantine
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.License.Enabled || cfg.License.Policy.Action != "block" {
		t.Fatalf("license config not parsed: %+v", cfg.License)
	}
	if len(cfg.License.Policy.Allow) != 2 || len(cfg.License.Policy.Deny) != 2 {
		t.Errorf("license lists = allow %v deny %v", cfg.License.Policy.Allow, cfg.License.Policy.Deny)
	}
	if !cfg.License.DriftDetection {
		t.Error("driftDetection not parsed")
	}
	prop, ok := cfg.License.Tenants["proprietary"]
	if !ok || prop.Action != "quarantine" || len(prop.Deny) != 1 {
		t.Errorf("tenant override not parsed: %+v", cfg.License.Tenants)
	}
}

func TestValidateLicense_RejectsBadAction(t *testing.T) {
	c := Default()
	c.License = LicenseConfig{Enabled: true, Policy: LicensePolicyConfig{Action: "explode"}}
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for invalid license action")
	}
}

func TestValidateBackup(t *testing.T) {
	t.Run("scheduled backup requires a directory", func(t *testing.T) {
		c := Default()
		c.Backup = BackupConfig{Interval: time.Hour}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error when backup.interval is set without backup.dir")
		}
	})
	t.Run("scheduled backup with directory is valid", func(t *testing.T) {
		c := Default()
		c.Backup = BackupConfig{Interval: time.Hour, Dir: "/var/lib/pullthrough/backups"}
		if err := c.Validate(); err != nil {
			t.Fatalf("valid scheduled backup rejected: %v", err)
		}
	})
	t.Run("encryption requires exactly one secret", func(t *testing.T) {
		c := Default()
		c.Backup = BackupConfig{Encrypt: true}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error when encrypt is set without a secret")
		}
		c.Backup = BackupConfig{Encrypt: true, Passphrase: "pw", KeyFile: "/k"}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error when both passphrase and keyFile are set")
		}
		c.Backup = BackupConfig{Encrypt: true, Passphrase: "pw"}
		if err := c.Validate(); err != nil {
			t.Fatalf("valid encrypted backup rejected: %v", err)
		}
	})
	t.Run("negative interval is rejected", func(t *testing.T) {
		c := Default()
		c.Backup = BackupConfig{Interval: -time.Second}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for negative interval")
		}
	})
}

func TestBackupIncludeCacheDefault(t *testing.T) {
	if !(BackupConfig{}).IncludeCacheOrDefault() {
		t.Error("IncludeCache should default to true")
	}
	f := false
	if (BackupConfig{IncludeCache: &f}).IncludeCacheOrDefault() {
		t.Error("explicit false should disable cache inclusion")
	}
}
