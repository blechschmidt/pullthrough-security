package llmpkgscan

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

func TestConfigDefaults(t *testing.T) {
	cfg := Config{Provider: &pkgscantest.Provider{}, Model: " m "}.withDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if cfg.Mode != ModeAuto || cfg.Action != ActionBlock || cfg.FailMode != FailOpen {
		t.Errorf("mode/action/failMode = %s/%s/%s", cfg.Mode, cfg.Action, cfg.FailMode)
	}
	if cfg.MaliciousThreshold != DefaultMaliciousThreshold || cfg.SuspiciousThreshold != DefaultSuspiciousThreshold {
		t.Errorf("thresholds = %g/%g", cfg.MaliciousThreshold, cfg.SuspiciousThreshold)
	}
	if cfg.Timeout != defaultTimeout || cfg.MaxConcurrent != defaultMaxConcurrent || cfg.ErrorTTL != defaultErrorTTL || cfg.MaxRetries != defaultMaxRetries {
		t.Errorf("timeout %v concurrent %d errorTTL %v retries %d", cfg.Timeout, cfg.MaxConcurrent, cfg.ErrorTTL, cfg.MaxRetries)
	}
	if cfg.Limits != DefaultLimits() {
		t.Errorf("limits = %+v", cfg.Limits)
	}
	if cfg.Model != "m" || cfg.Pricing == nil || cfg.Logger == nil || cfg.Now == nil {
		t.Error("model not trimmed or helpers not defaulted")
	}
	if strings.Join(cfg.Include, ",") != "cargo,composer,npm,nuget,pip,rubygems" {
		t.Errorf("default ecosystems = %v", cfg.Include)
	}
	// Enums are case- and space-insensitive.
	norm := Config{Provider: &pkgscantest.Provider{}, Model: "m", Mode: " Bundle ", Action: "QUARANTINE", FailMode: " Closed"}.withDefaults()
	if norm.Mode != ModeBundle || norm.Action != ActionQuarantine || norm.FailMode != FailClosed {
		t.Errorf("normalized enums = %s/%s/%s", norm.Mode, norm.Action, norm.FailMode)
	}
	// A negative retry count disables retries.
	if c := (Config{Provider: &pkgscantest.Provider{}, Model: "m", MaxRetries: -1}).withDefaults(); c.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d, want 0", c.MaxRetries)
	}
}

func TestConfigValidation(t *testing.T) {
	good := func() Config { return Config{Provider: &pkgscantest.Provider{}, Model: "m"} }
	cases := map[string]func(*Config){
		"no provider":                     func(c *Config) { c.Provider = nil },
		"no model":                        func(c *Config) { c.Model = "  " },
		"bad mode":                        func(c *Config) { c.Mode = "agentic" },
		"bad action":                      func(c *Config) { c.Action = "warn" },
		"bad fail mode":                   func(c *Config) { c.FailMode = "ajar" },
		"malicious threshold > 1":         func(c *Config) { c.MaliciousThreshold = 1.5 },
		"negative malicious threshold":    func(c *Config) { c.MaliciousThreshold = -0.1 },
		"suspicious threshold > 1":        func(c *Config) { c.SuspiciousThreshold = 2 },
		"negative timeout":                func(c *Config) { c.Timeout = -time.Second },
		"negative artifact limit":         func(c *Config) { c.Limits.MaxArtifactBytes = -1 },
		"negative file count":             func(c *Config) { c.Limits.MaxFiles = -1 },
		"ratio below 1":                   func(c *Config) { c.Limits.MaxCompressionRatio = 0.5 },
		"prompt budget too small":         func(c *Config) { c.Limits.MaxPromptBytes = 100 },
		"tool result too small":           func(c *Config) { c.Limits.MaxToolResultBytes = 10 },
		"tool total below one result":     func(c *Config) { c.Limits.MaxToolBytes = 2000; c.Limits.MaxToolResultBytes = 4000 },
		"too many turns":                  func(c *Config) { c.Limits.MaxTurns = 1000 },
		"negative turns":                  func(c *Config) { c.Limits.MaxTurns = -1 },
		"too many tool calls":             func(c *Config) { c.Limits.MaxToolCalls = 100000 },
		"output tokens too small":         func(c *Config) { c.Limits.MaxOutputTokens = 10 },
		"total tokens below output":       func(c *Config) { c.Limits.MaxTotalTokens = 500; c.Limits.MaxOutputTokens = 1000 },
		"negative global budget":          func(c *Config) { c.Budget.GlobalCeilingUSD = -1 },
		"negative tenant budget":          func(c *Config) { c.Budget.TenantCeilingUSD = -1 },
		"negative per-tenant budget":      func(c *Config) { c.Budget.TenantCeilingsUSD = map[string]float64{"a": -5} },
		"negative budget window":          func(c *Config) { c.Budget.Window = -time.Hour },
		"negative cache ttl":              func(c *Config) { c.CacheTTL = -time.Hour },
		"negative error ttl":              func(c *Config) { c.ErrorTTL = -time.Hour },
		"negative concurrency":            func(c *Config) { c.MaxConcurrent = -2 },
		"tools mode without tool support": func(c *Config) { c.Provider = (&pkgscantest.Provider{}).BundleOnly(); c.Mode = ModeTools },
	}
	for name, mutate := range cases {
		cfg := good()
		mutate(&cfg)
		if _, err := NewService(cfg); err == nil {
			t.Errorf("%s: NewService accepted an invalid config", name)
		}
	}
	if _, err := NewService(good()); err != nil {
		t.Errorf("a valid config was rejected: %v", err)
	}
	// Boundary values that must be accepted.
	for name, mutate := range map[string]func(*Config){
		"threshold exactly 1":   func(c *Config) { c.MaliciousThreshold = 1; c.SuspiciousThreshold = 1 },
		"one turn":              func(c *Config) { c.Limits.MaxTurns = 1 },
		"turn ceiling":          func(c *Config) { c.Limits.MaxTurns = maxTurnsCeiling },
		"ratio exactly 1":       func(c *Config) { c.Limits.MaxCompressionRatio = 1 },
		"minimum prompt budget": func(c *Config) { c.Limits.MaxPromptBytes = minPromptBytes },
	} {
		cfg := good()
		mutate(&cfg)
		svc, err := NewService(cfg)
		if err != nil {
			t.Errorf("%s: rejected: %v", name, err)
			continue
		}
		_ = svc.Close()
	}
}

func TestCanonEcosystem(t *testing.T) {
	for in, want := range map[string]string{
		"npm": "npm", "NodeJS": "npm", "node": "npm", "PyPI": "pip", "python": "pip", "pip": "pip",
		"crates": "cargo", "rust": "cargo", "gem": "rubygems", "Ruby": "rubygems", "packagist": "composer",
		"php": "composer", "dotnet": "nuget", ".NET": "nuget", "golang": "go", "java": "maven", "gradle": "maven",
		" Maven ": "maven", "docker": "docker", "": "",
	} {
		if got := CanonEcosystem(in); got != want {
			t.Errorf("CanonEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
	if got := canonList([]string{"PyPI", "pip", "python", "", "npm", "node"}); strings.Join(got, ",") != "npm,pip" {
		t.Errorf("canonList = %v", got)
	}
}

func TestActionRefuses(t *testing.T) {
	if ActionAnnotate.Refuses() || !ActionBlock.Refuses() || !ActionQuarantine.Refuses() {
		t.Error("only block and quarantine can refuse")
	}
}

func TestContentAttributableCodes(t *testing.T) {
	for code, want := range map[string]bool{
		CodeOversized: true, CodeUnsupported: true, CodeEmptyArchive: true, CodeUnpackLimit: true,
		CodeProviderRefusal: true, CodeMalformedOutput: true, CodeInjectionSuspected: true, CodeTokenLimit: true,
		CodeProviderError: false, CodeProviderUnavailable: false, CodeTimeout: false, CodeBudgetExhausted: false,
		CodeUnavailable: false, CodeInternalError: false, CodeDigestMismatch: false,
	} {
		if got := contentAttributable(code); got != want {
			t.Errorf("contentAttributable(%s) = %v, want %v", code, got, want)
		}
	}
	// A code is never both: transient faults are the scanner's, not the package's.
	for _, code := range []string{CodeProviderError, CodeProviderUnavailable, CodeTimeout, CodeUnavailable, CodeInternalError} {
		if !transient(code) || contentAttributable(code) {
			t.Errorf("%s should be transient and not content-attributable", code)
		}
	}
}
