package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/secrets"
)

func TestLLMPackageScanDefaults(t *testing.T) {
	l := Default().LLMPackageScan
	if l.Enabled {
		t.Error("the gate spends money per artifact: it must be off by default")
	}
	if l.Action != "block" || l.FailMode != "open" || l.Mode != "auto" {
		t.Errorf("defaults = action %q failMode %q mode %q", l.Action, l.FailMode, l.Mode)
	}
	if l.MaliciousThreshold != 0.7 || l.SuspiciousThreshold != 0.5 {
		t.Errorf("thresholds = %v / %v", l.MaliciousThreshold, l.SuspiciousThreshold)
	}
	if l.Timeout != 2*time.Minute || l.MaxConcurrent != 4 || l.MaxRetries != 1 || l.ErrorTTL != 5*time.Minute {
		t.Errorf("timing defaults = %+v", l)
	}
	if l.Limits.MaxArtifactBytes != 64<<20 || l.Limits.MaxFiles != 5000 || l.Limits.MaxDepth != 32 ||
		l.Limits.MaxCompressionRatio != 200 || l.Limits.MaxTurns != 8 || l.Limits.MaxToolCalls != 24 {
		t.Errorf("limit defaults = %+v", l.Limits)
	}
	if l.Budget.Enabled || l.Budget.Window != 24*time.Hour {
		t.Errorf("budget defaults = %+v", l.Budget)
	}
	if l.APIKey != "" || l.Provider != "" || l.StoreDir != "" {
		t.Errorf("no provider, key or path may be assumed: %+v", l)
	}
	// The untouched default configuration validates.
	c := Default()
	if err := c.validateLLMPackageScan(); err != nil {
		t.Errorf("default config: %v", err)
	}
}

func TestLLMPackageScanParsesFromYAML(t *testing.T) {
	const doc = `
server:
  httpAddr: ":8080"
upstreams:
  npm: {type: npm, url: "https://registry.npmjs.org"}
llmPackageScan:
  enabled: true
  provider: claude
  model: claude-opus-4-8
  apiKey: "${PTS_TEST_PKGSCAN_KEY}"
  mode: tools
  thinking: false
  action: quarantine
  failMode: closed
  maliciousThreshold: 0.8
  suspiciousThreshold: 0.6
  timeout: 90s
  maxConcurrent: 2
  include: [npm, pip]
  exclude: [pip]
  storeDir: /var/lib/pullthrough/llm-verdicts
  cacheTtl: 720h
  limits:
    maxArtifactBytes: 1048576
    maxFiles: 100
    maxTurns: 4
  budget:
    enabled: true
    globalCeilingUsd: 250
    tenantCeilingUsd: 25
    tenantCeilingsUsd: {platform: 100}
    window: 12h
    pricing:
      claude-opus-4-8: {inputPerMTok: 5, outputPerMTok: 25}
`
	t.Setenv("PTS_TEST_PKGSCAN_KEY", "sk-from-env")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	// The strict pass knows every key used above.
	if r := CheckBytes([]byte(doc)); r.Errors != 0 {
		t.Fatalf("preflight errors: %+v", r.Issues)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	l := c.LLMPackageScan
	if !l.Enabled || l.Provider != "claude" || l.Model != "claude-opus-4-8" || l.Mode != "tools" {
		t.Errorf("parsed = %+v", l)
	}
	if l.APIKey != "sk-from-env" {
		t.Errorf("apiKey = %q, want the expanded environment value", l.APIKey)
	}
	if l.Thinking == nil || *l.Thinking {
		t.Errorf("thinking = %v, want an explicit false", l.Thinking)
	}
	if l.Action != "quarantine" || l.FailMode != "closed" || l.MaliciousThreshold != 0.8 || l.SuspiciousThreshold != 0.6 {
		t.Errorf("enforcement = %+v", l)
	}
	if l.Timeout != 90*time.Second || l.MaxConcurrent != 2 || l.CacheTTL != 720*time.Hour {
		t.Errorf("timing = %+v", l)
	}
	if strings.Join(l.Include, ",") != "npm,pip" || strings.Join(l.Exclude, ",") != "pip" {
		t.Errorf("scope = %v / %v", l.Include, l.Exclude)
	}
	// Set limits override; unset ones keep their defaults.
	if l.Limits.MaxArtifactBytes != 1<<20 || l.Limits.MaxFiles != 100 || l.Limits.MaxTurns != 4 || l.Limits.MaxDepth != 32 || l.Limits.MaxToolCalls != 24 {
		t.Errorf("limits = %+v", l.Limits)
	}
	b := l.Budget
	if !b.Enabled || b.GlobalCeilingUSD != 250 || b.TenantCeilingUSD != 25 || b.TenantCeilingsUSD["platform"] != 100 ||
		b.Window != 12*time.Hour || b.Pricing["claude-opus-4-8"].OutputPerMTok != 25 {
		t.Errorf("budget = %+v", b)
	}
}

func TestEffectiveLLMPackageScanInheritance(t *testing.T) {
	base := func() Config {
		c := Default()
		c.Scanning.Provider = "openai"
		c.Scanning.APIKey = "sk-commit"
		c.Scanning.BaseURL = "https://gateway.internal/v1"
		c.Scanning.APIVersion = "2024-06-01"
		c.Scanning.ReasoningEffort = "high"
		c.Scanning.Timeout = 45 * time.Second
		c.Scanning.Commit.DeepModel = "deep-model"
		c.LLMPackageScan.Enabled = true
		return c
	}

	t.Run("an empty provider inherits everything from scanning", func(t *testing.T) {
		c := base()
		l := c.EffectiveLLMPackageScan()
		if l.Provider != "openai" || l.APIKey != "sk-commit" || l.BaseURL != "https://gateway.internal/v1" ||
			l.APIVersion != "2024-06-01" || l.ReasoningEffort != "high" || l.RequestTimeout != 45*time.Second || l.Model != "deep-model" {
			t.Errorf("effective = %+v", l)
		}
		// The stored configuration is not rewritten: inheritance is a view.
		if c.LLMPackageScan.Provider != "" || c.LLMPackageScan.APIKey != "" {
			t.Error("EffectiveLLMPackageScan mutated the configuration")
		}
	})

	t.Run("explicit values win over inherited ones", func(t *testing.T) {
		c := base()
		c.LLMPackageScan.APIKey = "sk-package"
		c.LLMPackageScan.BaseURL = "https://other.internal/v1"
		c.LLMPackageScan.Model = "package-model"
		c.LLMPackageScan.RequestTimeout = 5 * time.Second
		l := c.EffectiveLLMPackageScan()
		if l.APIKey != "sk-package" || l.BaseURL != "https://other.internal/v1" || l.Model != "package-model" || l.RequestTimeout != 5*time.Second {
			t.Errorf("effective = %+v", l)
		}
	})

	t.Run("the same provider family shares credentials, not the model", func(t *testing.T) {
		c := base()
		c.LLMPackageScan.Provider = "codex" // the OpenAI-compatible client under another name
		l := c.EffectiveLLMPackageScan()
		if l.Provider != "codex" || l.APIKey != "sk-commit" || l.BaseURL != "https://gateway.internal/v1" {
			t.Errorf("effective = %+v", l)
		}
		if l.Model != "" {
			t.Errorf("model = %q: an explicitly chosen provider must not take the commit scanner's model", l.Model)
		}
	})

	t.Run("a different provider inherits nothing", func(t *testing.T) {
		c := base()
		c.LLMPackageScan.Provider = "claude"
		l := c.EffectiveLLMPackageScan()
		if l.APIKey != "" || l.BaseURL != "" || l.APIVersion != "" || l.ReasoningEffort != "" || l.Model != "" {
			t.Errorf("a key for one provider was handed to another: %+v", l)
		}
	})

	t.Run("an unusable scanning provider is not inherited", func(t *testing.T) {
		c := base()
		c.Scanning.Provider = "none"
		l := c.EffectiveLLMPackageScan()
		if l.Provider != "" || l.APIKey != "" {
			t.Errorf("effective = %+v", l)
		}
		if err := c.validateLLMPackageScan(); err == nil || !strings.Contains(err.Error(), "llmPackageScan.provider is required") {
			t.Errorf("err = %v, want a provider-required error", err)
		}
	})
}

func TestValidateLLMPackageScan(t *testing.T) {
	enabled := func() Config {
		c := Default()
		c.LLMPackageScan.Enabled = true
		c.LLMPackageScan.Provider = "claude"
		c.LLMPackageScan.APIKey = "sk"
		return c
	}
	if c := enabled(); c.validateLLMPackageScan() != nil {
		t.Fatalf("a minimal enabled configuration must validate: %v", c.validateLLMPackageScan())
	}

	// A disabled gate is never a reason to refuse to start.
	off := Default()
	off.LLMPackageScan.Action = "nonsense"
	off.LLMPackageScan.Limits.MaxTurns = -5
	if err := off.validateLLMPackageScan(); err != nil {
		t.Errorf("a disabled gate enforced its bounds: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*LLMPackageScanConfig)
		want   string
	}{
		{"unknown provider", func(l *LLMPackageScanConfig) { l.Provider = "bard" }, "provider must be"},
		{"relative baseUrl", func(l *LLMPackageScanConfig) { l.BaseURL = "gateway.internal/v1" }, "baseUrl"},
		{"file baseUrl", func(l *LLMPackageScanConfig) { l.BaseURL = "file:///etc/passwd" }, "baseUrl"},
		{"mode", func(l *LLMPackageScanConfig) { l.Mode = "agentic" }, "mode must be"},
		{"action", func(l *LLMPackageScanConfig) { l.Action = "warn" }, "action must be"},
		{"failMode", func(l *LLMPackageScanConfig) { l.FailMode = "soft" }, "failMode must be"},
		{"malicious threshold high", func(l *LLMPackageScanConfig) { l.MaliciousThreshold = 1.01 }, "maliciousThreshold"},
		{"malicious threshold negative", func(l *LLMPackageScanConfig) { l.MaliciousThreshold = -0.1 }, "maliciousThreshold"},
		{"suspicious threshold high", func(l *LLMPackageScanConfig) { l.SuspiciousThreshold = 7 }, "suspiciousThreshold"},
		{"negative timeout", func(l *LLMPackageScanConfig) { l.Timeout = -time.Second }, "durations"},
		{"negative cacheTtl", func(l *LLMPackageScanConfig) { l.CacheTTL = -time.Hour }, "durations"},
		{"negative concurrency", func(l *LLMPackageScanConfig) { l.MaxConcurrent = -1 }, "maxConcurrent"},
		{"unknown include", func(l *LLMPackageScanConfig) { l.Include = []string{"npm", "cobol"} }, `unknown ecosystem "cobol"`},
		{"unknown exclude", func(l *LLMPackageScanConfig) { l.Exclude = []string{"n p m"} }, "unknown ecosystem"},
		{"negative artifact size", func(l *LLMPackageScanConfig) { l.Limits.MaxArtifactBytes = -1 }, "limits"},
		{"ratio below one", func(l *LLMPackageScanConfig) { l.Limits.MaxCompressionRatio = 0.5 }, "maxCompressionRatio"},
		{"prompt too small", func(l *LLMPackageScanConfig) { l.Limits.MaxPromptBytes = 1024 }, "maxPromptBytes"},
		{"tool result too small", func(l *LLMPackageScanConfig) { l.Limits.MaxToolResultBytes = 10 }, "maxToolResultBytes"},
		{"tool bytes below one result", func(l *LLMPackageScanConfig) { l.Limits.MaxToolBytes = 2048; l.Limits.MaxToolResultBytes = 4096 }, "maxToolBytes"},
		{"too many turns", func(l *LLMPackageScanConfig) { l.Limits.MaxTurns = 1000 }, "maxTurns"},
		{"too many tool calls", func(l *LLMPackageScanConfig) { l.Limits.MaxToolCalls = 100000 }, "maxToolCalls"},
		{"output tokens too small", func(l *LLMPackageScanConfig) { l.Limits.MaxOutputTokens = 10 }, "maxOutputTokens"},
		{"total below output", func(l *LLMPackageScanConfig) { l.Limits.MaxTotalTokens = 1000 }, "maxTotalTokens"},
		{"negative global ceiling", func(l *LLMPackageScanConfig) { l.Budget.GlobalCeilingUSD = -1 }, "budget"},
		{"negative tenant override", func(l *LLMPackageScanConfig) { l.Budget.TenantCeilingsUSD = map[string]float64{"a": -1} }, "tenantCeilingsUsd"},
		{"negative price", func(l *LLMPackageScanConfig) {
			l.Budget.Pricing = map[string]ModelPriceConfig{"m": {InputPerMTok: -1}}
		}, "pricing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := enabled()
			tc.mutate(&c.LLMPackageScan)
			err := c.validateLLMPackageScan()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "llmPackageScan") {
				t.Errorf("the error does not name the section: %v", err)
			}
			// The same failure stops the whole configuration from loading.
			if c.Validate() == nil {
				t.Error("Validate accepted a configuration validateLLMPackageScan rejects")
			}
		})
	}

	// excludeUpstreams must name real upstreams: a typo would send a private
	// registry's packages to the provider.
	ex := enabled()
	ex.Upstreams = map[string]UpstreamConfig{
		"npmjs":    {Type: "npm", URL: "https://registry.npmjs.org"},
		"corp-npm": {Type: "npm", URL: "https://npm.corp.example"},
	}
	ex.LLMPackageScan.ExcludeUpstreams = []string{"corp-npm"}
	if err := ex.validateLLMPackageScan(); err != nil {
		t.Errorf("a defined upstream was rejected: %v", err)
	}
	ex.LLMPackageScan.ExcludeUpstreams = []string{"corp-npm", "corp-nmp"}
	if err := ex.validateLLMPackageScan(); err == nil || !strings.Contains(err.Error(), `"corp-nmp"`) || !strings.Contains(err.Error(), "excludeUpstreams") {
		t.Errorf("err = %v, want one naming the undefined upstream", err)
	}

	// Aliases and case are accepted where the gate accepts them.
	ok := enabled()
	ok.LLMPackageScan.Include = []string{"NPM", "pypi", "crates", "gem"}
	ok.LLMPackageScan.Action = "Quarantine"
	ok.LLMPackageScan.FailMode = "CLOSED"
	ok.LLMPackageScan.Mode = "Bundle"
	if err := ok.validateLLMPackageScan(); err != nil {
		t.Errorf("aliases / case: %v", err)
	}
}

func TestCheckLLMPackageScanWarnings(t *testing.T) {
	check := func(doc string) *Report {
		t.Helper()
		r := CheckBytes([]byte("server:\n  httpAddr: \":8080\"\n  writeTimeout: 60s\nupstreams:\n  npm: {type: npm, url: \"https://registry.npmjs.org\"}\n" + doc))
		if r.Errors != 0 {
			t.Fatalf("unexpected errors: %+v", r.Issues)
		}
		return r
	}

	// Disabled: nothing to say.
	if r := check("llmPackageScan:\n  enabled: false\n"); hasIssue(r, SeverityWarning, "llmPackageScan.budget", "") || hasIssue(r, SeverityWarning, "llmPackageScan.apiKey", "") {
		t.Errorf("a disabled gate produced warnings: %+v", r.Issues)
	}

	bare := check("llmPackageScan:\n  enabled: true\n  provider: claude\n  timeout: 2m\n  include: [npm, cargo]\n")
	for path, substr := range map[string]string{
		"llmPackageScan.apiKey":   "no apiKey",
		"llmPackageScan.budget":   "no cost ceiling",
		"llmPackageScan.storeDir": "memory only",
		"llmPackageScan.timeout":  "server.writeTimeout",
		"llmPackageScan.failMode": "served anyway",
		"llmPackageScan.include":  `"cargo"`,
	} {
		if !hasIssue(bare, SeverityWarning, path, substr) {
			t.Errorf("missing warning at %s containing %q; got %+v", path, substr, bare.Issues)
		}
	}
	if hasIssue(bare, SeverityWarning, "llmPackageScan.include", `"npm"`) {
		t.Error("npm has an enabled upstream and must not be flagged")
	}

	// A deliberate, complete configuration is quiet.
	quiet := check(`llmPackageScan:
  enabled: true
  provider: claude
  apiKey: env://ANTHROPIC_KEY
  timeout: 30s
  failMode: closed
  storeDir: /var/lib/pullthrough/llm-verdicts
  budget: {enabled: true, globalCeilingUsd: 100}
`)
	for _, is := range quiet.Issues {
		if strings.HasPrefix(is.Path, "llmPackageScan") {
			t.Errorf("unexpected issue on a complete configuration: %+v", is)
		}
	}

	// Annotate with fail-open is a coherent observe-only setup: no failMode nag.
	observe := check("llmPackageScan:\n  enabled: true\n  provider: claude\n  apiKey: k\n  action: annotate\n")
	if hasIssue(observe, SeverityWarning, "llmPackageScan.failMode", "") {
		t.Error("observe-only (annotate) with fail-open should not be warned about")
	}

	// A key inherited from the commit scanner counts.
	inherited := check("scanning:\n  enabled: true\n  provider: claude\n  apiKey: k\nllmPackageScan:\n  enabled: true\n")
	if hasIssue(inherited, SeverityWarning, "llmPackageScan.apiKey", "") {
		t.Error("an inherited apiKey was reported as missing")
	}

	// An authenticated upstream is probably a private registry: sending its
	// packages to the provider should be a decision.
	const privateUpstreams = `upstreams:
  npmjs: {type: npm, url: "https://registry.npmjs.org"}
  corp-npm:
    type: npm
    url: "https://npm.corp.example"
    credentials: {token: "t"}
  corp-docker:
    type: docker
    url: "https://registry.corp.example"
    credentials: {username: "u", password: "p"}
`
	checkWith := func(doc string) *Report {
		t.Helper()
		r := CheckBytes([]byte("server:\n  httpAddr: \":8080\"\n" + privateUpstreams + doc))
		if r.Errors != 0 {
			t.Fatalf("unexpected errors: %+v", r.Issues)
		}
		return r
	}
	exposed := checkWith("llmPackageScan:\n  enabled: true\n  provider: claude\n  apiKey: k\n")
	if !hasIssue(exposed, SeverityWarning, "llmPackageScan.excludeUpstreams", `"corp-npm"`) {
		t.Errorf("an authenticated npm upstream should be flagged: %+v", exposed.Issues)
	}
	if hasIssue(exposed, SeverityWarning, "llmPackageScan.excludeUpstreams", `"npmjs"`) {
		t.Error("an unauthenticated public upstream must not be flagged")
	}
	if hasIssue(exposed, SeverityWarning, "llmPackageScan.excludeUpstreams", `"corp-docker"`) {
		t.Error("an upstream whose ecosystem is not scanned must not be flagged")
	}
	decided := checkWith("llmPackageScan:\n  enabled: true\n  provider: claude\n  apiKey: k\n  excludeUpstreams: [corp-npm]\n")
	if hasIssue(decided, SeverityWarning, "llmPackageScan.excludeUpstreams", "") {
		t.Errorf("an excluded upstream is still flagged: %+v", decided.Issues)
	}
	ecoOff := checkWith("llmPackageScan:\n  enabled: true\n  provider: claude\n  apiKey: k\n  exclude: [npm]\n")
	if hasIssue(ecoOff, SeverityWarning, "llmPackageScan.excludeUpstreams", "") {
		t.Errorf("an upstream of an excluded ecosystem is flagged: %+v", ecoOff.Issues)
	}

	// A budget that is enabled but has no ceiling bounds nothing.
	hollow := check("llmPackageScan:\n  enabled: true\n  provider: claude\n  apiKey: k\n  budget: {enabled: true}\n")
	if !hasIssue(hollow, SeverityWarning, "llmPackageScan.budget", "no cost ceiling") {
		t.Error("a budget with no ceiling should be flagged")
	}
}

// The API key goes through the same secret handling as every other credential:
// secretRefs resolve, the fingerprint is blind to its value, and an unresolved
// reference names the field without echoing anything.
func TestLLMPackageScanAPIKeyIsACredential(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "llm-key")
	if err := os.WriteFile(keyFile, []byte("file-llm-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.Server.HTTPAddr = ":8080"
	c.LLMPackageScan.APIKey = "file://" + keyFile
	resolver := secrets.NewResolver(nil)
	defer resolver.Close()
	if err := ResolveRefs(context.Background(), &c, resolver); err != nil {
		t.Fatalf("ResolveRefs: %v", err)
	}
	if c.LLMPackageScan.APIKey != "file-llm-key" {
		t.Fatalf("apiKey = %q, want the file's content", c.LLMPackageScan.APIKey)
	}

	missing := Default()
	missing.LLMPackageScan.APIKey = "env://PTS_TEST_LLM_KEY_DEFINITELY_MISSING"
	err := ResolveRefs(context.Background(), &missing, resolver)
	if err == nil || !strings.Contains(err.Error(), "llmPackageScan.apiKey") {
		t.Fatalf("err = %v, want one naming llmPackageScan.apiKey", err)
	}

	one, two, none := Default(), Default(), Default()
	one.LLMPackageScan.APIKey = "secret-one"
	two.LLMPackageScan.APIKey = "secret-two"
	if Fingerprint(&one) != Fingerprint(&two) {
		t.Error("rotating the key changed the configuration fingerprint: the value is not redacted")
	}
	if Fingerprint(&one) == Fingerprint(&none) {
		t.Error("setting vs. clearing the key should still be visible as drift")
	}

	// The dedicated environment override.
	t.Setenv("PTS_LLM_PACKAGE_SCAN_API_KEY", "sk-from-override")
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  httpAddr: \":8080\"\nllmPackageScan:\n  apiKey: in-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.LLMPackageScan.APIKey != "sk-from-override" {
		t.Errorf("apiKey = %q, want the PTS_LLM_PACKAGE_SCAN_API_KEY override", loaded.LLMPackageScan.APIKey)
	}
}
