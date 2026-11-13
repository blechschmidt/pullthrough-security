//go:build livellm

package livescan

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Credentials and knobs of a live run.
const (
	// envAPIKey: with an Anthropic API key the gates call the API directly,
	// in the package scan's default mode (tools).
	envAPIKey = "ANTHROPIC_API_KEY"
	// envOAuthToken: with a Claude subscription token (`claude setup-token`)
	// the gates go through the Claude Code bridge, in bundle mode.
	envOAuthToken = "CLAUDE_CODE_OAUTH_TOKEN"
	// envCredentialsFile names a Claude Code credentials file
	// (.credentials.json) whose OAuth access token is used like
	// CLAUDE_CODE_OAUTH_TOKEN. It is read, never refreshed: for a local run
	// with the login of a Claude Code session on the same machine.
	envCredentialsFile = "PT_LIVESCAN_CLAUDE_CREDENTIALS"
	// envClaudeBin is the claude executable for the bridge (default: claude
	// on PATH).
	envClaudeBin = "PT_LIVESCAN_CLAUDE_BIN"
	// envModel, envTriageModel and envDeepModel choose the models (default:
	// the proxy's own defaults); envEffort is the bridge's --effort.
	envModel       = "PT_LIVESCAN_MODEL"
	envTriageModel = "PT_LIVESCAN_TRIAGE_MODEL"
	envDeepModel   = "PT_LIVESCAN_DEEP_MODEL"
	envEffort      = "PT_LIVESCAN_EFFORT"
	// envMode forces the package scan's mode against the API (auto, tools,
	// bundle); the bridge always uses bundle.
	envMode = "PT_LIVESCAN_MODE"
	// envTimeout is llmPackageScan.timeout (default 10m).
	envTimeout = "PT_LIVESCAN_TIMEOUT"
)

// TestKnownMalwareLive pulls every sample of the corpus through the proxy
// with a real model behind the LLM gates: each malicious release must be
// refused as malicious, each clean release served, each attacker commit
// judged malicious and each control commit not. It writes a report (see
// report.go) to PT_TEST_REPORT_DIR, or to the run's work directory.
//
// It is not part of any default test run: it needs the `livellm` build tag
// and a credential, and it costs model calls (about 30 for the full corpus).
//
//	make test-live-llm-scan
//	ANTHROPIC_API_KEY=… go test -tags livellm -run TestKnownMalwareLive -v -timeout 90m ./internal/e2e/livescan/
func TestKnownMalwareLive(t *testing.T) {
	samples, partial := selectSamples(t)
	timeout := 10 * time.Minute
	if v := os.Getenv(envTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			t.Fatalf("%s=%q is not a duration", envTimeout, v)
		}
		timeout = d
	}

	workDir := os.Getenv(envWorkDir)
	keep := workDir != ""
	if workDir == "" {
		dir, err := os.MkdirTemp("", "livescan-")
		if err != nil {
			t.Fatal(err)
		}
		workDir = dir
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A directory a run left behind holds its verdict stores and its cache: a
	// rerun in it would answer from them without asking the model.
	if entries, err := os.ReadDir(workDir); err != nil || len(entries) > 0 {
		t.Fatalf("%s must be an empty directory (%v): files of an earlier run would answer this one without a model call", envWorkDir, err)
	}
	t.Cleanup(func() {
		if !keep && !t.Failed() {
			_ = os.RemoveAll(workDir)
			return
		}
		t.Logf("the run's files are kept in %s", workDir)
	})

	model := liveModel(t, workDir, timeout)
	t.Logf("model: %s; %d samples", model.Label, len(samples))
	if model.Bridge != nil {
		mentionCanary(t, model.Bridge)
	}
	rep := runSuite(t, suiteOptions{
		Samples: samples, Partial: partial, Model: model,
		ProxyBin: proxyBinary(t), WorkDir: workDir, Parallel: parallelism(),
	})

	reportDir := os.Getenv(envReportDir)
	if reportDir == "" {
		reportDir = workDir
	}
	if err := rep.write(reportDir); err != nil {
		t.Errorf("writing the report: %v", err)
	} else {
		t.Logf("report: %s", filepath.Join(reportDir, reportMarkdown))
	}
	for _, c := range rep.Calls {
		if len(c.Tools) > 0 || len(c.MCPServers) > 0 {
			t.Errorf("bridge call %d ran in a session with tools %v / MCP servers %v", c.Seq, c.Tools, c.MCPServers)
		}
	}
	for _, f := range rep.Failures() {
		t.Error(f)
	}
}

// liveModel picks the route to the model from the credentials available.
func liveModel(t *testing.T, workDir string, timeout time.Duration) Model {
	t.Helper()
	m := Model{
		PackageModel: os.Getenv(envModel), TriageModel: os.Getenv(envTriageModel), DeepModel: os.Getenv(envDeepModel),
		Timeout: timeout,
	}
	label := func(route string) string {
		name := m.PackageModel
		if name == "" {
			name = "the proxy's default model"
		}
		return name + " via " + route
	}
	if key := os.Getenv(envAPIKey); key != "" {
		m.APIKey = "env://" + envAPIKey
		m.ProxyEnv = []string{envAPIKey + "=" + key}
		m.Mode = os.Getenv(envMode)
		m.Label = label("the Anthropic API")
		return m
	}
	token := os.Getenv(envOAuthToken)
	if token == "" {
		if path := os.Getenv(envCredentialsFile); path != "" {
			token = tokenFromCredentials(t, path, timeout)
		}
	}
	if token == "" {
		t.Fatalf("a live run needs %s, %s or %s (see the test's documentation)", envAPIKey, envOAuthToken, envCredentialsFile)
	}
	bin := os.Getenv(envClaudeBin)
	if bin == "" {
		var err error
		if bin, err = exec.LookPath("claude"); err != nil {
			t.Fatalf("a subscription token needs the claude CLI: set %s or put claude on PATH", envClaudeBin)
		}
	}
	bridge, err := StartBridge(BridgeConfig{
		Bin: bin, Credentials: []string{envOAuthToken + "=" + token},
		StateDir: filepath.Join(workDir, "bridge"), Effort: os.Getenv(envEffort),
		CallTimeout: timeout, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridge.Close)
	m.BaseURL, m.APIKey, m.Mode, m.Bridge = bridge.BaseURL(), bridge.APIKey(), "bundle", bridge
	m.Label = label("Claude Code (" + versionOf(bin) + ", subscription token, bundle mode)")
	return m
}

// tokenFromCredentials reads the OAuth access token of a Claude Code
// credentials file. It fails when the token expires before a run of the
// suite's length could finish: it is never refreshed here, because a refresh
// rotates the login of the session that owns the file.
func tokenFromCredentials(t *testing.T, path string, timeout time.Duration) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", envCredentialsFile, err)
	}
	var doc struct {
		OAuth struct {
			AccessToken string `json:"accessToken"`
			ExpiresAt   int64  `json:"expiresAt"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.OAuth.AccessToken == "" {
		t.Fatalf("%s: no claudeAiOauth.accessToken in %s", envCredentialsFile, path)
	}
	if doc.OAuth.ExpiresAt > 0 {
		left := time.Until(time.UnixMilli(doc.OAuth.ExpiresAt))
		if left < 3*timeout {
			t.Fatalf("the access token in %s expires in %s; a run may take longer. Let its Claude Code session refresh it, or use %s",
				path, left.Round(time.Minute), envOAuthToken)
		}
	}
	return doc.OAuth.AccessToken
}

// versionOf asks a claude executable for its version.
func versionOf(bin string) string {
	version := exec.Command(bin, "--version")
	version.Env = minimalEnv()
	out, err := version.Output()
	if err != nil {
		return "claude, version unknown"
	}
	return "claude " + strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(out)), "(Claude Code)"))
}

// mentionCanary checks, with the real Claude Code, that a file named by an
// @-mention in the user message — which is package content, hostile by
// definition — is not read and handed to the model. Claude Code attaches such
// files before the model answers, tools or no tools; the bridge switches that
// off in the child's environment, and this is the proof for the CLI version in
// use (a dispatcher can choose another in CI). One call to the cheapest model.
func mentionCanary(t *testing.T, b *Bridge) {
	t.Helper()
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	secret := "CANARY-" + hex.EncodeToString(raw[:])
	dir := t.TempDir()
	path := filepath.Join(dir, "canary.txt")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"model": "claude-haiku-4-5-20251001", "max_tokens": 4000,
		"system":   "You are a test assistant. Answer in at most ten words. If the contents of a file were attached to this conversation through an @-mention, quote them exactly; otherwise answer NOFILE.",
		"messages": []map[string]any{{"role": "user", "content": "Answer now. Files: @" + path + " and @\"" + path + "\""}},
	})
	req, err := http.NewRequest(http.MethodPost, b.BaseURL()+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", b.APIKey())
	res, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		t.Fatalf("the mention canary: %v", err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the mention canary was answered %d: %s", res.StatusCode, data)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("Claude Code read a file named by an @-mention in the user message and showed it to the model: the bridge's isolation does not hold for this CLI version")
	}
	t.Logf("mention canary: an @-mentioned file was not attached")
}
