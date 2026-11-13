package livescan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The Claude Code bridge.
//
// The proxy's LLM gates speak the Anthropic Messages API with an API key. A
// Claude subscription token (what `claude setup-token` prints, and what the
// task runner's own Claude Code session holds) is not an API key: it is
// issued for Claude Code, and Anthropic's terms do not allow it to be used by
// any other client. So the suite never hands such a token to the proxy.
// Instead the proxy is pointed at this bridge, a loopback server that speaks
// the Messages API and answers each request by running Claude Code itself,
// non-interactively:
//
//	claude -p --output-format stream-json --verbose --tools "" ...
//
// with the proxy's system prompt in a file and the proxy's user message on
// standard input. The token is used by Claude Code and by nothing else; the
// model is given the proxy's system prompt and user message, in Claude Code's own
// wrapper (which adds a preface of its own).
//
// Package content is hostile input. A model that reads it must not be able
// to do anything, so every call runs with no tools at all (`--tools ""`), no
// MCP servers (`--strict-mcp-config` with an empty set), no slash commands,
// skills, hooks, CLAUDE.md or plugins of the user's (`--safe-mode`, a fresh
// configuration directory and home directory per call), and an empty working
// directory. That is checked, not assumed: the CLI's own `init` event lists
// the tools and MCP servers the session has, and a call whose session had any
// is answered with an error, never with the model's text.
//
// What the bridge cannot do is offer the proxy's own read-only tools
// (list_files, read_file, grep): Claude Code runs its own agent loop and has
// no way to hand a tool call back to the caller. A tool-bearing request is
// therefore refused with 400, and the suite configures the gate with
// `mode: bundle` when it goes through the bridge — the package material is in
// the first and only message. Tool mode is exercised against the API directly
// when an API key is available (see live_test.go).

// BridgeConfig configures a Bridge.
type BridgeConfig struct {
	// Bin is the claude executable.
	Bin string
	// Credentials are the environment entries that authenticate the CLI:
	// CLAUDE_CODE_OAUTH_TOKEN=… (a subscription token) or ANTHROPIC_API_KEY=….
	// They are passed to the child process only and never logged.
	Credentials []string
	// ExtraEnv is added to the child's environment (the hermetic tests use it
	// to turn the test binary into a fake CLI).
	ExtraEnv []string
	// StateDir is where each call gets its own home, configuration directory,
	// working directory and prompt file, all removed when the call ends.
	StateDir string
	// MaxConcurrent bounds the CLI processes running at once (0 => 3).
	MaxConcurrent int
	// Effort is passed as --effort when set (low, medium, high, xhigh, max).
	Effort string
	// CallTimeout bounds one CLI run (0 => 10m). The proxy's own timeout,
	// which ends the HTTP request, also ends the run.
	CallTimeout time.Duration
	// Logf receives one line per call; nil discards them.
	Logf func(format string, args ...any)
}

// BridgeCall records one completion the bridge served.
type BridgeCall struct {
	Seq int `json:"seq"`
	// Kind is "package" for a package-content scan, "commit" for a commit
	// scan, "other" otherwise — read from the system prompt.
	Kind  string `json:"kind"`
	Model string `json:"model"`
	// Thinking reports that the request asked for extended thinking.
	Thinking bool `json:"thinking,omitempty"`
	// SystemBytes and UserBytes are the sizes of the two prompt parts; UserSHA256
	// identifies the user message without keeping it.
	SystemBytes int    `json:"systemBytes"`
	UserBytes   int    `json:"userBytes"`
	UserSHA256  string `json:"userSha256"`
	// Status is the HTTP status the bridge answered with; Outcome says why.
	Status  int    `json:"status"`
	Outcome string `json:"outcome"`
	// Result is the model's text (the verdict the proxy parses), capped.
	Result     string        `json:"result,omitempty"`
	StopReason string        `json:"stopReason,omitempty"`
	Duration   time.Duration `json:"duration"`
	// Usage as the CLI reported it.
	InputTokens         int     `json:"inputTokens"`
	OutputTokens        int     `json:"outputTokens"`
	CacheReadTokens     int     `json:"cacheReadTokens,omitempty"`
	CacheCreationTokens int     `json:"cacheCreationTokens,omitempty"`
	CostUSD             float64 `json:"costUsd,omitempty"`
	// What the CLI's init event said about the session.
	ClaudeVersion string   `json:"claudeVersion,omitempty"`
	SessionModel  string   `json:"sessionModel,omitempty"`
	Tools         []string `json:"tools"`
	MCPServers    []string `json:"mcpServers"`
}

// Bridge is a running Claude Code bridge.
type Bridge struct {
	cfg BridgeConfig
	key string
	srv *httptest.Server
	sem chan struct{}

	mu    sync.Mutex
	seq   int
	calls []BridgeCall
}

// Limits of what the bridge reads and keeps.
const (
	maxBridgeRequestBytes = 32 << 20
	maxCLIStdoutBytes     = 16 << 20
	maxCLIStderrBytes     = 64 << 10
	maxKeptResultChars    = 64 << 10
)

// refusalCategory reads the policy category Claude Code prints with a
// refusal ("Details: `[cyber]`").
var refusalCategory = regexp.MustCompile("`\\[([A-Za-z_-]{1,32})\\]`")

// Markers that tell the proxy's two scanners' system prompts apart: the
// package scanner's data delimiter, and the commit scanner's opening line.
const (
	packagePromptMark = "UNTRUSTED_PACKAGE_DATA"
	commitPromptMark  = "reviewing a single Git commit"
)

// StartBridge starts a bridge on a free loopback port.
func StartBridge(cfg BridgeConfig) (*Bridge, error) {
	if strings.TrimSpace(cfg.Bin) == "" {
		return nil, errors.New("livescan: bridge: no claude executable")
	}
	if len(cfg.Credentials) == 0 {
		return nil, errors.New("livescan: bridge: no credentials for the claude CLI")
	}
	if cfg.StateDir == "" {
		return nil, errors.New("livescan: bridge: no state directory")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 3
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 10 * time.Minute
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	b := &Bridge{cfg: cfg, key: "ccbridge-" + hex.EncodeToString(raw[:]), sem: make(chan struct{}, cfg.MaxConcurrent)}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", b.serveMessages)
	b.srv = httptest.NewServer(mux)
	return b, nil
}

// BaseURL is the value of the gate's baseUrl: the SDK appends /v1/messages.
func (b *Bridge) BaseURL() string { return b.srv.URL }

// APIKey is the key the proxy must present. It only keeps other local
// processes from spending the CLI's credentials through the bridge.
func (b *Bridge) APIKey() string { return b.key }

// Close stops the bridge. It waits for the calls in flight (the server does,
// up to the call timeout), then removes whatever call directories a killed run
// left in the state directory: they hold a home and a configuration directory.
func (b *Bridge) Close() {
	b.srv.Close()
	if entries, err := os.ReadDir(b.cfg.StateDir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "call-") {
				_ = os.RemoveAll(filepath.Join(b.cfg.StateDir, e.Name()))
			}
		}
	}
}

// Calls returns the completions served so far.
func (b *Bridge) Calls() []BridgeCall {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]BridgeCall(nil), b.calls...)
}

func (b *Bridge) logf(format string, args ...any) {
	if b.cfg.Logf != nil {
		b.cfg.Logf(format, args...)
	}
}

// messagesRequest is the part of a Messages API request the bridge reads.
type messagesRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    json.RawMessage `json:"system"`
	Messages  []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Tools    json.RawMessage `json:"tools"`
	Thinking json.RawMessage `json:"thinking"`
	Stream   bool            `json:"stream"`
}

// writeAPIError answers in the Messages API's error shape.
func writeAPIError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error", "error": map[string]string{"type": typ, "message": msg},
	})
}

// errorType is the Messages API error type for an HTTP status.
func errorType(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return "authentication_error"
	case status == http.StatusForbidden:
		return "permission_error"
	case status == http.StatusTooManyRequests:
		return "rate_limit_error"
	case status == 529:
		return "overloaded_error"
	case status >= 500:
		return "api_error"
	default:
		return "invalid_request_error"
	}
}

// textOf flattens a "system" or "content" value — a string, or an array of
// typed blocks — into its text. ok is false when a block is not text.
func textOf(raw json.RawMessage) (text string, ok bool) {
	raw = json.RawMessage(bytes.TrimSpace(raw))
	if len(raw) == 0 || string(raw) == "null" {
		return "", true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s, true
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return "", false
	}
	parts := make([]string, 0, len(blocks))
	for _, blk := range blocks {
		if blk.Type != "text" {
			return "", false
		}
		parts = append(parts, blk.Text)
	}
	return strings.Join(parts, "\n\n"), true
}

func (b *Bridge) serveMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "invalid_request_error", "POST required")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Api-Key")), []byte(b.key)) != 1 {
		writeAPIError(w, http.StatusUnauthorized, "authentication_error", "this bridge serves only the proxy it was started for")
		return
	}
	var req messagesRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBridgeRequestBytes)).Decode(&req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "decoding the request: "+err.Error())
		return
	}
	switch {
	case req.Stream:
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "the Claude Code bridge does not stream")
		return
	case len(bytes.TrimSpace(req.Tools)) > 0 && string(bytes.TrimSpace(req.Tools)) != "null" && string(bytes.TrimSpace(req.Tools)) != "[]":
		// Claude Code runs its own agent loop: it cannot hand a tool call back
		// to the caller. The gate falls back to bundle mode on this answer.
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "the Claude Code bridge cannot offer tools; use mode: bundle")
		return
	case strings.TrimSpace(req.Model) == "":
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "model is required")
		return
	}
	system, ok := textOf(req.System)
	if !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "the system prompt must be text")
		return
	}
	if len(req.Messages) != 1 || req.Messages[0].Role != "user" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "the Claude Code bridge answers single-turn requests: exactly one user message")
		return
	}
	user, ok := textOf(req.Messages[0].Content)
	if !ok || strings.TrimSpace(user) == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request_error", "the user message must be non-empty text")
		return
	}

	call := BridgeCall{
		Kind: promptKind(system), Model: req.Model,
		Thinking:    len(bytes.TrimSpace(req.Thinking)) > 0 && string(bytes.TrimSpace(req.Thinking)) != "null",
		SystemBytes: len(system), UserBytes: len(user),
	}
	sum := sha256.Sum256([]byte(user))
	call.UserSHA256 = hex.EncodeToString(sum[:])

	select {
	case b.sem <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	started := time.Now()
	res, err := b.run(r.Context(), req.Model, req.MaxTokens, system, user)
	<-b.sem
	call.Duration = time.Since(started)
	res.fill(&call)

	status, body := b.answer(&call, res, err)
	b.mu.Lock()
	b.seq++
	call.Seq = b.seq
	b.calls = append(b.calls, call)
	b.mu.Unlock()
	b.logf("bridge call %d: %s scan, model %s, %d+%d bytes -> %d %s in %s (%d in / %d out tokens)",
		call.Seq, call.Kind, call.Model, call.SystemBytes, call.UserBytes, call.Status, call.Outcome,
		call.Duration.Round(time.Millisecond), call.InputTokens, call.OutputTokens)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// promptKind tells the package scanner's prompt from the commit scanner's.
func promptKind(system string) string {
	switch {
	case strings.Contains(system, packagePromptMark):
		return "package"
	case strings.Contains(system, commitPromptMark):
		return "commit"
	default:
		return "other"
	}
}

// cliResult is what one CLI run produced.
type cliResult struct {
	// From the init event(s). inits counts them: the isolation check wants
	// exactly one, with both lists present (a CLI whose schema drifted would
	// otherwise look like a session with nothing in it).
	sawInit        bool
	inits          int
	initIncomplete bool
	tools          []string
	mcpServers     []string
	claudeVersion  string
	sessionModel   string
	// From the result event.
	sawResult    bool
	isError      bool
	subtype      string
	result       string
	stopReason   string
	apiStatus    int
	usage        cliUsage
	totalCostUSD float64
	// The process.
	exitErr error
	stderr  string
}

type cliUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
}

// fill copies what the run says about the session and its usage into call.
func (res cliResult) fill(call *BridgeCall) {
	call.ClaudeVersion = res.claudeVersion
	call.SessionModel = res.sessionModel
	call.Tools = append([]string{}, res.tools...)
	call.MCPServers = append([]string{}, res.mcpServers...)
	call.InputTokens = res.usage.InputTokens
	call.OutputTokens = res.usage.OutputTokens
	call.CacheReadTokens = res.usage.CacheReadInputTokens
	call.CacheCreationTokens = res.usage.CacheCreationInputTokens
	call.CostUSD = res.totalCostUSD
	call.StopReason = res.stopReason
}

// answer turns a run into the bridge's HTTP answer and records the outcome.
func (b *Bridge) answer(call *BridgeCall, res cliResult, err error) (int, []byte) {
	apiError := func(status int, msg string) (int, []byte) {
		msg = b.scrub(msg)
		call.Status, call.Outcome = status, msg
		body, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": errorType(status), "message": msg}})
		return status, body
	}
	switch {
	case err != nil:
		return apiError(http.StatusBadGateway, "claude CLI: "+err.Error())
	case !res.sawInit:
		return apiError(http.StatusBadGateway, "claude CLI: no init event"+stderrHint(res))
	case res.inits != 1 || res.initIncomplete:
		// The session could not be inspected: not exactly one init event, or
		// one without its tool and MCP lists. Treated like a session with tools.
		return apiError(http.StatusInternalServerError, fmt.Sprintf(
			"isolation check failed: %d init event(s), lists complete: %v; the claude session could not be inspected and its answer is discarded", res.inits, !res.initIncomplete))
	case len(res.tools) > 0 || len(res.mcpServers) > 0:
		// Fail closed: a model that could act on package content must not
		// have its answer used, whatever it says.
		return apiError(http.StatusInternalServerError, fmt.Sprintf(
			"isolation check failed: the claude session had tools %v and MCP servers %v; its answer is discarded", res.tools, res.mcpServers))
	case !res.sawResult:
		return apiError(http.StatusBadGateway, "claude CLI: no result event"+stderrHint(res))
	case res.stopReason == "refusal":
		// The provider's safety system declined. The Messages API answers that
		// with 200, no content and stop_reason "refusal"; Claude Code renders it
		// as an error result (is_error true, the provider's explanation as the
		// text), so the stop reason, not is_error, identifies it. Passing it on
		// as the API sent it lets the gate see what it would see without the
		// bridge: a terminal refusal, not a transport failure to retry.
		call.Status, call.Outcome = http.StatusOK, "refusal"
		call.Result = capText(res.result, 400)
		details := map[string]string{"type": "refusal"}
		if m := refusalCategory.FindStringSubmatch(res.result); m != nil {
			details["category"] = m[1]
		}
		body, _ := json.Marshal(map[string]any{
			"id":            "msg_ccbridge_" + strconv.Itoa(int(time.Now().UnixNano()%1e12)),
			"type":          "message",
			"role":          "assistant",
			"model":         call.Model,
			"content":       []map[string]string{},
			"stop_reason":   "refusal",
			"stop_sequence": nil,
			"stop_details":  details,
			"usage": map[string]int{
				"input_tokens":                res.usage.InputTokens,
				"output_tokens":               res.usage.OutputTokens,
				"cache_read_input_tokens":     res.usage.CacheReadInputTokens,
				"cache_creation_input_tokens": res.usage.CacheCreationInputTokens,
			},
		})
		return http.StatusOK, body
	case res.isError:
		status := res.apiStatus
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		return apiError(status, "claude CLI: "+res.subtype+": "+capText(res.result, 400))
	}
	stop := res.stopReason
	if stop == "" {
		stop = "end_turn"
	}
	call.Status, call.Outcome = http.StatusOK, "ok"
	call.Result = capText(res.result, maxKeptResultChars)
	body, _ := json.Marshal(map[string]any{
		"id":            "msg_ccbridge_" + strconv.Itoa(int(time.Now().UnixNano()%1e12)),
		"type":          "message",
		"role":          "assistant",
		"model":         call.Model,
		"content":       []map[string]string{{"type": "text", "text": res.result}},
		"stop_reason":   stop,
		"stop_sequence": nil,
		"usage": map[string]int{
			"input_tokens":                res.usage.InputTokens,
			"output_tokens":               res.usage.OutputTokens,
			"cache_read_input_tokens":     res.usage.CacheReadInputTokens,
			"cache_creation_input_tokens": res.usage.CacheCreationInputTokens,
		},
	})
	return http.StatusOK, body
}

// scrub removes the credentials the CLI runs with from text the bridge keeps
// or sends back (a CLI error can quote what it was given). A value too short to
// be a credential is left alone: replacing it would damage ordinary text.
func (b *Bridge) scrub(s string) string {
	for _, kv := range b.cfg.Credentials {
		if _, v, ok := strings.Cut(kv, "="); ok {
			// A secret stored with a trailing newline (`gh secret set < file`)
			// reaches the environment with it; the CLI quotes the bare token.
			if v = strings.TrimSpace(v); len(v) >= 8 {
				s = strings.ReplaceAll(s, v, "[redacted]")
			}
		}
	}
	return s
}

func stderrHint(res cliResult) string {
	parts := []string{}
	if res.exitErr != nil {
		parts = append(parts, res.exitErr.Error())
	}
	if s := strings.TrimSpace(res.stderr); s != "" {
		parts = append(parts, "stderr: "+capText(s, 400))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// capText cuts s to at most n bytes on a rune boundary.
func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// CLIArgs returns the arguments of one run. Exported for the tests that pin
// the isolation flags.
func CLIArgs(model, systemPromptFile, effort string) []string {
	args := []string{
		"-p",
		"--output-format", "stream-json", "--verbose",
		"--model", model,
		"--system-prompt-file", systemPromptFile,
		// No built-in tools, no MCP servers, no commands or skills: the model
		// can read what it is shown and answer, nothing else.
		"--tools", "",
		"--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`,
		"--disable-slash-commands",
		// None of the user's CLAUDE.md, hooks, plugins or settings.
		"--safe-mode",
		"--no-session-persistence",
	}
	if effort != "" {
		args = append(args, "--effort", effort)
	}
	return args
}

// childEnv is the complete environment of one run: nothing is inherited from
// the test process (whose environment may hold other credentials, or say it
// runs inside a Claude Code session) beyond PATH and the locale.
func (b *Bridge) childEnv(dir string, maxTokens int) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	env := []string{
		"PATH=" + path,
		"HOME=" + filepath.Join(dir, "home"),
		"TMPDIR=" + filepath.Join(dir, "tmp"),
		"CLAUDE_CONFIG_DIR=" + filepath.Join(dir, "config"),
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		// Claude Code reads a file named by an @-mention in the prompt and
		// attaches its contents before the model answers. The user message is
		// package content, hostile by definition, so a package could name the
		// credentials file of the user running the suite (or the checkout's
		// .git/config) and have the model quote it back. --tools "" does not
		// stop that; these two switches do (TestKnownMalwareLive checks it with
		// a canary file on every live run).
		"CLAUDE_CODE_DISABLE_ATTACHMENTS=1",
		"CLAUDE_CODE_DISABLE_FILE_MENTIONS=1",
		"DISABLE_AUTOUPDATER=1",
		"LANG=C.UTF-8",
	}
	if maxTokens > 0 {
		env = append(env, "CLAUDE_CODE_MAX_OUTPUT_TOKENS="+strconv.Itoa(maxTokens))
	}
	env = append(env, b.cfg.Credentials...)
	return append(env, b.cfg.ExtraEnv...)
}

// run runs the CLI once.
func (b *Bridge) run(ctx context.Context, model string, maxTokens int, system, user string) (cliResult, error) {
	var res cliResult
	dir, err := os.MkdirTemp(b.cfg.StateDir, "call-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(dir)
	for _, sub := range []string{"home", "tmp", "config", "work"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return res, err
		}
	}
	systemFile := filepath.Join(dir, "system-prompt.txt")
	if err := os.WriteFile(systemFile, []byte(system), 0o600); err != nil {
		return res, err
	}

	ctx, cancel := context.WithTimeout(ctx, b.cfg.CallTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.cfg.Bin, CLIArgs(model, systemFile, b.cfg.Effort)...)
	cmd.Dir = filepath.Join(dir, "work")
	cmd.Env = b.childEnv(dir, maxTokens)
	cmd.Stdin = strings.NewReader(user)
	var stdout bytes.Buffer
	stderr := &cappedBuffer{max: maxCLIStderrBytes}
	cmd.Stdout = &cappedWriter{w: &stdout, max: maxCLIStdoutBytes}
	cmd.Stderr = stderr
	prepareCLI(cmd)
	cmd.WaitDelay = 5 * time.Second

	res.exitErr = cmd.Run()
	reapCLI(cmd)
	// Scrubbed before anything is cut or kept: a token that straddled a cut
	// would leak its prefix, and the model's answer goes to the proxy verbatim.
	res.stderr = b.scrub(stderr.String())
	parseStream(stdout.Bytes(), &res)
	res.result = b.scrub(res.result)
	if ctx.Err() != nil && !res.sawResult {
		return res, fmt.Errorf("the run was cut off: %w", ctx.Err())
	}
	if res.exitErr != nil && !res.sawResult {
		return res, fmt.Errorf("%v%s", res.exitErr, stderrHint(cliResult{stderr: res.stderr}))
	}
	return res, nil
}

// parseStream reads the CLI's stream-json output: the init event and the
// result event. Other events are ignored.
func parseStream(out []byte, res *cliResult) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), maxCLIStdoutBytes)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Subtype string `json:"subtype"`
			// init
			Tools      []string        `json:"tools"`
			MCPServers json.RawMessage `json:"mcp_servers"`
			Version    string          `json:"claude_code_version"`
			Model      string          `json:"model"`
			// result
			IsError        bool     `json:"is_error"`
			Result         string   `json:"result"`
			StopReason     string   `json:"stop_reason"`
			APIErrorStatus *int     `json:"api_error_status"`
			Usage          cliUsage `json:"usage"`
			TotalCostUSD   float64  `json:"total_cost_usd"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		switch {
		case ev.Type == "system" && ev.Subtype == "init":
			res.sawInit = true
			res.inits++
			if ev.Tools == nil || len(bytes.TrimSpace(ev.MCPServers)) == 0 {
				res.initIncomplete = true
			}
			// The union over every init event: a later one cannot hide an
			// earlier one's tools.
			res.tools = append(res.tools, ev.Tools...)
			res.mcpServers = append(res.mcpServers, mcpServerNames(ev.MCPServers)...)
			res.claudeVersion = ev.Version
			res.sessionModel = ev.Model
		case ev.Type == "result":
			res.sawResult = true
			res.isError = ev.IsError
			res.subtype = ev.Subtype
			res.result = ev.Result
			res.stopReason = ev.StopReason
			if ev.APIErrorStatus != nil {
				res.apiStatus = *ev.APIErrorStatus
			}
			res.usage = ev.Usage
			res.totalCostUSD = ev.TotalCostUSD
		}
	}
}

// mcpServerNames reads the init event's MCP server list: names, or objects
// with a name.
func mcpServerNames(raw json.RawMessage) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var names []string
	if json.Unmarshal(raw, &names) == nil {
		return names
	}
	var objs []struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &objs) == nil {
		for _, o := range objs {
			names = append(names, o.Name)
		}
		return names
	}
	// Unreadable: count it as a server, so the isolation check fails closed.
	return []string{"(unreadable mcp_servers: " + capText(string(raw), 80) + ")"}
}

// cappedWriter writes up to max bytes and drops the rest.
type cappedWriter struct {
	w   io.Writer
	max int
	n   int
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if room := c.max - c.n; room > 0 {
		if len(p) > room {
			_, err := c.w.Write(p[:room])
			c.n += room
			return len(p), err
		}
		_, err := c.w.Write(p)
		c.n += len(p)
		return len(p), err
	}
	return len(p), nil
}

// cappedBuffer keeps the first max bytes written to it.
type cappedBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }
