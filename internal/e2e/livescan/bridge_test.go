package livescan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// startFakeBridge starts a bridge whose CLI is the fake (see
// fakeclaude_test.go) in the given mode.
func startFakeBridge(t *testing.T, mode string) *Bridge {
	t.Helper()
	return startFakeBridgeWith(t, mode, "CLAUDE_CODE_OAUTH_TOKEN=fake-token-for-tests")
}

// startFakeBridgeWith is startFakeBridge with the given credential entry.
func startFakeBridgeWith(t *testing.T, mode, credential string) *Bridge {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := StartBridge(BridgeConfig{
		Bin:         self,
		Credentials: []string{credential},
		ExtraEnv:    []string{fakeClaudeEnv + "=1", fakeModeEnv + "=" + mode},
		StateDir:    t.TempDir(),
		CallTimeout: time.Minute,
		Logf:        t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b
}

// postMessages sends a raw Messages API request to the bridge.
func postMessages(t *testing.T, b *Bridge, key string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, b.BaseURL()+"/v1/messages", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", key)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("the bridge answered %d with a body that is not JSON: %s", res.StatusCode, data)
	}
	return res.StatusCode, out
}

func simpleRequest(system, user string) map[string]any {
	return map[string]any{
		"model": "claude-test-model", "max_tokens": 1000,
		"system":   system,
		"messages": []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": user}}}},
	}
}

// answerText returns the text of a Messages API answer.
func answerText(t *testing.T, out map[string]any) string {
	t.Helper()
	content, _ := out["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("answer content = %v, want one text block", out["content"])
	}
	blk, _ := content[0].(map[string]any)
	if blk["type"] != "text" {
		t.Fatalf("answer block = %v, want a text block", blk)
	}
	s, _ := blk["text"].(string)
	return s
}

// The CLI runs with no tools, no MCP servers, none of the user's
// configuration, a fresh home and configuration directory, an empty working
// directory and an environment that holds only what the bridge puts there.
func TestBridgeRunsTheCLIIsolated(t *testing.T) {
	t.Setenv("PT_LIVESCAN_CANARY", "must-not-reach-the-cli")
	t.Setenv("ANTHROPIC_API_KEY", "must-not-reach-the-cli-either")
	b := startFakeBridge(t, fakeEcho)

	system := "SYSTEM PROMPT of the test <<<UNTRUSTED_PACKAGE_DATA>>>"
	user := "the material\nwith two lines"
	status, out := postMessages(t, b, b.APIKey(), simpleRequest(system, user))
	if status != http.StatusOK {
		t.Fatalf("status = %d (%v), want 200", status, out)
	}
	var echo fakeEchoAnswer
	if err := json.Unmarshal([]byte(answerText(t, out)), &echo); err != nil {
		t.Fatal(err)
	}

	args := strings.Join(quoteArgs(echo.Args), " ")
	for _, want := range []string{
		`"-p"`, `"--output-format" "stream-json" "--verbose"`, `"--model" "claude-test-model"`,
		`"--tools" ""`, `"--strict-mcp-config" "--mcp-config" "{\"mcpServers\":{}}"`,
		`"--disable-slash-commands"`, `"--safe-mode"`, `"--no-session-persistence"`,
	} {
		if !strings.Contains(args, want) {
			t.Errorf("CLI arguments %s lack %s", args, want)
		}
	}
	if echo.SystemPrompt != system {
		t.Errorf("system prompt file held %q, want %q", echo.SystemPrompt, system)
	}
	if echo.Stdin != user {
		t.Errorf("stdin was %q, want the user message %q", echo.Stdin, user)
	}

	allowed := map[string]bool{
		"PATH": true, "HOME": true, "TMPDIR": true, "CLAUDE_CONFIG_DIR": true, "LANG": true,
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": true, "DISABLE_AUTOUPDATER": true,
		"CLAUDE_CODE_MAX_OUTPUT_TOKENS": true, "CLAUDE_CODE_OAUTH_TOKEN": true,
		"CLAUDE_CODE_DISABLE_ATTACHMENTS": true, "CLAUDE_CODE_DISABLE_FILE_MENTIONS": true,
		fakeClaudeEnv: true, fakeModeEnv: true,
	}
	env := map[string]string{}
	for _, kv := range echo.Env {
		k, v, _ := strings.Cut(kv, "=")
		env[k] = v
		if !allowed[k] {
			t.Errorf("the CLI's environment holds %s, which the bridge does not set", k)
		}
	}
	sum := sha256.Sum256([]byte("fake-token-for-tests"))
	if env["CLAUDE_CODE_OAUTH_TOKEN"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Errorf("the CLI did not get the credentials (it reported %q)", env["CLAUDE_CODE_OAUTH_TOKEN"])
	}
	// No @-mention of a file in the (hostile) user message is read and attached.
	if env["CLAUDE_CODE_DISABLE_ATTACHMENTS"] != "1" || env["CLAUDE_CODE_DISABLE_FILE_MENTIONS"] != "1" {
		t.Errorf("the CLI may read files named in the user message: %v", env)
	}
	if env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] != "1000" {
		t.Errorf("CLAUDE_CODE_MAX_OUTPUT_TOKENS = %q, want the request's max_tokens", env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"])
	}
	home, cfgDir := env["HOME"], env["CLAUDE_CONFIG_DIR"]
	if home == "" || cfgDir == "" || filepath.Dir(home) != filepath.Dir(cfgDir) || filepath.Dir(echo.Cwd) != filepath.Dir(home) {
		t.Errorf("HOME %q, CLAUDE_CONFIG_DIR %q and the working directory %q are not one call's private directories", home, cfgDir, echo.Cwd)
	}
	if _, err := os.Stat(filepath.Dir(home)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the call's directory %s was not removed after the call (stat: %v)", filepath.Dir(home), err)
	}

	calls := b.Calls()
	if len(calls) != 1 || calls[0].Kind != "package" || calls[0].Status != http.StatusOK || calls[0].UserBytes != len(user) {
		t.Errorf("recorded calls = %+v, want one package call answered 200", calls)
	}
}

// The exact argument vector, in order. --tools and --mcp-config take several
// values in the real CLI, so what isolates the session is that a flag follows
// each of them; a reordering that put a value after "--tools" would turn it
// into a tool list.
func TestCLIArgsOrderIsPinned(t *testing.T) {
	got := CLIArgs("claude-test-model", "/tmp/system.txt", "high")
	want := []string{
		"-p", "--output-format", "stream-json", "--verbose", "--model", "claude-test-model",
		"--system-prompt-file", "/tmp/system.txt", "--tools", "",
		"--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`,
		"--disable-slash-commands", "--safe-mode", "--no-session-persistence", "--effort", "high",
	}
	if strings.Join(quoteArgs(got), " ") != strings.Join(quoteArgs(want), " ") {
		t.Errorf("CLIArgs =\n%v\nwant\n%v", quoteArgs(got), quoteArgs(want))
	}
	if without := CLIArgs("m", "f", ""); len(without) != len(want)-2 {
		t.Errorf("without an effort the vector must lose --effort and its value: %v", without)
	}
}

func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		b, _ := json.Marshal(a)
		out[i] = string(b)
	}
	return out
}

// A session that had a tool or an MCP server is refused: its answer is never
// passed on, whatever it says.
func TestBridgeRefusesSessionsThatCouldAct(t *testing.T) {
	for _, mode := range []string{fakeTools, fakeMCP} {
		t.Run(mode, func(t *testing.T) {
			b := startFakeBridge(t, mode)
			status, out := postMessages(t, b, b.APIKey(), simpleRequest("system", "material"))
			if status != http.StatusInternalServerError {
				t.Fatalf("status = %d (%v), want 500", status, out)
			}
			e, _ := out["error"].(map[string]any)
			if msg, _ := e["message"].(string); !strings.Contains(msg, "isolation check failed") {
				t.Errorf("error = %v, want the isolation check", out)
			}
			if c := b.Calls(); len(c) != 1 || c[0].Result != "" {
				t.Errorf("calls = %+v, want one call with no result kept", c)
			}
		})
	}
}

// Errors are reported the way the API reports them, so the proxy's provider
// client classifies them as it would the API's: a rate limit as a rate limit.
func TestBridgeMapsCLIOutcomes(t *testing.T) {
	cases := []struct {
		mode    string
		status  int
		errType string
		stop    string
	}{
		{fakeLimited, http.StatusTooManyRequests, "rate_limit_error", ""},
		{fakeCrash, http.StatusBadGateway, "api_error", ""},
		{fakeRefusal, http.StatusOK, "", "refusal"},
		{fakeVerdict, http.StatusOK, "", "end_turn"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			b := startFakeBridge(t, tc.mode)
			status, out := postMessages(t, b, b.APIKey(), simpleRequest("system", "material"))
			if status != tc.status {
				t.Fatalf("status = %d (%v), want %d", status, out, tc.status)
			}
			if tc.errType != "" {
				e, _ := out["error"].(map[string]any)
				if e["type"] != tc.errType {
					t.Errorf("error type = %v, want %s", e["type"], tc.errType)
				}
				return
			}
			if out["stop_reason"] != tc.stop {
				t.Errorf("stop_reason = %v, want %s", out["stop_reason"], tc.stop)
			}
			if tc.mode == fakeRefusal {
				// As the API sends a refusal: no content, and the category.
				if c, _ := out["content"].([]any); len(c) != 0 {
					t.Errorf("a refusal carries content %v, want none", out["content"])
				}
				if d, _ := out["stop_details"].(map[string]any); d["type"] != "refusal" || d["category"] != "cyber" {
					t.Errorf("stop_details = %v, want a refusal in the category cyber", out["stop_details"])
				}
				if c := b.Calls(); len(c) != 1 || c[0].Outcome != "refusal" || c[0].Status != http.StatusOK {
					t.Errorf("calls = %+v, want one call recorded as a refusal", c)
				}
			}
		})
	}
}

// A provider refusal reaches the proxy's own provider as the typed, terminal
// refusal — not as a transport failure that is retried (the first live run
// retried Opus 4.8's cyber-safeguard refusal of a stealer commit twelve times
// because the bridge had reported it as a 502).
func TestBridgeRefusalIsTerminalForTheProxysProvider(t *testing.T) {
	b := startFakeBridge(t, fakeRefusal)
	p, err := commit.NewClaudeProvider(commit.ClaudeOptions{APIKey: b.APIKey(), BaseURL: b.BaseURL(), MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _, err = p.Complete(ctx, commit.Request{Model: "claude-test-model", System: "s", User: "material", MaxTokens: 2000})
	ref, ok := commit.IsRefusal(err)
	if !ok {
		t.Fatalf("Complete error = %v, want a RefusalError", err)
	}
	if ref.Category != "cyber" || commit.IsRetryable(err) {
		t.Errorf("refusal = %+v, retryable %v; want category cyber, terminal", ref, commit.IsRetryable(err))
	}
	if n := len(b.Calls()); n != 1 {
		t.Errorf("%d CLI runs for one refused request, want 1", n)
	}
}

// A CLI error, or the model, can quote the credential it was given; the
// bridge neither sends it back to the proxy (which stores the model's text and
// shows it on the admin surface) nor keeps it in the call record (which is
// written to the report that CI uploads). It is scrubbed before anything is
// cut — a token across the cut would leak its prefix — and a value stored with
// a trailing newline is scrubbed as the bare token the CLI quotes.
func TestBridgeScrubsCredentials(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		status int
	}{
		{fakeLeak, http.StatusBadGateway}, {fakeLeakCut, http.StatusBadGateway}, {fakeSay, http.StatusOK},
	} {
		for _, suffix := range []string{"", "\n"} {
			t.Run(fmt.Sprintf("%s newline=%v", tc.mode, suffix != ""), func(t *testing.T) {
				b := startFakeBridgeWith(t, tc.mode, "CLAUDE_CODE_OAUTH_TOKEN=fake-token-for-tests"+suffix)
				status, out := postMessages(t, b, b.APIKey(), simpleRequest("system", "material"))
				if status != tc.status {
					t.Fatalf("status = %d (%v), want %d", status, out, tc.status)
				}
				raw, _ := json.Marshal(out)
				calls, _ := json.Marshal(b.Calls())
				for what, text := range map[string]string{"the answer": string(raw), "the call record": string(calls)} {
					// Not the token, and not a prefix of it that a cut could leave.
					if strings.Contains(text, "fake-tok") {
						t.Errorf("%s holds (a prefix of) the credential: %s", what, text)
					}
				}
				if !strings.Contains(string(raw), "[redacted]") {
					t.Errorf("the answer %s does not show that something was redacted", raw)
				}
			})
		}
	}
}

// A session that cannot be inspected is refused as one that had tools: an init
// event without its lists (a CLI whose output schema drifted), or more than one
// init event (the later one must not hide the earlier one's tools).
func TestBridgeIsolationCheckFailsClosed(t *testing.T) {
	for _, mode := range []string{fakeNoLists, fakeTwoInit} {
		t.Run(mode, func(t *testing.T) {
			b := startFakeBridge(t, mode)
			status, out := postMessages(t, b, b.APIKey(), simpleRequest("system", "material"))
			if status != http.StatusInternalServerError {
				t.Fatalf("status = %d (%v), want 500", status, out)
			}
			e, _ := out["error"].(map[string]any)
			if msg, _ := e["message"].(string); !strings.Contains(msg, "isolation check failed") {
				t.Errorf("error = %v, want the isolation check", out)
			}
			if c := b.Calls(); len(c) != 1 || c[0].Result != "" {
				t.Errorf("calls = %+v, want one call with no result kept", c)
			}
		})
	}
}

// Requests the bridge cannot serve faithfully are refused, not approximated.
func TestBridgeRefusesWhatItCannotServe(t *testing.T) {
	b := startFakeBridge(t, fakeVerdict)
	if status, _ := postMessages(t, b, "wrong-key", simpleRequest("s", "u")); status != http.StatusUnauthorized {
		t.Errorf("a request without the bridge's key got %d, want 401", status)
	}
	withTools := simpleRequest("s", "u")
	withTools["tools"] = []map[string]any{{"name": "read_file", "input_schema": map[string]any{"type": "object"}}}
	twoTurns := simpleRequest("s", "u")
	twoTurns["messages"] = []map[string]any{
		{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"},
	}
	streaming := simpleRequest("s", "u")
	streaming["stream"] = true
	image := simpleRequest("s", "u")
	image["messages"] = []map[string]any{{"role": "user", "content": []map[string]any{{"type": "image", "source": map[string]string{}}}}}
	for name, req := range map[string]map[string]any{"tools": withTools, "multi-turn": twoTurns, "stream": streaming, "non-text": image} {
		if status, out := postMessages(t, b, b.APIKey(), req); status != http.StatusBadRequest {
			t.Errorf("%s: status = %d (%v), want 400", name, status, out)
		}
	}
	if n := len(b.Calls()); n != 0 {
		t.Errorf("%d CLI runs for requests that were refused, want 0", n)
	}
}

// The proxy's own Claude provider — the Anthropic SDK — reads the bridge's
// answers: a completion is returned as text with its usage, and a tool
// request fails with the 400 that makes the package scan fall back to bundle
// mode.
func TestBridgeAnswersTheProxysProvider(t *testing.T) {
	b := startFakeBridge(t, fakeVerdict)
	p, err := commit.NewClaudeProvider(commit.ClaudeOptions{APIKey: b.APIKey(), BaseURL: b.BaseURL(), MaxRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	text, usage, err := p.Complete(ctx, commit.Request{Model: "claude-test-model", System: "a <<<UNTRUSTED_PACKAGE_DATA>>> prompt", User: "harmless material", MaxTokens: 2000})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !strings.Contains(text, `"verdict": "benign"`) || usage.OutputTokens == 0 {
		t.Errorf("Complete = %q, usage %+v; want the fake's benign verdict and its usage", text, usage)
	}
	_, _, err = p.CompleteTools(ctx, commit.ToolRequest{
		Model: "claude-test-model", System: "s",
		Messages: []commit.ToolMessage{{Role: commit.ToolRoleUser, Text: "u"}},
		Tools:    []commit.ToolSpec{{Name: "read_file", Description: "reads a file"}},
	})
	if status, ok := commit.HTTPStatus(err); !ok || status != http.StatusBadRequest {
		t.Errorf("CompleteTools error = %v (status %d), want a 400", err, status)
	}
}
