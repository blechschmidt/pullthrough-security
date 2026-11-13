package livescan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// The fake Claude Code CLI.
//
// The hermetic tests point the bridge at the test binary itself with
// fakeClaudeEnv set; TestMain then behaves as the CLI instead of running
// tests. It speaks the CLI's stream-json output (an init event, a result
// event) and plays a model by a rule a test can state: material that holds
// one of the corpus's indicators is malicious, anything else benign. What the
// fake does is chosen by fakeModeEnv; the bridge tests use the other modes to
// see how the bridge handles a CLI that misbehaves.

const (
	fakeClaudeEnv = "PT_LIVESCAN_FAKE_CLAUDE"
	fakeModeEnv   = "PT_LIVESCAN_FAKE_MODE"
)

// Fake modes.
const (
	fakeVerdict = "verdict" // the default: judge by the corpus indicators
	fakeTools   = "tools"   // report a session with a tool (the isolation check must refuse it)
	fakeMCP     = "mcp"     // report a session with an MCP server
	fakeLimited = "429"     // fail with a rate limit, as the CLI reports one
	fakeCrash   = "crash"   // exit 1 with a message on stderr, no events
	fakeLeak    = "leak"    // exit 1 with a message on stderr that quotes the credential it was given
	fakeLeakCut = "leakcut" // like leak, with the credential across the 400-byte cut of a kept message
	fakeSay     = "say"     // answer with the credential in the model's text
	fakeNoLists = "nolists" // an init event without its tools and mcp_servers lists
	fakeTwoInit = "twoinit" // two init events, the first of them with a tool
	fakeRefusal = "refusal" // answer as the CLI does when the provider's safeguards decline
	fakeEcho    = "echo"    // answer with the arguments, environment and stdin seen
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeClaudeEnv) == "1" {
		os.Exit(fakeClaudeMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// fakeEchoAnswer is what the echo mode answers: everything a test may want to
// check about how the bridge ran the CLI.
type fakeEchoAnswer struct {
	Args         []string `json:"args"`
	Env          []string `json:"env"`
	Stdin        string   `json:"stdin"`
	SystemPrompt string   `json:"systemPrompt"`
	Cwd          string   `json:"cwd"`
}

func fakeClaudeMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	model, systemFile := "", ""
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "--model":
			model = args[i+1]
		case "--system-prompt-file":
			systemFile = args[i+1]
		}
	}
	in, _ := io.ReadAll(stdin)
	system, _ := os.ReadFile(systemFile)
	mode := os.Getenv(fakeModeEnv)
	if mode == "" {
		mode = fakeVerdict
	}
	emit := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(stdout, "%s\n", b)
	}
	if mode == fakeCrash {
		fmt.Fprintln(stderr, "Error: fake CLI crashed on purpose")
		return 1
	}
	if mode == fakeLeak {
		fmt.Fprintf(stderr, "Error: authentication failed for token %s\n", os.Getenv("CLAUDE_CODE_OAUTH_TOKEN"))
		return 1
	}
	if mode == fakeLeakCut {
		fmt.Fprintf(stderr, "Error: %s%s\n", strings.Repeat("x", 380), strings.TrimSpace(os.Getenv("CLAUDE_CODE_OAUTH_TOKEN")))
		return 1
	}
	init := map[string]any{
		"type": "system", "subtype": "init", "tools": []string{}, "mcp_servers": []any{},
		"claude_code_version": "0.0.0-fake", "model": model, "apiKeySource": "none",
	}
	switch mode {
	case fakeTools:
		init["tools"] = []string{"Bash", "Read"}
	case fakeMCP:
		init["mcp_servers"] = []map[string]string{{"name": "filesystem", "status": "connected"}}
	case fakeNoLists:
		delete(init, "tools")
		delete(init, "mcp_servers")
	case fakeTwoInit:
		first := map[string]any{}
		for k, v := range init {
			first[k] = v
		}
		first["tools"] = []string{"Bash"}
		emit(first)
	}
	emit(init)
	usage := map[string]int{"input_tokens": len(in)/4 + len(system)/4, "output_tokens": 64}
	result := map[string]any{
		"type": "result", "subtype": "success", "is_error": false, "stop_reason": "end_turn",
		"usage": usage, "total_cost_usd": 0,
	}
	switch mode {
	case fakeLimited:
		result["subtype"] = "error_during_execution"
		result["is_error"] = true
		result["api_error_status"] = 429
		result["result"] = "API Error: 429 rate limited"
	case fakeRefusal:
		// What Claude Code 2.1.319 printed when Opus 4.8's cyber safeguards
		// declined a request: the API's "refusal" stop reason, rendered as an
		// error result whose text names the policy category.
		result["stop_reason"] = "refusal"
		result["is_error"] = true
		result["result"] = "API Error: Opus 4.8's safeguards flagged this message. Our intentionally broad safeguards allow us to " +
			"deliver more capabilities faster, but can sometimes flag legitimate cybersecurity work.\n\nDetails: `[cyber]`\n\nRequest ID: req_fake"
	case fakeSay:
		result["result"] = "the credential is " + strings.TrimSpace(os.Getenv("CLAUDE_CODE_OAUTH_TOKEN")) + " as given"
	case fakeEcho:
		wd, _ := os.Getwd()
		// The credential is reported as a digest: the bridge scrubs the model's
		// text, so the test learns that the CLI got it without the CLI saying it.
		var env []string
		for _, kv := range os.Environ() {
			if k, v, ok := strings.Cut(kv, "="); ok && k == "CLAUDE_CODE_OAUTH_TOKEN" {
				sum := sha256.Sum256([]byte(v))
				kv = k + "=sha256:" + hex.EncodeToString(sum[:])
			}
			env = append(env, kv)
		}
		b, _ := json.Marshal(fakeEchoAnswer{Args: args, Env: env, Stdin: string(in), SystemPrompt: string(system), Cwd: wd})
		result["result"] = string(b)
	default:
		result["result"] = fakeJudge(string(system), string(in))
	}
	emit(result)
	return 0
}

// fakeJudge is the stand-in model: malicious when the material holds one of
// the corpus's indicators. It answers in the shape of the scanner that asked.
func fakeJudge(system, material string) string {
	hit := ""
	if samples, err := Corpus(); err == nil {
		for _, s := range samples {
			for _, ind := range s.Indicators {
				if strings.Contains(material, ind) {
					hit = ind
					break
				}
			}
			if hit != "" {
				break
			}
		}
	}
	if strings.Contains(system, commitPromptMark) && !strings.Contains(system, packagePromptMark) {
		if hit == "" {
			return `{"riskScore": 3, "malicious": false, "rationale": "routine change", "findings": []}`
		}
		b, _ := json.Marshal(map[string]any{
			"riskScore": 97, "malicious": true, "rationale": "the change contains a known attack indicator: " + hit,
			"findings": []map[string]any{{
				"category": "backdoor", "severity": "critical", "title": "Known attack indicator",
				"detail": "the diff contains " + hit, "confidence": 0.95,
			}},
		})
		return string(b)
	}
	if hit == "" {
		return `{"verdict": "benign", "confidence": 0.9, "reasons": ["nothing indicates harm"], "evidence": []}`
	}
	b, _ := json.Marshal(map[string]any{
		"verdict": "malicious", "confidence": 0.97,
		"reasons":  []string{"the artifact contains a known attack indicator"},
		"evidence": []map[string]any{{"path": "", "line": 0, "excerpt": hit}},
	})
	return string(b)
}
