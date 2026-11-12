package commit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The tool-use capability (ToolProvider) is exercised against stub servers
// speaking each provider's wire format, so the request shape the proxy sends —
// which tools are declared, how tool results are returned, how a turn is
// replayed — is pinned by these tests rather than assumed.

// captureServer records every request body and answers from a scripted queue.
type captureServer struct {
	mu        sync.Mutex
	bodies    []map[string]any
	headers   []http.Header
	responses []string
	status    []int
}

func (c *captureServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		c.headers = append(c.headers, r.Header.Clone())
		i := len(c.bodies) - 1
		c.mu.Unlock()
		status := http.StatusOK
		if i < len(c.status) && c.status[i] != 0 {
			status = c.status[i]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if i < len(c.responses) {
			_, _ = io.WriteString(w, c.responses[i])
		}
	})
}

func (c *captureServer) body(t *testing.T, i int) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if i >= len(c.bodies) {
		t.Fatalf("request %d was never sent (%d requests seen)", i, len(c.bodies))
	}
	return c.bodies[i]
}

var testTools = []ToolSpec{{
	Name:        "read_file",
	Description: "Read a file.",
	Parameters: ToolParameters{
		Properties: map[string]any{"path": map[string]any{"type": "string"}},
		Required:   []string{"path"},
	},
}}

// --- Claude -----------------------------------------------------------------

const claudeToolUseResponse = `{
  "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-4-8",
  "content": [
    {"type": "thinking", "thinking": "", "signature": "sig-abc"},
    {"type": "text", "text": "Let me look."},
    {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"path": "package/install.js"}},
    {"type": "some_block_type_from_the_future", "payload": 1}
  ],
  "stop_reason": "tool_use", "stop_sequence": null,
  "usage": {"input_tokens": 10, "output_tokens": 20, "cache_creation_input_tokens": 400, "cache_read_input_tokens": 1000}
}`

const claudeFinalResponse = `{
  "id": "msg_2", "type": "message", "role": "assistant", "model": "claude-opus-4-8",
  "content": [{"type": "text", "text": "{\"verdict\":\"benign\"}"}],
  "stop_reason": "end_turn", "stop_sequence": null,
  "usage": {"input_tokens": 5, "output_tokens": 7}
}`

func newClaudeStub(t *testing.T, c *captureServer) *ClaudeProvider {
	t.Helper()
	srv := httptest.NewServer(c.handler(t))
	t.Cleanup(srv.Close)
	p, err := NewClaudeProvider(ClaudeOptions{APIKey: "test-key", BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("NewClaudeProvider: %v", err)
	}
	return p
}

func TestClaudeCompleteToolsRoundTrip(t *testing.T) {
	c := &captureServer{responses: []string{claudeToolUseResponse, claudeFinalResponse}}
	p := newClaudeStub(t, c)

	var _ ToolProvider = p // the provider advertises the capability

	req := ToolRequest{
		Model:    "claude-opus-4-8",
		System:   "system rules",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "review this"}},
		Tools:    testTools,
		Thinking: true,
	}
	resp, usage, err := p.CompleteTools(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteTools: %v", err)
	}
	if resp.Stop != ToolStopToolUse {
		t.Errorf("stop = %q, want tool_use", resp.Stop)
	}
	if resp.Text != "Let me look." {
		t.Errorf("text = %q", resp.Text)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].ID != "toolu_1" || resp.ToolCalls[0].Name != "read_file" {
		t.Fatalf("tool calls = %+v", resp.ToolCalls)
	}
	var args struct{ Path string }
	if err := json.Unmarshal(resp.ToolCalls[0].Input, &args); err != nil || args.Path != "package/install.js" {
		t.Errorf("tool input = %s (err %v)", resp.ToolCalls[0].Input, err)
	}
	// input_tokens excludes cache activity; the counters must stay separate and
	// the billable figure must apply the cache multipliers.
	if usage.InputTokens != 10 || usage.CacheReadTokens != 1000 || usage.CacheCreationTokens != 400 {
		t.Errorf("usage = %+v", usage)
	}
	if got, want := usage.BillableInputTokens(), 10+500+100; got != want {
		t.Errorf("billable input tokens = %d, want %d", got, want)
	}

	// The request declares exactly the caller's tool, as a custom tool, and
	// nothing provider-hosted.
	first := c.body(t, 0)
	tools, _ := first["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("declared tools = %v, want exactly one", first["tools"])
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "read_file" {
		t.Errorf("tool name = %v", tool["name"])
	}
	if typ, ok := tool["type"]; ok && typ != "custom" {
		t.Errorf("tool type = %v; only caller-executed tools may be declared", typ)
	}
	schema := tool["input_schema"].(map[string]any)
	if schema["type"] != "object" || schema["properties"] == nil {
		t.Errorf("input_schema = %v", schema)
	}
	if _, set := first["tool_choice"]; set {
		t.Errorf("tool_choice must be unset (auto) on an ordinary turn, got %v", first["tool_choice"])
	}
	if th, _ := first["thinking"].(map[string]any); th["type"] != "adaptive" {
		t.Errorf("thinking = %v, want adaptive", first["thinking"])
	}
	// The system prompt carries a cache breakpoint.
	sys, _ := first["system"].([]any)
	if len(sys) != 1 || sys[0].(map[string]any)["cache_control"] == nil {
		t.Errorf("system = %v, want one block with cache_control", first["system"])
	}

	// Second turn: replay the assistant turn and answer its tool call.
	req.Messages = append(req.Messages, resp.AssistantMessage(), ToolMessage{
		Role:        ToolRoleUser,
		ToolResults: []ToolResult{{CallID: "toolu_1", Content: "file body"}},
		Text:        "that was your last tool call",
	})
	req.NoTools = true
	final, _, err := p.CompleteTools(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteTools (final): %v", err)
	}
	if final.Stop != ToolStopEnd || final.Text != `{"verdict":"benign"}` || len(final.ToolCalls) != 0 {
		t.Errorf("final = %+v", final)
	}

	second := c.body(t, 1)
	// The tools stay declared, and "none" forbids a further call.
	if tc, _ := second["tool_choice"].(map[string]any); tc["type"] != "none" {
		t.Errorf("tool_choice = %v, want none", second["tool_choice"])
	}
	if tools, _ := second["tools"].([]any); len(tools) != 1 {
		t.Errorf("tools must stay declared on the final turn, got %v", second["tools"])
	}
	msgs, _ := second["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("messages = %d, want 3", len(msgs))
	}
	// The assistant turn is replayed with its reasoning block and signature
	// intact, and the unknown block type is dropped rather than crashing.
	assistant := msgs[1].(map[string]any)
	if assistant["role"] != "assistant" {
		t.Fatalf("message 1 role = %v", assistant["role"])
	}
	var kinds []string
	for _, b := range assistant["content"].([]any) {
		blk := b.(map[string]any)
		kinds = append(kinds, blk["type"].(string))
		if blk["type"] == "thinking" && blk["signature"] != "sig-abc" {
			t.Errorf("thinking block signature = %v, want it replayed verbatim", blk["signature"])
		}
	}
	if got := strings.Join(kinds, ","); got != "thinking,text,tool_use" {
		t.Errorf("replayed assistant blocks = %s, want thinking,text,tool_use", got)
	}
	// The tool result precedes the text of the turn that answers it, and the
	// last block of the newest user turn carries the cache breakpoint.
	user := msgs[2].(map[string]any)
	content := user["content"].([]any)
	if len(content) != 2 {
		t.Fatalf("user turn blocks = %d, want 2", len(content))
	}
	result := content[0].(map[string]any)
	if result["type"] != "tool_result" || result["tool_use_id"] != "toolu_1" {
		t.Errorf("first block = %v, want the tool_result", result)
	}
	trailer := content[1].(map[string]any)
	if trailer["type"] != "text" || trailer["cache_control"] == nil {
		t.Errorf("last block = %v, want text with cache_control", trailer)
	}
}

func TestClaudeCompleteToolsRefusalIsTyped(t *testing.T) {
	c := &captureServer{responses: []string{`{
	  "id": "msg_r", "type": "message", "role": "assistant", "model": "m",
	  "content": [], "stop_reason": "refusal", "stop_sequence": null,
	  "stop_details": {"type": "refusal", "category": "cyber"},
	  "usage": {"input_tokens": 3, "output_tokens": 0}
	}`}}
	p := newClaudeStub(t, c)
	_, _, err := p.CompleteTools(context.Background(), ToolRequest{
		Model:    "m",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}},
		Tools:    testTools,
	})
	ref, ok := IsRefusal(err)
	if !ok {
		t.Fatalf("err = %v, want a RefusalError", err)
	}
	if ref.Provider != "claude" || ref.Category != "cyber" {
		t.Errorf("refusal = %+v", ref)
	}
	if IsRetryable(err) {
		t.Error("a refusal must be terminal, not retryable")
	}
}

func TestClaudeCompleteRefusalIsTyped(t *testing.T) {
	c := &captureServer{responses: []string{`{
	  "id": "msg_r", "type": "message", "role": "assistant", "model": "m",
	  "content": [], "stop_reason": "refusal", "stop_sequence": null,
	  "usage": {"input_tokens": 3, "output_tokens": 0}
	}`}}
	p := newClaudeStub(t, c)
	_, _, err := p.Complete(context.Background(), Request{Model: "m", User: "x"})
	if _, ok := IsRefusal(err); !ok {
		t.Fatalf("err = %v, want a RefusalError", err)
	}
}

func TestClaudeMessagesRejectsMalformedHistory(t *testing.T) {
	for name, msgs := range map[string][]ToolMessage{
		"empty":           nil,
		"empty user":      {{Role: ToolRoleUser}},
		"empty assistant": {{Role: ToolRoleUser, Text: "a"}, {Role: ToolRoleAssistant}},
		"unknown role":    {{Role: "system", Text: "a"}},
	} {
		if _, err := claudeMessages(msgs); err == nil {
			t.Errorf("%s: claudeMessages accepted a malformed history", name)
		}
	}
}

func TestSupportsAdaptiveThinking(t *testing.T) {
	for model, want := range map[string]bool{
		"claude-opus-4-8":           true,
		"claude-opus-5-5":           true,
		"claude-sonnet-5-5":         true,
		"claude-haiku-5-5":          true,
		"claude-fable-5-1":          true,
		" Claude-Sonnet-4-6 ":       true,
		"claude-haiku-4-5":          false,
		"claude-haiku-4-5-20251001": false,
		"claude-opus-4-5":           false,
		"gpt-4o":                    false,
		"":                          false,
	} {
		if got := SupportsAdaptiveThinking(model); got != want {
			t.Errorf("SupportsAdaptiveThinking(%q) = %v, want %v", model, got, want)
		}
	}
}

// --- OpenAI -----------------------------------------------------------------

const openAIToolCallResponse = `{
  "id": "c1", "object": "chat.completion",
  "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
    "role": "assistant", "content": null, "vendor_extra": "keep-me",
    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"setup.py\"}"}}]
  }}],
  "usage": {"prompt_tokens": 11, "completion_tokens": 22}
}`

const openAIFinalResponse = `{
  "id": "c2", "object": "chat.completion",
  "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "{\"verdict\":\"malicious\"}"}}],
  "usage": {"prompt_tokens": 5, "completion_tokens": 6}
}`

func newOpenAIStub(t *testing.T, c *captureServer) *OpenAIProvider {
	t.Helper()
	srv := httptest.NewServer(c.handler(t))
	t.Cleanup(srv.Close)
	p, err := NewOpenAIProvider(OpenAIOptions{APIKey: "sk-test", BaseURL: srv.URL, MaxRetries: -1})
	if err != nil {
		t.Fatalf("NewOpenAIProvider: %v", err)
	}
	return p
}

func TestOpenAICompleteToolsRoundTrip(t *testing.T) {
	c := &captureServer{responses: []string{openAIToolCallResponse, openAIFinalResponse}}
	p := newOpenAIStub(t, c)

	var _ ToolProvider = p

	req := ToolRequest{
		Model:    "gpt-4o",
		System:   "system rules",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "review this"}},
		Tools:    testTools,
	}
	resp, usage, err := p.CompleteTools(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteTools: %v", err)
	}
	if resp.Stop != ToolStopToolUse || len(resp.ToolCalls) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	call := resp.ToolCalls[0]
	if call.ID != "call_1" || call.Name != "read_file" || string(call.Input) != `{"path":"setup.py"}` {
		t.Errorf("tool call = %+v", call)
	}
	if usage.InputTokens != 11 || usage.OutputTokens != 22 {
		t.Errorf("usage = %+v", usage)
	}

	first := c.body(t, 0)
	if first["tool_choice"] != "auto" {
		t.Errorf("tool_choice = %v, want auto", first["tool_choice"])
	}
	tools, _ := first["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["type"] != "function" {
		t.Fatalf("tools = %v, want one function tool", first["tools"])
	}
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	params := fn["parameters"].(map[string]any)
	if fn["name"] != "read_file" || params["type"] != "object" {
		t.Errorf("function = %v", fn)
	}
	msgs := first["messages"].([]any)
	if len(msgs) != 2 || msgs[0].(map[string]any)["role"] != "system" {
		t.Errorf("messages = %v, want system + user", msgs)
	}

	req.Messages = append(req.Messages, resp.AssistantMessage(), ToolMessage{
		Role:        ToolRoleUser,
		ToolResults: []ToolResult{{CallID: "call_1", Content: "print('hi')"}, {CallID: "call_2", Content: "nope", IsError: true}},
		Text:        "answer now",
	})
	req.NoTools = true
	final, _, err := p.CompleteTools(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteTools (final): %v", err)
	}
	if final.Stop != ToolStopEnd || final.Text != `{"verdict":"malicious"}` {
		t.Errorf("final = %+v", final)
	}

	second := c.body(t, 1)
	if second["tool_choice"] != "none" {
		t.Errorf("tool_choice = %v, want none", second["tool_choice"])
	}
	msgs = second["messages"].([]any)
	// system, user, assistant (verbatim), tool, tool, user
	if len(msgs) != 6 {
		t.Fatalf("messages = %d, want 6: %v", len(msgs), msgs)
	}
	assistant := msgs[2].(map[string]any)
	if assistant["role"] != "assistant" || assistant["vendor_extra"] != "keep-me" {
		t.Errorf("assistant turn = %v, want the API's own message replayed verbatim", assistant)
	}
	tool1 := msgs[3].(map[string]any)
	if tool1["role"] != "tool" || tool1["tool_call_id"] != "call_1" || tool1["content"] != "print('hi')" {
		t.Errorf("tool message = %v", tool1)
	}
	tool2 := msgs[4].(map[string]any)
	if tool2["tool_call_id"] != "call_2" || !strings.HasPrefix(tool2["content"].(string), "ERROR: ") {
		t.Errorf("failed tool message = %v, want it marked as an error", tool2)
	}
	if last := msgs[5].(map[string]any); last["role"] != "user" || last["content"] != "answer now" {
		t.Errorf("trailing user message = %v", last)
	}
}

func TestOpenAICompleteToolsContentFilterIsRefusal(t *testing.T) {
	c := &captureServer{responses: []string{`{
	  "choices": [{"index": 0, "finish_reason": "content_filter", "message": {"role": "assistant", "content": ""}}],
	  "usage": {"prompt_tokens": 1, "completion_tokens": 0}
	}`}}
	p := newOpenAIStub(t, c)
	_, _, err := p.CompleteTools(context.Background(), ToolRequest{
		Model:    "gpt-4o",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}},
		Tools:    testTools,
	})
	ref, ok := IsRefusal(err)
	if !ok || ref.Provider != "openai" {
		t.Fatalf("err = %v, want an openai RefusalError", err)
	}
}

func TestOpenAICompleteToolsStatusErrors(t *testing.T) {
	// A gateway without function calling rejects the request: terminal.
	c := &captureServer{status: []int{http.StatusBadRequest}, responses: []string{`{"error":{"message":"tools are not supported"}}`}}
	p := newOpenAIStub(t, c)
	_, _, err := p.CompleteTools(context.Background(), ToolRequest{
		Model:    "local-model",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}},
		Tools:    testTools,
	})
	if err == nil || IsRetryable(err) {
		t.Fatalf("err = %v, want a terminal error", err)
	}
	if !strings.Contains(err.Error(), "tools are not supported") {
		t.Errorf("err = %v, want the gateway's message", err)
	}

	// A 503 is transient.
	c2 := &captureServer{status: []int{http.StatusServiceUnavailable}, responses: []string{`{"error":{"message":"overloaded"}}`}}
	p2 := newOpenAIStub(t, c2)
	_, _, err = p2.CompleteTools(context.Background(), ToolRequest{
		Model:    "gpt-4o",
		Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}},
	})
	if !IsRetryable(err) {
		t.Fatalf("err = %v, want a retryable error", err)
	}
}

func TestOpenAIToolsStopNormalization(t *testing.T) {
	// A "stop" finish that still carries tool calls is a tool-use turn.
	out, _, err := decodeToolsResponse([]byte(`{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":null,
	  "tool_calls":[{"id":"a","type":"function","function":{"name":"grep","arguments":""}}]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.Stop != ToolStopToolUse || string(out.ToolCalls[0].Input) != "{}" {
		t.Errorf("out = %+v", out)
	}
	// A length finish is a truncated answer.
	out, _, err = decodeToolsResponse([]byte(`{"choices":[{"finish_reason":"length","message":{"role":"assistant","content":"{\"verd"}}]}`))
	if err != nil || out.Stop != ToolStopMaxTokens {
		t.Errorf("out = %+v err = %v", out, err)
	}
	if _, _, err := decodeToolsResponse([]byte(`{"choices":[]}`)); err == nil {
		t.Error("an empty choices array must be an error")
	}
	if _, _, err := decodeToolsResponse([]byte(`not json`)); err == nil {
		t.Error("a non-JSON body must be an error")
	}
}

func TestUsageAdd(t *testing.T) {
	var u Usage
	u.Add(Usage{InputTokens: 1, OutputTokens: 2, CacheReadTokens: 3, CacheCreationTokens: 4})
	u.Add(Usage{InputTokens: 10, OutputTokens: 20})
	if u != (Usage{InputTokens: 11, OutputTokens: 22, CacheReadTokens: 3, CacheCreationTokens: 4}) {
		t.Errorf("u = %+v", u)
	}
	if (Usage{InputTokens: 7}).BillableInputTokens() != 7 {
		t.Error("without cache activity the billable count is the input count")
	}
}

func TestPricingClaude5Family(t *testing.T) {
	p := DefaultPricing()
	for model, want := range map[string]ModelPrice{
		"claude-opus-5-5":   {InputPerMTok: 4, OutputPerMTok: 20},
		"claude-opus-5":     {InputPerMTok: 5, OutputPerMTok: 25},
		"claude-sonnet-5-5": {InputPerMTok: 2, OutputPerMTok: 10},
		"claude-haiku-5-5":  {InputPerMTok: 0.10, OutputPerMTok: 0.50},
		"claude-fable-5-1":  {InputPerMTok: 10, OutputPerMTok: 50},
	} {
		if got := p.priceFor(model); got != want {
			t.Errorf("priceFor(%q) = %+v, want %+v", model, got, want)
		}
	}
}

// A provider API error carries the HTTP status it was answered with, through
// every layer of wrapping, so a caller can tell a rejected request shape from
// bad credentials or an outage.
func TestProviderErrorsCarryTheHTTPStatus(t *testing.T) {
	for _, tc := range []struct {
		status    int
		retryable bool
	}{
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusServiceUnavailable, true},
	} {
		body := `{"error":{"message":"nope","type":"invalid_request_error"}}`

		openai := newOpenAIStub(t, &captureServer{status: []int{tc.status}, responses: []string{body}})
		_, _, err := openai.CompleteTools(context.Background(), ToolRequest{
			Model: "gpt-4o", Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}}, Tools: testTools,
		})
		if got, ok := HTTPStatus(err); !ok || got != tc.status {
			t.Errorf("openai %d: HTTPStatus = %d, %v (err %v)", tc.status, got, ok, err)
		}
		if IsRetryable(err) != tc.retryable {
			t.Errorf("openai %d: retryable = %v, want %v", tc.status, IsRetryable(err), tc.retryable)
		}

		// The SDK retries a 5xx by itself, so the stub answers every attempt alike.
		claudeBody := `{"type":"error","error":{"type":"invalid_request_error","message":"nope"}}`
		claude := newClaudeStub(t, &captureServer{
			status:    []int{tc.status, tc.status, tc.status, tc.status},
			responses: []string{claudeBody, claudeBody, claudeBody, claudeBody},
		})
		_, _, err = claude.CompleteTools(context.Background(), ToolRequest{
			Model: "claude-opus-4-8", Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}}, Tools: testTools, MaxTokens: 64,
		})
		if got, ok := HTTPStatus(err); !ok || got != tc.status {
			t.Errorf("claude %d: HTTPStatus = %d, %v (err %v)", tc.status, got, ok, err)
		}
		if IsRetryable(err) != tc.retryable {
			t.Errorf("claude %d: retryable = %v, want %v", tc.status, IsRetryable(err), tc.retryable)
		}
	}

	if _, ok := HTTPStatus(errors.New("dial tcp: connection refused")); ok {
		t.Error("a transport error has no HTTP status")
	}
	if _, ok := HTTPStatus(nil); ok {
		t.Error("nil has no HTTP status")
	}
	wrapped := fmt.Errorf("outer: %w", MarkRetryable(NewStatusError(503, errors.New("overloaded"))))
	if got, ok := HTTPStatus(wrapped); !ok || got != 503 || wrapped.Error() != "outer: overloaded" {
		t.Errorf("wrapped: status %d %v, message %q", got, ok, wrapped.Error())
	}
}

// A large max_tokens must not turn into a client-side refusal to send the
// request: the SDK's "streaming is required" estimate is pre-empted by an
// explicit timeout, for the plain and the tool-bearing call alike, including
// for a model with a non-streaming token limit in the SDK's table.
func TestClaudeLargeMaxTokensIsSentNotRefused(t *testing.T) {
	for _, model := range []string{"claude-opus-4-8", "claude-opus-4-1-20250805"} {
		c := &captureServer{responses: []string{claudeFinalResponse, claudeFinalResponse}}
		p := newClaudeStub(t, c)

		if _, _, err := p.Complete(context.Background(), Request{Model: model, User: "x", MaxTokens: 64000}); err != nil {
			t.Fatalf("%s: Complete with a large max_tokens: %v", model, err)
		}
		if _, _, err := p.CompleteTools(context.Background(), ToolRequest{
			Model: model, Messages: []ToolMessage{{Role: ToolRoleUser, Text: "x"}}, Tools: testTools, MaxTokens: 64000,
		}); err != nil {
			t.Fatalf("%s: CompleteTools with a large max_tokens: %v", model, err)
		}
		if got := c.body(t, 1)["max_tokens"]; got != float64(64000) {
			t.Errorf("%s: max_tokens sent = %v", model, got)
		}
	}
}

func TestClaudeRequestTimeoutFollowsTheContext(t *testing.T) {
	// The option list is opaque, so the rule is checked through its effect: a
	// context with little time left bounds the request to that time.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body first: the server only notices a client hanging up once
		// the request has been read.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	p, err := NewClaudeProvider(ClaudeOptions{APIKey: "k", BaseURL: slow.URL, MaxRetries: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = p.Complete(ctx, Request{Model: "claude-opus-4-8", User: "x", MaxTokens: 64000})
	if err == nil {
		t.Fatal("a request to a hung endpoint returned no error")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the request outlived its context by far: %v", took)
	}
}

// "No retries" means one request, whichever provider is configured. The
// OpenAI-compatible provider has always read a negative MaxRetries that way;
// the Claude provider used to leave the SDK's own default (two more attempts)
// in force, so `maxRetries: -1` still made three requests and spent the backoff
// between them.
func TestClaudeNegativeMaxRetriesDisablesTheSDKRetries(t *testing.T) {
	const overloaded = `{"type":"error","error":{"type":"api_error","message":"overloaded"}}`
	attempts := func(maxRetries int) int {
		t.Helper()
		var mu sync.Mutex
		n := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			mu.Lock()
			n++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			// Ask for an immediate retry so the test does not sit out a backoff.
			w.Header().Set("Retry-After-Ms", "1")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, overloaded)
		}))
		defer srv.Close()
		p, err := NewClaudeProvider(ClaudeOptions{APIKey: "k", BaseURL: srv.URL, MaxRetries: maxRetries})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Complete(context.Background(), Request{Model: "claude-opus-4-8", User: "x", MaxTokens: 256}); err == nil {
			t.Fatal("a failing endpoint returned no error")
		}
		mu.Lock()
		defer mu.Unlock()
		return n
	}

	if got := attempts(-1); got != 1 {
		t.Errorf("MaxRetries -1 made %d requests, want exactly 1", got)
	}
	if got := attempts(1); got != 2 {
		t.Errorf("MaxRetries 1 made %d requests, want 2 (one retry)", got)
	}
}
