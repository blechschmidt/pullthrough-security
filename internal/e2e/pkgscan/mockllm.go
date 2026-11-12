//go:build integration
// +build integration

package pkgscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/llmpkgscan/pkgscantest"
)

// mockLLM is a deterministic, offline stand-in for a hosted LLM provider. It
// serves the two wire formats the proxy's provider clients speak —
//
//   - Anthropic Messages:      POST /v1/messages
//   - OpenAI Chat Completions: POST /v1/chat/completions
//
// — so the proxy is configured exactly as in production (llmPackageScan.provider
// and llmPackageScan.baseUrl) and its real HTTP clients, request construction,
// answer parsing and evidence verification run unmodified. Only the model's
// judgement is replaced, by rules a test can state and a reader can check:
//
//   - material containing hangToken is never answered (a scan timeout);
//   - material containing errorToken fails with a server error (an outage);
//   - material containing obeyToken is "benign", whatever else it holds (a
//     model that followed an injected instruction);
//   - material containing maliciousMarker is "malicious", citing the file and
//     line the marker stands on;
//   - anything else is "benign".
//
// The rules read the material only — the user turns and tool results, which is
// where package content appears — never the system prompt, whose own wording
// ("malicious", "benign") must not decide anything.
//
// It also answers the LLM commit scanner's prompts, in that scanner's answer
// shape, by the same marker rule: the Git row runs both scanners against it.
type mockLLM struct {
	srv *httptest.Server

	mu    sync.Mutex
	calls []llmCall
}

// llmCall is one completion the mock was asked for.
type llmCall struct {
	// Wire is the API that was spoken: "anthropic" or "openai".
	Wire string
	// Kind is "package" for a package-content scan, "commit" for a commit scan.
	Kind string
	// Model is the model the request named.
	Model string
	// Material is what the model was shown: every user turn and tool result.
	Material string
	// Tools lists the tools the request declared, by name.
	Tools []string
	// Outcome is what the mock did: benign, malicious, obeyed, error or hang.
	Outcome string
	// Authorized reports whether the request carried the configured API key.
	Authorized bool
}

// mockAPIKey is the key the proxies are configured with; the mock notes
// whether each request presented it.
const mockAPIKey = "pkgscan-e2e-mock-key"

// hangLimit bounds how long the mock holds a request it will never answer. The
// proxy abandons such a request at llmPackageScan.timeout; the bound only
// keeps a broken run from hanging the suite.
const hangLimit = 60 * time.Second

// packagePromptMark is a string of the package scanner's system prompt that no
// commit-scan prompt contains: the name of its data delimiter.
const packagePromptMark = "UNTRUSTED_PACKAGE_DATA"

// Answers to a commit-scan prompt, in the shape internal/scan/commit parses.
const (
	commitBenign    = `{"riskScore": 4, "malicious": false, "rationale": "routine change; no supply-chain risk", "findings": []}`
	commitMalicious = `{"riskScore": 96, "malicious": true, "rationale": "the commit adds an install hook that downloads and executes a remote payload", ` +
		`"findings": [{"category": "backdoor", "severity": "critical", "title": "Install-time remote code execution", ` +
		`"detail": "post-install hook pipes a remote script into a shell", "file": "install.js", "line": 2, "confidence": 0.97}]}`
)

// startMockLLM starts a mock provider endpoint on a free loopback port.
func startMockLLM() *mockLLM {
	m := &mockLLM{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", m.handleAnthropic)
	mux.HandleFunc("/v1/chat/completions", m.handleOpenAI)
	m.srv = httptest.NewServer(mux)
	return m
}

// Close stops the mock.
func (m *mockLLM) Close() { m.srv.Close() }

// BaseURL is the value of llmPackageScan.baseUrl for a provider: the Anthropic
// SDK appends "/v1/messages" to it, the OpenAI client "/chat/completions".
func (m *mockLLM) BaseURL(provider string) string {
	if provider == "openai" || provider == "codex" {
		return m.srv.URL + "/v1"
	}
	return m.srv.URL
}

// Calls returns every completion asked for so far.
func (m *mockLLM) Calls() []llmCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]llmCall(nil), m.calls...)
}

// PackageScans returns the package-scan completions whose material contains
// token, in order.
func (m *mockLLM) PackageScans(token string) []llmCall {
	var out []llmCall
	for _, c := range m.Calls() {
		if c.Kind == "package" && strings.Contains(c.Material, token) {
			out = append(out, c)
		}
	}
	return out
}

// CommitScans returns the commit-scan completions asked for so far.
func (m *mockLLM) CommitScans() []llmCall {
	var out []llmCall
	for _, c := range m.Calls() {
		if c.Kind == "commit" {
			out = append(out, c)
		}
	}
	return out
}

// record notes a completion.
func (m *mockLLM) record(c llmCall) {
	m.mu.Lock()
	m.calls = append(m.calls, c)
	m.mu.Unlock()
}

// maxLLMRequestBytes bounds a request body; a scan prompt is far smaller.
const maxLLMRequestBytes = 16 << 20

// blockText flattens a provider "content" value — a plain string, or an array
// of typed blocks, some of which (a tool result) nest further content — into
// the text it carries.
func blockText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type    string          `json:"type"`
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var b strings.Builder
	for _, blk := range blocks {
		switch blk.Type {
		case "tool_use", "thinking", "redacted_thinking":
			// The model's own earlier output: not material it was shown.
			continue
		}
		if blk.Text != "" {
			b.WriteString(blk.Text)
			b.WriteByte('\n')
		}
		if len(blk.Content) > 0 {
			b.WriteString(blockText(blk.Content))
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// decision is what the mock makes of one request.
type decision struct {
	kind    string // package | commit
	outcome string // benign | malicious | obeyed | error | hang
	answer  string // the model's reply text, for an answered request
}

// decide applies the mock's rules to a request's system prompt and material.
func decide(system, material string) decision {
	d := decision{kind: "commit"}
	if strings.Contains(system, packagePromptMark) {
		d.kind = "package"
	}
	switch {
	case strings.Contains(material, hangToken):
		d.outcome = "hang"
	case strings.Contains(material, errorToken):
		d.outcome = "error"
	case d.kind == "commit":
		d.outcome, d.answer = "benign", commitBenign
		if strings.Contains(material, maliciousMarker) {
			d.outcome, d.answer = "malicious", commitMalicious
		}
	case strings.Contains(material, obeyToken):
		d.outcome, d.answer = "obeyed", pkgscantest.BenignVerdict
	case strings.Contains(material, maliciousMarker):
		// Cite the marker where it stands, the way a model cites a line: the
		// proxy checks the citation against the unpacked file.
		path, line, excerpt := pkgscantest.Locate(material, maliciousMarker)
		d.outcome, d.answer = "malicious", pkgscantest.MaliciousVerdict(path, line, excerpt)
	default:
		d.outcome, d.answer = "benign", pkgscantest.BenignVerdict
	}
	return d
}

// hold keeps a request open until the client gives up.
func hold(r *http.Request) {
	t := time.NewTimer(hangLimit)
	defer t.Stop()
	select {
	case <-r.Context().Done():
	case <-t.C:
	}
}

func writeLLMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// toolNames extracts the names of the tools a request declares. Anthropic
// lists them as {"name": …}, OpenAI as {"function": {"name": …}}.
func toolNames(raw json.RawMessage) []string {
	var tools []struct {
		Name     string `json:"name"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if json.Unmarshal(raw, &tools) != nil {
		return nil
	}
	var out []string
	for _, t := range tools {
		switch {
		case t.Name != "":
			out = append(out, t.Name)
		case t.Function.Name != "":
			out = append(out, t.Function.Name)
		}
	}
	return out
}

func (m *mockLLM) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeLLMJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": "POST required"},
		})
		return
	}
	var req struct {
		Model    string          `json:"model"`
		System   json.RawMessage `json:"system"`
		Tools    json.RawMessage `json:"tools"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLLMRequestBytes)).Decode(&req); err != nil {
		writeLLMJSON(w, http.StatusBadRequest, map[string]any{
			"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": err.Error()},
		})
		return
	}
	var material strings.Builder
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			material.WriteString(blockText(msg.Content))
			material.WriteByte('\n')
		}
	}
	d := decide(blockText(req.System), material.String())
	m.record(llmCall{
		Wire: "anthropic", Kind: d.kind, Model: req.Model, Material: material.String(),
		Tools: toolNames(req.Tools), Outcome: d.outcome,
		Authorized: r.Header.Get("X-Api-Key") == mockAPIKey,
	})
	switch d.outcome {
	case "hang":
		hold(r)
		return
	case "error":
		writeLLMJSON(w, http.StatusInternalServerError, map[string]any{
			"type": "error", "error": map[string]string{"type": "api_error", "message": "mock provider failure"},
		})
		return
	}
	writeLLMJSON(w, http.StatusOK, map[string]any{
		"id":            fmt.Sprintf("msg_mock_%d", len(m.Calls())),
		"type":          "message",
		"role":          "assistant",
		"model":         req.Model,
		"content":       []map[string]string{{"type": "text", "text": d.answer}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage":         map[string]int{"input_tokens": 128, "output_tokens": 48},
	})
}

func (m *mockLLM) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeLLMJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error": map[string]string{"type": "invalid_request_error", "message": "POST required"},
		})
		return
	}
	var req struct {
		Model    string          `json:"model"`
		Tools    json.RawMessage `json:"tools"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxLLMRequestBytes)).Decode(&req); err != nil {
		writeLLMJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]string{"type": "invalid_request_error", "message": err.Error()},
		})
		return
	}
	var system, material strings.Builder
	for _, msg := range req.Messages {
		switch msg.Role {
		case "system", "developer":
			system.WriteString(blockText(msg.Content))
			system.WriteByte('\n')
		case "user", "tool":
			material.WriteString(blockText(msg.Content))
			material.WriteByte('\n')
		}
	}
	d := decide(system.String(), material.String())
	m.record(llmCall{
		Wire: "openai", Kind: d.kind, Model: req.Model, Material: material.String(),
		Tools: toolNames(req.Tools), Outcome: d.outcome,
		Authorized: r.Header.Get("Authorization") == "Bearer "+mockAPIKey,
	})
	switch d.outcome {
	case "hang":
		hold(r)
		return
	case "error":
		writeLLMJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]string{"type": "server_error", "message": "mock provider failure"},
		})
		return
	}
	writeLLMJSON(w, http.StatusOK, map[string]any{
		"id":      fmt.Sprintf("chatcmpl-mock-%d", len(m.Calls())),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": d.answer},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{"prompt_tokens": 128, "completion_tokens": 48, "total_tokens": 176},
	})
}
