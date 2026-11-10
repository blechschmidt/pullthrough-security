package ecotest

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MaliciousMarker is the plain alphanumeric sentinel the mock LLM keys on. The
// "bad" fixture commit carries it in its diff; the mock returns a malicious
// verdict for any prompt that contains it and a benign verdict otherwise. It is
// deliberately alphanumeric so the commit pipeline's prompt-hardening pass
// (zero-width stripping, injection-directive wrapping, boundary escaping) leaves
// it intact: the mock decides on content that genuinely reaches the model.
const MaliciousMarker = "PTE2EMALICIOUSMARKER"

// The two verdicts the mock emits. They are the exact JSON shape the real
// providers are instructed to return (internal/scan/commit/prompt.go parses
// it), so the pipeline's parsing, sanitizing and scoring run unmodified.
const (
	benignVerdict = `{"riskScore": 4, "malicious": false, ` +
		`"rationale": "routine change; no supply-chain risk", "findings": []}`
	maliciousVerdict = `{"riskScore": 96, "malicious": true, ` +
		`"rationale": "the commit adds an install hook that downloads and executes a remote payload", ` +
		`"findings": [{"category": "backdoor", "severity": "critical", "title": "Install-time remote code execution", ` +
		`"detail": "post-install hook pipes a remote script into a shell", "file": "install.js", "line": 2, "confidence": 0.97}]}`
)

// MockLLM is a deterministic, offline stand-in for a hosted LLM provider. It
// serves the two wire formats the proxy's provider clients speak:
//
//   - Anthropic Messages:       POST /v1/messages
//   - OpenAI Chat Completions:  POST /chat/completions (also /v1/chat/completions)
//
// so the proxy is configured exactly as in production (scanning.provider +
// scanning.baseUrl) and its real HTTP client, request construction and response
// decoding are exercised. Only the model's judgement is replaced: a prompt
// containing MaliciousMarker is malicious, anything else is benign.
type MockLLM struct {
	srv *http.Server
	ln  net.Listener

	mu        sync.Mutex
	calls     int
	malicious int
	models    map[string]int
}

// MockLLMStats is a snapshot of what the mock has served.
type MockLLMStats struct {
	// Calls is the number of completions served.
	Calls int `json:"calls"`
	// Malicious is how many of them returned the malicious verdict.
	Malicious int `json:"malicious"`
	// Models counts completions per requested model identifier.
	Models map[string]int `json:"models"`
}

// StartMockLLM starts the mock on a free loopback port.
func StartMockLLM() (*MockLLM, error) {
	return StartMockLLMOn("127.0.0.1:0")
}

// StartMockLLMOn starts the mock on the given listen address.
func StartMockLLMOn(addr string) (*MockLLM, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mock llm: listen: %w", err)
	}
	m := &MockLLM{ln: ln, models: map[string]int{}}
	m.srv = &http.Server{Handler: m.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = m.srv.Serve(ln) }()
	return m, nil
}

// URL is the base URL to configure as scanning.baseUrl for the "claude"
// provider (the Anthropic SDK appends "/v1/messages").
func (m *MockLLM) URL() string { return "http://" + m.ln.Addr().String() }

// OpenAIURL is the base URL to configure as scanning.baseUrl for the
// "openai"/"codex" provider (the client appends "/chat/completions").
func (m *MockLLM) OpenAIURL() string { return m.URL() + "/v1" }

// Close stops the mock.
func (m *MockLLM) Close() error { return m.srv.Close() }

// Stats returns a snapshot of the completions served so far.
func (m *MockLLM) Stats() MockLLMStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	models := make(map[string]int, len(m.models))
	for k, v := range m.models {
		models[k] = v
	}
	return MockLLMStats{Calls: m.calls, Malicious: m.malicious, Models: models}
}

// Handler returns the mock's HTTP handler (exposed for in-process tests).
func (m *MockLLM) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", m.handleAnthropic)
	mux.HandleFunc("/chat/completions", m.handleOpenAI)
	mux.HandleFunc("/v1/chat/completions", m.handleOpenAI)
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, m.Stats())
	})
	return mux
}

// verdictFor decides the verdict for a prompt and records the call.
func (m *MockLLM) verdictFor(model, prompt string) string {
	bad := strings.Contains(prompt, MaliciousMarker)
	m.mu.Lock()
	m.calls++
	if bad {
		m.malicious++
	}
	m.models[model]++
	m.mu.Unlock()
	if bad {
		return maliciousVerdict
	}
	return benignVerdict
}

// maxPromptBytes bounds a request body; a commit prompt is far smaller.
const maxPromptBytes = 8 << 20

// textOf flattens an Anthropic/OpenAI "content" value — either a plain string or
// an array of typed blocks — into its text.
func textOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var sb strings.Builder
		for _, b := range blocks {
			sb.WriteString(b.Text)
			sb.WriteByte('\n')
		}
		return sb.String()
	}
	return ""
}

func (m *MockLLM) handleAnthropic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": "POST required"},
		})
		return
	}
	var req struct {
		Model    string          `json:"model"`
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPromptBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": err.Error()},
		})
		return
	}
	var prompt strings.Builder
	prompt.WriteString(textOf(req.System))
	for _, msg := range req.Messages {
		prompt.WriteString(textOf(msg.Content))
	}
	verdict := m.verdictFor(req.Model, prompt.String())

	writeJSON(w, http.StatusOK, map[string]any{
		"id":            fmt.Sprintf("msg_mock_%d", m.Stats().Calls),
		"type":          "message",
		"role":          "assistant",
		"model":         req.Model,
		"content":       []map[string]string{{"type": "text", "text": verdict}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage":         map[string]int{"input_tokens": 128, "output_tokens": 48},
	})
}

func (m *MockLLM) handleOpenAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error": map[string]string{"type": "invalid_request_error", "message": "POST required"},
		})
		return
	}
	var req struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxPromptBytes)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": map[string]string{"type": "invalid_request_error", "message": err.Error()},
		})
		return
	}
	var prompt strings.Builder
	for _, msg := range req.Messages {
		prompt.WriteString(textOf(msg.Content))
	}
	verdict := m.verdictFor(req.Model, prompt.String())

	writeJSON(w, http.StatusOK, map[string]any{
		"id":      fmt.Sprintf("chatcmpl-mock-%d", m.Stats().Calls),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]string{"role": "assistant", "content": verdict},
			"finish_reason": "stop",
		}},
		"usage": map[string]int{"prompt_tokens": 128, "completion_tokens": 48, "total_tokens": 176},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
