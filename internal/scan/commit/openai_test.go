package commit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestProvider builds an OpenAIProvider pointed at srv with fast, zero-jitter
// backoff so retry tests run quickly and deterministically.
func newTestProvider(t *testing.T, srv *httptest.Server, opts OpenAIOptions) *OpenAIProvider {
	t.Helper()
	opts.BaseURL = srv.URL
	opts.HTTPClient = srv.Client()
	if opts.RetryBaseDelay == 0 {
		opts.RetryBaseDelay = time.Millisecond
	}
	p, err := NewOpenAIProvider(opts)
	if err != nil {
		t.Fatalf("NewOpenAIProvider: %v", err)
	}
	// Deterministic jitter so backoff timing is reproducible.
	p.rng = rand.New(rand.NewSource(1))
	return p
}

func TestOpenAISuccess(t *testing.T) {
	var gotBody chatRequest
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"choices":[{"message":{"content":"VERDICT: ok"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":12,"completion_tokens":34}
		}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "sk-test"})
	text, usage, err := p.Complete(context.Background(), Request{
		Model:  "gpt-4o",
		System: "you are a reviewer",
		User:   "diff here",
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if text != "VERDICT: ok" {
		t.Errorf("text = %q", text)
	}
	if usage.InputTokens != 12 || usage.OutputTokens != 34 {
		t.Errorf("usage = %+v", usage)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPath != "/chat/completions" {
		t.Errorf("path = %q", gotPath)
	}
	if gotBody.Model != "gpt-4o" || len(gotBody.Messages) != 2 {
		t.Errorf("request body = %+v", gotBody)
	}
	if gotBody.Messages[0].Role != "system" || gotBody.Messages[1].Role != "user" {
		t.Errorf("message roles = %+v", gotBody.Messages)
	}
}

func TestOpenAINameAndModelRequired(t *testing.T) {
	p, err := NewOpenAIProvider(OpenAIOptions{APIKey: "x"})
	if err != nil {
		t.Fatalf("NewOpenAIProvider: %v", err)
	}
	if p.Name() != "openai" {
		t.Errorf("Name() = %q", p.Name())
	}
	if _, _, err := p.Complete(context.Background(), Request{User: "x"}); err == nil {
		t.Fatal("expected error for missing model")
	}
}

func TestOpenAIMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices": [ this is not json`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x"})
	_, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"})
	if err == nil {
		t.Fatal("expected decode error")
	}
	if IsRetryable(err) {
		t.Errorf("malformed JSON on a 200 must be terminal, got retryable: %v", err)
	}
	if !strings.Contains(err.Error(), "decoding response") {
		t.Errorf("error = %v", err)
	}
}

func TestOpenAINoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[],"usage":{}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x"})
	if _, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"}); err == nil {
		t.Fatal("expected error for empty choices")
	}
}

func TestOpenAIRateLimitRetrySucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"message":"slow down","type":"rate_limit_error"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x", MaxRetries: 3})
	text, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if text != "ok" {
		t.Errorf("text = %q", text)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Errorf("expected 3 calls (2 x 429 + 1 success), got %d", got)
	}
}

func TestOpenAIRateLimitRetryExhausted(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"message":"nope"}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x", MaxRetries: 2})
	_, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"})
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if !IsRetryable(err) {
		t.Errorf("exhausted transient error must stay retryable, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 { // 1 + 2 retries
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestOpenAIServerErrorRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x"})
	if _, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"}); err != nil {
		t.Fatalf("Complete after 502 retry: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("expected 2 calls, got %d", got)
	}
}

func TestOpenAIAuthErrorTerminal(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"invalid api key","code":"invalid_api_key"}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "bad", MaxRetries: 5})
	_, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if IsRetryable(err) {
		t.Errorf("401 must be terminal, got retryable: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("401 must not be retried, got %d calls", got)
	}
	if !strings.Contains(err.Error(), "invalid api key") {
		t.Errorf("error should surface API message: %v", err)
	}
}

func TestOpenAITimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // block until the client has given up
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"late"}}]}`)
	}))
	defer srv.Close()
	defer close(release)

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x", MaxRetries: 0})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := p.Complete(ctx, Request{Model: "gpt-4o", User: "x"})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	if IsRetryable(err) {
		t.Errorf("context timeout must be terminal, got retryable: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestOpenAIContextCanceledNoRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x", MaxRetries: 5, RetryBaseDelay: time.Hour})
	// Cancel after the first attempt returns 429 and backoff begins.
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	_, _, err := p.Complete(ctx, Request{Model: "gpt-4o", User: "x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOpenAIContentFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":""},"finish_reason":"content_filter"}],"usage":{}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x"})
	_, _, err := p.Complete(context.Background(), Request{Model: "gpt-4o", User: "x"})
	if err == nil {
		t.Fatal("expected content-filter error")
	}
	if IsRetryable(err) {
		t.Errorf("content filter must be terminal, got retryable: %v", err)
	}
}

func TestOpenAIAzureMode(t *testing.T) {
	var gotAPIKey, gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("api-key")
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.Query().Get("api-version")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "azkey", APIVersion: "2024-06-01"})
	if _, _, err := p.Complete(context.Background(), Request{Model: "deployment", User: "x"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotAPIKey != "azkey" {
		t.Errorf("api-key header = %q", gotAPIKey)
	}
	if gotAuth != "" {
		t.Errorf("Azure mode must not send Authorization, got %q", gotAuth)
	}
	if gotQuery != "2024-06-01" {
		t.Errorf("api-version query = %q", gotQuery)
	}
}

func TestOpenAIReasoningEffort(t *testing.T) {
	var body chatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{}}`)
	}))
	defer srv.Close()

	p := newTestProvider(t, srv, OpenAIOptions{APIKey: "x", ReasoningEffort: "high"})
	// Thinking off: no reasoning_effort.
	if _, _, err := p.Complete(context.Background(), Request{Model: "o3", User: "x"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if body.ReasoningEffort != "" {
		t.Errorf("reasoning_effort should be omitted when Thinking is off, got %q", body.ReasoningEffort)
	}
	// Thinking on: reasoning_effort carried through.
	if _, _, err := p.Complete(context.Background(), Request{Model: "o3", User: "x", Thinking: true}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if body.ReasoningEffort != "high" {
		t.Errorf("reasoning_effort = %q, want high", body.ReasoningEffort)
	}
}

func TestOpenAIBaseURLValidation(t *testing.T) {
	if _, err := NewOpenAIProvider(OpenAIOptions{BaseURL: "ftp://nope"}); err == nil {
		t.Fatal("expected error for non-http base URL")
	}
	// Trailing slash is trimmed; default applies when empty.
	p, err := NewOpenAIProvider(OpenAIOptions{BaseURL: "https://gw.example/v1/"})
	if err != nil {
		t.Fatalf("NewOpenAIProvider: %v", err)
	}
	if p.endpoint() != "https://gw.example/v1/chat/completions" {
		t.Errorf("endpoint = %q", p.endpoint())
	}
}

func TestOpenAIAPIKeyFromEnv(t *testing.T) {
	orig := getenv
	getenv = func(key string) string {
		if key == envOpenAIAPIKey {
			return "env-key"
		}
		return ""
	}
	defer func() { getenv = orig }()

	p, err := NewOpenAIProvider(OpenAIOptions{})
	if err != nil {
		t.Fatalf("NewOpenAIProvider: %v", err)
	}
	if p.apiKey != "env-key" {
		t.Errorf("apiKey = %q, want env fallback", p.apiKey)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d, ok := parseRetryAfter("5"); !ok || d != 5*time.Second {
		t.Errorf("seconds parse: %v %v", d, ok)
	}
	if _, ok := parseRetryAfter(""); ok {
		t.Error("empty must not parse")
	}
	if _, ok := parseRetryAfter("garbage"); ok {
		t.Error("garbage must not parse")
	}
	future := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if d, ok := parseRetryAfter(future); !ok || d <= 0 {
		t.Errorf("http-date parse: %v %v", d, ok)
	}
}
