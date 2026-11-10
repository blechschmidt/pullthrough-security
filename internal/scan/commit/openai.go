package commit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Default OpenAI/Codex model identifiers. Operators normally override these via
// configuration; they exist so an OpenAI provider works out of the box. A fast,
// inexpensive model is used for first-pass triage and a capable model for deep
// analysis on escalation.
const (
	// DefaultOpenAITriageModel is a fast, inexpensive model for triage.
	DefaultOpenAITriageModel = "gpt-4o-mini"
	// DefaultOpenAIDeepModel is a capable model for deep analysis.
	DefaultOpenAIDeepModel = "gpt-4o"
	// defaultOpenAIBaseURL is the public OpenAI Chat Completions endpoint root.
	defaultOpenAIBaseURL = "https://api.openai.com/v1"
	// envOpenAIAPIKey is the fallback environment variable for the API key.
	envOpenAIAPIKey = "OPENAI_API_KEY"
)

// OpenAIProvider is a Provider backed by an OpenAI-compatible Chat Completions
// API. It targets the public OpenAI API by default but, via a configurable base
// URL (and optional Azure api-version), also drives Azure OpenAI and any other
// OpenAI-compatible gateway (vLLM, LiteLLM, OpenRouter, a corporate proxy, ...).
//
// It is implemented against net/http directly rather than a vendored SDK so the
// wire contract — request shape, auth header, retry/backoff, timeout — is
// explicit and fully exercised by the unit tests' stub server. It is safe for
// concurrent use.
type OpenAIProvider struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	apiVersion string // when non-empty, Azure mode: api-version query + api-key header

	maxRetries     int
	retryBaseDelay time.Duration

	// reasoningEffort, when non-empty, is sent as "reasoning_effort" on requests
	// that enable Thinking. It is only meaningful for OpenAI reasoning models; it
	// is omitted otherwise so the provider stays compatible with plain
	// chat-completion gateways that reject unknown fields.
	reasoningEffort string

	// rng is the backoff jitter source; nil uses the package rand. Tests inject a
	// deterministic source.
	rng *rand.Rand
}

// OpenAIOptions configures an OpenAIProvider.
type OpenAIOptions struct {
	// APIKey authenticates to the API. When empty, the OPENAI_API_KEY environment
	// variable is used. A missing key is tolerated at construction so the process
	// can start and fail loudly (with a clear 401) on first use rather than at
	// startup.
	APIKey string
	// BaseURL overrides the API endpoint root (default https://api.openai.com/v1).
	// A trailing "/chat/completions" is appended automatically; any trailing slash
	// on the configured value is trimmed. Set this to an Azure OpenAI deployment
	// root or any OpenAI-compatible gateway.
	BaseURL string
	// APIVersion, when set, selects Azure OpenAI mode: the value is sent as the
	// "api-version" query parameter and the key is sent via the "api-key" header
	// instead of "Authorization: Bearer".
	APIVersion string
	// Timeout bounds a single HTTP attempt (connect + headers + body). Zero
	// disables the per-attempt timeout and relies solely on the request context.
	Timeout time.Duration
	// MaxRetries is the number of additional attempts after the first on a
	// transient failure (429 / 5xx / network error). Zero uses a built-in default;
	// a negative value disables provider-side retries entirely (the pipeline's
	// outer loop still applies).
	MaxRetries int
	// RetryBaseDelay is the base for the provider's exponential backoff between
	// retries. Zero uses a built-in default. A server-supplied Retry-After header
	// always takes precedence.
	RetryBaseDelay time.Duration
	// ReasoningEffort, when set (e.g. "low"/"medium"/"high"), is forwarded as
	// "reasoning_effort" for requests that enable Thinking. Leave empty for
	// non-reasoning models and gateways.
	ReasoningEffort string
	// HTTPClient overrides the HTTP client (for tests or custom transports). When
	// nil a client with Timeout is constructed.
	HTTPClient *http.Client
}

const (
	defaultOpenAIMaxRetries     = 3
	defaultOpenAIRetryBaseDelay = 500 * time.Millisecond
	defaultOpenAITimeout        = 60 * time.Second
	maxOpenAIBackoff            = 30 * time.Second
	maxOpenAIErrorBodyBytes     = 16 << 10 // cap error-body reads at 16 KiB
)

// NewOpenAIProvider constructs an OpenAIProvider. It returns an error only for
// clearly invalid configuration (a malformed base URL); a missing API key is
// tolerated so startup does not fail on a key that is only needed at first use.
func NewOpenAIProvider(opts OpenAIOptions) (*OpenAIProvider, error) {
	apiKey := opts.APIKey
	if strings.TrimSpace(apiKey) == "" {
		apiKey = strings.TrimSpace(getenv(envOpenAIAPIKey))
	}

	baseURL := strings.TrimSpace(opts.BaseURL)
	if baseURL == "" {
		baseURL = defaultOpenAIBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("commit: openai: invalid baseUrl %q: must be an absolute http(s) URL", opts.BaseURL)
	}

	maxRetries := opts.MaxRetries
	switch {
	case maxRetries < 0:
		maxRetries = 0
	case maxRetries == 0:
		maxRetries = defaultOpenAIMaxRetries
	}

	retryBaseDelay := opts.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = defaultOpenAIRetryBaseDelay
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = defaultOpenAITimeout
		}
		httpClient = &http.Client{Timeout: timeout}
	}

	return &OpenAIProvider{
		httpClient:      httpClient,
		baseURL:         baseURL,
		apiKey:          apiKey,
		apiVersion:      strings.TrimSpace(opts.APIVersion),
		maxRetries:      maxRetries,
		retryBaseDelay:  retryBaseDelay,
		reasoningEffort: strings.TrimSpace(opts.ReasoningEffort),
	}, nil
}

// getenv is a seam so tests can stub environment lookups; it defers to os.Getenv
// in production.
var getenv = os.Getenv

// Name implements Provider.
func (p *OpenAIProvider) Name() string { return "openai" }

// chatRequest is the Chat Completions request payload.
type chatRequest struct {
	Model           string        `json:"model"`
	Messages        []chatMessage `json:"messages"`
	MaxTokens       int           `json:"max_tokens,omitempty"`
	ReasoningEffort string        `json:"reasoning_effort,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse is the subset of the Chat Completions response we consume.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// apiErrorEnvelope is the OpenAI error-response shape.
type apiErrorEnvelope struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// Complete implements Provider against the Chat Completions API, with internal
// retry/backoff on transient failures.
func (p *OpenAIProvider) Complete(ctx context.Context, req Request) (string, Usage, error) {
	if strings.TrimSpace(req.Model) == "" {
		return "", Usage{}, errors.New("commit: openai: model is required")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	messages := make([]chatMessage, 0, 2)
	if req.System != "" {
		messages = append(messages, chatMessage{Role: "system", Content: req.System})
	}
	messages = append(messages, chatMessage{Role: "user", Content: req.User})

	payload := chatRequest{
		Model:     req.Model,
		Messages:  messages,
		MaxTokens: maxTokens,
	}
	if req.Thinking && p.reasoningEffort != "" {
		payload.ReasoningEffort = p.reasoningEffort
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", Usage{}, fmt.Errorf("commit: openai: marshaling request: %w", err)
	}

	// Attempt loop: 1 initial attempt + maxRetries additional attempts.
	var lastErr error
	for attempt := 0; attempt <= p.maxRetries; attempt++ {
		if attempt > 0 {
			delay := p.backoff(attempt, lastErr)
			if werr := sleepCtx(ctx, delay); werr != nil {
				return "", Usage{}, werr
			}
		}
		text, usage, retryable, err := p.doOnce(ctx, body)
		if err == nil {
			return text, usage, nil
		}
		// Context errors are terminal and must surface verbatim.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", Usage{}, err
		}
		if !retryable {
			return "", Usage{}, err
		}
		lastErr = err
	}
	// Retries exhausted: report the last transient error, still marked retryable
	// so the pipeline's outer backoff loop may make a further attempt.
	return "", Usage{}, markRetryable(fmt.Errorf("commit: openai: retries exhausted: %w", lastErr))
}

// doOnce performs a single HTTP attempt. It returns whether the error is a
// transient one worth retrying.
func (p *OpenAIProvider) doOnce(ctx context.Context, body []byte) (text string, usage Usage, retryable bool, err error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return "", Usage{}, false, fmt.Errorf("commit: openai: building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if p.apiKey != "" {
		if p.apiVersion != "" {
			httpReq.Header.Set("api-key", p.apiKey) // Azure OpenAI
		} else {
			httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
		}
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		// Preserve context errors so the caller can treat them as terminal.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return "", Usage{}, false, err
		}
		// Transport-level failures (DNS, connection reset, client timeout) never
		// reached a definitive server answer and are worth retrying.
		return "", Usage{}, true, fmt.Errorf("commit: openai: request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxOpenAIErrorBodyBytes))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", Usage{}, isRetryableStatus(resp.StatusCode), p.statusError(resp)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		// A truncated body on an otherwise-OK response is a transient read error.
		return "", Usage{}, true, fmt.Errorf("commit: openai: reading response body: %w", err)
	}

	var parsed chatResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", Usage{}, false, fmt.Errorf("commit: openai: decoding response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", Usage{}, false, errors.New("commit: openai: response contained no choices")
	}

	choice := parsed.Choices[0]
	usage = Usage{
		InputTokens:  parsed.Usage.PromptTokens,
		OutputTokens: parsed.Usage.CompletionTokens,
	}
	if choice.FinishReason == "content_filter" {
		return choice.Message.Content, usage, false,
			errors.New("commit: openai: request blocked by content filter")
	}
	return choice.Message.Content, usage, false, nil
}

// endpoint returns the full Chat Completions URL, including the Azure
// api-version query parameter when in Azure mode.
func (p *OpenAIProvider) endpoint() string {
	url := p.baseURL + "/chat/completions"
	if p.apiVersion != "" {
		url += "?api-version=" + p.apiVersion
	}
	return url
}

// statusError reads a non-2xx response and renders a descriptive error. The
// returned error is marked retryable (via the caller) based on the status code,
// not here, so classification stays in one place.
func (p *OpenAIProvider) statusError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxOpenAIErrorBodyBytes))
	msg := strings.TrimSpace(string(data))
	var env apiErrorEnvelope
	if json.Unmarshal(data, &env) == nil && env.Error.Message != "" {
		msg = env.Error.Message
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	base := fmt.Errorf("commit: openai: API error (status %d): %s", resp.StatusCode, msg)
	if !isRetryableStatus(resp.StatusCode) {
		return base
	}
	// Carry a server-requested Retry-After delay (when present) through the error
	// so the backoff loop can honor it in preference to exponential backoff.
	if d, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
		return markRetryable(retryAfterErr{d: d, err: base})
	}
	return markRetryable(base)
}

// isRetryableStatus reports whether an HTTP status warrants a retry: 429
// (rate-limited) and any 5xx (server/overload). 408 (request timeout) is also
// transient.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests ||
		code == http.StatusRequestTimeout ||
		code >= 500
}

// backoff computes the delay before the given retry attempt (1-based), honoring
// a server-supplied Retry-After header carried on lastErr when present, else
// exponential backoff with full jitter capped at maxOpenAIBackoff.
func (p *OpenAIProvider) backoff(attempt int, lastErr error) time.Duration {
	if d, ok := retryAfterFrom(lastErr); ok {
		if d > maxOpenAIBackoff {
			d = maxOpenAIBackoff
		}
		return d
	}
	// Exponential base * 2^(attempt-1), with full jitter.
	exp := float64(p.retryBaseDelay) * math.Pow(2, float64(attempt-1))
	if exp > float64(maxOpenAIBackoff) {
		exp = float64(maxOpenAIBackoff)
	}
	jitter := p.randFloat()
	return time.Duration(exp * jitter)
}

// randFloat returns a jitter factor in [0.5, 1.0] so backoff never collapses to
// zero yet still spreads retries.
func (p *OpenAIProvider) randFloat() float64 {
	if p.rng != nil {
		return 0.5 + 0.5*p.rng.Float64()
	}
	return 0.5 + 0.5*rand.Float64()
}

// retryAfterErr carries a server-requested retry delay through the error chain.
type retryAfterErr struct {
	d   time.Duration
	err error
}

func (e retryAfterErr) Error() string { return e.err.Error() }
func (e retryAfterErr) Unwrap() error { return e.err }

// retryAfterFrom extracts a Retry-After delay from an error chain, if any.
func retryAfterFrom(err error) (time.Duration, bool) {
	var ra retryAfterErr
	if errors.As(err, &ra) {
		return ra.d, true
	}
	return 0, false
}

// parseRetryAfter parses a Retry-After header value: either delay-seconds or an
// HTTP-date. It returns false when absent or unparseable.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// sleepCtx waits for d or until ctx is done, returning the context error if
// cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
