package commit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Default Claude model identifiers. The pipeline uses the cheap model for
// first-pass triage and the capable model for deep analysis on escalation.
const (
	// DefaultTriageModel is a fast, inexpensive model for triage.
	DefaultTriageModel = anthropic.ModelClaudeHaiku4_5_20251001
	// DefaultDeepModel is the most capable Opus-tier model for deep analysis.
	DefaultDeepModel = anthropic.ModelClaudeOpus4_8
)

// ClaudeProvider is a Provider backed by the Anthropic Messages API via the
// official Go SDK.
type ClaudeProvider struct {
	client anthropic.Client
}

// ClaudeOptions configures a ClaudeProvider.
type ClaudeOptions struct {
	// APIKey authenticates to the Anthropic API. When empty, the SDK falls back
	// to the ANTHROPIC_API_KEY environment variable.
	APIKey string
	// BaseURL optionally overrides the API endpoint (e.g. for a gateway/proxy).
	BaseURL string
	// MaxRetries bounds the SDK's own transient-error retries. The pipeline adds
	// an outer retry/backoff loop on top; this is the inner, per-request bound.
	MaxRetries int
}

// NewClaudeProvider constructs a ClaudeProvider. It returns an error only for
// clearly invalid configuration; a missing API key is tolerated here so the
// process can start and fail loudly on first use (with a clear 401) rather than
// at construction.
func NewClaudeProvider(opts ClaudeOptions) (*ClaudeProvider, error) {
	clientOpts := []option.RequestOption{}
	if opts.APIKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(opts.APIKey))
	}
	if opts.BaseURL != "" {
		clientOpts = append(clientOpts, option.WithBaseURL(opts.BaseURL))
	}
	if opts.MaxRetries > 0 {
		clientOpts = append(clientOpts, option.WithMaxRetries(opts.MaxRetries))
	}
	return &ClaudeProvider{client: anthropic.NewClient(clientOpts...)}, nil
}

// Name implements Provider.
func (p *ClaudeProvider) Name() string { return "claude" }

// Complete implements Provider using the Anthropic Messages API.
func (p *ClaudeProvider) Complete(ctx context.Context, req Request) (string, Usage, error) {
	if strings.TrimSpace(req.Model) == "" {
		return "", Usage{}, errors.New("commit: claude: model is required")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: int64(maxTokens),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(req.User)),
		},
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{Text: req.System}}
	}
	if req.Thinking {
		// Adaptive thinking is the recommended mode for Claude 4.6+; the model
		// decides how much to reason. There is no helper for the adaptive union,
		// so construct it directly.
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
	}

	resp, err := p.client.Messages.New(ctx, params)
	if err != nil {
		return "", Usage{}, classifyClaudeError(err)
	}

	var sb strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			sb.WriteString(t.Text)
		}
	}
	usage := Usage{
		InputTokens:  int(resp.Usage.InputTokens),
		OutputTokens: int(resp.Usage.OutputTokens),
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return sb.String(), usage, fmt.Errorf("commit: claude: request refused by safety system (category %q)", resp.StopDetails.Category)
	}
	return sb.String(), usage, nil
}

// classifyClaudeError maps SDK errors onto the pipeline's retryable/terminal
// distinction. Rate limits (429), overload (529), and 5xx are transient;
// context cancellation and 4xx (auth, bad request) are terminal.
func classifyClaudeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == http.StatusTooManyRequests,
			apiErr.StatusCode == 529, // overloaded_error
			apiErr.StatusCode >= 500:
			return markRetryable(fmt.Errorf("commit: claude: transient API error: %w", err))
		default:
			return fmt.Errorf("commit: claude: API error: %w", err)
		}
	}
	// Network/transport errors that never reached the API are worth retrying.
	return markRetryable(fmt.Errorf("commit: claude: request failed: %w", err))
}
