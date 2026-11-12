package commit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	// Zero keeps the SDK's default; a negative value disables the SDK's retries,
	// as it does for the OpenAI-compatible provider — so that a caller's "no
	// retries" means one request, whichever provider is configured.
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
	switch {
	case opts.MaxRetries > 0:
		clientOpts = append(clientOpts, option.WithMaxRetries(opts.MaxRetries))
	case opts.MaxRetries < 0:
		clientOpts = append(clientOpts, option.WithMaxRetries(0))
	}
	return &ClaudeProvider{client: anthropic.NewClient(clientOpts...)}, nil
}

// Name implements Provider.
func (p *ClaudeProvider) Name() string { return "claude" }

// claudeNonStreamingTimeout is the longest a single non-streaming request is
// allowed to run: the SDK's own default for such requests.
const claudeNonStreamingTimeout = 10 * time.Minute

// claudeRequestOptions returns the per-request options for a non-streaming
// call: an explicit request timeout.
//
// Left to itself, the SDK estimates how long a non-streaming request could take
// from max_tokens and refuses to send one it thinks may exceed ten minutes — or
// one whose max_tokens exceeds a per-model table — asking for streaming instead.
// That estimate would turn an output-token setting into a hard failure of every
// request (and it depends on the model), so the timeout is stated outright: the
// time left on the caller's context, capped at the SDK's ten minutes. The
// context still bounds the call as a whole, retries included.
func claudeRequestOptions(ctx context.Context) []option.RequestOption {
	timeout := claudeNonStreamingTimeout
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left > 0 && left < timeout {
			timeout = left
		}
	}
	return []option.RequestOption{option.WithRequestTimeout(timeout)}
}

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

	resp, err := p.client.Messages.New(ctx, params, claudeRequestOptions(ctx)...)
	if err != nil {
		return "", Usage{}, classifyClaudeError(err)
	}

	var sb strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			sb.WriteString(t.Text)
		}
	}
	usage := claudeUsage(resp.Usage)
	if resp.StopReason == anthropic.StopReasonRefusal {
		return sb.String(), usage, claudeRefusal(resp)
	}
	return sb.String(), usage, nil
}

// claudeRefusal renders a "refusal" stop reason as the typed, terminal
// RefusalError. The category is informational: it may be empty even on a
// refusal, so callers branch on the error type, never on the category.
func claudeRefusal(resp *anthropic.Message) error {
	category := string(resp.StopDetails.Category)
	return &RefusalError{
		Provider: "claude",
		Category: category,
		msg:      fmt.Sprintf("commit: claude: request refused by safety system (category %q)", category),
	}
}

// claudeUsage maps the SDK's usage block onto Usage, keeping the prompt-cache
// counters separate: the Messages API reports input_tokens exclusive of cache
// reads and cache writes, so folding them together would misprice every turn
// of a conversation that replays a cached prefix.
func claudeUsage(u anthropic.Usage) Usage {
	return Usage{
		InputTokens:         int(u.InputTokens),
		OutputTokens:        int(u.OutputTokens),
		CacheReadTokens:     int(u.CacheReadInputTokens),
		CacheCreationTokens: int(u.CacheCreationInputTokens),
	}
}

// adaptiveThinkingModels are the model-ID prefixes that accept
// thinking: {type: "adaptive"}. Older models (e.g. claude-haiku-4-5) take a
// fixed token budget instead and reject the adaptive form with a 400, so a
// caller that lets an operator pick the model must not send it blindly.
var adaptiveThinkingModels = []string{
	"claude-opus-4-6", "claude-opus-4-7", "claude-opus-4-8", "claude-sonnet-4-6",
	"claude-opus-5", "claude-sonnet-5", "claude-haiku-5",
	"claude-fable-5", "claude-mythos-5",
}

// SupportsAdaptiveThinking reports whether a Claude model ID is known to accept
// adaptive thinking. It is a conservative allowlist: an unrecognized model
// yields false, and the request is then sent without a thinking parameter —
// which every model accepts.
func SupportsAdaptiveThinking(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	for _, prefix := range adaptiveThinkingModels {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

// CompleteTools implements ToolProvider on the Anthropic Messages API: it sends
// the conversation with the caller's tool definitions and returns the model's
// next turn — prose, tool calls, or both.
//
// Only caller-executed ("client") tools are ever declared; no Anthropic-hosted
// tool (web search, code execution, …) can be reached through this method, so
// the model has exactly the capabilities the caller implements and no others.
//
// The system prompt and the newest user turn carry a prompt-cache breakpoint:
// a tool conversation re-sends its whole history on every turn, and caching the
// unchanged prefix is what keeps a multi-turn review from paying for the same
// package content over and over.
func (p *ClaudeProvider) CompleteTools(ctx context.Context, req ToolRequest) (ToolResponse, Usage, error) {
	if strings.TrimSpace(req.Model) == "" {
		return ToolResponse{}, Usage{}, errors.New("commit: claude: model is required")
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096
	}
	messages, err := claudeMessages(req.Messages)
	if err != nil {
		return ToolResponse{}, Usage{}, err
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(req.Model),
		MaxTokens: int64(maxTokens),
		Messages:  messages,
		Tools:     claudeTools(req.Tools),
	}
	if req.System != "" {
		params.System = []anthropic.TextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}}
	}
	if req.Thinking {
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
	}
	if req.NoTools && len(params.Tools) > 0 {
		// The tools stay declared (earlier turns reference them); "none" only
		// forbids a call on this turn, which every model accepts.
		params.ToolChoice = anthropic.ToolChoiceUnionParam{OfNone: &anthropic.ToolChoiceNoneParam{}}
	}

	resp, err := p.client.Messages.New(ctx, params, claudeRequestOptions(ctx)...)
	if err != nil {
		return ToolResponse{}, Usage{}, classifyClaudeError(err)
	}
	usage := claudeUsage(resp.Usage)
	if resp.StopReason == anthropic.StopReasonRefusal {
		return ToolResponse{}, usage, claudeRefusal(resp)
	}

	// Rebuild the assistant turn block by block rather than via Message.ToParam:
	// that helper dereferences every block's variant and panics on a block type
	// this SDK version does not know, which a newer API can legitimately send.
	// Reasoning blocks are kept verbatim (signature included) because the API
	// requires them to be replayed unmodified on the next turn.
	native := anthropic.MessageParam{Role: anthropic.MessageParamRoleAssistant}
	out := ToolResponse{}
	var text strings.Builder
	for _, block := range resp.Content {
		switch b := block.AsAny().(type) {
		case anthropic.TextBlock:
			text.WriteString(b.Text)
			if b.Text != "" {
				native.Content = append(native.Content, anthropic.NewTextBlock(b.Text))
			}
		case anthropic.ThinkingBlock:
			tp := b.ToParam()
			native.Content = append(native.Content, anthropic.ContentBlockParamUnion{OfThinking: &tp})
		case anthropic.RedactedThinkingBlock:
			rp := b.ToParam()
			native.Content = append(native.Content, anthropic.ContentBlockParamUnion{OfRedactedThinking: &rp})
		case anthropic.ToolUseBlock:
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Input: json.RawMessage(b.Input)})
			up := b.ToParam()
			native.Content = append(native.Content, anthropic.ContentBlockParamUnion{OfToolUse: &up})
		}
	}
	out.Text = text.String()
	out.Native = native
	switch resp.StopReason {
	case anthropic.StopReasonToolUse:
		out.Stop = ToolStopToolUse
	case anthropic.StopReasonMaxTokens:
		out.Stop = ToolStopMaxTokens
	case anthropic.StopReasonEndTurn, anthropic.StopReasonStopSequence:
		out.Stop = ToolStopEnd
	default:
		out.Stop = ToolStopOther
	}
	return out, usage, nil
}

// claudeTools renders the caller's tool specs as custom ("client") tools.
func claudeTools(specs []ToolSpec) []anthropic.ToolUnionParam {
	if len(specs) == 0 {
		return nil
	}
	tools := make([]anthropic.ToolUnionParam, 0, len(specs))
	for _, s := range specs {
		tool := anthropic.ToolParam{
			Name:        s.Name,
			Description: anthropic.String(s.Description),
			InputSchema: anthropic.ToolInputSchemaParam{
				Properties: s.Parameters.Properties,
				Required:   s.Parameters.Required,
			},
		}
		if tool.InputSchema.Properties == nil {
			tool.InputSchema.Properties = map[string]any{}
		}
		tools = append(tools, anthropic.ToolUnionParam{OfTool: &tool})
	}
	return tools
}

// claudeMessages converts a tool conversation into Messages API turns. An
// assistant turn that carries a native representation is replayed verbatim;
// otherwise it is reconstructed from its text and tool calls. The final user
// turn's last block gets the prompt-cache breakpoint.
func claudeMessages(msgs []ToolMessage) ([]anthropic.MessageParam, error) {
	out := make([]anthropic.MessageParam, 0, len(msgs))
	lastUser := -1
	for i, m := range msgs {
		switch m.Role {
		case ToolRoleAssistant:
			if native, ok := m.Native.(anthropic.MessageParam); ok && len(native.Content) > 0 {
				out = append(out, native)
				continue
			}
			var blocks []anthropic.ContentBlockParamUnion
			if m.Text != "" {
				blocks = append(blocks, anthropic.NewTextBlock(m.Text))
			}
			for _, c := range m.ToolCalls {
				var input any = map[string]any{}
				if len(c.Input) > 0 {
					input = c.Input
				}
				blocks = append(blocks, anthropic.NewToolUseBlock(c.ID, input, c.Name))
			}
			if len(blocks) == 0 {
				return nil, fmt.Errorf("commit: claude: assistant message %d is empty", i)
			}
			out = append(out, anthropic.NewAssistantMessage(blocks...))
		case ToolRoleUser:
			// Tool results must precede any text in the turn that answers them.
			var blocks []anthropic.ContentBlockParamUnion
			for _, r := range m.ToolResults {
				content := r.Content
				if content == "" {
					content = "(no output)"
				}
				blocks = append(blocks, anthropic.NewToolResultBlock(r.CallID, content, r.IsError))
			}
			if m.Text != "" {
				blocks = append(blocks, anthropic.NewTextBlock(m.Text))
			}
			if len(blocks) == 0 {
				return nil, fmt.Errorf("commit: claude: user message %d is empty", i)
			}
			out = append(out, anthropic.NewUserMessage(blocks...))
			lastUser = len(out) - 1
		default:
			return nil, fmt.Errorf("commit: claude: message %d has unknown role %q", i, m.Role)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("commit: claude: a conversation needs at least one message")
	}
	if lastUser >= 0 {
		content := out[lastUser].Content
		last := &content[len(content)-1]
		switch {
		case last.OfToolResult != nil:
			last.OfToolResult.CacheControl = anthropic.NewCacheControlEphemeralParam()
		case last.OfText != nil:
			last.OfText.CacheControl = anthropic.NewCacheControlEphemeralParam()
		}
	}
	return out, nil
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
			return markRetryable(&StatusError{Status: apiErr.StatusCode, Err: fmt.Errorf("commit: claude: transient API error: %w", err)})
		default:
			return &StatusError{Status: apiErr.StatusCode, Err: fmt.Errorf("commit: claude: API error: %w", err)}
		}
	}
	// Network/transport errors that never reached the API are worth retrying.
	return markRetryable(fmt.Errorf("commit: claude: request failed: %w", err))
}
