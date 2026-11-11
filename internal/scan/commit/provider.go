package commit

import (
	"context"
	"encoding/json"
	"errors"
)

// Request is a single, provider-agnostic LLM completion request. The pipeline
// builds these; a Provider turns them into provider-specific API calls.
type Request struct {
	// Model is the provider-specific model identifier (e.g. "claude-opus-4-8").
	Model string
	// System is the system prompt (instructions/persona).
	System string
	// User is the user message content (the commit + diff to analyze).
	User string
	// MaxTokens bounds the response length.
	MaxTokens int
	// Thinking requests extended/adaptive reasoning when the provider supports
	// it. The pipeline enables it for deep analysis and leaves it off for cheap
	// triage.
	Thinking bool
}

// Usage reports token consumption for a completion, for cost accounting.
type Usage struct {
	InputTokens  int
	OutputTokens int
	// CacheReadTokens and CacheCreationTokens report prompt-cache activity when the
	// provider breaks it out separately from InputTokens (the Anthropic Messages
	// API does: input_tokens excludes both). They are zero for providers that fold
	// cached tokens into InputTokens. A multi-turn tool conversation re-sends its
	// whole history every turn, so these are what make its cost accounting honest.
	CacheReadTokens     int
	CacheCreationTokens int
}

// BillableInputTokens returns the input-token count to price a completion at the
// model's plain input rate: uncached input, plus cache writes at their 1.25x
// premium, plus cache reads at their 0.1x discount (the published prompt-caching
// multipliers). For a provider that reports no cache breakdown it is InputTokens.
func (u Usage) BillableInputTokens() int {
	if u.CacheReadTokens == 0 && u.CacheCreationTokens == 0 {
		return u.InputTokens
	}
	eff := float64(u.InputTokens) + 1.25*float64(u.CacheCreationTokens) + 0.1*float64(u.CacheReadTokens)
	return int(eff + 0.5)
}

// Add folds another completion's usage into u.
func (u *Usage) Add(o Usage) {
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadTokens += o.CacheReadTokens
	u.CacheCreationTokens += o.CacheCreationTokens
}

// Provider is the pluggable LLM backend. Implementations must be safe for
// concurrent use and must honor context cancellation. They return the model's
// text output verbatim; prompt construction and verdict parsing live in the
// pipeline so they are shared across providers.
type Provider interface {
	// Name identifies the provider (e.g. "claude", "codex").
	Name() string
	// Complete sends req and returns the model's text response. A non-nil error
	// indicates the request could not be completed; transient failures should be
	// reported with an error that satisfies IsRetryable so the pipeline can back
	// off and retry.
	Complete(ctx context.Context, req Request) (text string, usage Usage, err error)
}

// retryableError wraps an error to mark it as transient. Providers use
// markRetryable; the pipeline checks with IsRetryable.
type retryableError struct{ err error }

func (e retryableError) Error() string { return e.err.Error() }
func (e retryableError) Unwrap() error { return e.err }

// markRetryable annotates err as a transient failure worth retrying.
func markRetryable(err error) error {
	if err == nil {
		return nil
	}
	return retryableError{err: err}
}

// IsRetryable reports whether err (or anything it wraps) was marked transient.
func IsRetryable(err error) bool {
	var re retryableError
	return errors.As(err, &re)
}

// MarkRetryable annotates err as a transient failure worth retrying, for a
// Provider implemented outside this package (a test double, a custom backend).
func MarkRetryable(err error) error { return markRetryable(err) }

// StatusError is a provider API error that carries the HTTP status the endpoint
// answered with. Most callers only need IsRetryable; the status is for the few
// that must tell "this request shape is not accepted here" (400, 404, 422 — an
// OpenAI-compatible gateway without function calling answers a tool-bearing
// request this way) from "the credentials are wrong" (401, 403).
type StatusError struct {
	Status int
	Err    error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

// NewStatusError builds a StatusError, for a Provider implemented outside this
// package.
func NewStatusError(status int, err error) error {
	return &StatusError{Status: status, Err: err}
}

// HTTPStatus returns the HTTP status a provider error carries, if it carries
// one. An error that never reached the API (a transport failure, a canceled
// context) carries none.
func HTTPStatus(err error) (int, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status, true
	}
	return 0, false
}

// RefusalError reports that a provider's safety system declined to answer (the
// Anthropic "refusal" stop reason, an OpenAI content-filter finish). It is a
// terminal, non-retryable outcome and — unlike a transport failure — it is
// caused by the *content* of the request. A caller that scans untrusted content
// must therefore never read it as "nothing found": an input that makes the
// scanner decline is, if anything, more suspect than one that does not.
type RefusalError struct {
	// Provider is the provider that declined ("claude", "openai").
	Provider string
	// Category is the provider-reported policy category, when one is given
	// (e.g. "cyber"). It is informational and may be empty.
	Category string
	// msg is the provider-specific rendering.
	msg string
}

func (e *RefusalError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "commit: " + e.Provider + ": request refused by safety system (category \"" + e.Category + "\")"
}

// NewRefusalError builds a RefusalError, for a Provider implemented outside
// this package.
func NewRefusalError(provider, category string) *RefusalError {
	return &RefusalError{Provider: provider, Category: category}
}

// IsRefusal reports whether err (or anything it wraps) is a provider safety
// refusal, returning the typed error so the caller can read its category.
func IsRefusal(err error) (*RefusalError, bool) {
	var re *RefusalError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// --- Tool use: an optional provider capability -------------------------------
//
// Complete is one prompt in, one text out. Some analyses are better served by
// letting the model ask for the material it wants to look at — the package
// content scanner (internal/llmpkgscan) offers it a small, read-only set of
// tools over an unpacked archive rather than guessing up front which files
// matter. ToolProvider is that capability: a provider that implements it can
// carry a multi-turn conversation in which the model requests tool calls and the
// caller answers them.
//
// It is deliberately an OPTIONAL interface on the same provider value, not a
// second client: a caller type-asserts a Provider to ToolProvider and falls back
// to Complete when the assertion fails, so every provider — including a test
// double that only implements Complete — keeps working. The tools themselves are
// executed by the caller, in-process; a provider only transports the requests
// and results. No provider-hosted ("server") tool is ever declared through this
// interface, so the model gains no capability the caller did not implement.

// ToolSpec declares one caller-executed tool the model may request.
type ToolSpec struct {
	// Name is the tool identifier the model calls it by.
	Name string
	// Description tells the model what the tool does and when to use it.
	Description string
	// Parameters is the JSON Schema of the tool's input: an object schema's
	// "properties" and "required" (the enclosing {"type":"object"} is implied).
	Parameters ToolParameters
}

// ToolParameters is the object schema of a tool's input.
type ToolParameters struct {
	// Properties maps each parameter name to its JSON Schema.
	Properties map[string]any
	// Required lists the mandatory parameter names.
	Required []string
}

// ToolCall is one tool invocation the model requested.
type ToolCall struct {
	// ID correlates the call with its result; it is echoed in ToolResult.CallID.
	ID string
	// Name is the requested tool. It is model output: a caller must match it
	// against its own allowlist, never dispatch on it blindly.
	Name string
	// Input is the raw JSON arguments, exactly as the model produced them. It is
	// untrusted and must be validated by the caller.
	Input json.RawMessage
}

// ToolResult is the caller's answer to a ToolCall.
type ToolResult struct {
	CallID  string
	Content string
	// IsError marks a failed call (unknown tool, bad arguments, limit reached) so
	// the model can adapt instead of treating the text as data.
	IsError bool
}

// ToolRole is the author of a ToolMessage.
type ToolRole string

const (
	ToolRoleUser      ToolRole = "user"
	ToolRoleAssistant ToolRole = "assistant"
)

// ToolMessage is one turn of a tool conversation.
type ToolMessage struct {
	Role ToolRole
	// Text is the turn's prose (the prompt for a user turn, the model's answer for
	// an assistant turn). On a user turn that also carries ToolResults it is sent
	// after them.
	Text string
	// ToolCalls are the calls an assistant turn requested.
	ToolCalls []ToolCall
	// ToolResults answer the preceding assistant turn's calls (user turns only).
	ToolResults []ToolResult
	// Native is the provider's own representation of an assistant turn, as
	// returned in ToolResponse.Native. A caller must hand it back unmodified on the
	// next request: it carries provider state that has no portable form (reasoning
	// blocks and their signatures) and that the provider requires to be replayed
	// verbatim. It is opaque to the caller and nil on turns the caller authored.
	Native any
}

// ToolRequest is one request in a tool conversation: the full history so far.
type ToolRequest struct {
	Model    string
	System   string
	Messages []ToolMessage
	Tools    []ToolSpec
	// MaxTokens bounds the response length.
	MaxTokens int
	// Thinking requests extended/adaptive reasoning when the provider supports it.
	Thinking bool
	// NoTools forbids a tool call on this turn: the tools stay declared (the
	// history refers to them) but the model must answer in text. A caller uses it
	// to force a final answer once its tool budget is spent.
	NoTools bool
}

// ToolStop is why the model stopped generating.
type ToolStop string

const (
	// ToolStopEnd is a completed answer.
	ToolStopEnd ToolStop = "end"
	// ToolStopToolUse means the model is waiting for tool results.
	ToolStopToolUse ToolStop = "tool_use"
	// ToolStopMaxTokens means the response was cut off at MaxTokens; its text and
	// any tool call arguments may be incomplete and must not be trusted.
	ToolStopMaxTokens ToolStop = "max_tokens"
	// ToolStopOther is any other provider-specific reason.
	ToolStopOther ToolStop = "other"
)

// ToolResponse is the model's turn.
type ToolResponse struct {
	// Text is the concatenated prose of the turn.
	Text string
	// ToolCalls are the tool invocations the model requested, in order.
	ToolCalls []ToolCall
	// Stop is why generation ended.
	Stop ToolStop
	// Native is the provider's representation of this turn, to be replayed as
	// ToolMessage.Native (see there).
	Native any
}

// AssistantMessage renders the response as the assistant turn to append to the
// conversation history.
func (r ToolResponse) AssistantMessage() ToolMessage {
	return ToolMessage{Role: ToolRoleAssistant, Text: r.Text, ToolCalls: r.ToolCalls, Native: r.Native}
}

// ToolProvider is a Provider that can carry a tool conversation. Implementations
// must be safe for concurrent use, must honor context cancellation, and classify
// errors exactly as Complete does (IsRetryable for transient failures, a
// *RefusalError for a safety refusal).
type ToolProvider interface {
	Provider
	// CompleteTools sends the conversation and returns the model's next turn.
	CompleteTools(ctx context.Context, req ToolRequest) (ToolResponse, Usage, error)
}
