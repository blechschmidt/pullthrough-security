package commit

import (
	"context"
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
