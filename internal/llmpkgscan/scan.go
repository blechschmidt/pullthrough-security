package llmpkgscan

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// Reason codes for an artifact that could not be given a verdict. They are
// stable identifiers: they appear in response headers, metrics labels, audit
// records and the policy-engine input.
const (
	// The artifact itself made a scan impossible.
	CodeOversized      = "oversized"          // larger than limits.maxArtifactBytes
	CodeUnsupported    = "unsupported-format" // not an archive the unpacker understands
	CodeEmptyArchive   = "empty-archive"      // an archive with no files in it
	CodeUnpackLimit    = "unpack-limit"       // nothing could be unpacked within the limits
	CodeDigestMismatch = "digest-mismatch"    // the bytes read are not the bytes the cache recorded

	// The model did not produce a usable answer.
	CodeProviderRefusal    = "provider-refusal"    // the provider's safety system declined
	CodeMalformedOutput    = "malformed-output"    // the answer was not a valid verdict
	CodeInjectionSuspected = "injection-suspected" // the answer leaked the system prompt
	CodeTokenLimit         = "token-limit"         // the token cap was reached before a verdict

	// The scan could not run or finish.
	CodeProviderError       = "provider-error"       // the provider call failed
	CodeProviderUnavailable = "provider-unavailable" // the circuit breaker is open
	CodeTimeout             = "timeout"              // the wall-clock limit elapsed
	CodeBudgetExhausted     = "budget-exhausted"     // a cost ceiling was reached
	CodeBusy                = "scanner-busy"         // every scan slot is taken and the queue is full
	CodeUnavailable         = "artifact-unavailable" // the cached bytes could not be read
	CodeInternalError       = "internal-error"       // a bug in the scanner
)

// contentAttributable reports whether a reason code is caused by the artifact's
// own bytes rather than by the scanner's environment. The distinction matters
// because the publisher controls those bytes: an artifact padded past the size
// limit, built to defeat the unpacker, or written to make the model refuse or
// babble is one the publisher may have made unscannable on purpose. Such an
// artifact is never served silently — under fail-open it is served with a
// finding that says it went unexamined.
func contentAttributable(code string) bool {
	switch code {
	case CodeOversized, CodeUnsupported, CodeEmptyArchive, CodeUnpackLimit,
		CodeProviderRefusal, CodeMalformedOutput, CodeInjectionSuspected, CodeTokenLimit:
		return true
	}
	return false
}

// publicReason is the fixed sentence shown for a reason code wherever the
// reader is not an operator: the 403 body and response headers a package client
// sees, a notification. The underlying error is diagnostic detail — it can
// quote a provider's error message (which may name an endpoint or echo part of a
// credential) or a fragment of the model's malformed answer (which the package
// under review shaped) — so it goes to the logs and the admin surface only.
func publicReason(code string) string {
	switch code {
	case CodeOversized:
		return "the artifact is larger than the scan size limit"
	case CodeUnsupported:
		return "the artifact is not an archive format the scanner can unpack"
	case CodeEmptyArchive:
		return "the archive contains no files"
	case CodeUnpackLimit:
		return "nothing could be unpacked from the archive within the scan limits"
	case CodeDigestMismatch:
		return "the artifact's bytes do not match its recorded digest"
	case CodeProviderRefusal:
		return "the LLM provider's safety system declined to analyze the package"
	case CodeMalformedOutput:
		return "the model did not return a valid verdict"
	case CodeInjectionSuspected:
		return "the model's answer disclosed its instructions and was discarded"
	case CodeTokenLimit:
		return "the scan reached its token limit before the model gave a verdict"
	case CodeProviderError:
		return "the LLM provider call failed"
	case CodeProviderUnavailable:
		return "the LLM provider is failing; scans are paused briefly"
	case CodeTimeout:
		return "the scan did not finish within its time limit"
	case CodeBudgetExhausted:
		return "the LLM package-scan budget is exhausted"
	case CodeBusy:
		return "the scanner is at capacity; the artifact has not been scanned yet"
	case CodeUnavailable:
		return "the cached artifact could not be read"
	default:
		return "the scanner failed internally"
	}
}

// transient reports whether a reason is expected to clear by itself shortly, so
// the artifact is worth retrying soon rather than after the full error TTL.
func transient(code string) bool {
	switch code {
	case CodeProviderError, CodeProviderUnavailable, CodeTimeout, CodeBusy, CodeUnavailable, CodeInternalError:
		return true
	}
	return false
}

// scanError is a scan that ended without a verdict.
type scanError struct {
	code string
	err  error
}

func (e *scanError) Error() string { return e.code + ": " + e.err.Error() }
func (e *scanError) Unwrap() error { return e.err }

func fail(code string, err error) *scanError { return &scanError{code: code, err: err} }

func failf(code, format string, args ...any) *scanError {
	return &scanError{code: code, err: fmt.Errorf(format, args...)}
}

// classifyProviderError maps a provider-call error onto a reason code.
func classifyProviderError(ctx context.Context, err error) *scanError {
	var se *scanError
	if errors.As(err, &se) {
		return se
	}
	if ref, ok := commit.IsRefusal(err); ok {
		category := ref.Category
		if category == "" {
			category = "unspecified"
		}
		return failf(CodeProviderRefusal, "the provider's safety system declined to analyze the package (category %s)", cleanText(category, 40))
	}
	if errors.Is(err, context.DeadlineExceeded) || (ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return failf(CodeTimeout, "the scan did not finish within its time limit")
	}
	if errors.Is(err, context.Canceled) {
		return failf(CodeTimeout, "the scan was canceled")
	}
	return fail(CodeProviderError, err)
}

// modelRun is what running the model over a tree produced.
type modelRun struct {
	verdict   *ModelVerdict
	mode      string
	turns     int
	toolCalls int
	byTool    map[string]int
	toolErrs  int
	usage     commit.Usage
	costUSD   float64
	// seedComplete reports that the first prompt showed every readable file whole.
	seedComplete bool
	// calls is the number of provider completions made (retries included).
	calls int
}

// Modes recorded on a verdict.
const (
	modeTools  = "tools"
	modeBundle = "bundle"
)

// runModel shows the tree to the model and returns its verdict. With a
// tool-capable provider it runs the bounded tool loop; otherwise it sends the
// one-shot bundle. The run's token usage and cost are returned even when it
// fails, so a failed scan is still charged for what it consumed.
func (s *Service) runModel(ctx context.Context, t *Tree, art Artifact) (*modelRun, error) {
	nonce, err := newNonce()
	if err != nil {
		return &modelRun{}, fail(CodeInternalError, err)
	}
	run := &modelRun{byTool: map[string]int{}}
	lim := s.cfg.Limits
	fellBack := false
	if s.toolsUsable() && lim.MaxToolCalls > 0 && lim.MaxTurns > 1 {
		sd := buildSeed(t, art, lim, nonce, true)
		// A seed that already shows every readable file whole leaves nothing for a
		// tool to fetch: such a package (most small ones) is settled in one plain
		// completion, exactly like a provider without tools.
		if !sd.complete {
			run.mode = modeTools
			run.seedComplete = false
			err := s.runTools(ctx, t, sd, nonce, run)
			if s.cfg.Mode != ModeAuto || run.turns > 0 || !toolRequestRejected(err) {
				return run, err
			}
			// The endpoint turned the first tool-bearing request down as a request
			// it does not accept. An OpenAI-compatible gateway whose model has no
			// function calling answers this way, and "auto" promises the bundle for
			// such a provider — so try it, and if it works, stop offering tools for
			// a while (see suspendTools). Nothing was consumed by the rejected call.
			fellBack = true
		}
	}
	run.mode = modeBundle
	err = s.runBundle(ctx, t, art, nonce, run)
	if fellBack && err == nil {
		s.suspendTools()
	}
	return run, err
}

// toolRequestRejected reports whether a tool-loop error is the endpoint
// rejecting the request's shape, as opposed to its credentials (401/403), its
// rate (429) or its health (5xx): the statuses an API uses for "I do not
// understand, or do not offer, what you asked for".
func toolRequestRejected(err error) bool {
	status, ok := commit.HTTPStatus(err)
	if !ok {
		return false
	}
	switch status {
	case 400, 404, 405, 415, 422, 501:
		return true
	}
	return false
}

// toolsSuspension is how long tools stay off after the endpoint rejected them.
// It is a pause rather than a permanent switch: a gateway that was briefly
// misconfigured gets its tools back without a restart.
const toolsSuspension = time.Hour

// toolsUsable reports whether scans may use the tool loop right now.
func (s *Service) toolsUsable() bool {
	return s.tools != nil && s.now().UnixNano() >= s.toolsOffUntil.Load()
}

// suspendTools turns the tool loop off for toolsSuspension.
func (s *Service) suspendTools() {
	s.toolsOffUntil.Store(s.now().Add(toolsSuspension).UnixNano())
	s.log.Warn("llmpkgscan: the provider endpoint rejected a tool-bearing request and a single-shot scan succeeded; "+
		"using single-shot bundle scans for now (set llmPackageScan.mode: bundle to make this permanent, or mode: tools to disable the fallback)",
		"retryToolsAfter", toolsSuspension.String())
}

// runBundle is the single-shot path: one prompt, one answer.
func (s *Service) runBundle(ctx context.Context, t *Tree, art Artifact, nonce string, run *modelRun) error {
	sd := buildSeed(t, art, s.cfg.Limits, nonce, false)
	run.seedComplete = sd.complete
	req := commit.Request{
		Model:     s.cfg.Model,
		System:    systemPrompt(false),
		User:      sd.text,
		MaxTokens: s.cfg.Limits.MaxOutputTokens,
		Thinking:  s.cfg.Thinking,
	}
	var text string
	err := s.call(ctx, run, func() (commit.Usage, error) {
		out, usage, cerr := s.provider.Complete(ctx, req)
		text = out
		return usage, cerr
	})
	if err != nil {
		return classifyProviderError(ctx, err)
	}
	run.turns = 1
	return s.accept(t, text, run)
}

// runTools is the tool loop. Every way out of it is bounded: turns, tool calls,
// tool output bytes, tokens, and the context's deadline. When any budget is
// spent the next request forbids further tool calls, which forces an answer.
func (s *Service) runTools(ctx context.Context, t *Tree, sd seed, nonce string, run *modelRun) error {
	lim := s.cfg.Limits
	tb := newToolbox(t, lim, nonce)
	defer func() {
		run.toolCalls, run.byTool = tb.stats()
		run.toolErrs = tb.errors
	}()

	req := commit.ToolRequest{
		Model:     s.cfg.Model,
		System:    systemPrompt(true),
		Messages:  []commit.ToolMessage{{Role: commit.ToolRoleUser, Text: sd.text}},
		Tools:     toolSpecs(),
		MaxTokens: lim.MaxOutputTokens,
		Thinking:  s.cfg.Thinking,
	}

	lastInput := 0
	for turn := 1; ; turn++ {
		if turn >= lim.MaxTurns || tb.exhausted() {
			req.NoTools = true
		}
		var resp commit.ToolResponse
		var usage commit.Usage
		err := s.call(ctx, run, func() (commit.Usage, error) {
			r, u, cerr := s.tools.CompleteTools(ctx, req)
			resp, usage = r, u
			return u, cerr
		})
		if err != nil {
			return classifyProviderError(ctx, err)
		}
		run.turns = turn
		lastInput = usage.InputTokens + usage.CacheReadTokens + usage.CacheCreationTokens

		if resp.Stop == commit.ToolStopMaxTokens {
			// A cut-off reply is neither a verdict nor a trustworthy tool call.
			return failf(CodeMalformedOutput, "the model's reply was cut off at the output token limit")
		}
		if len(resp.ToolCalls) == 0 {
			return s.accept(t, resp.Text, run)
		}
		if req.NoTools {
			return failf(CodeMalformedOutput, "the model asked for a tool after its tool allowance was spent instead of giving a verdict")
		}

		// Answer every call of the turn, in one user turn.
		results := make([]commit.ToolResult, 0, len(resp.ToolCalls))
		resultBytes := 0
		for _, c := range resp.ToolCalls {
			res := tb.run(ctx, c)
			resultBytes += len(res.Content)
			results = append(results, res)
		}
		next := commit.ToolMessage{Role: commit.ToolRoleUser, ToolResults: results}

		// Decide whether another tool turn is affordable. The next request carries
		// everything sent so far plus this turn's output and results.
		used := totalTokens(run.usage)
		if used >= lim.MaxTotalTokens {
			return failf(CodeTokenLimit, "the scan reached its limit of %d tokens before the model gave a verdict", lim.MaxTotalTokens)
		}
		projected := used + lastInput + usage.OutputTokens + resultBytes/4 + lim.MaxOutputTokens
		if turn+1 >= lim.MaxTurns || tb.exhausted() || projected >= lim.MaxTotalTokens {
			req.NoTools = true
			next.Text = "[proxy] Your tool allowance for this review is spent. Reply now with only the JSON verdict."
		}
		req.Messages = append(req.Messages, resp.AssistantMessage(), next)
	}
}

// accept turns the model's final text into the run's verdict.
func (s *Service) accept(t *Tree, text string, run *modelRun) error {
	mv, err := ParseVerdict(text)
	switch {
	case errors.Is(err, ErrPromptLeak):
		return fail(CodeInjectionSuspected, err)
	case err != nil:
		return fail(CodeMalformedOutput, err)
	}
	verifyEvidence(t, mv.Evidence)
	run.verdict = mv
	return nil
}

func totalTokens(u commit.Usage) int {
	return u.InputTokens + u.OutputTokens + u.CacheReadTokens + u.CacheCreationTokens
}

// call makes one provider completion with retries on transient errors, folding
// its token usage and cost into the run. Retries back off exponentially with
// jitter and stop when ctx is done.
func (s *Service) call(ctx context.Context, run *modelRun, do func() (commit.Usage, error)) error {
	var lastErr error
	for attempt := 0; attempt <= s.cfg.MaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		usage, err := do()
		run.calls++
		run.usage.Add(usage)
		cost := s.cfg.Pricing.Cost(s.cfg.Model, usage.BillableInputTokens(), usage.OutputTokens)
		run.costUSD += cost
		s.observeCall(usage, cost, err == nil)
		if err == nil {
			return nil
		}
		lastErr = err
		if !commit.IsRetryable(err) || attempt == s.cfg.MaxRetries {
			return err
		}
		delay := backoff(s.cfg.RetryBaseDelay, attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

// backoff is an exponential delay with full jitter, capped at 15s.
func backoff(base time.Duration, attempt int) time.Duration {
	const maxDelay = 15 * time.Second
	d := base << attempt
	if d <= 0 || d > maxDelay {
		d = maxDelay
	}
	return time.Duration(rand.Int63n(int64(d) + 1))
}
