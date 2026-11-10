// Package extension implements a sandboxed WebAssembly extensibility mechanism
// for the admission pipeline (Task 59). Enterprises frequently need org-specific
// gate logic — custom naming rules, internal CMDB lookups, bespoke metadata
// checks — that does not belong in the proxy core and must not require forking
// it. This package loads operator-supplied WebAssembly modules and invokes them
// as additional, late-stage admission gates over the same aggregated signal set
// the policy-as-code (Task 32) and risk-scoring (Task 37) engines consume.
//
// Design principles:
//
//   - Sandboxed by default. Modules run in a pure-Go WebAssembly interpreter
//     (wazero — no cgo, no native code generation, air-gap friendly) with no host
//     filesystem, no network, and no environment access. A WASI surface is
//     instantiated only so language runtimes that import it can initialize; it is
//     configured with no preopened directories, no stdio, and no sockets, so a
//     module cannot reach the host even through WASI.
//
//   - Strictly bounded. Every invocation runs under a wall-clock CPU/time budget
//     (a context deadline that closes a runaway module), a linear-memory page cap,
//     and an optional instruction-approximating "fuel" budget (a function-call
//     meter that aborts deep recursion or call-count explosions deterministically,
//     independent of wall-clock time). A module that exceeds any bound is
//     terminated and never returns a verdict.
//
//   - Stable, versioned ABI. The host passes a serialized, read-only view of the
//     request's admission context (artifact coordinate, ecosystem, digest, the
//     accumulated gate signals, and the composite risk score) and the module
//     returns a structured verdict (allow / warn / block + reason + annotations).
//     The wire contract is JSON over a small, explicitly-versioned export ABI
//     (see abi.go), so a module is decoupled from the proxy's internal Go types.
//
//   - Composes, never re-admits. Like the policy and risk gates, an extension
//     gate layers on top of the hard-coded gates: it can turn an otherwise-allowed
//     artifact into a warn or block, but it is never consulted to re-admit
//     something an earlier gate already refused. Per-tenant module selection,
//     hot-reload, and per-module fail-open/fail-closed policy are all configurable.
//
// All exported types are safe for concurrent use unless noted. The Manager is the
// entry point the proxy wires as a gate; everything below it (Module, the wazero
// sandbox) is an implementation detail.
package extension

import (
	"sort"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// Decision is a module's admission verdict. The ordering allow < warn < block is
// meaningful: when several modules run for one artifact, the most severe decision
// wins (see Result).
type Decision string

const (
	// DecisionAllow admits the artifact (the module found nothing disqualifying).
	DecisionAllow Decision = "allow"
	// DecisionWarn admits the artifact but flags it; the gate annotates the
	// response and emits a notification, mirroring the risk-score warn action.
	DecisionWarn Decision = "warn"
	// DecisionBlock refuses the artifact with a 403, like the other hard gates.
	DecisionBlock Decision = "block"
)

// Valid reports whether d is a recognized decision.
func (d Decision) Valid() bool {
	switch d {
	case DecisionAllow, DecisionWarn, DecisionBlock:
		return true
	default:
		return false
	}
}

// severity orders decisions so the most severe wins when combining modules
// (allow=0 < warn=1 < block=2). An unrecognized decision ranks below allow so a
// malformed verdict can never silently escalate.
func (d Decision) severity() int {
	switch d {
	case DecisionBlock:
		return 2
	case DecisionWarn:
		return 1
	case DecisionAllow:
		return 0
	default:
		return -1
	}
}

// Verdict is the structured result a module returns from pt_eval. It is decoded
// from the module's JSON output (see abi.go) under strict size limits.
type Verdict struct {
	// Decision is the admission outcome (allow|warn|block).
	Decision Decision `json:"decision"`
	// Reason is a short, human-readable explanation surfaced in the block/warn
	// response, the audit log, and notifications.
	Reason string `json:"reason,omitempty"`
	// Annotations carries module-specific structured key/values (e.g. a CMDB id,
	// a matched rule, an internal ticket reference). They are bounded in count and
	// size and folded into the audit detail and the response annotations.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// RiskView is the read-only projection of the composite risk score (Task 37)
// passed to modules. It lets an extension gate make a decision relative to the
// proxy's own risk assessment without recomputing it.
type RiskView struct {
	Score  int    `json:"score"`
	Band   string `json:"band"`
	Action string `json:"action,omitempty"`
}

// HostInput is the serialized, read-only request context the host marshals into
// the module's memory for each invocation. Signals reuses the canonical
// admission document (policyengine.Input) so a module sees exactly the same
// vulnerability/license/signature/secret/nameguard/provenance signals the policy
// and risk engines do, plus the artifact coordinate it already carries. The
// envelope's ABIVersion lets a module reject a host it was not built against.
type HostInput struct {
	// ABIVersion is the host ABI revision this document conforms to. The host
	// stamps it (see MarshalHostInput); a module may verify it.
	ABIVersion int `json:"abiVersion"`
	// Module is the configured name of the module being invoked, so a single
	// shared module can branch on which logical gate it is serving.
	Module string `json:"module,omitempty"`
	// Signals is the aggregated admission document (artifact + every gate signal).
	Signals policyengine.Input `json:"signals"`
	// Risk is the composite risk assessment, when the risk engine ran upstream.
	Risk *RiskView `json:"risk,omitempty"`
}

// Outcome classifies how a single module invocation terminated. It is distinct
// from Decision: a module can return a Decision (allow/warn/block) only when it
// ran to completion; the remaining outcomes are host-side terminations that
// never produced a verdict and are resolved by the module's fail-open/fail-closed
// policy.
type Outcome string

const (
	// OutcomeAllow / OutcomeWarn / OutcomeBlock mirror the returned Decision.
	OutcomeAllow Outcome = "allow"
	OutcomeWarn  Outcome = "warn"
	OutcomeBlock Outcome = "block"
	// OutcomeTimeout is a CPU/time-budget exhaustion: the wall-clock deadline
	// elapsed and the runtime closed the module mid-execution.
	OutcomeTimeout Outcome = "timeout"
	// OutcomeFuel is a fuel (instruction/call-count) budget exhaustion: the module
	// exceeded its configured function-call meter and was aborted deterministically.
	OutcomeFuel Outcome = "fuel"
	// OutcomeError is any other failure: instantiation failure, an ABI violation,
	// a wasm trap, or a malformed/oversized verdict.
	OutcomeError Outcome = "error"
)

// decisionFor maps a completed Decision to its Outcome.
func decisionFor(d Decision) Outcome {
	switch d {
	case DecisionWarn:
		return OutcomeWarn
	case DecisionBlock:
		return OutcomeBlock
	default:
		return OutcomeAllow
	}
}

// terminal reports whether the outcome is a host-side termination (no verdict),
// which the fail-open/fail-closed policy must resolve.
func (o Outcome) terminal() bool {
	switch o {
	case OutcomeTimeout, OutcomeFuel, OutcomeError:
		return true
	default:
		return false
	}
}

// ModuleResult is the outcome of invoking one module for one artifact.
type ModuleResult struct {
	// Module is the configured module name.
	Module string `json:"module"`
	// Outcome classifies how the invocation terminated.
	Outcome Outcome `json:"outcome"`
	// Decision is the effective decision after applying the module's
	// fail-open/fail-closed policy to a terminal outcome (so a timed-out
	// fail-closed module reads as block here).
	Decision Decision `json:"decision"`
	// Verdict is the module's returned verdict, populated only for a completed
	// (non-terminal) invocation.
	Verdict *Verdict `json:"verdict,omitempty"`
	// FailClosed records the module's policy, so an operator reading the result
	// can see why a terminal outcome resolved to block vs allow.
	FailClosed bool `json:"failClosed"`
	// DurationMicros is the wall-clock invocation time in microseconds.
	DurationMicros int64 `json:"durationMicros"`
	// Err carries the underlying error for a terminal outcome (nil otherwise). It
	// is not serialized; the Outcome and a log line convey it to operators.
	Err error `json:"-"`
}

// Result is the combined decision across every module that ran for one artifact.
// The effective Decision is the most severe across the per-module decisions
// (after each module's fail policy is applied), so any module can block and any
// can warn.
type Result struct {
	// Decision is the combined effective decision (most severe across modules).
	Decision Decision `json:"decision"`
	// Block / Warn restate the decision for convenient call-site branching.
	Block bool `json:"block"`
	Warn  bool `json:"warn"`
	// Reason is the reason from the module that drove the decision (the first
	// module at the winning severity).
	Reason string `json:"reason,omitempty"`
	// Module names the module that drove the decision.
	Module string `json:"module,omitempty"`
	// Annotations merges the annotations of the modules at the winning severity,
	// prefixed by module name to avoid collisions.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Modules is the full per-module breakdown, in evaluation order.
	Modules []ModuleResult `json:"modules,omitempty"`
}

// combine folds an ordered set of per-module results into a single Result. The
// most severe decision wins; ties keep the earliest module's reason. It returns
// an allow Result with no modules when results is empty.
func combine(results []ModuleResult) Result {
	out := Result{Decision: DecisionAllow, Modules: results}
	best := -2
	for _, r := range results {
		if sev := r.Decision.severity(); sev > best {
			best = sev
			out.Decision = r.Decision
			out.Reason = reasonOf(r)
			out.Module = r.Module
		}
	}
	out.Block = out.Decision == DecisionBlock
	out.Warn = out.Decision == DecisionWarn
	// Merge annotations from the modules that share the winning severity, namespaced
	// by module so two modules cannot clobber each other's keys.
	for _, r := range results {
		if r.Decision != out.Decision || r.Verdict == nil || len(r.Verdict.Annotations) == 0 {
			continue
		}
		if out.Annotations == nil {
			out.Annotations = make(map[string]string)
		}
		keys := make([]string, 0, len(r.Verdict.Annotations))
		for k := range r.Verdict.Annotations {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out.Annotations[r.Module+"."+k] = r.Verdict.Annotations[k]
		}
	}
	return out
}

func reasonOf(r ModuleResult) string {
	if r.Verdict != nil && r.Verdict.Reason != "" {
		return r.Verdict.Reason
	}
	switch r.Outcome {
	case OutcomeTimeout:
		return "extension module timed out"
	case OutcomeFuel:
		return "extension module exhausted its fuel budget"
	case OutcomeError:
		return "extension module failed to evaluate"
	default:
		return ""
	}
}
