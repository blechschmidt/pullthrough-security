// Package policy implements admission gating for content served by the proxy.
// It is the enforcement point that turns the signals produced by earlier tasks —
// LLM commit scan verdicts (Task 7) and package-to-commit provenance (Task 8) —
// into a serve/deny decision for each artifact a client pulls.
//
// The engine is deliberately decoupled from the scanning and provenance
// implementations: it consumes a flattened Assessment (provenance confidence,
// signature/attestation state, and the source commit's risk verdict) via an
// AssessmentSource the caller injects. This keeps the package free of import
// cycles and makes the decision logic exhaustively unit-testable in isolation.
//
// Policy is expressed as a default Rule plus optional per-ecosystem Rules. Each
// Rule supports configurable block/warn/allow actions driven by:
//
//   - source-commit risk-score thresholds (and a malicious-commit kill switch);
//   - how to treat artifacts with missing provenance or an unscanned commit;
//   - signature-verification / full-attestation requirements and a minimum
//     provenance confidence floor;
//   - per-ecosystem allowlists and denylists of package-name glob patterns.
//
// The proxy core invokes Evaluate as an admission middleware between resolving an
// artifact and serving it; a blocked decision is surfaced to the client as an
// actionable error and never reaches the cache or upstream.
package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// Action is the gating outcome of a policy check.
type Action string

const (
	// ActionAllow serves the artifact. An empty/unset action normalizes to allow,
	// so a check is disabled until an operator opts into warn or block.
	ActionAllow Action = "allow"
	// ActionWarn serves the artifact but records a warning (audit event + response
	// header) so the condition is visible without breaking the build.
	ActionWarn Action = "warn"
	// ActionBlock refuses to serve the artifact and returns an actionable error.
	ActionBlock Action = "block"
	// ActionQuarantine refuses to serve the artifact like ActionBlock and, in
	// addition, evicts any cached copy so the offending content does not linger in
	// the cache. It is the strongest outcome and is used by the vulnerability gate
	// for artifacts whose known CVEs exceed the configured threshold.
	ActionQuarantine Action = "quarantine"
)

// severity orders actions so the most restrictive outcome wins when several
// checks fire.
func (a Action) severity() int {
	switch a {
	case ActionQuarantine:
		return 3
	case ActionBlock:
		return 2
	case ActionWarn:
		return 1
	default:
		return 0
	}
}

// normalize coerces an arbitrary/empty action to a known value; unknown values
// fail open to allow so a typo never silently blocks all traffic (validation in
// the config layer rejects unknown values up front).
func (a Action) normalize() Action {
	switch Action(strings.ToLower(strings.TrimSpace(string(a)))) {
	case ActionQuarantine:
		return ActionQuarantine
	case ActionBlock:
		return ActionBlock
	case ActionWarn:
		return ActionWarn
	default:
		return ActionAllow
	}
}

// ValidAction reports whether s is a recognized action string (used by config
// validation). The empty string is valid and means "allow" (check disabled).
func ValidAction(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(ActionAllow), string(ActionWarn), string(ActionBlock), string(ActionQuarantine):
		return true
	default:
		return false
	}
}

// Blocked reports whether the action denies serving (block or quarantine).
func (a Action) Blocked() bool {
	switch a.normalize() {
	case ActionBlock, ActionQuarantine:
		return true
	default:
		return false
	}
}

// Artifact is the unit of work the engine gates: a concrete, versioned package
// release flowing through the proxy.
type Artifact struct {
	// Ecosystem is the normalized ecosystem (npm, pip, cargo, go, nuget, docker).
	Ecosystem string
	// Backend is the upstream/backend name the request was routed to.
	Backend string
	// Name and Version are the package coordinate.
	Name    string
	Version string
	// Digest is the content digest (e.g. "sha256:..."), when known.
	Digest string
}

// String renders a human-readable coordinate for messages and logs.
func (a Artifact) String() string {
	switch {
	case a.Name != "" && a.Version != "":
		return fmt.Sprintf("%s %s@%s", a.Ecosystem, a.Name, a.Version)
	case a.Name != "":
		return fmt.Sprintf("%s %s", a.Ecosystem, a.Name)
	case a.Digest != "":
		return fmt.Sprintf("%s %s", a.Ecosystem, a.Digest)
	default:
		return a.Ecosystem
	}
}

// Assessment is the flattened provenance + scan view the engine evaluates. The
// caller (see the proxy's adapter over the provenance Service) is responsible for
// resolving it without leaking provenance/scan types into this package.
type Assessment struct {
	// Found reports whether any provenance link could be established.
	Found bool
	// Confidence is the provenance confidence: "attested", "claimed", or
	// "heuristic" (empty when not found).
	Confidence string
	// SignatureVerified reports the attestation's signature verified against its
	// signing certificate.
	SignatureVerified bool
	// ChainTrusted reports the signing certificate chained to a configured trust
	// root. Full attestation requires SignatureVerified && ChainTrusted.
	ChainTrusted bool
	// CommitSHA and RepositoryURL identify the source revision the artifact was
	// built from, when resolved.
	CommitSHA     string
	RepositoryURL string

	// HasVerdict reports whether the source commit has a scan verdict.
	HasVerdict bool
	// RiskScore is the source commit's supply-chain risk score, 0..100.
	RiskScore int
	// Malicious is the scanner's boolean call on the source commit.
	Malicious bool
	// HighestSeverity is the most severe finding's severity (info..critical).
	HighestSeverity string
}

// AssessmentSource resolves the provenance + scan Assessment for an artifact. An
// artifact with no provenance must be reported as Assessment{Found: false} with a
// nil error; a non-nil error means the assessment could not be performed (and is
// subject to the engine's fail-open/closed handling).
type AssessmentSource interface {
	Assess(ctx context.Context, a Artifact) (Assessment, error)
}

// confidenceRank orders provenance confidence for the MinConfidence floor.
func confidenceRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "attested":
		return 3
	case "claimed":
		return 2
	case "heuristic":
		return 1
	default:
		return 0
	}
}

// Rule is a complete admission policy. Config.Default is the baseline; an entry
// in Config.Ecosystems fully replaces it for that ecosystem (no field merge), so
// each ecosystem's effective policy is exactly one Rule — predictable and easy to
// reason about for an auditor.
type Rule struct {
	// BlockAtRiskScore blocks artifacts whose source-commit risk score is at or
	// above this value (1..100; 0 disables the threshold).
	BlockAtRiskScore int
	// WarnAtRiskScore warns on artifacts at or above this value but below
	// BlockAtRiskScore (1..100; 0 disables).
	WarnAtRiskScore int
	// BlockMalicious blocks any artifact whose source commit the scanner flagged
	// malicious, regardless of the numeric score.
	BlockMalicious bool

	// OnMissingProvenance is applied when no provenance link can be established.
	OnMissingProvenance Action
	// OnMissingScan is applied when provenance exists but the source commit has no
	// scan verdict.
	OnMissingScan Action

	// RequireSignature blocks artifacts whose provenance signature did not verify.
	RequireSignature bool
	// RequireAttested blocks artifacts that are not fully attested (a verified
	// signature chaining to a trusted root).
	RequireAttested bool
	// MinConfidence is the minimum acceptable provenance confidence
	// ("heuristic" < "claimed" < "attested"). Below it, OnLowConfidence applies.
	// Empty disables the floor.
	MinConfidence string
	// OnLowConfidence is applied when provenance confidence is below MinConfidence.
	OnLowConfidence Action

	// Allowlist, when non-empty, restricts admission to package names matching one
	// of these glob patterns; any other name is blocked.
	Allowlist []string
	// Denylist blocks package names matching any of these glob patterns. Denylist
	// is evaluated before Allowlist.
	Denylist []string
}

// Config is the engine configuration.
type Config struct {
	// FailClosed controls behavior when an AssessmentSource returns an error: when
	// true the artifact is blocked, otherwise it is served with a warning. The
	// default (false) fails open so a transient provenance-backend outage degrades
	// to warn rather than halting all pulls.
	FailClosed bool
	// Default is the baseline policy applied to every ecosystem without an entry in
	// Ecosystems.
	Default Rule
	// Ecosystems holds per-ecosystem policies that fully replace Default for the
	// keyed ecosystem.
	Ecosystems map[string]Rule
}

// Decision is the outcome of evaluating an artifact.
type Decision struct {
	// Action is the gating outcome.
	Action Action
	// Code is a stable machine-readable reason code (e.g. "denylist",
	// "risk-score", "missing-provenance"), suitable for metrics and audit detail.
	Code string
	// Reason is a human-readable, actionable explanation suitable for returning to
	// the client on a block (and logging on a warn).
	Reason string
	// Artifact echoes the evaluated artifact.
	Artifact Artifact
	// Assessment echoes the provenance/scan inputs behind the decision.
	Assessment Assessment
}

// Blocked reports whether the decision denies serving (block or quarantine).
func (d Decision) Blocked() bool { return d.Action.Blocked() }

// Warned reports whether the decision serves with a warning.
func (d Decision) Warned() bool { return d.Action == ActionWarn }

// Engine evaluates artifacts against the configured policy. It is safe for
// concurrent use.
type Engine struct {
	cfg    Config
	source AssessmentSource
	logger *slog.Logger
}

// New constructs an Engine. source may be nil, in which case every artifact is
// treated as having no provenance (so allow/deny lists and OnMissingProvenance
// still apply, but signature/risk checks cannot fire).
func New(cfg Config, source AssessmentSource, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{cfg: cfg, source: source, logger: logger}
}

// ruleFor returns the effective Rule for an ecosystem: its dedicated entry when
// present, otherwise the default.
func (e *Engine) ruleFor(ecosystem string) Rule {
	if r, ok := e.cfg.Ecosystems[ecosystem]; ok {
		return r
	}
	return e.cfg.Default
}

// Evaluate gates an artifact and returns the decision. It never returns an error:
// an assessment failure is folded into the decision per Config.FailClosed so the
// caller has a single, total contract for admission.
func (e *Engine) Evaluate(ctx context.Context, a Artifact) Decision {
	rule := e.ruleFor(a.Ecosystem)

	// Denylist and allowlist are evaluated first: they are operator intent that
	// does not depend on any external lookup, and an explicit deny must win.
	if pat, ok := matchAny(rule.Denylist, a.Name); ok {
		return e.block(a, Assessment{}, "denylist",
			fmt.Sprintf("package %q is denylisted by policy (matched pattern %q). "+
				"If you believe this is in error, contact your platform security team to review the denylist.",
				a.Name, pat))
	}
	if len(rule.Allowlist) > 0 {
		if _, ok := matchAny(rule.Allowlist, a.Name); !ok {
			return e.block(a, Assessment{}, "allowlist",
				fmt.Sprintf("package %q is not on the approved allowlist for ecosystem %q. "+
					"Request that your platform team add it to the %s allowlist before it can be pulled.",
					a.Name, a.Ecosystem, a.Ecosystem))
		}
	}

	asmt, err := e.assess(ctx, a)
	if err != nil {
		if e.cfg.FailClosed {
			return e.block(a, asmt, "evaluation-error",
				"the admission policy could not be evaluated (provenance lookup failed) and policy is fail-closed; "+
					"retry shortly or contact your platform team if the condition persists")
		}
		e.logger.Warn("policy assessment failed; failing open with warning",
			"artifact", a.String(), "error", err)
		return Decision{Action: ActionWarn, Code: "evaluation-error", Artifact: a, Assessment: asmt,
			Reason: "admission policy could not be fully evaluated (provenance lookup failed); served with a warning"}
	}

	// Without provenance we cannot evaluate signature/risk; the configured
	// missing-provenance action is terminal.
	if !asmt.Found {
		return e.decide(rule.OnMissingProvenance, a, asmt, "missing-provenance",
			fmt.Sprintf("no build provenance could be established for %s, so its source commit and supply-chain risk are unknown. "+
				"Publish signed build provenance (e.g. SLSA / GitHub build attestations) for this package, or ask your platform team to adjust the missing-provenance policy.",
				a.String()))
	}

	// Signature / attestation requirements are hard gates.
	if rule.RequireSignature && !asmt.SignatureVerified {
		return e.block(a, asmt, "signature-required",
			fmt.Sprintf("policy requires a verified provenance signature for %s, but its attestation signature did not verify. "+
				"Ensure the package is published with a valid signed attestation.", a.String()))
	}
	if rule.RequireAttested && !(asmt.SignatureVerified && asmt.ChainTrusted) {
		return e.block(a, asmt, "attestation-required",
			fmt.Sprintf("policy requires fully attested provenance (verified signature chaining to a trusted root) for %s, "+
				"but the provenance is %q. Publish a signed attestation that chains to a configured trust root.",
				a.String(), confidenceOrUnknown(asmt.Confidence)))
	}

	// Collect the strongest non-blocking outcome from soft checks; any block
	// short-circuits immediately.
	best := Decision{Action: ActionAllow, Code: "ok", Artifact: a, Assessment: asmt,
		Reason: fmt.Sprintf("%s admitted", a.String())}

	if rule.MinConfidence != "" && confidenceRank(asmt.Confidence) < confidenceRank(rule.MinConfidence) {
		d := e.decide(rule.OnLowConfidence, a, asmt, "low-confidence",
			fmt.Sprintf("provenance confidence for %s is %q, below the required minimum %q. "+
				"Stronger (signed/attested) provenance is required.",
				a.String(), confidenceOrUnknown(asmt.Confidence), rule.MinConfidence))
		if d.Blocked() {
			return d
		}
		best = stronger(best, d)
	}

	if !asmt.HasVerdict {
		d := e.decide(rule.OnMissingScan, a, asmt, "missing-scan",
			fmt.Sprintf("the source commit %s for %s has not been scanned, so its risk is unknown",
				shortSHA(asmt.CommitSHA), a.String()))
		if d.Blocked() {
			return d
		}
		best = stronger(best, d)
	} else {
		if rule.BlockMalicious && asmt.Malicious {
			return e.block(a, asmt, "malicious",
				fmt.Sprintf("the source commit %s for %s was flagged malicious by the scanner (risk score %d). "+
					"This artifact is blocked. Investigate the commit and the publishing pipeline before overriding policy.",
					shortSHA(asmt.CommitSHA), a.String(), asmt.RiskScore))
		}
		if rule.BlockAtRiskScore > 0 && asmt.RiskScore >= rule.BlockAtRiskScore {
			return e.block(a, asmt, "risk-score",
				fmt.Sprintf("the source commit %s for %s has supply-chain risk score %d, at or above the block threshold %d. "+
					"Review the scan findings for this commit; once remediated, the new release will re-scan.",
					shortSHA(asmt.CommitSHA), a.String(), asmt.RiskScore, rule.BlockAtRiskScore))
		}
		if rule.WarnAtRiskScore > 0 && asmt.RiskScore >= rule.WarnAtRiskScore {
			best = stronger(best, Decision{Action: ActionWarn, Code: "risk-score", Artifact: a, Assessment: asmt,
				Reason: fmt.Sprintf("the source commit %s for %s has risk score %d, at or above the warn threshold %d",
					shortSHA(asmt.CommitSHA), a.String(), asmt.RiskScore, rule.WarnAtRiskScore)})
		}
	}

	return best
}

// assess resolves the provenance/scan view, tolerating a nil source.
func (e *Engine) assess(ctx context.Context, a Artifact) (Assessment, error) {
	if e.source == nil {
		return Assessment{Found: false}, nil
	}
	return e.source.Assess(ctx, a)
}

// decide builds a Decision applying the given (normalized) action with the shared
// code/reason. An allow action yields an explicit allow Decision carrying the
// code so callers can still observe which check passed.
func (e *Engine) decide(action Action, a Artifact, asmt Assessment, code, reason string) Decision {
	return Decision{Action: action.normalize(), Code: code, Reason: reason, Artifact: a, Assessment: asmt}
}

// block is a shorthand for a blocking Decision.
func (e *Engine) block(a Artifact, asmt Assessment, code, reason string) Decision {
	return Decision{Action: ActionBlock, Code: code, Reason: reason, Artifact: a, Assessment: asmt}
}

// stronger returns whichever decision carries the more restrictive action,
// preferring b on a tie so a later, more specific reason is surfaced.
func stronger(a, b Decision) Decision {
	if b.Action.severity() >= a.Action.severity() {
		return b
	}
	return a
}

// matchAny reports whether name matches any of the glob patterns, returning the
// matched pattern. Matching is case-insensitive (so case variation cannot evade a
// denylist) and supports '*' wildcards that span path separators.
func matchAny(patterns []string, name string) (string, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "", false
	}
	for _, p := range patterns {
		if globMatch(strings.ToLower(strings.TrimSpace(p)), n) {
			return p, true
		}
	}
	return "", false
}

// globMatch implements case-folded wildcard matching where '*' matches any
// (possibly empty) run of characters, including '/'. It is intentionally simpler
// than path.Match (which does not cross '/') because package names contain '/'
// (npm scopes, Go module paths, OCI repositories) and operators expect
// "@scope/*" or "evil/*" to match across separators.
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern == "*" {
		return true
	}
	// Two-pointer wildcard match with backtracking on the last '*'.
	var (
		px, sx         int
		starIdx        = -1
		matchAfterStar int
	)
	for sx < len(s) {
		if px < len(pattern) && (pattern[px] == s[sx] || pattern[px] == '?') {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			starIdx = px
			matchAfterStar = sx
			px++
		} else if starIdx != -1 {
			px = starIdx + 1
			matchAfterStar++
			sx = matchAfterStar
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// confidenceOrUnknown renders a confidence string, substituting "unknown" for
// the empty value.
func confidenceOrUnknown(c string) string {
	if strings.TrimSpace(c) == "" {
		return "unknown"
	}
	return c
}

// shortSHA abbreviates a commit SHA for messages, tolerating an empty value.
func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if sha == "" {
		return "(unknown)"
	}
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
