// Package reposcore computes lightweight, OpenSSF Scorecard-style health signals
// for the source repository a package was built from (Task 63).
//
// The proxy already associates a served artifact with its source Git
// commit/repository via the provenance subsystem (Task 8). This package takes
// that association one step further: given a repository it can reach as an
// already-mirrored local clone, it derives a small set of supply-chain health
// signals — branch-protection presence, the signed-commit/tag ratio in recent
// history, the presence of CI configuration and a security policy (SECURITY.md),
// a maintainer-count / bus-factor estimate from commit authorship, recent
// maintenance activity, and dependency-update-automation hints — and folds them
// into a single 0..100 health score (and inverse 0..100 risk score) plus an
// explainable per-signal breakdown.
//
// Three properties drive the design:
//
//   - Offline / air-gap friendly. Every signal is derived from a local git
//     directory using the git binary alone (no GitHub/GitLab API calls). When the
//     repository cannot be reached as a local clone the report is simply marked
//     unresolved and contributes nothing to risk — a missing source repo is the
//     provenance signal's concern, not this one's. An optional online Enricher
//     hook can fill in signals that genuinely require an API (true branch
//     protection settings) without changing the offline path.
//
//   - Explainability. Like the unified risk-scoring engine (Task 37), a bare score
//     is useless to an operator. Every Report carries an ordered set of SubSignals,
//     each with its 0..1 health value, its weight, and a human-readable detail
//     string, so "why is this repo's health 48/100?" is always answerable.
//
//   - Decoupling. The package produces a plain, self-describing Report and the
//     wiring layer translates it into a policyengine.Input field consumed by the
//     risk-scoring engine (with per-tenant weights). reposcore imports neither the
//     risk engine nor the policy engine, so it stays trivially unit-testable, and
//     its git extraction (RepoFacts) is separated from its scoring so the scoring
//     math can be tested without a repository at all.
//
// See docs/reposcore.md for the heuristics, their rationale, and their
// limitations. All exported methods of Service are safe for concurrent use.
package reposcore

import "time"

// SignalKind identifies a repository health sub-signal. The values are stable,
// lowercase identifiers suitable for metric labels, UI keys, and the explainable
// breakdown.
type SignalKind string

const (
	// SignalBranchProtection reflects whether the default branch is protected.
	// Offline this is a heuristic hint (presence of a CODEOWNERS file, which
	// GitHub/GitLab use to require reviews); an online Enricher can replace the
	// hint with the true branch-protection setting.
	SignalBranchProtection SignalKind = "branch-protection"
	// SignalSignedCommits reflects the fraction of recent commits (and tags)
	// carrying a cryptographic signature.
	SignalSignedCommits SignalKind = "signed-commits"
	// SignalCI reflects the presence of a continuous-integration configuration.
	SignalCI SignalKind = "ci"
	// SignalSecurityPolicy reflects the presence of a SECURITY.md security policy.
	SignalSecurityPolicy SignalKind = "security-policy"
	// SignalMaintainers reflects the maintainer count and bus-factor estimate
	// derived from recent commit authorship.
	SignalMaintainers SignalKind = "maintainers"
	// SignalActivity reflects recent maintenance activity (recency of the last
	// commit and the spread of active days in the analyzed window).
	SignalActivity SignalKind = "activity"
	// SignalDepAutomation reflects the presence of dependency-update automation
	// (Dependabot / Renovate configuration).
	SignalDepAutomation SignalKind = "dep-automation"
)

// allSignals is the canonical evaluation/render order, so identical inputs always
// produce byte-identical reports.
var allSignals = []SignalKind{
	SignalBranchProtection,
	SignalSignedCommits,
	SignalCI,
	SignalSecurityPolicy,
	SignalMaintainers,
	SignalActivity,
	SignalDepAutomation,
}

// SubSignal is one repository-health sub-signal's explainable contribution.
type SubSignal struct {
	// Kind identifies the sub-signal.
	Kind SignalKind `json:"kind"`
	// Health is the sub-signal's normalized health in [0,1] (1 = healthiest).
	Health float64 `json:"health"`
	// Weight is the configured (raw) weight for this sub-signal.
	Weight float64 `json:"weight"`
	// Points is the marginal contribution to the 0..100 composite health score.
	Points float64 `json:"points"`
	// Hint reports whether this sub-signal is a heuristic hint rather than an
	// authoritative measurement (currently only branch protection when not
	// enriched from an online source).
	Hint bool `json:"hint,omitempty"`
	// Detail is a short human-readable rendering of the underlying value(s).
	Detail string `json:"detail"`
}

// Report is the explainable result of scoring a repository's health.
type Report struct {
	// RepositoryURL is the (normalized) repository the report describes.
	RepositoryURL string `json:"repositoryUrl,omitempty"`
	// CommitSHA, when known, is the source commit the artifact was built from. It
	// is carried through for correlation; the signals describe the repository, not
	// the single commit.
	CommitSHA string `json:"commitSha,omitempty"`
	// Evaluated reports that scoring ran for this repository (whether or not a
	// local clone was found).
	Evaluated bool `json:"evaluated"`
	// Resolved reports that a local clone was found and inspected. When false the
	// report carries no health signal and contributes nothing to risk.
	Resolved bool `json:"resolved"`
	// Online reports whether an online Enricher contributed to this report.
	Online bool `json:"online"`

	// Health is the composite repository-health score in [0,100] (higher =
	// healthier). Risk is its inverse (100 - Health), the value the risk-scoring
	// engine consumes.
	Health int    `json:"health"`
	Risk   int    `json:"risk"`
	Grade  string `json:"grade"`

	// Signals is the explainable breakdown in canonical order. Empty when
	// unresolved.
	Signals []SubSignal `json:"signals,omitempty"`
	// Weak lists the sub-signals whose health fell at or below the weak threshold,
	// for a quick at-a-glance "what's wrong" view.
	Weak []SignalKind `json:"weak,omitempty"`

	// Facts is the raw, offline-derived observation set the score was computed
	// from, retained for transparency and the admin drill-down.
	Facts RepoFacts `json:"facts"`

	// Summary is a one-line, human-readable explanation.
	Summary string `json:"summary"`
	// Error, when non-empty, explains why the repository could not be resolved or
	// fully analyzed (the report is still usable; it is just degraded).
	Error string `json:"error,omitempty"`

	EvaluatedAt time.Time `json:"evaluatedAt"`
}

// gradeFor maps a 0..100 health score to a coarse letter grade.
func gradeFor(health int) string {
	switch {
	case health >= 85:
		return "A"
	case health >= 70:
		return "B"
	case health >= 55:
		return "C"
	case health >= 40:
		return "D"
	default:
		return "F"
	}
}
