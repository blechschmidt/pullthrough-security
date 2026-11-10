package reposcore

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// signalEval is the intermediate result of evaluating one sub-signal against the
// facts: its normalized health in [0,1], whether it is a heuristic hint, and an
// explainable rendering.
type signalEval struct {
	kind   SignalKind
	health float64
	hint   bool
	detail string
}

// scoreFacts converts a RepoFacts observation set into the explainable, weighted
// health/risk report fields, using the tenant's effective weights. It is a pure
// function of its inputs (no clock, no I/O), so the scoring math is fully
// deterministic and unit-testable without a repository.
func scoreFacts(f RepoFacts, w Weights) (health int, signals []SubSignal, weak []SignalKind, grade string) {
	evals := []signalEval{
		branchProtectionScored(f),
		signedCommitsScored(f),
		ciScored(f),
		securityPolicyScored(f),
		maintainersScored(f),
		activityScored(f),
		depAutomationScored(f),
	}

	// Normalize by the weights of the signals actually evaluated (all of them, when
	// the repo resolved) so the composite is a clean weighted average in [0,100].
	var sumW float64
	for _, e := range evals {
		sumW += w.forSignal(e.kind)
	}

	signals = make([]SubSignal, 0, len(evals))
	var composite float64
	for _, e := range evals {
		wt := w.forSignal(e.kind)
		var points float64
		if sumW > 0 {
			points = 100 * (wt / sumW) * e.health
		}
		composite += points
		signals = append(signals, SubSignal{
			Kind:   e.kind,
			Health: round4(e.health),
			Weight: wt,
			Points: round2(points),
			Hint:   e.hint,
			Detail: e.detail,
		})
		if e.health <= weakThreshold {
			weak = append(weak, e.kind)
		}
	}

	health = int(math.Round(composite))
	if health < 0 {
		health = 0
	}
	if health > 100 {
		health = 100
	}
	return health, signals, weak, gradeFor(health)
}

// branchProtectionScored scores branch protection. An authoritative setting from
// an online Enricher is trusted directly; otherwise a CODEOWNERS file is a weak
// offline hint that review enforcement is configured.
func branchProtectionScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalBranchProtection, hint: true}
	switch {
	case f.BranchProtectionKnown && f.BranchProtected:
		e.health, e.hint, e.detail = 1.0, false, "default branch protected (verified)"
	case f.BranchProtectionKnown:
		e.health, e.hint, e.detail = 0.0, false, "default branch not protected (verified)"
	case f.HasCodeowners:
		e.health, e.detail = 0.5, "CODEOWNERS present (offline hint; true setting unverified)"
	default:
		e.detail = "no branch-protection signal (offline; CODEOWNERS absent)"
	}
	return e
}

// signedCommitsScored scores the signed-commit ratio over recent history, with a
// small bonus for signed tags. A valid signature counts fully; a present-but-
// unverifiable one counts at a discount (offline we cannot confirm the key).
func signedCommitsScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalSignedCommits}
	if f.CommitsAnalyzed == 0 {
		e.detail = "no commits analyzed"
		return e
	}
	good := float64(f.GoodSignedCommits) / float64(f.CommitsAnalyzed)
	anySig := float64(f.SignedCommits) / float64(f.CommitsAnalyzed)
	// Blend: valid signatures dominate; unverifiable-but-present signatures get
	// 60% credit so a repo that signs (key just not local) still scores well.
	ratio := good + 0.6*(anySig-good)
	health := clamp01(ratio)
	if f.SignedTags > 0 {
		health = clamp01(health + 0.05)
	}
	e.health = health
	e.detail = fmt.Sprintf("%d/%d recent commits signed (%d valid); %d/%d tags signed",
		f.SignedCommits, f.CommitsAnalyzed, f.GoodSignedCommits, f.SignedTags, f.Tags)
	return e
}

func ciScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalCI}
	if f.HasCI {
		e.health = 1.0
		e.detail = "CI configured: " + strings.Join(f.CISystems, ", ")
	} else {
		e.detail = "no CI configuration found"
	}
	return e
}

func securityPolicyScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalSecurityPolicy}
	if f.HasSecurityPolicy {
		e.health = 1.0
		e.detail = "SECURITY.md present"
	} else {
		e.detail = "no SECURITY.md security policy"
	}
	return e
}

// maintainersScored scores the maintainer base: more independent maintainers and
// a higher bus factor are healthier; a single-maintainer repo with all commits
// from one author is the weakest.
func maintainersScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalMaintainers}
	if f.CommitsAnalyzed == 0 {
		e.detail = "no commits analyzed"
		return e
	}
	// Bus factor drives the score: 1 → 0.2, 2 → 0.55, 3 → 0.8, >=4 → 1.0.
	var busHealth float64
	switch {
	case f.BusFactor >= 4:
		busHealth = 1.0
	case f.BusFactor == 3:
		busHealth = 0.8
	case f.BusFactor == 2:
		busHealth = 0.55
	case f.BusFactor == 1:
		busHealth = 0.2
	}
	// Penalize extreme single-author concentration even when several authors exist.
	if f.TopAuthorShare > 0.9 && busHealth > 0.2 {
		busHealth = 0.2
	}
	e.health = clamp01(busHealth)
	e.detail = fmt.Sprintf("%d distinct authors, bus factor %d, top author %.0f%% of commits",
		f.DistinctAuthors, f.BusFactor, f.TopAuthorShare*100)
	return e
}

// activityScored scores recent maintenance: how recently the last commit landed,
// blended with how many distinct days saw activity in the window.
func activityScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalActivity}
	if f.LastCommitUnix == 0 {
		e.detail = "no datable commits"
		return e
	}
	// Recency: <=30d → 1.0, linearly to 0 at 730d (2 years).
	var recency float64
	switch {
	case f.LastCommitAgeDays <= 30:
		recency = 1.0
	case f.LastCommitAgeDays >= 730:
		recency = 0.0
	default:
		recency = 1.0 - float64(f.LastCommitAgeDays-30)/700.0
	}
	// Cadence: distinct active days, saturating at 20.
	cadence := clamp01(float64(f.ActiveDays) / 20.0)
	// Recency dominates (a stale repo is risky even if it was once busy).
	e.health = clamp01(0.7*recency + 0.3*cadence)
	e.detail = fmt.Sprintf("last commit %dd ago, %d active days in last %d commits",
		f.LastCommitAgeDays, f.ActiveDays, f.CommitsAnalyzed)
	return e
}

func depAutomationScored(f RepoFacts) signalEval {
	e := signalEval{kind: SignalDepAutomation}
	if f.HasDepAutomation {
		e.health = 1.0
		e.detail = "dependency automation: " + strings.Join(f.DepTools, ", ")
	} else {
		e.detail = "no Dependabot/Renovate configuration"
	}
	return e
}

// summarize produces a one-line explanation naming the weakest weighted drivers.
func summarize(r Report) string {
	if !r.Resolved {
		if r.Error != "" {
			return "repository health unavailable: " + r.Error
		}
		return "repository health unavailable (no local clone)"
	}
	// Rank signals by lost points (weight share not earned) to name what is
	// dragging the score down.
	ranked := make([]SubSignal, len(r.Signals))
	copy(ranked, r.Signals)
	sort.SliceStable(ranked, func(i, j int) bool {
		return (ranked[i].Weight * (1 - ranked[i].Health)) > (ranked[j].Weight * (1 - ranked[j].Health))
	})
	var parts []string
	for _, c := range ranked {
		if c.Health >= 0.95 {
			continue
		}
		parts = append(parts, string(c.Kind))
		if len(parts) == 3 {
			break
		}
	}
	drivers := "all health signals strong"
	if len(parts) > 0 {
		drivers = "weakest: " + strings.Join(parts, ", ")
	}
	return fmt.Sprintf("repo health %d/100 (%s) — %s", r.Health, r.Grade, drivers)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }
