package proxy

import (
	"context"
	"net/http"
	"strconv"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/reposcore"
	"github.com/blechschmidt/pullthrough-security/internal/tracing"
)

// The source-repository health provider (Task 63) is a signal provider, not a
// hard gate: it derives OpenSSF Scorecard-style health signals for the
// repository the artifact was built from (taken from the provenance association
// recorded earlier in this request) and folds them into the admission
// accumulator. The policy-as-code and risk-scoring gates that run after it can
// then key on those signals (with per-tenant weights). It never blocks a pull on
// its own — a missing or unhealthy source repo influences the composite risk
// score rather than forcing a refusal — so it is best-effort and always returns
// true.

// gateRepoScore computes the source-repository health for the artifact's
// associated commit/repository and records it into the per-request signal
// accumulator. It runs after the provenance-bearing gates (so the repository URL
// is known) and before the aggregating policy/risk gates (so its signal feeds
// them). It always returns true; it is observe-and-feed, never block.
func (g *Gateway) gateRepoScore(w http.ResponseWriter, r *http.Request, name, ecosystem string) bool {
	if g.deps.RepoScore == nil || !g.deps.RepoScore.Enabled() {
		return true
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return true
	}

	// The repository association is produced by the provenance/policy gate earlier
	// in the request. Without it there is no repository to score.
	s.mu.Lock()
	prov := s.input.Provenance
	tenant := s.input.Tenant
	s.mu.Unlock()
	if prov == nil || prov.RepositoryURL == "" {
		return true
	}

	report := g.deps.RepoScore.Score(r.Context(), reposcore.RepoRef{
		RepositoryURL: prov.RepositoryURL,
		CommitSHA:     prov.CommitSHA,
		Tenant:        tenant,
	})
	if !report.Evaluated {
		return true
	}

	recordRepoHealthSignal(r.Context(), report)

	// Surface the health score so clients/proxies downstream can observe it, and
	// fold it into the request span for trace filtering. Only meaningful when the
	// repository resolved.
	if report.Resolved {
		w.Header().Set("X-Repo-Health", strconv.Itoa(report.Health))
		if report.Grade != "" {
			w.Header().Set("X-Repo-Health-Grade", report.Grade)
		}
		tracing.SpanFromContext(r.Context()).SetAttributes(
			tracing.Int("pullthrough.repo.health", report.Health),
			tracing.String("pullthrough.repo.grade", report.Grade),
		)
	}
	return true
}

// recordRepoHealthSignal translates a reposcore.Report into the policyengine
// RepoHealth input and records it on the per-request accumulator.
func recordRepoHealthSignal(ctx context.Context, report reposcore.Report) {
	s := signalsFrom(ctx)
	if s == nil || !report.Evaluated {
		return
	}
	in := &policyengine.RepoHealthInput{
		Evaluated:         true,
		Resolved:          report.Resolved,
		RepositoryURL:     report.RepositoryURL,
		CommitSHA:         report.CommitSHA,
		Health:            report.Health,
		Risk:              report.Risk,
		Grade:             report.Grade,
		BranchProtection:  report.Facts.BranchProtected || report.Facts.HasCodeowners,
		SignedCommitRatio: signedRatio(report.Facts),
		HasCI:             report.Facts.HasCI,
		HasSecurityPolicy: report.Facts.HasSecurityPolicy,
		Maintainers:       report.Facts.DistinctAuthors,
		BusFactor:         report.Facts.BusFactor,
		LastActivityDays:  report.Facts.LastCommitAgeDays,
		DepAutomation:     report.Facts.HasDepAutomation,
		Online:            report.Online,
		Error:             report.Error,
	}
	for _, k := range report.Weak {
		in.Weak = append(in.Weak, string(k))
	}
	s.mu.Lock()
	s.input.RepoHealth = in
	s.mu.Unlock()
}

// signedRatio computes the signed-commit ratio from the raw facts for the policy
// input (a convenience field rules can key on directly).
func signedRatio(f reposcore.RepoFacts) float64 {
	if f.CommitsAnalyzed == 0 {
		return 0
	}
	return float64(f.SignedCommits) / float64(f.CommitsAnalyzed)
}
