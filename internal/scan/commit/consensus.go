package commit

import (
	"fmt"
	"sort"
	"strings"
)

// Multi-provider consensus (Task 78).
//
// When more than one provider is configured, the deep (escalated) pass runs the
// commit through every provider and combines their verdicts. A 'malicious' call
// only blocks a pull when a quorum of providers agree; this guards against a
// single model being jailbroken, hallucinating, or being unavailable. Provider
// disagreement is recorded both as structured metadata (ConsensusInfo) and as a
// finding so an operator can see the split.

// ConsensusInfo records the outcome of a multi-provider consensus deep pass.
type ConsensusInfo struct {
	// Votes is the per-provider result.
	Votes []ProviderVote `json:"votes"`
	// Quorum is the minimum number of agreeing malicious votes required to call
	// the commit malicious.
	Quorum int `json:"quorum"`
	// MaliciousVotes is how many providers called the commit malicious.
	MaliciousVotes int `json:"maliciousVotes"`
	// Agreed reports whether all responding providers agreed on the malicious call.
	Agreed bool `json:"agreed"`
}

// ProviderVote is one provider's contribution to a consensus.
type ProviderVote struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	RiskScore int    `json:"riskScore"`
	Malicious bool   `json:"malicious"`
	// Error, when non-empty, records that this provider failed; its vote does not
	// count toward the quorum.
	Error string `json:"error,omitempty"`
}

// providerResult pairs a provider's verdict with the provider/model identity and
// any error, as produced by the per-provider deep pass.
type providerResult struct {
	provider string
	model    string
	verdict  *Verdict
	err      error
}

// defaultQuorum returns the default quorum for n providers: a strict majority
// (n/2 + 1), so 1->1, 2->2, 3->2, 4->3.
func defaultQuorum(n int) int {
	if n <= 0 {
		return 1
	}
	return n/2 + 1
}

// combineConsensus merges per-provider deep-pass results into a single verdict.
// quorum is the minimum number of agreeing malicious votes required to set
// Malicious. It returns the combined verdict and whether the responding
// providers disagreed on the malicious call (for metrics). At least one result
// must have succeeded; if all failed the combined verdict carries the last error.
func combineConsensus(sha string, results []providerResult, quorum int) (*Verdict, bool) {
	agg := &Verdict{SHA: sha}
	info := &ConsensusInfo{Quorum: quorum}

	var (
		responded      int
		maliciousVotes int
		maxRisk        int
		riskScores     []int
		rationales     []string
		lastErr        error
	)
	for _, r := range results {
		vote := ProviderVote{Provider: r.provider, Model: r.model}
		if r.err != nil || r.verdict == nil {
			if r.err != nil {
				vote.Error = r.err.Error()
				lastErr = r.err
			} else {
				vote.Error = "no verdict"
			}
			info.Votes = append(info.Votes, vote)
			continue
		}
		responded++
		v := r.verdict
		vote.RiskScore = v.RiskScore
		vote.Malicious = v.Malicious
		info.Votes = append(info.Votes, vote)

		// Tokens and cost accumulate across all providers.
		agg.InputTokens += v.InputTokens
		agg.OutputTokens += v.OutputTokens
		agg.CostUSD += v.CostUSD
		agg.Findings = append(agg.Findings, v.Findings...)
		if v.Truncated {
			agg.Truncated = true
		}
		if v.Malicious {
			maliciousVotes++
		}
		if v.RiskScore > maxRisk {
			maxRisk = v.RiskScore
		}
		riskScores = append(riskScores, v.RiskScore)
		if r := trimRationale(v.Rationale); r != "" {
			rationales = append(rationales, r)
		}
	}

	info.MaliciousVotes = maliciousVotes
	// Agreement is over the providers that actually responded.
	info.Agreed = responded > 0 && (maliciousVotes == 0 || maliciousVotes == responded)

	if responded == 0 {
		// Every provider failed: surface the error so the caller degrades.
		agg.Error = "all consensus providers failed"
		if lastErr != nil {
			agg.Error = "all consensus providers failed: " + lastErr.Error()
		}
		agg.Consensus = info
		return agg, false
	}

	agg.Malicious = maliciousVotes >= quorum && quorum > 0
	// Risk score: when a quorum calls it malicious, take the most severe view;
	// otherwise take the median so a single outlier does not dominate.
	if agg.Malicious {
		agg.RiskScore = maxRisk
	} else {
		agg.RiskScore = median(riskScores)
	}

	disagreed := !info.Agreed
	if disagreed {
		agg.Findings = append(agg.Findings, Finding{
			Category:   CategoryOther,
			Severity:   "medium",
			Title:      "Provider disagreement on commit risk",
			Detail:     consensusDisagreementDetail(info),
			Confidence: 0.6,
		})
	}
	agg.Rationale = joinRationales(rationales)
	agg.Consensus = info
	return agg, disagreed
}

// median returns the median of xs (0 for empty).
func median(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]int(nil), xs...)
	sort.Ints(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 1 {
		return cp[mid]
	}
	return (cp[mid-1] + cp[mid]) / 2
}

// consensusDisagreementDetail renders a human-readable summary of the split.
func consensusDisagreementDetail(info *ConsensusInfo) string {
	var mal, benign []string
	for _, v := range info.Votes {
		if v.Error != "" {
			continue
		}
		label := v.Provider
		if v.Model != "" {
			label += "/" + v.Model
		}
		if v.Malicious {
			mal = append(mal, label)
		} else {
			benign = append(benign, label)
		}
	}
	return fmt.Sprintf("providers disagreed: malicious=[%s], benign=[%s]; quorum of %d not met, so the commit is not blocked on the malicious call alone",
		strings.Join(mal, ", "), strings.Join(benign, ", "), info.Quorum)
}
