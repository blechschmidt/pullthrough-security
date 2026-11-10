package remediation

import "github.com/blechschmidt/pullthrough-security/internal/findings"

// AnnotateDocument threads the advisory's suggested fix into a unified findings
// Document so the proxy's SARIF export (Task 42) carries a result-level fix
// suggestion on each finding the recommended upgrade resolves. It is the bridge
// from "this artifact is blocked" to the actionable "upgrade to X to fix it"
// that CI pull-request decoration surfaces.
//
// A finding is annotated when the advice has a recommendation and the finding's
// gate+identifier matches one of the recommendation's resolved findings. Only
// matching findings get a fix: a residual finding the upgrade does not clear is
// deliberately left without one, so the CI annotation never over-promises.
// AnnotateDocument is a no-op when there is no recommendation or no resolved
// finding, and it never overwrites a fix a gate already attached.
func (a *Advice) AnnotateDocument(doc *findings.Document) int {
	if a == nil || doc == nil || a.Recommendation == nil {
		return 0
	}
	resolved := findingKeys(a.Recommendation.ResolvedFindings)
	if len(resolved) == 0 {
		return 0
	}
	desc := a.Recommendation.FixDescription
	n := 0
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if f.Fix != nil {
			continue
		}
		if !resolved[canonicalKey(string(f.Gate), f.Identifier)] {
			continue
		}
		f.Fix = &findings.SuggestedFix{Description: desc, Version: a.Recommendation.Version}
		n++
	}
	return n
}

// canonicalKey mirrors Finding.key so a findings.Finding (gate, identifier) can
// be matched against the advisor's resolved set without constructing an
// intermediate Finding.
func canonicalKey(gate, id string) string { return gate + "\x00" + id }
