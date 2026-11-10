package grpcapi

import "github.com/blechschmidt/pullthrough-security/internal/findings"

// severityRank orders canonical severities worst-first for worstSeverity.
var severityRank = map[findings.Severity]int{
	findings.SeverityCritical: 5,
	findings.SeverityHigh:     4,
	findings.SeverityMedium:   3,
	findings.SeverityLow:      2,
	findings.SeverityInfo:     1,
	findings.SeverityNone:     0,
}

// countBlocking counts the non-suppressed error-level findings — the signal a CI
// gate uses to fail a build.
func countBlocking(doc findings.Document) int {
	n := 0
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if !f.Suppressed && f.Level == findings.LevelError {
			n++
		}
	}
	return n
}

// worstSeverity returns the highest-ranked severity across the non-suppressed
// findings, or "" when there are none.
func worstSeverity(doc findings.Document) string {
	worst := ""
	worstRank := -1
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if f.Suppressed {
			continue
		}
		if r, ok := severityRank[f.Severity]; ok && r > worstRank {
			worstRank = r
			worst = string(f.Severity)
		}
	}
	return worst
}

// gatesOf returns the distinct originating gates across the findings, in
// first-seen order so the output is deterministic for a given document.
func gatesOf(doc findings.Document) []string {
	seen := map[string]bool{}
	var out []string
	for i := range doc.Findings {
		g := string(doc.Findings[i].Gate)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}
