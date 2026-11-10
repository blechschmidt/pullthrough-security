package remediation

import (
	"fmt"
	"strings"
)

// Table renders advice as a compact, human-first plain-text report suitable for
// a terminal (ptctl) or a log. It leads with the verdict and the one-line fix,
// then tabulates the evaluated upgrade ladder.
func (a *Advice) Table() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Remediation advice: %s\n", a.Coordinate)
	fmt.Fprintf(&b, "Status: %s\n", a.Status)
	if len(a.FailingGates) > 0 {
		fmt.Fprintf(&b, "Failing gates: %s\n", gateList(a.FailingGates))
	}
	if a.Summary != "" {
		fmt.Fprintf(&b, "%s\n", a.Summary)
	}
	b.WriteByte('\n')

	if rec := a.Recommendation; rec != nil {
		fmt.Fprintf(&b, "Suggested fix: upgrade to %s\n", rec.Version)
		if len(rec.ResolvedFindings) > 0 {
			fmt.Fprintf(&b, "  resolves:   %s\n", strings.Join(findingLabels(rec.ResolvedFindings), ", "))
		}
		if len(rec.ResidualFindings) > 0 {
			fmt.Fprintf(&b, "  residual:   %s\n", strings.Join(findingLabels(rec.ResidualFindings), ", "))
		}
		if len(rec.IntroducedFindings) > 0 {
			fmt.Fprintf(&b, "  introduces: %s\n", strings.Join(findingLabels(rec.IntroducedFindings), ", "))
		}
		b.WriteByte('\n')
	}

	if len(a.CurrentFindings) > 0 {
		fmt.Fprintf(&b, "Current findings on %s:\n", a.CurrentVersion)
		for _, f := range a.CurrentFindings {
			fmt.Fprintf(&b, "  %s\n", findingLine(f))
		}
		b.WriteByte('\n')
	}

	if len(a.Candidates) > 0 {
		fmt.Fprintf(&b, "Evaluated upgrade ladder (%d version(s)):\n", a.VersionsConsidered)
		fmt.Fprintf(&b, "  %-18s %-6s %-9s %-8s %s\n", "VERSION", "SAFE", "BLOCKING", "TOTAL", "RESOLVES")
		for _, c := range a.Candidates {
			safe := "no"
			if c.Safe {
				safe = "yes"
			}
			resolves := "-"
			if len(c.Resolved) > 0 {
				resolves = strings.Join(findingLabels(c.Resolved), ", ")
			}
			fmt.Fprintf(&b, "  %-18s %-6s %-9d %-8d %s\n", trunc(c.Version, 18), safe, c.Blocking, c.Total, resolves)
		}
	}
	return b.String()
}

// findingLabels renders each finding as a short "gate:ID" label.
func findingLabels(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		id := f.ID
		if id == "" {
			id = f.Title
		}
		out = append(out, fmt.Sprintf("%s:%s", f.Gate, id))
	}
	return out
}

// findingLine renders one finding with its severity and title for a detail list.
func findingLine(f Finding) string {
	var b strings.Builder
	block := " "
	if f.Blocking {
		block = "✗"
	}
	fmt.Fprintf(&b, "[%s] %s %s", block, f.Gate, f.ID)
	if f.Severity != "" {
		fmt.Fprintf(&b, " (%s)", f.Severity)
	}
	if f.Title != "" {
		fmt.Fprintf(&b, " — %s", f.Title)
	}
	return b.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
