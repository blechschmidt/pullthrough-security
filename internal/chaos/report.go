package chaos

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JSON renders the report as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Markdown renders the resilience matrix as a GitHub-flavored Markdown document,
// grouped by dependency. It is the human-readable form of the documented
// resilience guarantees (docs/resilience.md embeds the same contract).
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Chaos / fault-injection resilience matrix\n\n")
	fmt.Fprintf(&b, "%d guarantees — %d upheld, %d violated.\n\n", r.Total, r.Passed, r.Failed)

	// Group results by dependency, preserving a stable dependency order.
	order := []string{DepUpstream, DepStorage, DepScanner}
	byDep := map[string][]Result{}
	for _, res := range r.Results {
		byDep[res.Dependency] = append(byDep[res.Dependency], res)
	}
	// Append any dependencies not in the canonical order (future-proofing).
	for dep := range byDep {
		if !contains(order, dep) {
			order = append(order, dep)
		}
	}

	for _, dep := range order {
		results := byDep[dep]
		if len(results) == 0 {
			continue
		}
		sort.SliceStable(results, func(i, j int) bool { return results[i].ID < results[j].ID })
		fmt.Fprintf(&b, "## Dependency: %s\n\n", dep)
		fmt.Fprintf(&b, "| ID | Degraded condition | Expected behavior | Mechanism | Status |\n")
		fmt.Fprintf(&b, "| -- | ------------------ | ----------------- | --------- | ------ |\n")
		for _, res := range results {
			status := "✅ upheld"
			if !res.Pass {
				status = "❌ VIOLATED: " + res.Detail
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				res.ID, res.Condition, res.Expectation, res.Mechanism, status)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
