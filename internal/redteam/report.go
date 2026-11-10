package redteam

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// JSON renders the coverage matrix as indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Markdown renders the coverage matrix as a Markdown report suitable for a CI
// summary or a PR comment: a header line, a one-row-per-scenario table, and a
// failures section when any scenario did not meet its assertion.
func (r *Report) Markdown() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Supply-chain red-team gate-efficacy report\n\n")
	fmt.Fprintf(&b, "_Generated: %s_\n\n", r.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"))

	status := "✅ all scenarios passed"
	if r.Failed > 0 {
		status = fmt.Sprintf("❌ %d scenario(s) failed", r.Failed)
	}
	fmt.Fprintf(&b, "**%s** — %d total, %d passed, %d failed, %d regression(s).\n\n",
		status, r.Total, r.Passed, r.Failed, r.Regressions)

	fmt.Fprintln(&b, "| Result | Scenario | Category | Expected gate | Expectation | Outcome | Fired gate | Status |")
	fmt.Fprintln(&b, "|:------:|----------|----------|---------------|-------------|---------|------------|:------:|")
	for _, res := range r.Results {
		mark := "✅"
		if !res.Pass {
			mark = "❌"
		}
		expectation := "block"
		if !res.ExpectBlock {
			expectation = "admit"
		}
		fired := res.FiredGate
		if fired == "" {
			fired = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %d |\n",
			mark, res.Name, res.Category, res.ExpectedGate, expectation, res.Outcome, fired, res.Status)
	}

	if r.Failed > 0 {
		fmt.Fprintf(&b, "\n## Failures\n\n")
		for _, res := range r.Results {
			if res.Pass {
				continue
			}
			tag := ""
			if res.Regression {
				tag = " **[REGRESSION]**"
			}
			fmt.Fprintf(&b, "- **%s** (%s)%s: %s\n", res.Scenario, res.ExpectedGate, tag, res.Detail)
		}
	}
	return b.String()
}
