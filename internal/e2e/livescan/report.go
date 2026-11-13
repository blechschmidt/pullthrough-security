//go:build integration || livellm

package livescan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Report file names.
const (
	reportJSON     = "live-llm-scan-report.json"
	reportMarkdown = "live-llm-scan-report.md"
)

// write stores the report as JSON and Markdown in dir.
func (r *Report) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, reportJSON), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, reportMarkdown), []byte(r.Markdown()), 0o644)
}

// cell makes text safe for a Markdown table cell. Model output and package
// content are untrusted: no markup, no line breaks, bounded length.
func cell(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	s = capText(s, n)
	r := strings.NewReplacer("|", "\\|", "<", "&lt;", ">", "&gt;", "`", "'", "[", "\\[", "]", "\\]", "*", "\\*", "_", "\\_")
	return r.Replace(s)
}

func passMark(ok bool) string {
	if ok {
		return "pass"
	}
	return "**FAIL**"
}

// Markdown renders the report.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Known-malware LLM scan — live run\n\n")
	fmt.Fprintf(&b, "Model: %s. Run: %s – %s (%s).", cell(r.Model, 200),
		r.Started.Format(time.RFC3339), r.Finished.Format(time.RFC3339), r.Finished.Sub(r.Started).Round(time.Second))
	if r.Partial {
		b.WriteString(" Partial run: restricted to some samples.")
	}
	b.WriteString("\n\n")

	pass, total := 0, 0
	for _, p := range r.Packages {
		total++
		if p.Pass {
			pass++
		}
	}
	for _, c := range r.Commits {
		total++
		if c.Pass {
			pass++
		}
	}
	fmt.Fprintf(&b, "%d of %d checks met their expectation.\n\n", pass, total)

	if len(r.Packages) > 0 {
		b.WriteString("## Packages (LLM package-content scan)\n\n")
		b.WriteString("Malicious releases must be refused (403, `llm-package-malicious`); the last clean release of the same package must be served unchanged.\n\n")
		detected, blocked, other := 0, 0, 0
		for _, p := range r.Packages {
			if p.Variant != Malicious {
				continue
			}
			switch p.Outcome {
			case OutcomeDetected:
				detected++
			case OutcomeNoVerdict:
				blocked++
			default:
				other++
			}
		}
		fmt.Fprintf(&b, "Of the malicious releases, %d were refused on the model's malicious verdict, %d were blocked without a verdict (the provider declined to judge them; only `failMode: closed` stopped them) and %d were not blocked as expected.\n\n", detected, blocked, other)
		b.WriteString("| Sample | Variant | Artifact | Pull | Verdict | Confidence | Result |\n|---|---|---|---|---|---|---|\n")
		for _, p := range r.Packages {
			pullCell := fmt.Sprintf("%d", p.Status)
			if p.PolicyCode != "" {
				pullCell += " " + p.PolicyCode
			}
			if p.ScanCode != "" {
				pullCell += " (" + p.ScanCode + ")"
			}
			if rp := p.Repull; rp != nil {
				pullCell += fmt.Sprintf("; again %d", rp.Status)
				if rp.ModelCalls == 0 {
					pullCell += ", no model call"
				}
			}
			if p.PullError != "" {
				pullCell = "error"
			}
			result := passMark(p.Pass)
			if p.Pass && p.Outcome == OutcomeNoVerdict {
				result = "pass (blocked, no verdict)"
			}
			confidence := fmt.Sprintf("%.2f", p.Confidence)
			if p.ConfidenceUnstated {
				confidence += " (unstated)"
			}
			fmt.Fprintf(&b, "| %s | %s | %s %s@%s | %s | %s | %s | %s |\n",
				cell(p.Sample, 60), p.Variant, cell(p.Kind, 20), cell(p.Name, 60), cell(p.Version, 30),
				cell(pullCell, 60), cell(p.Verdict, 20), confidence, result)
		}
		b.WriteString("\n")
	}
	if len(r.Commits) > 0 {
		b.WriteString("## Commits (LLM commit scan)\n\n")
		b.WriteString("The attacker's commit must be judged malicious; the ordinary change before it must not.\n\n")
		b.WriteString("| Sample | Variant | Commit | Malicious | Risk | Deep stage | Result |\n|---|---|---|---|---|---|---|\n")
		for _, c := range r.Commits {
			fmt.Fprintf(&b, "| %s | %s | %.12s | %v | %d | %s | %s |\n", cell(c.Sample, 60), c.Variant, c.SHA, c.Malicious, c.RiskScore,
				cell(c.DeepStage, 20), passMark(c.Pass))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Why: the model's reasons\n\n")
	b.WriteString("Model output, shown as inert text. Citations marked ✓ were found verbatim in the named file by the proxy.\n\n")
	for _, p := range r.Packages {
		fmt.Fprintf(&b, "### %s — %s (%s)\n\n", cell(p.Sample, 80), p.Variant, cell(p.Verdict, 20))
		for _, pr := range p.Problems {
			fmt.Fprintf(&b, "- problem: %s\n", cell(pr, 400))
		}
		for _, n := range p.Notes {
			fmt.Fprintf(&b, "- note: %s\n", cell(n, 400))
		}
		for _, reason := range p.Reasons {
			fmt.Fprintf(&b, "- %s\n", cell(reason, 400))
		}
		for _, ev := range p.Evidence {
			mark := "✗"
			if ev.Verified {
				mark = "✓"
			}
			fmt.Fprintf(&b, "  - %s %s:%d — %s\n", mark, cell(ev.Path, 120), ev.Line, cell(ev.Excerpt, 200))
		}
		if p.Truncated {
			fmt.Fprintf(&b, "- coverage: %s\n", cell(strings.Join(p.Coverage, " "), 400))
		}
		b.WriteString("\n")
	}
	for _, c := range r.Commits {
		fmt.Fprintf(&b, "### %s — %s commit (malicious: %v, risk %d)\n\n", cell(c.Sample, 80), c.Variant, c.Malicious, c.RiskScore)
		for _, pr := range c.Problems {
			fmt.Fprintf(&b, "- problem: %s\n", cell(pr, 400))
		}
		for _, n := range c.Notes {
			fmt.Fprintf(&b, "- note: %s\n", cell(n, 400))
		}
		if c.Rationale != "" {
			fmt.Fprintf(&b, "- %s\n", cell(c.Rationale, 600))
		}
		for _, f := range c.Findings {
			fmt.Fprintf(&b, "  - %s/%s: %s (%s:%d)\n", cell(f.Category, 40), cell(f.Severity, 20), cell(f.Title, 200), cell(f.File, 120), f.Line)
		}
		b.WriteString("\n")
	}

	if len(r.Calls) > 0 {
		in, out := 0, 0
		var cost float64
		var longest time.Duration
		for _, c := range r.Calls {
			in += c.InputTokens + c.CacheReadTokens + c.CacheCreationTokens
			out += c.OutputTokens
			cost += c.CostUSD
			if c.Duration > longest {
				longest = c.Duration
			}
		}
		b.WriteString("## Model calls (Claude Code bridge)\n\n")
		fmt.Fprintf(&b, "%d calls, %d input and %d output tokens, longest %s; list-price equivalent USD %.2f.\n\n",
			len(r.Calls), in, out, longest.Round(time.Second), cost)
		b.WriteString("| # | Scan | Model | Prompt bytes | Status | Tokens in/out | Time | Tools in session |\n|---|---|---|---|---|---|---|---|\n")
		for _, c := range r.Calls {
			fmt.Fprintf(&b, "| %d | %s | %s | %d | %d %s | %d/%d | %s | %d |\n", c.Seq, c.Kind, cell(c.Model, 40),
				c.SystemBytes+c.UserBytes, c.Status, cell(c.Outcome, 80), c.InputTokens+c.CacheReadTokens+c.CacheCreationTokens,
				c.OutputTokens, c.Duration.Round(time.Second), len(c.Tools)+len(c.MCPServers))
		}
		b.WriteString("\n")
	}
	return b.String()
}
