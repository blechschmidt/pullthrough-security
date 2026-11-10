package commit

import (
	"fmt"
	"strconv"
	"time"
)

// SecretFinding is a deterministic secret/credential detection contributed by a
// SecretScanner (Task 29). It is the offline, LLM-independent half of the commit
// scanning pipeline: a regex/entropy match scoped to a commit's added diff
// lines. Match is always redacted (the raw secret is never carried here).
type SecretFinding struct {
	// RuleID identifies the rule that fired (e.g. "aws-access-key-id").
	RuleID string
	// Description is a human-readable explanation of the detection.
	Description string
	// Severity is one of info|low|medium|high|critical.
	Severity string
	// File and Line locate the secret in the commit's diff.
	File string
	Line int
	// Match is the redacted secret.
	Match string
}

// SecretScanner runs a fast, deterministic secret-detection pass over a commit's
// added diff lines. It is independent of the LLM provider, so it yields reliable,
// cheap coverage even when the provider is unavailable or disabled, and supplies
// ground-truth findings the LLM pass can corroborate.
//
// Implementations must be safe for concurrent use and must not return raw
// secrets (Match is redacted).
type SecretScanner interface {
	ScanCommit(c *Commit) []SecretFinding
}

// detectSecrets runs the configured deterministic secret scanner over the commit
// and converts its findings to pipeline Findings (category "secret"). It returns
// nil when no scanner is configured or nothing is found.
func (p *Pipeline) detectSecrets(commit *Commit) []Finding {
	if p.cfg.Secrets == nil {
		return nil
	}
	raw := p.cfg.Secrets.ScanCommit(commit)
	if len(raw) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(raw))
	for _, sf := range raw {
		title := sf.Description
		if title == "" {
			title = "Secret detected by rule " + sf.RuleID
		}
		detail := fmt.Sprintf("deterministic secret-detection rule %q matched", sf.RuleID)
		if sf.Match != "" {
			detail += " (redacted match: " + sf.Match + ")"
		}
		out = append(out, Finding{
			Category:   CategorySecret,
			Severity:   normalizeSeverity(sf.Severity),
			Title:      title,
			Detail:     detail,
			File:       sf.File,
			Line:       sf.Line,
			Confidence: 1, // deterministic match
		})
	}
	return out
}

// applySecretFindings merges deterministic secret findings into a verdict
// produced by the LLM pass and raises the risk score to the floor implied by the
// most severe secret, so a live credential drives the policy gate regardless of
// what the model scored. Deterministic findings are authoritative ground truth
// and are always retained; an LLM secret finding at the same location is dropped
// to avoid double-reporting.
func applySecretFindings(v *Verdict, secretFindings []Finding) {
	if len(secretFindings) == 0 {
		return
	}
	// Locations covered by deterministic findings; drop LLM "secret" findings
	// there so the same credential is not listed twice.
	covered := make(map[string]bool, len(secretFindings))
	for _, f := range secretFindings {
		covered[locationKey(f)] = true
	}
	kept := v.Findings[:0:0]
	for _, f := range v.Findings {
		if f.Category == CategorySecret && covered[locationKey(f)] {
			continue
		}
		kept = append(kept, f)
	}
	v.Findings = append(kept, secretFindings...)

	if floor := secretRiskFloor(secretFindings); floor > v.RiskScore {
		v.RiskScore = floor
	}
}

// deterministicVerdict builds the base verdict for the deterministic-only and
// degraded paths (no LLM provider, LLM failure, or budget exhaustion). The
// secret and injection findings themselves are merged in afterward by
// Pipeline.finalize, so this only carries the score floor, rationale, and
// provenance fields. errMsg, when non-empty, records the degradation so it is
// auditable.
func (p *Pipeline) deterministicVerdict(commit *Commit, detFindings []Finding, errMsg string) *Verdict {
	v := &Verdict{
		SHA:       commit.SHA,
		RiskScore: secretRiskFloor(detFindings),
		Provider:  p.providerName(),
		Models:    []string{"deterministic-scan"},
		ScannedAt: time.Now().UTC(),
		Error:     errMsg,
	}
	if len(detFindings) > 0 {
		v.Rationale = deterministicRationale(detFindings)
	} else {
		v.Rationale = "no deterministic findings"
	}
	v.sanitize()
	return v
}

// providerName returns the provider name, or "none" in deterministic-only mode.
func (p *Pipeline) providerName() string {
	if p.provider == nil {
		return "none"
	}
	return p.provider.Name()
}

// secretRiskFloor maps the most severe secret finding to a minimum risk score so
// the policy engine's BlockAtRiskScore/WarnAtRiskScore thresholds can act on
// deterministic detections. The floors are chosen so that, under the default
// policy (block at 75), a high- or critical-severity live secret blocks the
// associated artifact while medium/low only warn.
func secretRiskFloor(findings []Finding) int {
	best := 0
	for _, f := range findings {
		if r := severityRiskFloor(f.Severity); r > best {
			best = r
		}
	}
	return best
}

func severityRiskFloor(severity string) int {
	switch normalizeSeverity(severity) {
	case "critical":
		return 95
	case "high":
		return 80
	case "medium":
		return 55
	case "low":
		return 30
	default:
		return 10
	}
}

// deterministicRationale summarizes the deterministic findings for the verdict.
// The wording adapts to the finding category so a mixed secret/action-pinning
// set reads accurately.
func deterministicRationale(findings []Finding) string {
	if len(findings) == 1 {
		f := findings[0]
		loc := f.File
		if f.Line > 0 {
			loc += ":" + strconv.Itoa(f.Line)
		}
		prefix := "deterministic detection"
		if f.Category == CategorySecret {
			prefix = "deterministic secret detection"
		} else if f.Category == CategoryActionPinning {
			prefix = "GitHub Actions pinning"
		}
		if loc != "" {
			return fmt.Sprintf("%s: %s at %s", prefix, f.Title, loc)
		}
		return prefix + ": " + f.Title
	}
	return fmt.Sprintf("deterministic detection found %d finding(s) in the commit diff", len(findings))
}

// locationKey identifies a finding's location for de-duplication.
func locationKey(f Finding) string {
	return f.File + ":" + strconv.Itoa(f.Line)
}
