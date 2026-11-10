package compliance

import (
	"strconv"
	"strings"
	"time"
)

// Markdown renders the scorecard as a self-contained Markdown compliance report
// suitable for pasting into an audit ticket or exporting as a document.
func (card Scorecard) Markdown() string {
	var b strings.Builder
	b.WriteString("# Compliance Scorecard\n\n")
	if card.Version != "" {
		b.WriteString("**Proxy version:** `" + card.Version + "`  \n")
	}
	b.WriteString("**Generated:** " + card.GeneratedAt.Format(time.RFC3339) + "  \n")
	b.WriteString("**Overall:** " + grademoji(card.Status) + " " + strings.ToUpper(string(card.Status)) +
		" — score " + pct(card.Score) + " (grade " + card.Grade + ")  \n")
	b.WriteString("**SLSA (estimated):** " + card.SLSA.Track + " — " + card.SLSA.Rationale + "\n\n")

	b.WriteString("**Summary:** " +
		strconv.Itoa(card.Summary.Pass) + " pass, " +
		strconv.Itoa(card.Summary.Warn) + " warn, " +
		strconv.Itoa(card.Summary.Fail) + " fail, " +
		strconv.Itoa(card.Summary.NA) + " n/a\n\n")

	b.WriteString("## Controls\n\n")
	b.WriteString("| Status | Control | Score | Frameworks | Detail |\n")
	b.WriteString("|--------|---------|-------|------------|--------|\n")
	for _, c := range card.Controls {
		score := "—"
		if c.Status != StatusNA {
			score = pct(c.Score)
		}
		b.WriteString("| " + statusmoji(c.Status) + " " + string(c.Status) +
			" | " + mdEscape(c.Title) +
			" | " + score +
			" | " + mdEscape(strings.Join(c.Frameworks, ", ")) +
			" | " + mdEscape(c.Detail) + " |\n")
	}

	b.WriteString("\n## Raw posture\n\n")
	b.WriteString("Signals captured at " + card.Posture.CapturedAt.Format(time.RFC3339) + ".\n\n")
	b.WriteString("- Signatures: verified " + itoa64(card.Posture.SigVerified) +
		", unsigned " + itoa64(card.Posture.SigUnsigned) +
		", blocked " + itoa64(card.Posture.SigBlocked) + "\n")
	b.WriteString("- Provenance: " + itoa64(card.Posture.ArtifactsWithProvenance) +
		"/" + itoa64(card.Posture.ArtifactsTotal) + " artifacts with a source commit\n")
	b.WriteString("- Vulnerabilities: scans " + itoa64(card.Posture.VulnScans) +
		", blocked " + itoa64(card.Posture.VulnBlocked) +
		", quarantined " + itoa64(card.Posture.VulnQuarantined) +
		" (critical " + itoa64(card.Posture.VulnCritical) +
		", high " + itoa64(card.Posture.VulnHigh) + ")\n")
	b.WriteString("- License: allowed " + itoa64(card.Posture.LicenseAllowed) +
		"/" + itoa64(card.Posture.LicenseEvaluated) +
		", denied " + itoa64(card.Posture.LicenseDenied) + "\n")
	b.WriteString("- Secrets: findings " + itoa64(card.Posture.SecretsFindings) +
		" across " + itoa64(card.Posture.SecretsDiffsScanned) + " scanned diffs\n")
	b.WriteString("- Air-gap: sealed=" + strconv.FormatBool(card.Posture.Sealed) + "\n")
	b.WriteString("- Audit: transparency=" + strconv.FormatBool(card.Posture.AuditTransparency) +
		", verificationFailures=" + itoa64(card.Posture.AuditVerificationFailures) + "\n")

	b.WriteString("\n_This scorecard is a self-assessment derived from observed proxy telemetry; the SLSA build level is estimated, not asserted by an external verifier._\n")
	return b.String()
}

// pct renders a 0..1 ratio as a one-decimal percentage.
func pct(v float64) string {
	return strconv.FormatFloat(v*100, 'f', 1, 64) + "%"
}

// statusmoji returns a glyph for a control status.
func statusmoji(s Status) string {
	switch s {
	case StatusPass:
		return "✅"
	case StatusWarn:
		return "⚠️"
	case StatusFail:
		return "❌"
	default:
		return "➖"
	}
}

// grademoji returns a glyph for the overall rollup status.
func grademoji(s Status) string { return statusmoji(s) }

// mdEscape neutralizes the pipe character so a detail string cannot break the
// Markdown table layout.
func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }
