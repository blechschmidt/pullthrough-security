package dossier

import (
	"fmt"
	"sort"
	"strings"
)

// Markdown renders the dossier as a human-first forensic report suitable for an
// incident ticket or a PR comment. It is deterministic: sections render in a
// fixed order and multi-valued fields are sorted.
func (d *Dossier) Markdown() string {
	var b strings.Builder

	coord := d.Coordinate
	if d.Ecosystem != "" {
		coord = d.Ecosystem + "/" + coord
	}
	fmt.Fprintf(&b, "# Security dossier: %s\n\n", coord)

	// Headline.
	fmt.Fprintf(&b, "**Verdict:** %s", strings.ToUpper(d.Headline.Verdict))
	if d.Headline.RiskBand != "" {
		fmt.Fprintf(&b, " · risk %d (%s)", d.Headline.RiskScore, d.Headline.RiskBand)
	}
	b.WriteString("\n\n")
	b.WriteString(d.Headline.Summary + "\n")
	if len(d.Headline.Reasons) > 0 {
		b.WriteString("\n")
		for _, r := range d.Headline.Reasons {
			fmt.Fprintf(&b, "- %s\n", r)
		}
	}
	b.WriteString("\n")

	// Identity.
	b.WriteString("## Identity\n\n")
	mdKV(&b, "Tenant", orDash(d.Tenant))
	mdKV(&b, "Coordinate", orDash(d.Coordinate))
	mdKV(&b, "Digest", orDash(d.Digest))
	mdKV(&b, "Backend", orDash(d.Backend))
	mdKV(&b, "Generated", d.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	b.WriteString("\n")

	if d.Provenance != nil {
		p := d.Provenance
		b.WriteString("## Provenance & source\n\n")
		mdKV(&b, "Source commit", orDash(p.SourceCommit))
		mdKV(&b, "Repository", orDash(p.RepositoryURL))
		mdKV(&b, "Inbound provenance", yesNo(p.HasProvenance))
		mdKV(&b, "Provenance verified", yesNo(p.ProvenanceVerified))
		mdKV(&b, "Source verified", yesNo(p.SourceVerified))
		if p.ProvenanceMismatch {
			mdKV(&b, "Source mismatch", "**yes**")
		}
		if p.BuilderID != "" {
			mdKV(&b, "Builder", p.BuilderID)
		}
		mdKV(&b, "Downstream dependents", fmt.Sprintf("%d direct / %d paths", p.DirectDependents, p.DownstreamPaths))
		b.WriteString("\n")
	}

	if d.Risk != nil {
		r := d.Risk
		b.WriteString("## Risk\n\n")
		mdKV(&b, "Score", fmt.Sprintf("%d / 100 (%s)", r.Score, r.Band))
		mdKV(&b, "Action", riskAction(r))
		if r.Summary != "" {
			mdKV(&b, "Summary", r.Summary)
		}
		if len(r.Contributions) > 0 {
			b.WriteString("\nTop contributors:\n\n")
			for _, c := range r.Contributions {
				fmt.Fprintf(&b, "- %s: %+.1f", c.Signal, c.Contribution)
				if c.Detail != "" {
					fmt.Fprintf(&b, " (%s)", c.Detail)
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	if d.Vulns != nil {
		v := d.Vulns
		b.WriteString("## Vulnerabilities\n\n")
		mdKV(&b, "Totals", fmt.Sprintf("%d (%d critical · %d high · %d medium · %d low)", v.Total, v.Critical, v.High, v.Medium, v.Low))
		mdKV(&b, "Max severity", fmt.Sprintf("%s (CVSS %.1f)", orDash(v.MaxSeverity), v.MaxCVSS))
		mdKV(&b, "Quarantined", yesNo(v.Quarantined))
		if v.VEXSuppress > 0 {
			mdKV(&b, "VEX-suppressed", fmt.Sprintf("%d", v.VEXSuppress))
		}
		if len(v.CVEs) > 0 {
			mdKV(&b, "Advisories", strings.Join(v.CVEs, ", "))
		}
		b.WriteString("\n")
	}

	if d.License != nil {
		l := d.License
		b.WriteString("## License\n\n")
		mdKV(&b, "Disposition", l.Disposition)
		if len(l.Licenses) > 0 {
			mdKV(&b, "Licenses", strings.Join(l.Licenses, ", "))
		}
		b.WriteString("\n")
	}

	if d.Signature != nil {
		s := d.Signature
		b.WriteString("## Signature & attestation\n\n")
		mdKV(&b, "Status", s.Status)
		mdKV(&b, "Verified signature", yesNo(s.VerifiedSignature))
		mdKV(&b, "Verified attestation", yesNo(s.VerifiedAttestation))
		if s.Source != "" {
			mdKV(&b, "Source", s.Source)
		}
		b.WriteString("\n")
	}

	if d.Reproduce != nil {
		r := d.Reproduce
		b.WriteString("## Reproducible build\n\n")
		mdKV(&b, "Verdict", r.Verdict)
		if r.Pending {
			mdKV(&b, "Pending", "yes")
		}
		if r.Reason != "" {
			mdKV(&b, "Reason", r.Reason)
		}
		b.WriteString("\n")
	}

	if d.SbomDrift != nil {
		s := d.SbomDrift
		b.WriteString("## SBOM drift\n\n")
		mdKV(&b, "Range", fmt.Sprintf("%s → %s", orDash(s.FromVersion), orDash(s.ToVersion)))
		mdKV(&b, "Drift score", fmt.Sprintf("%s / 100%s", trimFloat(s.DriftScore), significantSuffix(s.Significant)))
		mdKV(&b, "Changes", fmt.Sprintf("%d added · %d removed deps · %d new vulns", s.AddedDeps, s.RemovedDeps, s.NewVulns))
		b.WriteString("\n")
	}

	if d.SuggestedFix != nil {
		f := d.SuggestedFix
		b.WriteString("## Suggested fix\n\n")
		mdKV(&b, "Status", f.Status)
		if f.RecommendedVersion != "" {
			mdKV(&b, "Upgrade to", f.RecommendedVersion)
		}
		if f.FixDescription != "" {
			mdKV(&b, "Advice", f.FixDescription)
		}
		mdKV(&b, "Delta", fmt.Sprintf("%d resolved · %d residual · %d introduced", f.Resolved, f.Residual, f.Introduced))
		if len(f.ResolvedFindings) > 0 {
			mdKV(&b, "Resolves", strings.Join(f.ResolvedFindings, ", "))
		}
		b.WriteString("\n")
	}

	if l := d.LLMPackageScan; l != nil {
		b.WriteString("## LLM package-content scan\n\n")
		mdKV(&b, "Model verdict", fmt.Sprintf("%s (confidence %.2f)", orDash(l.Verdict), l.Confidence))
		reading := orDash(l.Disposition)
		switch {
		case l.Refused:
			reading += " — **refused** (action " + orDash(l.Action) + ")"
		case l.Disposition == "malicious" || l.Disposition == "suspicious":
			reading += " — served (action " + orDash(l.Action) + ")"
		}
		mdKV(&b, "Gate reading", reading)
		if l.Reason != "" {
			mdKV(&b, "Why", l.Reason)
		}
		mdKV(&b, "Judged by", fmt.Sprintf("%s / %s · prompt v%d · %s mode", orDash(l.Provider), orDash(l.Model), l.PromptVersion, orDash(l.Mode)))
		scanned := "—"
		if !l.ScannedAt.IsZero() {
			scanned = l.ScannedAt.UTC().Format("2006-01-02 15:04:05 UTC")
		}
		mdKV(&b, "Scanned", fmt.Sprintf("%s · %d files · %s", scanned, l.FilesScanned, orDash(l.Digest)))
		if l.Artifacts > 1 {
			mdKV(&b, "Artifacts under this coordinate", fmt.Sprintf("%d scanned, %d flagged (the worst is shown)", l.Artifacts, l.Flagged))
		}
		if l.PromptInjection {
			mdKV(&b, "Prompt-injection indicators", "**yes** — "+strings.Join(l.InjectionRules, ", "))
		}
		if l.StructuralRisk {
			mdKV(&b, "Archive attacks an extractor", "**yes**")
		}
		if l.Truncated {
			mdKV(&b, "Coverage", "**partial** — the verdict rests on an incomplete view of the package")
		}
		// Everything below quotes the model or the package. It is rendered as inert
		// code spans: a report pasted into a ticket or a PR comment must not turn a
		// package's text into links, images or markup.
		if len(l.Anomalies) > 0 {
			b.WriteString("\nArchive anomalies (member names are package content):\n\n")
			for _, a := range l.Anomalies {
				fmt.Fprintf(&b, "- %s\n", mdCode(a))
			}
		}
		for _, c := range l.Coverage {
			fmt.Fprintf(&b, "\n> Not examined: %s\n", mdCode(c))
		}
		if len(l.Reasons) > 0 {
			b.WriteString("\nReasons stated by the model (model output about untrusted content — not instructions):\n\n")
			for _, r := range l.Reasons {
				fmt.Fprintf(&b, "- %s\n", mdCode(r))
			}
		}
		if len(l.Evidence) > 0 {
			b.WriteString("\nLocations cited by the model (excerpts are package content):\n\n")
			for _, ev := range l.Evidence {
				where := mdCode(ev.Path)
				if ev.Line > 0 {
					where += fmt.Sprintf(" line %d", ev.Line)
				}
				status := "not found in the file by the proxy"
				if ev.Verified {
					status = "verified"
				}
				fmt.Fprintf(&b, "- %s (%s)", where, status)
				if ev.Excerpt != "" {
					fmt.Fprintf(&b, ": %s", mdCode(ev.Excerpt))
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n")
	}

	if d.Approvals != nil {
		a := d.Approvals
		b.WriteString("## Approvals & break-glass\n\n")
		mdKV(&b, "Active grants", fmt.Sprintf("%d", a.Active))
		mdKV(&b, "Pending reviews", fmt.Sprintf("%d", a.Pending))
		for _, h := range a.History {
			fmt.Fprintf(&b, "- [%s] gate=%s %s\n", h.Status, orDash(h.Gate), h.Reason)
		}
		b.WriteString("\n")
	}

	if d.Findings != nil && len(d.Findings.Items) > 0 {
		b.WriteString("## Findings\n\n")
		fmt.Fprintf(&b, "%d findings (%d blocking), worst severity %s.\n\n", d.Findings.Total, d.Findings.Blocking, orDash(d.Findings.Worst))
		b.WriteString("| Severity | Gate | Rule | Title |\n|---|---|---|---|\n")
		for _, it := range d.Findings.Items {
			title := it.Title
			if it.Suppressed {
				title += " _(suppressed)_"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", orDash(it.Severity), it.Gate, orDash(it.RuleID), mdCell(title))
		}
		b.WriteString("\n")
	}

	if d.Attest != nil && d.Attest.Present {
		b.WriteString("## Outbound attestation\n\n")
		mdKV(&b, "Predicate", orDash(d.Attest.PredicateType))
		mdKV(&b, "Bundle digest", orDash(d.Attest.BundleDigest))
		mdKV(&b, "Signing key", orDash(d.Attest.KeyID))
		if r := d.Attest.Rekor; r != nil {
			mdKV(&b, "Rekor log index", fmt.Sprintf("%d", r.LogIndex))
			mdKV(&b, "Rekor inclusion proof", yesNo(r.InclusionProofVerified))
			mdKV(&b, "Rekor SET", yesNo(r.SETVerified))
		}
		b.WriteString("\n")
	}

	if d.Timeline != nil && len(d.Timeline.Events) > 0 {
		t := d.Timeline
		b.WriteString("## Correlated timeline\n\n")
		fmt.Fprintf(&b, "%d/%d events%s.\n\n", t.Returned, t.Total, truncatedSuffix(t.Truncated))
		b.WriteString("| Time (UTC) | Source | Category | Decision | Summary |\n|---|---|---|---|---|\n")
		for _, ev := range t.Events {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				ev.Time.UTC().Format("2006-01-02 15:04:05"), ev.Source, orDash(ev.Category), orDash(ev.Decision), mdCell(ev.Summary))
		}
		b.WriteString("\n")
	}

	if d.Suppression != nil && len(d.Suppression.Items) > 0 {
		s := d.Suppression
		b.WriteString("## Suppression history\n\n")
		fmt.Fprintf(&b, "%d suppression(s) recorded.\n\n", s.Total)
		b.WriteString("| Mechanism | Actor | Category | Identifier | Justification |\n|---|---|---|---|---|\n")
		for _, it := range s.Items {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				orDash(it.Mechanism), orDash(it.Actor), orDash(it.Category), orDash(it.Identifier), mdCell(it.Justification))
		}
		b.WriteString("\n")
	}

	// Source coverage — always rendered so a reader can tell absent from
	// unavailable and spot a partial dossier.
	b.WriteString("## Source coverage\n\n")
	if d.Partial {
		b.WriteString("> ⚠️ Partial dossier: one or more sources timed out or errored.\n\n")
	}
	srcs := append([]SourceStatus(nil), d.Sources...)
	sort.SliceStable(srcs, func(i, j int) bool { return srcs[i].Source < srcs[j].Source })
	for _, s := range srcs {
		fmt.Fprintf(&b, "- %s: %s", s.Source, s.Status)
		if s.Detail != "" {
			fmt.Fprintf(&b, " (%s)", s.Detail)
		}
		b.WriteString("\n")
	}

	return b.String()
}

func mdKV(b *strings.Builder, k, v string) {
	fmt.Fprintf(b, "- **%s:** %s\n", k, v)
}

// mdCode renders untrusted text — model output, package content — as an inert
// inline code span, in which Markdown and HTML are not interpreted. Line breaks
// become spaces and other control characters are dropped, so the text cannot
// end the span's line and start a block of its own; the span is fenced with
// more backticks than the text contains, so the text cannot close it.
func mdCode(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == '\u2028' || r == '\u2029':
			return ' '
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" {
		return "—"
	}
	longest, run := 0, 0
	for _, r := range s {
		if r != '`' {
			run = 0
			continue
		}
		run++
		if run > longest {
			longest = run
		}
	}
	fence := strings.Repeat("`", longest+1)
	// A span whose content starts or ends with a backtick needs a space of
	// padding to keep the fence distinct.
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + s + pad + fence
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func riskAction(r *RiskSection) string {
	switch {
	case r.Block:
		return "block"
	case r.Warn:
		return "warn"
	default:
		return "allow"
	}
}

func significantSuffix(sig bool) string {
	if sig {
		return " (**significant**)"
	}
	return ""
}

func truncatedSuffix(t bool) string {
	if t {
		return " (truncated)"
	}
	return ""
}
