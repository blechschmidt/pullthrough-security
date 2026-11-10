package simreplay

import (
	"fmt"
	"strings"
)

// Markdown renders the diff report as an operator-readable Markdown document: a
// headline summary, the admit/block and risk-band movements, a per-tenant blast-
// radius table, and (when records are included) the changed records. It is the
// human-facing complement to the JSON form returned by the CLI and admin API.
func (r DiffReport) Markdown() string {
	var b strings.Builder
	s := r.Summary

	fmt.Fprintf(&b, "# Policy & risk what-if simulation\n\n")
	fmt.Fprintf(&b, "_Generated %s — replayed %d captured pull(s)._\n\n",
		r.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"), s.Total)

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Count |\n|---|---:|\n")
	fmt.Fprintf(&b, "| Replayed pulls | %d |\n", s.Total)
	fmt.Fprintf(&b, "| Outcome changed | %d |\n", s.Changed)
	fmt.Fprintf(&b, "| Admit→Block (newly blocked) | %d |\n", s.NowBlocked)
	fmt.Fprintf(&b, "| Block→Admit (newly admitted) | %d |\n", s.NowAdmitted)
	fmt.Fprintf(&b, "| Risk band shifts (up / down) | %d / %d |\n", s.BandUp, s.BandDown)
	fmt.Fprintf(&b, "| New policy violations | %d |\n", s.NewViolations)
	fmt.Fprintf(&b, "| Blocked baseline → candidate | %d → %d |\n", s.BaselineBlocked, s.CandidateBlocked)
	b.WriteString("\n")

	if s.Total > 0 && s.Changed == 0 {
		b.WriteString("✅ The candidate configuration produces no admission changes on the captured traffic.\n\n")
	} else if s.NowBlocked > 0 {
		fmt.Fprintf(&b, "⚠️ The candidate would newly **block %d** previously-admitted pull(s). Review the blast radius below before rolling out.\n\n", s.NowBlocked)
	}

	// Per-tenant blast radius.
	if len(r.Tenants) > 0 {
		fmt.Fprintf(&b, "## Per-tenant blast radius\n\n")
		fmt.Fprintf(&b, "| Tenant | Pulls | Changed | Newly blocked | Newly admitted | Band shifts | New violations | Blast radius |\n")
		fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, t := range r.Tenants {
			name := t.Tenant
			if name == "" {
				name = "(anonymous)"
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %.1f%% |\n",
				name, t.Total, t.Changed, t.NowBlocked, t.NowAdmitted,
				t.BandShifts, t.NewViolations, t.BlastRadius*100)
		}
		b.WriteString("\n")
	}

	// Changed records, when included.
	if len(r.Records) > 0 {
		changed := make([]RecordDiff, 0, len(r.Records))
		for _, d := range r.Records {
			if d.Changed {
				changed = append(changed, d)
			}
		}
		if len(changed) > 0 {
			fmt.Fprintf(&b, "## Changed records (%d)\n\n", len(changed))
			fmt.Fprintf(&b, "| Seq | Tenant | Coordinate | Change | Risk (base→cand) | New deny rules |\n")
			fmt.Fprintf(&b, "|---:|---|---|---|---|---|\n")
			for _, d := range changed {
				fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s |\n",
					d.Seq, orDash(d.Tenant), orDash(d.Coordinate),
					changeLabel(d), riskCol(d), orDash(strings.Join(d.NewDenyRules, ", ")))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func changeLabel(d RecordDiff) string {
	var parts []string
	switch d.Flip {
	case FlipNowBlocked:
		parts = append(parts, "🚫 now-blocked")
	case FlipNowAdmitted:
		parts = append(parts, "✅ now-admitted")
	}
	switch d.BandShift {
	case ShiftUp:
		parts = append(parts, "▲ band up")
	case ShiftDown:
		parts = append(parts, "▼ band down")
	}
	if len(parts) == 0 {
		if len(d.NewDenyRules) > 0 {
			return "new rule match"
		}
		return "changed"
	}
	return strings.Join(parts, ", ")
}

func riskCol(d RecordDiff) string {
	if !d.Baseline.RiskEnabled && !d.Candidate.RiskEnabled {
		return "—"
	}
	return fmt.Sprintf("%d (%s) → %d (%s)",
		d.Baseline.RiskScore, orDash(string(d.Baseline.RiskBand)),
		d.Candidate.RiskScore, orDash(string(d.Candidate.RiskBand)))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
