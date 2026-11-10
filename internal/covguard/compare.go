package covguard

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Policy configures when a coverage comparison counts as a regression.
type Policy struct {
	// AllowedTotalDropPct is how far total (module-wide) coverage may fall below
	// the baseline, in percentage points, before the gate fails. A drop of
	// exactly this amount is tolerated; more fails. Expressed in points (e.g.
	// 1.0 means total may slip from 78.0% to 77.0% but not to 76.9%).
	AllowedTotalDropPct float64 `json:"allowedTotalDropPct"`
	// AllowedPackageDropPct, if > 0, additionally fails the gate when any single
	// package's coverage drops by more than this many percentage points versus
	// the baseline. 0 disables the per-package drop gate (per-package drops are
	// still surfaced in the report, just not failed on).
	AllowedPackageDropPct float64 `json:"allowedPackageDropPct"`
	// CriticalFloors maps a package import path to a hard minimum coverage
	// percentage. A critical package whose current coverage is below its floor —
	// or which is missing from the run entirely — fails the gate. This is the
	// floor gate independent of the baseline, so a critical package cannot be
	// allowed to rot even if the baseline itself is low.
	CriticalFloors map[string]float64 `json:"criticalFloors,omitempty"`
}

// DefaultPolicy is a conservative starting point: total coverage may slip by at
// most one percentage point, there is no extra per-package drop gate, and no
// critical floors (the operator seeds those).
func DefaultPolicy() Policy {
	return Policy{AllowedTotalDropPct: 1.0}
}

// PackageDelta is the per-package comparison line.
type PackageDelta struct {
	Package string `json:"package"`
	// State is "changed", "new" (absent from baseline), or "removed" (absent
	// from the current run).
	State string `json:"state"`
	// Baseline and Current are the coverage percentages on each side (0 for the
	// side the package is missing from).
	Baseline float64 `json:"baselinePct"`
	Current  float64 `json:"currentPct"`
	// DeltaPct is Current - Baseline in percentage points (negative is a drop).
	DeltaPct float64 `json:"deltaPct"`
	// Covered/Total are the current-run statement counts (0 when removed).
	Covered int `json:"coveredStatements"`
	Total   int `json:"totalStatements"`
	// Critical is set when the package has a critical floor.
	Critical bool `json:"critical,omitempty"`
	// Floor is the critical floor that applied (only when Critical).
	Floor float64 `json:"floor,omitempty"`
	// FloorViolated is set when a critical package is below its floor or missing.
	FloorViolated bool `json:"floorViolated,omitempty"`
	// Regressed is set when this package independently fails the gate (a floor
	// violation or a per-package drop beyond AllowedPackageDropPct).
	Regressed bool `json:"regressed,omitempty"`
}

// TotalComparison is the module-wide total comparison.
type TotalComparison struct {
	Baseline   float64 `json:"baselinePct"`
	Current    float64 `json:"currentPct"`
	DeltaPct   float64 `json:"deltaPct"`
	AllowedPct float64 `json:"allowedDropPct"`
	Regressed  bool    `json:"regressed"`
}

// Report is the full result of comparing a current run against a baseline.
type Report struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	Policy      Policy          `json:"policy"`
	Baseline    BaselineMeta    `json:"baseline"`
	Total       TotalComparison `json:"total"`
	// Packages is every package across the union of both sides, sorted by
	// ascending delta (biggest drops first) then by name.
	Packages []PackageDelta `json:"packages"`
}

// BaselineMeta is the provenance of the baseline a report was compared against.
type BaselineMeta struct {
	CapturedAt time.Time `json:"capturedAt"`
	Tool       string    `json:"tool,omitempty"`
	Mode       string    `json:"mode,omitempty"`
}

// Compare evaluates a fresh run against a stored baseline under a policy.
func Compare(baseline, current *Baseline, policy Policy) Report {
	rep := Report{
		GeneratedAt: time.Now().UTC(),
		Policy:      policy,
		Baseline: BaselineMeta{
			CapturedAt: baseline.CapturedAt,
			Tool:       baseline.Tool,
			Mode:       baseline.Mode,
		},
	}

	// Total gate: current may fall at most AllowedTotalDropPct points below the
	// baseline total. A tiny epsilon absorbs float rounding at the boundary.
	delta := current.Total.Pct - baseline.Total.Pct
	rep.Total = TotalComparison{
		Baseline:   baseline.Total.Pct,
		Current:    current.Total.Pct,
		DeltaPct:   delta,
		AllowedPct: policy.AllowedTotalDropPct,
		Regressed:  delta < -policy.AllowedTotalDropPct-1e-9,
	}

	// Union of package names across both sides for a complete picture.
	names := map[string]struct{}{}
	for n := range baseline.Packages {
		names[n] = struct{}{}
	}
	for n := range current.Packages {
		names[n] = struct{}{}
	}

	for name := range names {
		base, inBase := baseline.Packages[name]
		cur, inCur := current.Packages[name]
		floor, isCritical := policy.CriticalFloors[name]

		pd := PackageDelta{Package: name, Critical: isCritical}
		if isCritical {
			pd.Floor = floor
		}
		switch {
		case inBase && !inCur:
			// A package that vanished from the run: its tests stopped running or
			// it was removed. For a critical package this is a floor violation; it
			// is always surfaced as "removed".
			pd.State = "removed"
			pd.Baseline = base.Pct
			pd.Current = 0
			pd.DeltaPct = -base.Pct
			if isCritical {
				pd.FloorViolated = true
				pd.Regressed = true
			}
		case !inBase && inCur:
			pd.State = "new"
			pd.Current = cur.Pct
			pd.Covered = cur.Covered
			pd.Total = cur.Total
			pd.DeltaPct = cur.Pct // relative to an implicit 0 baseline
		default:
			pd.State = "changed"
			pd.Baseline = base.Pct
			pd.Current = cur.Pct
			pd.Covered = cur.Covered
			pd.Total = cur.Total
			pd.DeltaPct = cur.Pct - base.Pct
			if policy.AllowedPackageDropPct > 0 && pd.DeltaPct < -policy.AllowedPackageDropPct-1e-9 {
				pd.Regressed = true
			}
		}

		// Critical floor check applies to whatever coverage the package has now
		// (0 when removed). It is independent of the baseline.
		if isCritical && pd.State != "removed" {
			if pd.Current < floor-1e-9 {
				pd.FloorViolated = true
				pd.Regressed = true
			}
		}

		rep.Packages = append(rep.Packages, pd)
	}

	// Biggest drops first (most negative delta), then alphabetical for stability.
	sort.Slice(rep.Packages, func(i, j int) bool {
		if rep.Packages[i].DeltaPct != rep.Packages[j].DeltaPct {
			return rep.Packages[i].DeltaPct < rep.Packages[j].DeltaPct
		}
		return rep.Packages[i].Package < rep.Packages[j].Package
	})
	return rep
}

// Regressed reports whether the run failed the gate on any axis.
func (r Report) Regressed() bool {
	if r.Total.Regressed {
		return true
	}
	for _, p := range r.Packages {
		if p.Regressed {
			return true
		}
	}
	return false
}

// FloorViolations returns the critical packages below their floor (or missing).
func (r Report) FloorViolations() []PackageDelta {
	var out []PackageDelta
	for _, p := range r.Packages {
		if p.FloorViolated {
			out = append(out, p)
		}
	}
	return out
}

// RegressionCount returns the number of distinct failures: the total gate (0 or
// 1) plus every package that independently failed.
func (r Report) RegressionCount() int {
	n := 0
	if r.Total.Regressed {
		n++
	}
	for _, p := range r.Packages {
		if p.Regressed {
			n++
		}
	}
	return n
}

// drops returns the package deltas that are genuine coverage drops (negative
// delta on a package present in both sides), biggest first, capped at limit.
func (r Report) drops(limit int) []PackageDelta {
	var out []PackageDelta
	for _, p := range r.Packages {
		if p.State == "changed" && p.DeltaPct < 0 {
			out = append(out, p)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Format renders a human-readable comparison report. top bounds the
// "biggest drops" and per-package table lengths (0 = unbounded).
func (r Report) Format(top int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Coverage regression report\n")
	fmt.Fprintf(&b, "  baseline:   captured %s", r.Baseline.CapturedAt.Format(time.RFC3339))
	if r.Baseline.Tool != "" {
		fmt.Fprintf(&b, " by %s", r.Baseline.Tool)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "  tolerance:  total may drop at most %s", pts(r.Policy.AllowedTotalDropPct))
	if r.Policy.AllowedPackageDropPct > 0 {
		fmt.Fprintf(&b, ", per-package at most %s", pts(r.Policy.AllowedPackageDropPct))
	}
	fmt.Fprintf(&b, "\n\n")

	totalMark := "✓"
	if r.Total.Regressed {
		totalMark = "✗"
	}
	fmt.Fprintf(&b, "  %s total coverage  %.1f%% -> %.1f%%  (%+.2f pts, limit -%s)%s\n",
		totalMark, r.Total.Baseline, r.Total.Current, r.Total.DeltaPct, pts(r.Total.AllowedPct),
		regressionMark(r.Total.Regressed))

	if fv := r.FloorViolations(); len(fv) > 0 {
		fmt.Fprintf(&b, "\n  Critical-package floor violations:\n")
		for _, p := range fv {
			if p.State == "removed" {
				fmt.Fprintf(&b, "    ✗ %-55s removed from run (floor %s)\n", p.Package, pct(p.Floor))
				continue
			}
			fmt.Fprintf(&b, "    ✗ %-55s %.1f%% < floor %s\n", p.Package, p.Current, pct(p.Floor))
		}
	}

	if drops := r.drops(top); len(drops) > 0 {
		fmt.Fprintf(&b, "\n  Biggest coverage drops:\n")
		for _, p := range drops {
			fmt.Fprintf(&b, "    %s %-55s %.1f%% -> %.1f%%  (%+.2f pts)%s\n",
				dropMark(p.Regressed), p.Package, p.Baseline, p.Current, p.DeltaPct, regressionMark(p.Regressed))
		}
	}

	// Full per-package table (already sorted biggest-drop first).
	fmt.Fprintf(&b, "\n  Per-package coverage:\n")
	rows := r.Packages
	if top > 0 && len(rows) > top && !r.Regressed() {
		// Keep the full table when there is a failure (operators want the detail);
		// otherwise cap it so a passing run stays scannable.
		rows = rows[:top]
	}
	for _, p := range rows {
		switch p.State {
		case "new":
			fmt.Fprintf(&b, "    + %-55s     new  %.1f%%\n", p.Package, p.Current)
		case "removed":
			fmt.Fprintf(&b, "    - %-55s removed  (was %.1f%%)\n", p.Package, p.Baseline)
		default:
			crit := ""
			if p.Critical {
				crit = "  [critical floor " + pct(p.Floor) + "]"
			}
			fmt.Fprintf(&b, "      %-55s %.1f%% -> %.1f%%  (%+.2f pts)%s%s\n",
				p.Package, p.Baseline, p.Current, p.DeltaPct, crit, regressionMark(p.Regressed))
		}
	}
	if top > 0 && len(r.Packages) > len(rows) {
		fmt.Fprintf(&b, "    … %d more package(s) (use -top 0 for the full table)\n", len(r.Packages)-len(rows))
	}

	fmt.Fprintf(&b, "\n")
	if r.Regressed() {
		fmt.Fprintf(&b, "RESULT: FAIL — %d coverage gate(s) failed\n", r.RegressionCount())
	} else {
		fmt.Fprintf(&b, "RESULT: PASS — coverage held within threshold\n")
	}
	return b.String()
}

// Markdown renders the report as a GitHub-flavored Markdown summary suitable for
// a PR comment or $GITHUB_STEP_SUMMARY. top bounds the drop/table rows.
func (r Report) Markdown(top int) string {
	var b strings.Builder
	result := "✅ PASS"
	if r.Regressed() {
		result = "❌ FAIL"
	}
	fmt.Fprintf(&b, "## Coverage guard: %s\n\n", result)
	fmt.Fprintf(&b, "**Total coverage:** %.1f%% → **%.1f%%** (%+.2f pts, limit −%s)\n\n",
		r.Total.Baseline, r.Total.Current, r.Total.DeltaPct, pts(r.Total.AllowedPct))

	if fv := r.FloorViolations(); len(fv) > 0 {
		fmt.Fprintf(&b, "### ❌ Critical-package floor violations\n\n")
		fmt.Fprintf(&b, "| Package | Coverage | Floor |\n|---|---:|---:|\n")
		for _, p := range fv {
			cur := fmt.Sprintf("%.1f%%", p.Current)
			if p.State == "removed" {
				cur = "removed"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", p.Package, cur, pct(p.Floor))
		}
		fmt.Fprintf(&b, "\n")
	}

	if drops := r.drops(top); len(drops) > 0 {
		fmt.Fprintf(&b, "### Biggest coverage drops\n\n")
		fmt.Fprintf(&b, "| Package | Baseline | Current | Δ |\n|---|---:|---:|---:|\n")
		for _, p := range drops {
			fmt.Fprintf(&b, "| `%s` | %.1f%% | %.1f%% | %+.2f |\n", p.Package, p.Baseline, p.Current, p.DeltaPct)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func regressionMark(regressed bool) string {
	if regressed {
		return "  <-- regression"
	}
	return ""
}

func dropMark(regressed bool) string {
	if regressed {
		return "✗"
	}
	return "·"
}

// pct formats a coverage percentage compactly (e.g. "80%" or "79.5%").
func pct(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

// pts formats a percentage-point tolerance (e.g. "1 pt" / "1.5 pts").
func pts(v float64) string {
	unit := "pts"
	if v == 1 {
		unit = "pt"
	}
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f %s", v, unit)
	}
	return fmt.Sprintf("%.1f %s", v, unit)
}
