package muttest

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BaselineSchemaVersion is the on-disk schema version of a committed mutation
// baseline. Bumped if the layout changes incompatibly so a stale file is
// rejected with a clear message rather than silently mis-compared. This mirrors
// internal/covguard's baseline-versioning convention.
const BaselineSchemaVersion = 1

// PackageScore is the mutation tally for one package (or the whole run).
type PackageScore struct {
	// Killed is the number of mutants the suite detected (tests failed).
	Killed int `json:"killed"`
	// Survived is the number of mutants the suite did not detect (tests passed).
	Survived int `json:"survived"`
	// Invalid is the number of mutants that did not compile (excluded from score).
	Invalid int `json:"invalid"`
	// Scored is Killed+Survived: the mutants that count toward the score.
	Scored int `json:"scored"`
	// Pct is the derived mutation score (Killed/Scored*100), recomputed on load
	// so a hand-edited percentage can never desync from the counts.
	Pct float64 `json:"scorePct"`
}

func (s *PackageScore) recompute() {
	s.Scored = s.Killed + s.Survived
	s.Pct = score(s.Killed, s.Scored)
}

// Baseline is a committed snapshot of per-package and total mutation scores,
// produced by `ptctl mutguard --update-baseline` and checked in at
// mutation/mutation-baseline.json. A later run is compared against it by the
// regression gate. It is the mutation-score analogue of covguard's coverage
// baseline (Task 117).
type Baseline struct {
	SchemaVersion int       `json:"schemaVersion"`
	CapturedAt    time.Time `json:"capturedAt"`
	Tool          string    `json:"tool,omitempty"`
	// Seed, MaxPerPackage and Operators record the run parameters so the baseline
	// is reproducible: comparing against it requires the same knobs.
	Seed          int64                   `json:"seed"`
	MaxPerPackage int                     `json:"maxPerPackage"`
	Operators     []string                `json:"operators"`
	Total         PackageScore            `json:"total"`
	Packages      map[string]PackageScore `json:"packages"`
	// CriticalFloors maps a package import path to a hard minimum mutation score;
	// a critical package below its floor (or missing) fails the gate regardless of
	// the baseline, so critical security logic cannot be allowed to rot.
	CriticalFloors map[string]float64 `json:"criticalFloors,omitempty"`
}

// FromRun builds a Baseline snapshot from an engine RunResult.
func FromRun(r *RunResult) *Baseline {
	b := &Baseline{
		SchemaVersion: BaselineSchemaVersion,
		CapturedAt:    time.Now().UTC(),
		Seed:          r.Seed,
		Operators:     append([]string(nil), r.Operators...),
		Packages:      map[string]PackageScore{},
	}
	sort.Strings(b.Operators)
	for _, pr := range r.Packages {
		ps := PackageScore{Killed: pr.Killed, Survived: pr.Survived, Invalid: pr.Invalid}
		ps.recompute()
		b.Packages[pr.Package] = ps
		b.Total.Killed += pr.Killed
		b.Total.Survived += pr.Survived
		b.Total.Invalid += pr.Invalid
	}
	b.Total.recompute()
	return b
}

// LoadBaseline reads and validates a baseline JSON file.
func LoadBaseline(pathname string) (*Baseline, error) {
	f, err := os.Open(pathname)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return DecodeBaseline(f)
}

// DecodeBaseline reads a baseline from r, validates its schema version, and
// recomputes derived percentages so a hand-edited file stays self-consistent.
func DecodeBaseline(r io.Reader) (*Baseline, error) {
	var b Baseline
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("decode baseline: %w", err)
	}
	if b.SchemaVersion != BaselineSchemaVersion {
		return nil, fmt.Errorf("mutation baseline schema version %d is not supported (this build expects %d); regenerate with --update-baseline",
			b.SchemaVersion, BaselineSchemaVersion)
	}
	if len(b.Packages) == 0 {
		return nil, fmt.Errorf("mutation baseline contains no packages")
	}
	b.Total.recompute()
	for name, ps := range b.Packages {
		ps.recompute()
		b.Packages[name] = ps
	}
	return &b, nil
}

// Save writes the baseline to path as indented JSON (atomic temp+rename), making
// parent directories as needed.
func (b *Baseline) Save(pathname string) error {
	if err := os.MkdirAll(filepath.Dir(pathname), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(pathname), ".mutation-baseline-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, pathname)
}

// PackageNames returns the sorted package keys of the baseline.
func (b *Baseline) PackageNames() []string {
	out := make([]string, 0, len(b.Packages))
	for k := range b.Packages {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Policy configures when a mutation-score comparison counts as a regression. It
// is the mutation-testing analogue of covguard.Policy.
type Policy struct {
	// AllowedTotalDropPct is how far the total mutation score may fall below the
	// baseline, in percentage points, before the gate fails.
	AllowedTotalDropPct float64 `json:"allowedTotalDropPct"`
	// AllowedPackageDropPct, if > 0, fails the gate when any single package's
	// score drops by more than this many points versus the baseline.
	AllowedPackageDropPct float64 `json:"allowedPackageDropPct"`
	// CriticalFloors maps a package import path to a hard minimum mutation score.
	CriticalFloors map[string]float64 `json:"criticalFloors,omitempty"`
}

// PackageDelta is the per-package comparison line.
type PackageDelta struct {
	Package       string  `json:"package"`
	State         string  `json:"state"` // "changed", "new", "removed"
	Baseline      float64 `json:"baselinePct"`
	Current       float64 `json:"currentPct"`
	DeltaPct      float64 `json:"deltaPct"`
	Killed        int     `json:"killed"`
	Scored        int     `json:"scored"`
	Critical      bool    `json:"critical,omitempty"`
	Floor         float64 `json:"floor,omitempty"`
	FloorViolated bool    `json:"floorViolated,omitempty"`
	Regressed     bool    `json:"regressed,omitempty"`
}

// TotalComparison is the run-wide total comparison.
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
	Packages    []PackageDelta  `json:"packages"`
	// Survivors lists the surviving mutants in the current run, for triage. It is
	// populated from the engine result, not the baseline.
	Survivors []MutantResult `json:"survivors,omitempty"`
}

// BaselineMeta is the provenance of the baseline a report was compared against.
type BaselineMeta struct {
	CapturedAt time.Time `json:"capturedAt"`
	Tool       string    `json:"tool,omitempty"`
	Seed       int64     `json:"seed"`
}

// Compare evaluates a fresh run against a stored baseline under a policy.
func Compare(baseline, current *Baseline, policy Policy) Report {
	rep := Report{
		GeneratedAt: time.Now().UTC(),
		Policy:      policy,
		Baseline:    BaselineMeta{CapturedAt: baseline.CapturedAt, Tool: baseline.Tool, Seed: baseline.Seed},
	}

	delta := current.Total.Pct - baseline.Total.Pct
	rep.Total = TotalComparison{
		Baseline:   baseline.Total.Pct,
		Current:    current.Total.Pct,
		DeltaPct:   delta,
		AllowedPct: policy.AllowedTotalDropPct,
		Regressed:  delta < -policy.AllowedTotalDropPct-1e-9,
	}

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
			pd.State = "removed"
			pd.Baseline = base.Pct
			pd.DeltaPct = -base.Pct
			if isCritical {
				pd.FloorViolated = true
				pd.Regressed = true
			}
		case !inBase && inCur:
			pd.State = "new"
			pd.Current = cur.Pct
			pd.Killed = cur.Killed
			pd.Scored = cur.Scored
			pd.DeltaPct = cur.Pct
		default:
			pd.State = "changed"
			pd.Baseline = base.Pct
			pd.Current = cur.Pct
			pd.Killed = cur.Killed
			pd.Scored = cur.Scored
			pd.DeltaPct = cur.Pct - base.Pct
			if policy.AllowedPackageDropPct > 0 && pd.DeltaPct < -policy.AllowedPackageDropPct-1e-9 {
				pd.Regressed = true
			}
		}

		if isCritical && pd.State != "removed" && pd.Current < floor-1e-9 {
			pd.FloorViolated = true
			pd.Regressed = true
		}
		rep.Packages = append(rep.Packages, pd)
	}

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

// RegressionCount returns the number of distinct failures.
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

// Format renders a human-readable comparison report.
func (r Report) Format(top int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Mutation-score regression report\n")
	fmt.Fprintf(&b, "  baseline:   captured %s", r.Baseline.CapturedAt.Format(time.RFC3339))
	if r.Baseline.Tool != "" {
		fmt.Fprintf(&b, " by %s", r.Baseline.Tool)
	}
	fmt.Fprintf(&b, " (seed %d)\n", r.Baseline.Seed)
	fmt.Fprintf(&b, "  tolerance:  total may drop at most %s", pts(r.Policy.AllowedTotalDropPct))
	if r.Policy.AllowedPackageDropPct > 0 {
		fmt.Fprintf(&b, ", per-package at most %s", pts(r.Policy.AllowedPackageDropPct))
	}
	fmt.Fprintf(&b, "\n\n")

	totalMark := "✓"
	if r.Total.Regressed {
		totalMark = "✗"
	}
	fmt.Fprintf(&b, "  %s total mutation score  %.1f%% -> %.1f%%  (%+.2f pts, limit -%s)%s\n",
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
		fmt.Fprintf(&b, "\n  Biggest score drops:\n")
		for _, p := range drops {
			fmt.Fprintf(&b, "    %s %-55s %.1f%% -> %.1f%%  (%+.2f pts)%s\n",
				dropMark(p.Regressed), p.Package, p.Baseline, p.Current, p.DeltaPct, regressionMark(p.Regressed))
		}
	}

	fmt.Fprintf(&b, "\n  Per-package mutation score:\n")
	rows := r.Packages
	if top > 0 && len(rows) > top && !r.Regressed() {
		rows = rows[:top]
	}
	for _, p := range rows {
		switch p.State {
		case "new":
			fmt.Fprintf(&b, "    + %-55s     new  %.1f%% (%d/%d killed)\n", p.Package, p.Current, p.Killed, p.Scored)
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
		fmt.Fprintf(&b, "    … %d more package(s) (use --top 0 for the full table)\n", len(r.Packages)-len(rows))
	}

	if len(r.Survivors) > 0 {
		fmt.Fprintf(&b, "\n  Surviving mutants (triage these — add equivalents to the ignore list):\n")
		shown := r.Survivors
		if top > 0 && len(shown) > top {
			shown = shown[:top]
		}
		for _, s := range shown {
			fmt.Fprintf(&b, "    · %s  (id %s)\n", s.Describe(), s.ID)
		}
		if top > 0 && len(r.Survivors) > len(shown) {
			fmt.Fprintf(&b, "    … %d more survivor(s)\n", len(r.Survivors)-len(shown))
		}
	}

	fmt.Fprintf(&b, "\n")
	if r.Regressed() {
		fmt.Fprintf(&b, "RESULT: FAIL — %d mutation gate(s) failed\n", r.RegressionCount())
	} else {
		fmt.Fprintf(&b, "RESULT: PASS — mutation score held within threshold\n")
	}
	return b.String()
}

// Markdown renders the report as a GitHub-flavored Markdown summary.
func (r Report) Markdown(top int) string {
	var b strings.Builder
	result := "✅ PASS"
	if r.Regressed() {
		result = "❌ FAIL"
	}
	fmt.Fprintf(&b, "## Mutation guard: %s\n\n", result)
	fmt.Fprintf(&b, "**Total mutation score:** %.1f%% → **%.1f%%** (%+.2f pts, limit −%s)\n\n",
		r.Total.Baseline, r.Total.Current, r.Total.DeltaPct, pts(r.Total.AllowedPct))

	if fv := r.FloorViolations(); len(fv) > 0 {
		fmt.Fprintf(&b, "### ❌ Critical-package floor violations\n\n")
		fmt.Fprintf(&b, "| Package | Score | Floor |\n|---|---:|---:|\n")
		for _, p := range fv {
			cur := fmt.Sprintf("%.1f%%", p.Current)
			if p.State == "removed" {
				cur = "removed"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", p.Package, cur, pct(p.Floor))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "### Per-package mutation score\n\n")
	fmt.Fprintf(&b, "| Package | Baseline | Current | Δ | Killed/Scored |\n|---|---:|---:|---:|---:|\n")
	rows := r.Packages
	if top > 0 && len(rows) > top && !r.Regressed() {
		rows = rows[:top]
	}
	for _, p := range rows {
		ks := fmt.Sprintf("%d/%d", p.Killed, p.Scored)
		if p.State == "removed" {
			ks = "—"
		}
		fmt.Fprintf(&b, "| `%s` | %.1f%% | %.1f%% | %+.2f | %s |\n", p.Package, p.Baseline, p.Current, p.DeltaPct, ks)
	}
	fmt.Fprintf(&b, "\n")

	if len(r.Survivors) > 0 {
		fmt.Fprintf(&b, "### Surviving mutants (%d)\n\n", len(r.Survivors))
		fmt.Fprintf(&b, "| Location | Operator | Change | ID |\n|---|---|---|---|\n")
		shown := r.Survivors
		if top > 0 && len(shown) > top {
			shown = shown[:top]
		}
		for _, s := range shown {
			fmt.Fprintf(&b, "| `%s:%d:%d` | %s | `%s` → `%s` | `%s` |\n",
				s.File, s.Line, s.Col, s.Operator, s.Original, mdCode(s.Mutated), s.ID)
		}
		if top > 0 && len(r.Survivors) > len(shown) {
			fmt.Fprintf(&b, "\n_…%d more survivor(s)._\n", len(r.Survivors)-len(shown))
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func mdCode(s string) string {
	if s == "" {
		return "∅"
	}
	return s
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

func pct(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.0f%%", v)
	}
	return fmt.Sprintf("%.1f%%", v)
}

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

// CollectSurvivors flattens the surviving mutants across a run, sorted stably.
func CollectSurvivors(r *RunResult) []MutantResult {
	var out []MutantResult
	for _, pr := range r.Packages {
		for _, m := range pr.Mutants {
			if m.Status == StatusSurvived {
				out = append(out, m)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ID < out[j].ID
	})
	return out
}
