package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/covguard"
)

// defaultCoverageBaselinePath is the committed coverage baseline the guard
// compares against. It lives under coverage/ next to its documentation, and
// mirrors perf/perf-baseline.json for the performance guard (Task 112).
const defaultCoverageBaselinePath = "coverage/coverage-baseline.json"

// covguardFlags are the knobs for `ptctl covguard`. Unlike the other ptctl
// subcommands this one does not talk to a running proxy — it runs the local
// test suite with coverage — so it deliberately does not register the global
// connection flags.
type covguardFlags struct {
	baseline       string
	updateBaseline bool
	coverProfile   string
	keepProfile    bool
	packages       string
	coverMode      string
	testArgs       string
	allowedDrop    float64
	allowedPkgDrop float64
	critical       string
	criticalFloor  float64
	top            int
	jsonOut        bool
	jsonFile       string
	mdFile         string
	goBin          string
	timeout        time.Duration
}

// runCovguard implements `ptctl covguard`: it runs `go test ./... -coverprofile`
// (or consumes an existing profile), aggregates per-package and total statement
// coverage, and either records a committed baseline (-update-baseline) or
// compares the run against the stored baseline and exits non-zero when total
// coverage drops beyond the threshold or a critical package falls under its
// floor. It is the coverage-regression analogue of `ptctl perfguard`.
func runCovguard(args []string) error {
	fs := flag.NewFlagSet("covguard", flag.ContinueOnError)
	var cf covguardFlags
	fs.StringVar(&cf.baseline, "baseline", defaultCoverageBaselinePath, "path to the stored coverage baseline JSON")
	fs.BoolVar(&cf.updateBaseline, "update-baseline", false, "run the suite and overwrite the baseline file instead of comparing")
	fs.StringVar(&cf.coverProfile, "coverprofile", "", "use an existing coverprofile instead of running tests (skips `go test`)")
	fs.BoolVar(&cf.keepProfile, "keep-profile", false, "keep the generated coverprofile instead of removing it (written next to the baseline as coverage.out)")
	fs.StringVar(&cf.packages, "packages", "./...", "package pattern passed to `go test`")
	fs.StringVar(&cf.coverMode, "covermode", "set", "cover mode for `go test` (set|count|atomic); does not affect the percentage")
	fs.StringVar(&cf.testArgs, "test-args", "", "extra space-separated args appended to `go test` (e.g. \"-count=1 -tags=integration\")")
	fs.Float64Var(&cf.allowedDrop, "allowed-drop", 1.0, "max percentage-point drop in TOTAL coverage before the guard fails")
	fs.Float64Var(&cf.allowedPkgDrop, "allowed-package-drop", 0, "max percentage-point drop for any single package before failing (0 = per-package drop gate off)")
	fs.StringVar(&cf.critical, "critical", "", "comma-separated critical packages, each `pkg[=floorPct]`; a critical package below its floor (or removed) fails the guard")
	fs.Float64Var(&cf.criticalFloor, "critical-floor", 0, "default floor percent applied to -critical entries given without an explicit =floor")
	fs.IntVar(&cf.top, "top", 15, "limit the biggest-drops list and per-package table to this many rows (0 = unbounded)")
	fs.BoolVar(&cf.jsonOut, "json", false, "emit the baseline (update) or comparison report (compare) as JSON to stdout")
	fs.StringVar(&cf.jsonFile, "json-out", "", "also write the machine-readable JSON report to this file (for CI decoration)")
	fs.StringVar(&cf.mdFile, "md-out", "", "also write a Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
	fs.StringVar(&cf.goBin, "go", "go", "go binary used to run the suite")
	fs.DurationVar(&cf.timeout, "timeout", 20*time.Minute, "overall timeout for the `go test` run")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl covguard [flags]")
		fmt.Fprintln(os.Stderr, "Measure statement coverage across the module and guard against coverage")
		fmt.Fprintln(os.Stderr, "regressions versus a committed baseline. Exits non-zero when total coverage")
		fmt.Fprintln(os.Stderr, "drops beyond the threshold or a critical package falls under its floor.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  ptctl covguard -update-baseline          # seed/refresh coverage/coverage-baseline.json")
		fmt.Fprintln(os.Stderr, "  ptctl covguard                           # compare current coverage against the baseline")
		fmt.Fprintln(os.Stderr, "  ptctl covguard -allowed-drop 0.5 -json-out cov-report.json")
		fmt.Fprintln(os.Stderr, "  ptctl covguard -critical internal/cache=80,internal/proxy=75")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	critical, err := parseCriticalFloors(cf.critical, cf.criticalFloor)
	if err != nil {
		return err
	}

	// Produce the current snapshot, either from an existing profile or by running
	// the suite now.
	current, cleanup, err := buildCoverageSnapshot(cf)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}

	current.CapturedAt = time.Now().UTC()
	current.Tool = "ptctl " + version

	if cf.updateBaseline {
		current.CriticalFloors = critical
		if err := current.Save(cf.baseline); err != nil {
			return fmt.Errorf("write baseline %s: %w", cf.baseline, err)
		}
		if cf.jsonOut {
			return writeJSONIndented(os.Stdout, current)
		}
		fmt.Fprintf(os.Stdout, "Coverage baseline written to %s\n", cf.baseline)
		fmt.Fprintf(os.Stdout, "  captured:  %s\n", current.CapturedAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "  total:     %.1f%% (%d/%d statements)\n", current.Total.Pct, current.Total.Covered, current.Total.Total)
		fmt.Fprintf(os.Stdout, "  packages:  %d\n", len(current.Packages))
		if len(critical) > 0 {
			fmt.Fprintf(os.Stdout, "  critical:  %s\n", formatCritical(critical))
		}
		fmt.Fprintln(os.Stdout, "\nCommit this file. Refresh it whenever an intentional coverage change lands.")
		return nil
	}

	baseline, err := covguard.LoadBaseline(cf.baseline)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no baseline at %s: seed one first with `ptctl covguard -update-baseline`", cf.baseline)
		}
		return fmt.Errorf("load baseline %s: %w", cf.baseline, err)
	}

	// Critical floors: an explicit -critical flag overrides the committed floors
	// in the baseline; otherwise the baseline's floors apply, keeping the gate
	// repeatable without re-specifying floors on every run.
	floors := critical
	if len(floors) == 0 {
		floors = baseline.CriticalFloors
	}
	policy := covguard.Policy{
		AllowedTotalDropPct:   cf.allowedDrop,
		AllowedPackageDropPct: cf.allowedPkgDrop,
		CriticalFloors:        floors,
	}
	report := covguard.Compare(baseline, current, policy)

	if cf.jsonFile != "" {
		if err := writeJSONFile(cf.jsonFile, report); err != nil {
			return fmt.Errorf("write JSON report %s: %w", cf.jsonFile, err)
		}
	}
	if cf.mdFile != "" {
		if err := os.WriteFile(cf.mdFile, []byte(report.Markdown(cf.top)), 0o644); err != nil {
			return fmt.Errorf("write Markdown summary %s: %w", cf.mdFile, err)
		}
	}

	if cf.jsonOut {
		if err := writeJSONIndented(os.Stdout, report); err != nil {
			return err
		}
	} else {
		fmt.Fprint(os.Stdout, report.Format(cf.top))
	}

	if report.Regressed() {
		// A non-nil error propagates to main() and exits 1 — the CI gate.
		return fmt.Errorf("coverage regression detected: %d gate(s) failed", report.RegressionCount())
	}
	return nil
}

// buildCoverageSnapshot returns the current coverage snapshot and an optional
// cleanup func (removing a temp profile unless -keep-profile was set).
func buildCoverageSnapshot(cf covguardFlags) (snap *covguard.Baseline, cleanup func(), err error) {
	if cf.coverProfile != "" {
		b, perr := parseProfileFile(cf.coverProfile)
		return b, nil, perr
	}

	// Run the suite into a profile. Keep it at a stable, inspectable location on
	// -keep-profile; otherwise use a temp file we clean up.
	var profilePath string
	if cf.keepProfile {
		profilePath = "coverage.out"
	} else {
		f, terr := os.CreateTemp("", "covguard-*.out")
		if terr != nil {
			return nil, nil, fmt.Errorf("create temp coverprofile: %w", terr)
		}
		profilePath = f.Name()
		f.Close()
		cleanup = func() { os.Remove(profilePath) }
	}

	ctx, cancel := context.WithTimeout(context.Background(), cf.timeout)
	defer cancel()

	fmt.Fprintf(os.Stderr, ">> running `%s test %s -coverprofile` (covermode=%s)…\n", cf.goBin, cf.packages, cf.coverMode)
	runErr := covguard.RunGoTest(ctx, covguard.RunOptions{
		GoBin:        cf.goBin,
		Packages:     cf.packages,
		CoverMode:    cf.coverMode,
		CoverProfile: profilePath,
		ExtraArgs:    splitTestArgs(cf.testArgs),
		Stdout:       os.Stderr,
		Stderr:       os.Stderr,
	})
	if runErr != nil {
		return nil, cleanup, fmt.Errorf("test run failed (coverage not measured): %w", runErr)
	}

	b, perr := parseProfileFile(profilePath)
	if perr != nil {
		return nil, cleanup, perr
	}
	if cf.keepProfile {
		fmt.Fprintf(os.Stderr, ">> coverprofile kept at %s (inspect with `go tool cover -html=%s`)\n", profilePath, profilePath)
	}
	return b, cleanup, nil
}

// parseProfileFile opens and parses a coverprofile into a snapshot Baseline.
func parseProfileFile(path string) (*covguard.Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open coverprofile %s: %w", path, err)
	}
	defer f.Close()
	b, err := covguard.ParseProfile(f)
	if err != nil {
		return nil, fmt.Errorf("parse coverprofile %s: %w", path, err)
	}
	return b, nil
}

// parseCriticalFloors parses the -critical list ("pkg", "pkg=80", comma-joined)
// into a floor map. An entry without an explicit =floor uses defaultFloor; an
// entry with 0 and no default is rejected so a typo cannot silently create a
// no-op floor.
func parseCriticalFloors(spec string, defaultFloor float64) (map[string]float64, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	out := map[string]float64{}
	for _, raw := range strings.Split(spec, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		pkg := entry
		floor := defaultFloor
		if eq := strings.LastIndex(entry, "="); eq >= 0 {
			pkg = strings.TrimSpace(entry[:eq])
			val := strings.TrimSpace(entry[eq+1:])
			f, err := strconv.ParseFloat(val, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid floor %q for critical package %q: %w", val, pkg, err)
			}
			floor = f
		}
		if pkg == "" {
			return nil, fmt.Errorf("empty package name in -critical entry %q", entry)
		}
		if floor <= 0 {
			return nil, fmt.Errorf("critical package %q has no floor: give one as `%s=PCT` or set -critical-floor", pkg, pkg)
		}
		if floor > 100 {
			return nil, fmt.Errorf("critical floor for %q is %g%% (> 100%%)", pkg, floor)
		}
		out[pkg] = floor
	}
	return out, nil
}

// formatCritical renders a floor map as a stable, comma-separated string.
func formatCritical(m map[string]float64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s>=%g%%", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// splitTestArgs splits the -test-args string into fields, tolerating empty.
func splitTestArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// writeJSONFile writes v as indented JSON to path (for CI artifacts).
func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSONIndented(f, v)
}
