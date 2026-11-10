package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/muttest"
)

// defaultMutationBaselinePath is the committed mutation-score baseline the guard
// compares against. It lives under mutation/ next to its documentation, mirroring
// coverage/coverage-baseline.json (Task 117) and perf/perf-baseline.json.
const defaultMutationBaselinePath = "mutation/mutation-baseline.json"

// defaultEquivalentsPath is the committed list of mutant IDs accepted as
// equivalent/benign (excluded from the score). See docs/mutation-testing.md.
const defaultEquivalentsPath = "mutation/equivalent-mutants.txt"

// defaultMutationPackages is the focused, highest-risk admission-gate package
// set the gate targets by default: the vulnerability, signature, policy, risk,
// dependency-firewall and content-analysis gates.
var defaultMutationPackages = []string{
	"internal/vulnscan",
	"internal/sigverify",
	"internal/policyengine",
	"internal/riskscore",
	"internal/depfirewall",
	"internal/installhooks",
	"internal/contentscan",
	"internal/license",
}

// mutguardFlags are the knobs for `ptctl mutguard`. Like covguard it runs the
// local test suite (mutated) rather than talking to a running proxy, so it does
// not register the global connection flags.
type mutguardFlags struct {
	baseline       string
	updateBaseline bool
	packages       string
	operators      string
	maxPerPackage  int
	seed           int64
	short          bool
	keepAll        bool
	ignoreFile     string
	moduleDir      string
	allowedDrop    float64
	allowedPkgDrop float64
	critical       string
	criticalFloor  float64
	top            int
	jsonOut        bool
	jsonFile       string
	mdFile         string
	goBin          string
	testTimeout    time.Duration
	buildTimeout   time.Duration
	timeout        time.Duration
}

// runMutguard implements `ptctl mutguard`: it seeds behavior-changing mutants
// into the targeted packages' source, recompiles and reruns each package's test
// binary, computes per-package and total mutation scores, and either records a
// committed baseline (--update-baseline) or compares the run against the stored
// baseline and exits non-zero when the total score drops beyond the threshold or
// a critical package falls under its floor. It is the fault-detection analogue
// of `ptctl covguard`.
func runMutguard(args []string) error {
	fs := flag.NewFlagSet("mutguard", flag.ContinueOnError)
	var mf mutguardFlags
	fs.StringVar(&mf.baseline, "baseline", defaultMutationBaselinePath, "path to the stored mutation-score baseline JSON")
	fs.BoolVar(&mf.updateBaseline, "update-baseline", false, "run the harness and overwrite the baseline file instead of comparing")
	fs.StringVar(&mf.packages, "packages", strings.Join(defaultMutationPackages, ","), "comma-separated module-relative packages to mutate")
	fs.StringVar(&mf.operators, "operators", strings.Join(muttest.DefaultOperators(), ","), "comma-separated mutation operators (ROR,LCR,AOR,BOOL,COND,NEG,INCDEC)")
	fs.IntVar(&mf.maxPerPackage, "max-per-package", 60, "cap mutants run per package; a seeded sample is taken when exceeded (0 = unbounded)")
	fs.Int64Var(&mf.seed, "seed", 1, "random seed for deterministic mutant sampling")
	fs.BoolVar(&mf.short, "short", true, "pass -test.short to each mutant run (faster; skips long tests)")
	fs.BoolVar(&mf.keepAll, "keep-all", false, "keep killed/invalid mutants in the JSON report (survivors are always kept)")
	fs.StringVar(&mf.ignoreFile, "ignore-file", defaultEquivalentsPath, "newline-delimited file of mutant IDs accepted as equivalent (excluded from the score)")
	fs.StringVar(&mf.moduleDir, "module-dir", ".", "module root the `go` commands run from")
	fs.Float64Var(&mf.allowedDrop, "allowed-drop", 2.0, "max percentage-point drop in TOTAL mutation score before the guard fails")
	fs.Float64Var(&mf.allowedPkgDrop, "allowed-package-drop", 0, "max percentage-point drop for any single package before failing (0 = per-package drop gate off)")
	fs.StringVar(&mf.critical, "critical", "", "comma-separated critical packages, each `pkg[=floorPct]`; a critical package below its floor (or removed) fails the guard")
	fs.Float64Var(&mf.criticalFloor, "critical-floor", 0, "default floor percent applied to -critical entries given without an explicit =floor")
	fs.IntVar(&mf.top, "top", 20, "limit the drop list, per-package table, and survivor list to this many rows (0 = unbounded)")
	fs.BoolVar(&mf.jsonOut, "json", false, "emit the baseline (update) or comparison report (compare) as JSON to stdout")
	fs.StringVar(&mf.jsonFile, "json-out", "", "also write the machine-readable JSON report to this file (for CI decoration)")
	fs.StringVar(&mf.mdFile, "md-out", "", "also write a Markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
	fs.StringVar(&mf.goBin, "go", "go", "go binary used to build/run the mutated suites")
	fs.DurationVar(&mf.testTimeout, "test-timeout", 2*time.Minute, "per-mutant test-run timeout (a timeout counts as killed)")
	fs.DurationVar(&mf.buildTimeout, "build-timeout", 3*time.Minute, "per-mutant compile timeout")
	fs.DurationVar(&mf.timeout, "timeout", 2*time.Hour, "overall wall-clock timeout for the whole run")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl mutguard [flags]")
		fmt.Fprintln(os.Stderr, "Measure the fault-detection strength of the unit suite via mutation testing and")
		fmt.Fprintln(os.Stderr, "guard against a regression versus a committed per-package mutation-score baseline.")
		fmt.Fprintln(os.Stderr, "Exits non-zero when total score drops beyond the threshold or a critical package")
		fmt.Fprintln(os.Stderr, "falls under its floor. Deterministic: a given (seed, cap, operators) is reproducible.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  ptctl mutguard --update-baseline          # seed/refresh mutation/mutation-baseline.json")
		fmt.Fprintln(os.Stderr, "  ptctl mutguard                            # compare the current suite against the baseline")
		fmt.Fprintln(os.Stderr, "  ptctl mutguard --packages internal/sigverify --max-per-package 0   # full run of one package")
		fmt.Fprintln(os.Stderr, "  ptctl mutguard --critical internal/sigverify=80,internal/vulnscan=75")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	pkgs := splitList(mf.packages)
	if len(pkgs) == 0 {
		return fmt.Errorf("no packages selected (use --packages)")
	}
	ops := splitList(mf.operators)

	critical, err := parseCriticalFloors(mf.critical, mf.criticalFloor)
	if err != nil {
		return err
	}

	ignore, err := loadIgnoreFile(mf.ignoreFile)
	if err != nil {
		return err
	}

	modulePath, err := readModulePath(filepath.Join(mf.moduleDir, "go.mod"))
	if err != nil {
		return fmt.Errorf("read module path: %w", err)
	}

	// The baseline keys packages by their full import path (ModulePath + "/" +
	// relative dir), so the critical floors must use the same keys or Compare can
	// never match them and the floor silently never fires. --critical accepts the
	// convenient module-relative form (e.g. internal/sigverify), so normalize it
	// to the full import path here.
	critical = normalizeFloorKeys(critical, modulePath)

	ctx, cancel := context.WithTimeout(context.Background(), mf.timeout)
	defer cancel()

	engine := muttest.New(muttest.Options{
		GoBin:             mf.goBin,
		ModuleDir:         mf.moduleDir,
		ModulePath:        modulePath,
		Operators:         ops,
		MaxPerPackage:     mf.maxPerPackage,
		Seed:              mf.seed,
		TestTimeout:       mf.testTimeout,
		BuildTimeout:      mf.buildTimeout,
		Short:             mf.short,
		Ignore:            ignore,
		KeepMutantResults: mf.keepAll,
		Logf:              func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) },
	})

	fmt.Fprintf(os.Stderr, ">> mutation testing %d package(s) (seed %d, cap %d/pkg, operators %s)…\n",
		len(pkgs), mf.seed, mf.maxPerPackage, strings.Join(ops, ","))
	run, err := engine.Run(ctx, pkgs)
	if err != nil {
		return fmt.Errorf("mutation run failed: %w", err)
	}

	current := muttest.FromRun(run)
	current.Tool = "ptctl " + version
	current.MaxPerPackage = mf.maxPerPackage

	if mf.updateBaseline {
		// Preserve the committed critical floors on a re-seed: an explicit
		// --critical overrides them, but re-running `--update-baseline` without
		// one must not silently drop the floors already checked in.
		floors := critical
		if len(floors) == 0 {
			if existing, lerr := muttest.LoadBaseline(mf.baseline); lerr == nil {
				floors = existing.CriticalFloors
			}
		}
		current.CriticalFloors = floors
		if err := current.Save(mf.baseline); err != nil {
			return fmt.Errorf("write baseline %s: %w", mf.baseline, err)
		}
		if mf.jsonOut {
			return writeJSONIndented(os.Stdout, current)
		}
		fmt.Fprintf(os.Stdout, "Mutation baseline written to %s\n", mf.baseline)
		fmt.Fprintf(os.Stdout, "  captured:  %s\n", current.CapturedAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stdout, "  total:     %.1f%% (%d/%d mutants killed)\n", current.Total.Pct, current.Total.Killed, current.Total.Scored)
		fmt.Fprintf(os.Stdout, "  packages:  %d  (seed %d, cap %d/pkg)\n", len(current.Packages), current.Seed, current.MaxPerPackage)
		if len(floors) > 0 {
			fmt.Fprintf(os.Stdout, "  critical:  %s\n", formatCritical(floors))
		}
		fmt.Fprintln(os.Stdout, "\nCommit this file. Refresh it whenever an intentional test-quality change lands.")
		return nil
	}

	baseline, err := muttest.LoadBaseline(mf.baseline)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no baseline at %s: seed one first with `ptctl mutguard --update-baseline`", mf.baseline)
		}
		return fmt.Errorf("load baseline %s: %w", mf.baseline, err)
	}

	floors := critical
	if len(floors) == 0 {
		floors = baseline.CriticalFloors
	}
	policy := muttest.Policy{
		AllowedTotalDropPct:   mf.allowedDrop,
		AllowedPackageDropPct: mf.allowedPkgDrop,
		CriticalFloors:        floors,
	}
	report := muttest.Compare(baseline, current, policy)
	report.Survivors = muttest.CollectSurvivors(run)

	if mf.jsonFile != "" {
		if err := writeJSONFile(mf.jsonFile, report); err != nil {
			return fmt.Errorf("write JSON report %s: %w", mf.jsonFile, err)
		}
	}
	if mf.mdFile != "" {
		if err := os.WriteFile(mf.mdFile, []byte(report.Markdown(mf.top)), 0o644); err != nil {
			return fmt.Errorf("write Markdown summary %s: %w", mf.mdFile, err)
		}
	}

	if mf.jsonOut {
		if err := writeJSONIndented(os.Stdout, report); err != nil {
			return err
		}
	} else {
		fmt.Fprint(os.Stdout, report.Format(mf.top))
	}

	if report.Regressed() {
		return fmt.Errorf("mutation-score regression detected: %d gate(s) failed", report.RegressionCount())
	}
	return nil
}

// normalizeFloorKeys rewrites critical-floor keys to the full package import
// path used in the baseline's Packages map. A key that is already absolute
// (already carries the module path prefix) is left untouched; a module-relative
// key such as "internal/sigverify" is prefixed with the module path. This keeps
// the floors keyed consistently with the per-package scores so Compare matches
// them. An empty map is returned unchanged.
func normalizeFloorKeys(floors map[string]float64, modulePath string) map[string]float64 {
	if len(floors) == 0 || modulePath == "" {
		return floors
	}
	out := make(map[string]float64, len(floors))
	prefix := modulePath + "/"
	for k, v := range floors {
		if k == modulePath || strings.HasPrefix(k, prefix) {
			out[k] = v
			continue
		}
		out[prefix+k] = v
	}
	return out
}

// splitList splits a comma-separated flag value into trimmed, non-empty fields.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// loadIgnoreFile reads a newline-delimited file of accepted/equivalent mutant
// IDs. Blank lines and `#` comments are ignored. A missing file is not an error
// (an empty ignore set), so the gate works before any equivalents are triaged.
func loadIgnoreFile(path string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open ignore file %s: %w", path, err)
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Tolerate a trailing "  # note" comment after the ID.
		if i := strings.IndexAny(line, " \t#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out[line] = true
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ignore file %s: %w", path, err)
	}
	return out, nil
}

// readModulePath extracts the `module` path from a go.mod file.
func readModulePath(gomod string) (string, error) {
	f, err := os.Open(gomod)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module")), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no module directive in %s", gomod)
}
