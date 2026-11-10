package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// runDoctor implements `ptctl doctor`: a single consolidated, read-only health
// and configuration self-diagnostic (Task 152). It reuses the proxy's existing
// building blocks rather than reimplementing them — config validation + drift
// preflight (Task 85), backend reachability probes (Task 55), key/credential/
// certificate expiry monitoring (Tasks 128/148), secrets-provider resolution
// (Task 133), cache integrity sampling (Task 107), leader-election status
// (Task 56), kill-switch/lockdown state (Task 74), and gate-enablement coverage
// — and folds every signal into a single prioritized, color-coded report with
// remediation hints.
//
// It runs in two modes:
//
//   - online (default): against a running proxy over the admin API + gateway;
//     requires --url (or PULLTHROUGH_URL).
//   - offline (--config FILE): against a config file on disk, with no running
//     proxy; runs the checks that are computable statically (config validation,
//     secrets-provider resolution, gate coverage) and skips the live ones.
//
// A `--json` form is emitted for CI. The process exits non-zero when any check
// is at error severity (or, with --warn-as-error, at warning severity).
func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var g globalFlags
	registerGlobals(fs, &g)
	var (
		jsonOut     = fs.Bool("json", false, "emit the machine-readable JSON report (for CI)")
		configPath  = fs.String("config", "", "run offline against this config file instead of a running proxy")
		warnAsError = fs.Bool("warn-as-error", false, "treat warning-severity checks as failures (exit non-zero)")
		noColor     = fs.Bool("no-color", false, "disable ANSI color in the human-readable report")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl doctor [flags] [name=type ...]")
		fmt.Fprintln(os.Stderr, "Run a consolidated read-only health & configuration self-diagnostic against")
		fmt.Fprintln(os.Stderr, "a running proxy, or (with --config) against a config file in offline mode.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Explicit backends for the reachability probe may be given as name=type")
		fmt.Fprintln(os.Stderr, "arguments (e.g. npm=npm); otherwise they are auto-discovered from the proxy.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	opts := doctorOptions{
		jsonOut:     *jsonOut,
		warnAsError: *warnAsError,
		color:       !*noColor && !*jsonOut && colorEnabled(),
		backendArgs: fs.Args(),
	}

	var report *doctorReport
	var err error
	if strings.TrimSpace(*configPath) != "" {
		report = runDoctorOffline(*configPath, g.timeout)
	} else {
		report, err = runDoctorOnline(g, opts)
		if err != nil {
			return err
		}
	}
	report.finalize(opts.warnAsError)

	if opts.jsonOut {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		report.render(os.Stdout, opts.color)
	}

	if !report.Summary.Healthy {
		return fmt.Errorf("doctor: %d error(s), %d warning(s) — see report above", report.Summary.Error, report.Summary.Warning)
	}
	return nil
}

// doctorOptions carries the resolved run-time knobs shared by the checks and the
// renderer.
type doctorOptions struct {
	jsonOut     bool
	warnAsError bool
	color       bool
	backendArgs []string
}

// --- severity model ---------------------------------------------------------

// Severity classifies a single diagnostic check. The ordering (error > warn >
// skip > ok) drives the prioritized rendering: the most actionable findings
// float to the top of the report.
const (
	sevOK    = "ok"
	sevWarn  = "warning"
	sevError = "error"
	sevSkip  = "skipped"
)

// sevRank orders severities for prioritized output (higher sorts first). Errors
// lead, then warnings; passing checks precede skipped ones, so non-actionable
// "not run" rows sink to the bottom of the report.
func sevRank(s string) int {
	switch s {
	case sevError:
		return 3
	case sevWarn:
		return 2
	case sevOK:
		return 1
	default: // sevSkip
		return 0
	}
}

// sevSymbol is the leading glyph for a severity in the human-readable report.
func sevSymbol(s string) string {
	switch s {
	case sevError:
		return "✗"
	case sevWarn:
		return "!"
	case sevSkip:
		return "–"
	default:
		return "✓"
	}
}

// ansi color codes keyed by severity; empty when color is disabled.
func sevColor(s string) string {
	switch s {
	case sevError:
		return "\033[31m" // red
	case sevWarn:
		return "\033[33m" // yellow
	case sevSkip:
		return "\033[90m" // bright black / gray
	default:
		return "\033[32m" // green
	}
}

const ansiReset = "\033[0m"

// --- report model -----------------------------------------------------------

// checkResult is the outcome of one diagnostic check.
type checkResult struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Details     []string `json:"details,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// doctorReport is the full diagnostic, rendered as a table or emitted as JSON.
type doctorReport struct {
	Mode        string        `json:"mode"` // online | offline
	Target      string        `json:"target"`
	GeneratedAt time.Time     `json:"generatedAt"`
	Checks      []checkResult `json:"checks"`
	Summary     doctorSummary `json:"summary"`
}

// doctorSummary is the rolled-up tally plus the overall verdict.
type doctorSummary struct {
	Total   int  `json:"total"`
	OK      int  `json:"ok"`
	Warning int  `json:"warning"`
	Error   int  `json:"error"`
	Skipped int  `json:"skipped"`
	Healthy bool `json:"healthy"`
}

// add appends a check result to the report.
func (r *doctorReport) add(c checkResult) { r.Checks = append(r.Checks, c) }

// finalize recomputes the tally, decides the overall verdict, and sorts the
// checks by descending severity (stable within a severity, preserving the order
// in which the checks ran) so the report is deterministic and prioritized.
func (r *doctorReport) finalize(warnAsError bool) {
	// Stable sort by severity rank, descending.
	sort.SliceStable(r.Checks, func(i, j int) bool {
		return sevRank(r.Checks[i].Severity) > sevRank(r.Checks[j].Severity)
	})
	s := doctorSummary{Total: len(r.Checks)}
	for _, c := range r.Checks {
		switch c.Severity {
		case sevError:
			s.Error++
		case sevWarn:
			s.Warning++
		case sevSkip:
			s.Skipped++
		default:
			s.OK++
		}
	}
	s.Healthy = s.Error == 0 && (!warnAsError || s.Warning == 0)
	r.Summary = s
}

// render writes the human-readable report to w.
func (r *doctorReport) render(w *os.File, color bool) {
	fmt.Fprintf(w, "pullthrough doctor — %s mode (%s)\n", r.Mode, r.Target)
	fmt.Fprintf(w, "generated %s\n\n", r.GeneratedAt.Format(time.RFC3339))

	for _, c := range r.Checks {
		sym := sevSymbol(c.Severity)
		head := fmt.Sprintf("%s  %-26s %s", sym, c.Name, c.Summary)
		if color {
			head = sevColor(c.Severity) + head + ansiReset
		}
		fmt.Fprintln(w, head)
		for _, d := range c.Details {
			fmt.Fprintf(w, "       %s\n", d)
		}
		if c.Remediation != "" && (c.Severity == sevError || c.Severity == sevWarn) {
			hint := "   → " + c.Remediation
			if color {
				hint = "\033[2m" + hint + ansiReset // dim
			}
			fmt.Fprintln(w, hint)
		}
	}

	line := fmt.Sprintf("\n%d checks: %d ok, %d warning, %d error, %d skipped",
		r.Summary.Total, r.Summary.OK, r.Summary.Warning, r.Summary.Error, r.Summary.Skipped)
	fmt.Fprintln(w, line)
	verdict := "HEALTHY"
	vsev := sevOK
	if r.Summary.Error > 0 {
		verdict, vsev = "UNHEALTHY", sevError
	} else if r.Summary.Warning > 0 {
		verdict, vsev = "DEGRADED", sevWarn
	}
	v := "verdict: " + verdict
	if color {
		v = sevColor(vsev) + v + ansiReset
	}
	fmt.Fprintln(w, v)
}

// colorEnabled reports whether ANSI color should be used by default: stdout is a
// terminal and NO_COLOR is not set (https://no-color.org/).
func colorEnabled() bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
