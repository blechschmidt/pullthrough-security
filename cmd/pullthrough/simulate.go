package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// buildSimReplayRecorder constructs the live what-if capture recorder (Task 47)
// when enabled. It is the capture half of the harness: a bounded, sampled,
// redacted ring buffer of recent admission inputs and their live verdicts, wired
// into the pull path and exposed via the admin endpoint. It returns nil when
// disabled, in which case nothing is captured and only the offline `simulate`
// CLI (which works against an exported capture file) remains available.
func buildSimReplayRecorder(cfg *config.Config, logger *slog.Logger) *simreplay.Recorder {
	sc := cfg.SimReplay
	if !sc.Enabled {
		logger.Info("policy & risk what-if replay capture disabled (set simReplay.enabled to capture traffic for candidate-config simulation)")
		return nil
	}
	// Redaction defaults to on; only an explicit redact:false in the config turns
	// it off (not recommended for buffers shipped off-box).
	redact := sc.Redact == nil || *sc.Redact
	rec := simreplay.NewRecorder(simreplay.Config{
		Enabled:    true,
		Capacity:   sc.Capacity,
		SampleRate: sc.SampleRate,
		Redact:     redact,
	})
	st := rec.Status()
	logger.Info("policy & risk what-if replay capture enabled",
		"capacity", st.Capacity, "sampleRate", st.SampleRate, "redacted", st.Redacted)
	return rec
}

// runSimulateCommand implements the `simulate` CLI subcommand: a deterministic
// policy & risk what-if replay tool (Task 47). It reads a captured-traffic file
// (a buffer of recent admission inputs and their live verdicts, exported from a
// running proxy's admin endpoint or written by an air-gapped capture) and a
// candidate configuration file, replays every captured pull through the candidate
// policy/risk engines, and emits a diff report: admit↔block flips, risk-band
// shifts, new policy violations, and per-tenant blast radius.
//
// It owns its own flag set so the live server's global flags stay uncluttered,
// and it needs no running proxy — making it the CI / pre-rollout gate for policy
// and risk changes.
func runSimulateCommand(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	var (
		capturePath   = fs.String("capture", "", "path to a captured-traffic file (JSON capture envelope or bare record array); required")
		candidatePath = fs.String("candidate", "", "path to the candidate configuration file (YAML or JSON, simreplay CandidateConfig schema); required")
		baselinePath  = fs.String("baseline", "", "optional path to a baseline configuration file; when set, baselines are recomputed from it instead of using the verdicts captured live")
		format        = fs.String("format", "json", "output format: json or markdown")
		outPath       = fs.String("output", "", "path to write the report (default stdout)")
		records       = fs.Bool("records", false, "include per-record diffs in the report (default: summary + per-tenant only)")
		all           = fs.Bool("all", false, "with -records, include unchanged records too (default: only changed)")
		limit         = fs.Int("limit", 0, "with -records, cap the number of per-record diffs (0 = no cap)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pullthrough simulate -capture <file> -candidate <file> [flags]")
		fmt.Fprintln(os.Stderr, "Replays captured admission traffic through a candidate policy/risk config and reports the diff.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*capturePath) == "" {
		fs.Usage()
		return fmt.Errorf("simulate: -capture is required")
	}
	if strings.TrimSpace(*candidatePath) == "" {
		fs.Usage()
		return fmt.Errorf("simulate: -candidate is required")
	}
	mode := strings.ToLower(strings.TrimSpace(*format))
	if mode != "json" && mode != "markdown" && mode != "md" {
		return fmt.Errorf("simulate: invalid -format %q (want json or markdown)", *format)
	}

	capture, err := simreplay.LoadCapture(*capturePath)
	if err != nil {
		return fmt.Errorf("simulate: %w", err)
	}

	candidateCfg, err := simreplay.LoadCandidate(*candidatePath)
	if err != nil {
		return fmt.Errorf("simulate: loading candidate: %w", err)
	}
	candidate, cleanup, err := simreplay.BuildEvaluator(candidateCfg)
	if err != nil {
		return fmt.Errorf("simulate: %w", err)
	}
	defer func() { _ = cleanup() }()

	opts := simreplay.Options{
		IncludeRecords: *records,
		OnlyChanged:    !*all,
		MaxRecords:     *limit,
	}

	// An optional baseline config recomputes the reference verdicts, letting an
	// operator diff two candidate configs rather than candidate-vs-production.
	if strings.TrimSpace(*baselinePath) != "" {
		baselineCfg, berr := simreplay.LoadCandidate(*baselinePath)
		if berr != nil {
			return fmt.Errorf("simulate: loading baseline: %w", berr)
		}
		baseline, bcleanup, berr := simreplay.BuildEvaluator(baselineCfg)
		if berr != nil {
			return fmt.Errorf("simulate: baseline: %w", berr)
		}
		defer func() { _ = bcleanup() }()
		opts.Baseline = baseline
	}

	report := simreplay.Run(capture.Records, candidate, opts)

	out := os.Stdout
	if strings.TrimSpace(*outPath) != "" {
		f, ferr := os.Create(*outPath)
		if ferr != nil {
			return fmt.Errorf("simulate: creating output: %w", ferr)
		}
		defer f.Close()
		out = f
	}

	switch mode {
	case "markdown", "md":
		if _, werr := out.WriteString(report.Markdown()); werr != nil {
			return fmt.Errorf("simulate: writing report: %w", werr)
		}
	default:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if werr := enc.Encode(report); werr != nil {
			return fmt.Errorf("simulate: encoding report: %w", werr)
		}
	}

	if strings.TrimSpace(*outPath) != "" {
		s := report.Summary
		fmt.Fprintf(os.Stderr, "simulate: replayed %d pull(s); %d changed (%d newly blocked, %d newly admitted) -> %s\n",
			s.Total, s.Changed, s.NowBlocked, s.NowAdmitted, *outPath)
	}
	return nil
}
