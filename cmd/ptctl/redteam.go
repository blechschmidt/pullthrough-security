package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/redteam"
)

// runRedteam implements `ptctl redteam [flags]`: it runs the supply-chain attack
// red-team simulation and gate-efficacy suite (Task 76) and prints the coverage
// matrix (scenario × expected-gate × actual outcome).
//
// Unlike the other ptctl subcommands it is fully self-contained and offline: the
// harness spins up in-process gateways with deterministic stub backends, injects
// each synthetic attack end-to-end through the real admission pipeline, and
// asserts the expected gate blocks it. It needs no running proxy, URL, or token —
// it validates the gate code itself. It exits non-zero if any scenario fails (in
// particular, if any attack that should be blocked is admitted), so it doubles as
// a CI regression check.
func runRedteam(args []string) error {
	fs := flag.NewFlagSet("redteam", flag.ContinueOnError)
	var (
		format = fs.String("format", "markdown", "output format: markdown|json")
		output = fs.String("output", "", "write the report to this file instead of stdout")
		quiet  = fs.Bool("quiet", false, "suppress the report; only set the exit code")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl redteam [flags]")
		fmt.Fprintln(os.Stderr, "Run the supply-chain attack red-team / gate-efficacy suite in-process.")
		fmt.Fprintln(os.Stderr, "Exits non-zero if any scenario regresses (an attack that should block is admitted).")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	rep, err := redteam.Run(context.Background())
	if err != nil {
		return fmt.Errorf("running red-team suite: %w", err)
	}

	if !*quiet {
		var rendered string
		switch strings.ToLower(strings.TrimSpace(*format)) {
		case "json":
			b, err := rep.JSON()
			if err != nil {
				return fmt.Errorf("rendering JSON: %w", err)
			}
			rendered = string(b) + "\n"
		case "markdown", "md", "":
			rendered = rep.Markdown()
		default:
			return fmt.Errorf("unknown --format %q (want markdown|json)", *format)
		}

		if path := strings.TrimSpace(*output); path != "" {
			if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Fprintf(os.Stderr, "wrote red-team report to %s\n", path)
		} else {
			fmt.Print(rendered)
		}
	}

	// Summarize to stderr so the exit code's meaning is visible even when the
	// report is written to a file or suppressed.
	fmt.Fprintf(os.Stderr, "red-team: %d scenarios, %d passed, %d failed, %d regression(s)\n",
		rep.Total, rep.Passed, rep.Failed, rep.Regressions)
	if !rep.OK() {
		return fmt.Errorf("%d scenario(s) failed (%d regression(s))", rep.Failed, rep.Regressions)
	}
	return nil
}
