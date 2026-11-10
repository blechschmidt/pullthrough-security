package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/testset"
)

// runTestset implements `ptctl testset [flags]`: it validates the ecosystem
// test-set corpus (real minimal builds for npm, pip, cargo, go, nuget, maven,
// docker, helm, rubygems, composer, terraform, conan, apt, yum, git) and drives
// each fixture's representative pulls end-to-end through an in-process gateway,
// printing a coverage matrix (ecosystem × index/artifact × served/cached).
//
// Like `ptctl redteam`, it is fully self-contained and offline: it spins up
// in-process gateways with deterministic stub upstreams and needs no running
// proxy, URL, or token. It exits non-zero if the corpus is incomplete/malformed
// or any ecosystem fails to route/serve/cache, so it doubles as a CI check.
func runTestset(args []string) error {
	fs := flag.NewFlagSet("testset", flag.ContinueOnError)
	var (
		format = fs.String("format", "markdown", "output format: markdown|json")
		output = fs.String("output", "", "write the report to this file instead of stdout")
		list   = fs.Bool("list", false, "list the corpus fixtures and exit (no end-to-end run)")
		quiet  = fs.Bool("quiet", false, "suppress the report; only set the exit code")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ptctl testset [flags]")
		fmt.Fprintln(os.Stderr, "Validate and exercise the ecosystem test-set corpus of real minimal builds in-process.")
		fmt.Fprintln(os.Stderr, "Exits non-zero if the corpus is incomplete or any ecosystem fails to route/serve/cache.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *list {
		for _, f := range testset.Corpus() {
			fmt.Printf("%-10s %-20s %s (%s)\n", f.ID, f.Backend, f.Dep.Coordinate(), f.BuildCmd)
		}
		return nil
	}

	rep := testset.Run(context.Background())

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
			fmt.Fprintf(os.Stderr, "wrote test-set report to %s\n", path)
		} else {
			fmt.Print(rendered)
		}
	}

	if !rep.OK() {
		return fmt.Errorf("test-set run failed: %d/%d ecosystems passed (complete=%v)", rep.Passed, rep.Total, rep.Complete)
	}
	return nil
}
