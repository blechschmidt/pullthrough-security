// Command gen-llmscan-coverage renders docs/llm-package-scan-coverage.md from
// the LLM-scan coverage catalog (internal/scancoverage): for every upstream
// type, the request paths that carry installable content, the format each
// arrives in, the serve path it takes, and which LLM scan examines it.
//
// The catalog is checked against the real backends by a test, and this command
// keeps the published table identical to the catalog, so the document states
// what the code does rather than what someone once wrote down.
//
// Usage:
//
//	gen-llmscan-coverage            # write docs/llm-package-scan-coverage.md
//	gen-llmscan-coverage -o -       # write the document to stdout
//	gen-llmscan-coverage -check     # exit non-zero if the committed file is stale
//
// The Makefile wires `llmscan-coverage-gen` (write) and `llmscan-coverage-check`
// (CI staleness gate) to this command, mirroring the other reference generators.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/scancoverage"
)

const defaultOutput = "docs/llm-package-scan-coverage.md"

func main() {
	out := flag.String("o", defaultOutput, "output file path, or - for stdout")
	check := flag.Bool("check", false, "verify the committed document is up to date (no write); exit 1 if stale")
	flag.Parse()

	if err := scancoverage.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: %v\n", err)
		os.Exit(1)
	}
	content := scancoverage.GenerateReference()

	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: cannot read %s: %v\n", *out, err)
			os.Exit(1)
		}
		if string(existing) != content {
			fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: %s is stale; run `make llmscan-coverage-gen` and commit the result\n", *out)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: %s is up to date\n", *out)
		return
	}

	if *out == "-" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gen-llmscan-coverage: wrote %s\n", *out)
}
