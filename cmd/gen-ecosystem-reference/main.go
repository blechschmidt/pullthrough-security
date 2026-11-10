// Command gen-ecosystem-reference renders docs/ecosystem-tests-reference.md from
// the real-package-manager ecosystem test catalog (internal/ecotest): for every
// ecosystem, the client CI runs, the registry it pulls from, and the verbatim
// script that points that client at the proxy. Generating the document from
// what CI executes keeps the published client configurations from drifting away
// from the ones that are actually tested.
//
// Usage:
//
//	gen-ecosystem-reference            # write docs/ecosystem-tests-reference.md
//	gen-ecosystem-reference -o -       # write the reference to stdout
//	gen-ecosystem-reference -check     # exit non-zero if the committed file is stale
//
// The Makefile wires `ecosystem-reference-gen` (write) and
// `ecosystem-reference-check` (CI staleness gate) to this command, mirroring
// gen-config-reference and gen-gate-reference.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/ecotest"
)

const defaultOutput = "docs/ecosystem-tests-reference.md"

func main() {
	out := flag.String("o", defaultOutput, "output file path, or - for stdout")
	check := flag.Bool("check", false, "verify the committed reference is up to date (no write); exit 1 if stale")
	flag.Parse()

	if err := ecotest.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: %v\n", err)
		os.Exit(1)
	}
	content := ecotest.GenerateReference()

	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: cannot read %s: %v\n", *out, err)
			os.Exit(1)
		}
		if string(existing) != content {
			fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: %s is stale; run `make ecosystem-reference-gen` and commit the result\n", *out)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: %s is up to date\n", *out)
		return
	}

	if *out == "-" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gen-ecosystem-reference: wrote %s\n", *out)
}
