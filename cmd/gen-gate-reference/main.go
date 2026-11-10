// Command gen-gate-reference renders docs/gates-reference.md from the in-code
// admission-gate catalog (internal/gatedoc) joined with the findings SARIF rule
// catalog (internal/findings), so the unified gate reference cannot silently
// drift from the code.
//
// Usage:
//
//	gen-gate-reference            # write docs/gates-reference.md
//	gen-gate-reference -o -       # write the reference to stdout
//	gen-gate-reference -check     # exit non-zero if the committed file is stale
//
// The Makefile wires `gate-reference-gen` (write) and `gate-reference-check`
// (CI staleness gate) to this command, mirroring gen-config-reference.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/gatedoc"
)

const defaultOutput = "docs/gates-reference.md"

func main() {
	out := flag.String("o", defaultOutput, "output file path, or - for stdout")
	check := flag.Bool("check", false, "verify the committed reference is up to date (no write); exit 1 if stale")
	flag.Parse()

	content := gatedoc.GenerateReference()

	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-gate-reference: cannot read %s: %v\n", *out, err)
			os.Exit(1)
		}
		if string(existing) != content {
			fmt.Fprintf(os.Stderr, "gen-gate-reference: %s is stale; run `make gate-reference-gen` and commit the result\n", *out)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gen-gate-reference: %s is up to date\n", *out)
		return
	}

	if *out == "-" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-gate-reference: writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gen-gate-reference: wrote %s\n", *out)
}
