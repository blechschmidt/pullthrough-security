// Command gen-config-reference renders docs/configuration-reference.md from the
// configuration struct definitions and their compiled-in defaults, so the
// reference documentation cannot silently drift from the code.
//
// Usage:
//
//	gen-config-reference            # write docs/configuration-reference.md
//	gen-config-reference -o -       # write the reference to stdout
//	gen-config-reference -check     # exit non-zero if the committed file is stale
//
// The Makefile wires `config-reference-gen` (write) and `config-reference-check`
// (CI staleness gate) to this command, mirroring the observability-gen pattern.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

const defaultOutput = "docs/configuration-reference.md"

func main() {
	out := flag.String("o", defaultOutput, "output file path, or - for stdout")
	check := flag.Bool("check", false, "verify the committed reference is up to date (no write); exit 1 if stale")
	flag.Parse()

	content := config.GenerateReference()

	if *check {
		existing, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-config-reference: cannot read %s: %v\n", *out, err)
			os.Exit(1)
		}
		if string(existing) != content {
			fmt.Fprintf(os.Stderr, "gen-config-reference: %s is stale; run `make config-reference-gen` and commit the result\n", *out)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "gen-config-reference: %s is up to date\n", *out)
		return
	}

	if *out == "-" {
		fmt.Print(content)
		return
	}
	if err := os.WriteFile(*out, []byte(content), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-config-reference: writing %s: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "gen-config-reference: wrote %s\n", *out)
}
