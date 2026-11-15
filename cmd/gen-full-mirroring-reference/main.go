// Command gen-full-mirroring-reference renders the generated part of
// docs/full-mirroring.md from the full-mirroring catalog
// (internal/fullmirror): for every upstream type, how its public registry can
// be followed ahead of client requests — tier, feeds with their endpoints and
// cursors, rate limits, terms of use, the realistic size of a full mirror,
// private-upstream behaviour, sources and the implementation status. Only the
// part between the document's markers is generated; the rest of the page is
// written by hand.
//
// A test holds the catalog to config.UpstreamTypes, and this command keeps the
// published page identical to the catalog.
//
// Usage:
//
//	gen-full-mirroring-reference            # rewrite the generated part of docs/full-mirroring.md
//	gen-full-mirroring-reference -o -       # print the generated part
//	gen-full-mirroring-reference -check     # exit non-zero if the committed page is stale
//
// The Makefile wires `full-mirroring-reference-gen` (write) and
// `full-mirroring-reference-check` (CI staleness gate) to this command,
// mirroring the other reference generators.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/fullmirror"
)

const defaultOutput = "docs/full-mirroring.md"

func main() {
	out := flag.String("o", defaultOutput, "document to update, or - to print the generated part")
	check := flag.Bool("check", false, "verify the committed document is up to date (no write); exit 1 if stale")
	flag.Parse()

	if *check && *out == "-" {
		fail("-check compares a committed document; give it a file with -o, not -")
	}
	if err := fullmirror.Validate(); err != nil {
		fail("%v", err)
	}
	generated := fullmirror.GenerateReference()
	if *out == "-" {
		fmt.Print(generated)
		return
	}
	existing, err := os.ReadFile(*out)
	if err != nil {
		fail("cannot read %s: %v", *out, err)
	}
	updated, err := fullmirror.SpliceReference(string(existing), generated)
	if err != nil {
		fail("%s: %v", *out, err)
	}
	if *check {
		if updated != string(existing) {
			fail("%s is stale; run `make full-mirroring-reference-gen` and commit the result", *out)
		}
		fmt.Fprintf(os.Stderr, "gen-full-mirroring-reference: %s is up to date\n", *out)
		return
	}
	if updated == string(existing) {
		fmt.Fprintf(os.Stderr, "gen-full-mirroring-reference: %s is up to date\n", *out)
		return
	}
	if err := os.WriteFile(*out, []byte(updated), 0o644); err != nil {
		fail("writing %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "gen-full-mirroring-reference: wrote %s\n", *out)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-full-mirroring-reference: "+format+"\n", args...)
	os.Exit(1)
}
