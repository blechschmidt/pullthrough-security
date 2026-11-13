// Command gen-lockfile-reference renders the generated part of
// docs/lockfiles.md from the lock-file scanner's own tables
// (internal/lockfiles): every format with what is read from it, the digests
// it records and what they are hashes of, its limits, and the upstream types
// without a lock-file format with the reason. Only the part between the
// document's markers is generated; the rest of the page is written by hand.
//
// The tables are held to the code and to the golden fixtures by tests, and
// this command keeps the published page identical to the tables.
//
// Usage:
//
//	gen-lockfile-reference            # rewrite the generated part of docs/lockfiles.md
//	gen-lockfile-reference -o -       # print the generated part
//	gen-lockfile-reference -check     # exit non-zero if the committed page is stale
//
// The Makefile wires `lockfile-reference-gen` (write) and
// `lockfile-reference-check` (CI staleness gate) to this command, mirroring
// the other reference generators.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/lockfiles"
)

const defaultOutput = "docs/lockfiles.md"

func main() {
	out := flag.String("o", defaultOutput, "document to update, or - to print the generated part")
	check := flag.Bool("check", false, "verify the committed document is up to date (no write); exit 1 if stale")
	flag.Parse()

	generated := lockfiles.GenerateReference()
	if *out == "-" {
		fmt.Print(generated)
		return
	}
	existing, err := os.ReadFile(*out)
	if err != nil {
		fail("cannot read %s: %v", *out, err)
	}
	updated, err := lockfiles.SpliceReference(string(existing), generated)
	if err != nil {
		fail("%s: %v", *out, err)
	}
	if *check {
		if updated != string(existing) {
			fail("%s is stale; run `make lockfile-reference-gen` and commit the result", *out)
		}
		fmt.Fprintf(os.Stderr, "gen-lockfile-reference: %s is up to date\n", *out)
		return
	}
	if updated == string(existing) {
		fmt.Fprintf(os.Stderr, "gen-lockfile-reference: %s is up to date\n", *out)
		return
	}
	if err := os.WriteFile(*out, []byte(updated), 0o644); err != nil {
		fail("writing %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "gen-lockfile-reference: wrote %s\n", *out)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen-lockfile-reference: "+format+"\n", args...)
	os.Exit(1)
}
