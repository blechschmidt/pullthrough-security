// Command forwarder is the in-container half of a sandbox job for the
// package's tests: what "pullthrough sandbox-exec" is in production.
package main

import (
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/repos/sandbox"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] != "sandbox-exec" {
		fmt.Fprintln(os.Stderr, "usage: forwarder sandbox-exec <spec>")
		os.Exit(2)
	}
	os.Exit(sandbox.ExecMain(os.Args[2]))
}
