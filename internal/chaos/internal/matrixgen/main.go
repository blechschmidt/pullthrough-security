// Command matrixgen runs the chaos resilience catalog and prints the resilience
// matrix as Markdown to stdout. It is the generator behind docs/resilience.md
// and the task's resilience-matrix.md attachment:
//
//	go run ./internal/chaos/internal/matrixgen > docs/resilience-matrix.md
//
// It is a thin wrapper over chaos.Run; the catalog itself is the source of
// truth, so the generated matrix can never drift from the verified behavior.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/blechschmidt/pullthrough-security/internal/chaos"
)

func main() {
	rep, err := chaos.Run(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrixgen:", err)
		os.Exit(1)
	}
	fmt.Print(rep.Markdown())
	if rep.Failed > 0 {
		os.Exit(1)
	}
}
