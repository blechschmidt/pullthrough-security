package muttest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// compileResult is the outcome of building a package's test binary.
type compileResult struct {
	built   bool   // true if a runnable test binary was produced
	hasTest bool   // false when the package has no test files at all
	output  string // combined build output (compiler errors on failure)
}

// compileTestBinary runs `go test -c -o <out> <pattern>` from the module
// directory. It distinguishes three states the engine must treat differently:
//
//   - built:              a test binary was produced (ready to run)
//   - compile failure:    build error (a mutant that does not type-check — an
//     INVALID mutant that must be excluded from the score)
//   - no test files:      the package has nothing to run (not a valid target)
func compileTestBinary(ctx context.Context, goBin, moduleDir, pattern, outPath string, timeout time.Duration) (compileResult, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Remove any stale binary so a build failure cannot be mistaken for success.
	_ = os.Remove(outPath)

	cmd := exec.CommandContext(cctx, goBin, "test", "-c", "-o", outPath, pattern)
	cmd.Dir = moduleDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	res := compileResult{output: string(out)}

	if _, statErr := os.Stat(outPath); statErr == nil {
		res.built = true
		res.hasTest = true
		return res, nil
	}
	// No binary produced. "no test files" is a clean exit with no binary; a build
	// failure is a non-zero exit with compiler diagnostics.
	if strings.Contains(res.output, "[no test files]") || strings.Contains(res.output, "no test files") {
		res.hasTest = false
		return res, nil
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, context.DeadlineExceeded
	}
	// Treat any remaining non-success as a compile failure; err carries the exit.
	return res, err
}

// runOutcome classifies the result of running a compiled test binary.
type runOutcome int

const (
	outcomePass    runOutcome = iota // tests passed (mutant SURVIVED)
	outcomeFail                      // tests failed (mutant KILLED)
	outcomeTimeout                   // run exceeded the timeout (mutant KILLED)
)

// runTestBinary executes a compiled test binary with its working directory set
// to the package source directory (so tests that read testdata by relative path
// behave exactly as under `go test`). A timeout is enforced both via the Go
// test harness (`-test.timeout`) and the context, so a mutant that induces an
// infinite loop is reliably caught and counted as killed rather than hanging CI.
func runTestBinary(ctx context.Context, binPath, pkgDir string, timeout time.Duration, short bool) runOutcome {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Give the in-binary test timeout a little less than the hard context
	// deadline so Go prints a useful goroutine dump before the context kills it.
	inner := timeout - 2*time.Second
	if inner < time.Second {
		inner = timeout
	}
	args := []string{"-test.timeout", inner.String()}
	if short {
		args = append(args, "-test.short")
	}
	cmd := exec.CommandContext(rctx, binPath, args...)
	cmd.Dir = pkgDir
	cmd.Env = os.Environ()
	// Output is discarded: a mutant run is expected to fail noisily, and we only
	// care about the pass/fail signal, not the diagnostics.
	err := cmd.Run()

	if rctx.Err() == context.DeadlineExceeded {
		return outcomeTimeout
	}
	if err == nil {
		return outcomePass
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return outcomeFail
	}
	// A non-exit error (binary vanished, etc.) is treated as a failed run so a
	// transient issue is conservatively scored as killed rather than a survivor.
	return outcomeFail
}
