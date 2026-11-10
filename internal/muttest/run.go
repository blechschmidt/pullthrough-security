package muttest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// defaultMemLimitBytes bounds the resident memory of a single mutant test run.
// A runaway-allocation mutant would otherwise exhaust host RAM and get a CI
// runner OOM-reclaimed mid-run; the gate packages' legitimate tests run in well
// under this, so a process that exceeds it is a mutant that blew up and is
// scored as killed.
const defaultMemLimitBytes int64 = 1 << 31 // 2 GiB

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
// behave exactly as under `go test`). A timeout is enforced both via the Go test
// harness (`-test.timeout`) and a hard kill, so a mutant that induces an infinite
// loop is reliably caught and counted as killed rather than hanging CI. When
// memLimitBytes > 0 the run is additionally bounded in memory (see the watchdog
// below) so a runaway-allocation mutant cannot exhaust host RAM.
func runTestBinary(ctx context.Context, binPath, pkgDir string, timeout time.Duration, short bool, memLimitBytes int64) runOutcome {
	// Give the in-binary test timeout a little less than the hard kill deadline so
	// Go prints a useful goroutine dump before we SIGKILL the process group.
	inner := timeout - 2*time.Second
	if inner < time.Second {
		inner = timeout
	}
	args := []string{"-test.timeout", inner.String()}
	if short {
		args = append(args, "-test.short")
	}
	cmd := exec.Command(binPath, args...)
	cmd.Dir = pkgDir
	cmd.Env = os.Environ()
	if memLimitBytes > 0 {
		// Make the Go runtime GC hard as it nears the cap so a runaway allocation is
		// throttled enough for the RSS watchdog to catch it before it balloons.
		cmd.Env = append(cmd.Env, fmt.Sprintf("GOMEMLIMIT=%d", memLimitBytes))
	}
	// Put the child in its own process group so the timeout/memory watchdog can
	// kill the whole subtree, not just the parent.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Output is discarded: a mutant run is expected to fail noisily, and we only
	// care about the pass/fail signal, not the diagnostics.

	if err := cmd.Start(); err != nil {
		return outcomeFail
	}
	pid := cmd.Process.Pid
	killGroup := func() { _ = syscall.Kill(-pid, syscall.SIGKILL) }

	var timedOut, memKilled atomic.Bool
	stop := make(chan struct{})
	go func() {
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		var memTick <-chan time.Time
		if memLimitBytes > 0 && runtime.GOOS == "linux" {
			tk := time.NewTicker(150 * time.Millisecond)
			defer tk.Stop()
			memTick = tk.C
		}
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				killGroup()
				return
			case <-deadline.C:
				timedOut.Store(true)
				killGroup()
				return
			case <-memTick:
				if rss, ok := processRSSBytes(pid); ok && rss > uint64(memLimitBytes) {
					memKilled.Store(true)
					killGroup()
					return
				}
			}
		}
	}()

	err := cmd.Wait()
	close(stop)

	switch {
	case memKilled.Load():
		// A mutant that blew past the memory cap changed behavior detectably: killed.
		return outcomeFail
	case timedOut.Load():
		return outcomeTimeout
	case err == nil:
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

// processRSSBytes returns the resident set size of a process in bytes, read from
// /proc/<pid>/statm (Linux). The second field is the resident page count.
func processRSSBytes(pid int) (uint64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}
