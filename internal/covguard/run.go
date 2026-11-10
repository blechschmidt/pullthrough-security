package covguard

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// RunOptions configures a `go test ... -coverprofile` invocation.
type RunOptions struct {
	// GoBin is the go binary to invoke (default "go", resolved via PATH).
	GoBin string
	// Packages is the package pattern to test (default "./...").
	Packages string
	// CoverMode is the cover mode (set/count/atomic; default "set"). The chosen
	// mode does not affect the computed percentage.
	CoverMode string
	// CoverProfile is the path the profile is written to (required).
	CoverProfile string
	// ExtraArgs are appended to the `go test` command (e.g. "-count=1").
	ExtraArgs []string
	// Dir is the working directory for the command (default: current).
	Dir string
	// Stdout/Stderr receive the live test output; nil discards. go test output
	// is noisy but valuable in CI logs, so callers typically pass os.Stderr.
	Stdout io.Writer
	Stderr io.Writer
}

// RunGoTest runs `go test <packages> -coverprofile=<file> -covermode=<mode>`
// and returns an error if the test run itself failed. The coverage profile is
// still parsed by the caller afterward; a test failure must fail the guard, so
// a non-zero exit is surfaced here rather than swallowed.
func RunGoTest(ctx context.Context, opts RunOptions) error {
	if opts.CoverProfile == "" {
		return fmt.Errorf("covguard: CoverProfile is required")
	}
	goBin := opts.GoBin
	if goBin == "" {
		goBin = "go"
	}
	pkgs := opts.Packages
	if pkgs == "" {
		pkgs = "./..."
	}
	mode := opts.CoverMode
	if mode == "" {
		mode = "set"
	}

	args := []string{"test", pkgs,
		"-coverprofile=" + opts.CoverProfile,
		"-covermode=" + mode,
	}
	args = append(args, opts.ExtraArgs...)

	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Dir = opts.Dir
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	// Inherit the environment so GOFLAGS/GOCACHE/proxy settings apply.
	cmd.Env = os.Environ()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("`%s %s` failed: %w", goBin, strings.Join(args, " "), err)
	}
	return nil
}
