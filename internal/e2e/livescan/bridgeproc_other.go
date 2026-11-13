//go:build !linux

package livescan

import "os/exec"

// prepareCLI leaves the process as exec starts it; cancellation kills it.
func prepareCLI(*exec.Cmd) {}

// setParentDeathSignal is a no-op where the kernel has no parent-death signal.
func setParentDeathSignal(*exec.Cmd) {}

// reapCLI is a no-op where there are no process groups to sweep.
func reapCLI(*exec.Cmd) {}
