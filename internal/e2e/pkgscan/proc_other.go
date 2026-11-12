//go:build integration && !linux
// +build integration,!linux

package pkgscan

import "os/exec"

// setParentDeathSignal is a no-op where the kernel offers no parent-death
// signal; the suite stops every process it starts in its own cleanup.
func setParentDeathSignal(*exec.Cmd) {}
