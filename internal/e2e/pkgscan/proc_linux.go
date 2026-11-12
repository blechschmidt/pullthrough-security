//go:build integration && linux
// +build integration,linux

package pkgscan

import (
	"os/exec"
	"syscall"
)

// setParentDeathSignal has the kernel kill a proxy process when the test
// binary that started it dies, so an aborted run (a panic, a timeout, Ctrl-C)
// leaves no proxy behind.
func setParentDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
