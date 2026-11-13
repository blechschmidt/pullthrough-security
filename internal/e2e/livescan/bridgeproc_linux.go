//go:build linux

package livescan

import (
	"os/exec"
	"syscall"
)

// prepareCLI runs the CLI in a process group of its own, killed as a whole
// when the call is cancelled, and killed by the kernel if the test binary
// dies first — an aborted run leaves no CLI process behind.
func prepareCLI(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// setParentDeathSignal has the kernel kill a proxy process when the test
// binary that started it dies.
func setParentDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// reapCLI kills whatever the CLI left in its process group after it exited
// normally: a helper it started must not outlive the call.
func reapCLI(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
