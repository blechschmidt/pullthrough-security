//go:build unix

package git

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts cmd as the leader of a process group of its own, so
// that killProcessGroup ends it together with every helper it starts. git
// hands its pipes to its helpers (git-remote-http, ssh, a lazy fetch); killing
// git alone would leave them running, holding the pipes open, and the caller
// waiting.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// isolateProcess is ownProcessGroup for a command made with
// exec.CommandContext: a cancelled context kills the whole group.
func isolateProcess(cmd *exec.Cmd) {
	ownProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
}

// killProcessGroup kills cmd's process group.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
