//go:build !unix

package git

import "os/exec"

// ownProcessGroup has no process groups to work with on this platform; the
// process is killed alone (and WaitDelay bounds the wait for its pipes).
func ownProcessGroup(cmd *exec.Cmd) {}

// isolateProcess is ownProcessGroup for a command made with
// exec.CommandContext.
func isolateProcess(cmd *exec.Cmd) {}

// killProcessGroup kills cmd's process.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
