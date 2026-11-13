//go:build unix

package sandbox

import "syscall"

// limitFileSize caps the size of any one file the job's commands write
// (RLIMIT_FSIZE, inherited by every process they start): a write past it
// fails instead of filling the work directory, which is a host directory.
func limitFileSize(max uint64) error {
	return syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: max, Max: max})
}
