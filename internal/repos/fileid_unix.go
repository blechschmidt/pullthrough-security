//go:build unix

package repos

import (
	"io/fs"
	"syscall"
)

// fileID returns the inode of a file: every write of an object renames a new
// file into place, so a new write is a new inode even within one tick of the
// (coarse) modification-time clock.
func fileID(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
