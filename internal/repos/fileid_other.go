//go:build !unix

package repos

import "io/fs"

// fileID is not known here; the size and modification time stand alone.
func fileID(fs.FileInfo) uint64 { return 0 }
