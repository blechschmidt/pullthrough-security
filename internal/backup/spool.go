package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// spool holds the private copies of a backup's Volatile files, from the pass
// that builds the manifest to the pass that streams the archive.
type spool struct {
	parent string
	once   sync.Once
	dir    string
	err    error
	n      int
}

// capture copies src into the spool, hashing it on the way, and returns the
// copy's path, its "sha256:<hex>" digest and the source's file info. A source
// that no longer exists is reported with an error wrapping fs.ErrNotExist.
func (s *spool) capture(src string) (string, string, os.FileInfo, error) {
	s.once.Do(func() { s.dir, s.err = os.MkdirTemp(s.parent, "pullthrough-backup-spool-") })
	if s.err != nil {
		return "", "", nil, s.err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", "", nil, err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return "", "", nil, err
	}
	if !fi.Mode().IsRegular() {
		return "", "", nil, &fs.PathError{Op: "open", Path: src, Err: fs.ErrNotExist}
	}
	s.n++
	dst := filepath.Join(s.dir, "f"+strconv.Itoa(s.n))
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", nil, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", "", nil, err
	}
	// The open file is the one copied: report its size as copied, whatever a
	// rename has put at the path since.
	return dst, "sha256:" + hex.EncodeToString(h.Sum(nil)), sizedInfo{FileInfo: fi, size: n}, nil
}

// remove deletes the spool.
func (s *spool) remove() {
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
	}
}

// sizedInfo is a FileInfo whose size is the number of bytes copied.
type sizedInfo struct {
	os.FileInfo
	size int64
}

func (s sizedInfo) Size() int64 { return s.size }
