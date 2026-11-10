package coord

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// fileBackend is a compare-and-swap lease store backed by files on a shared
// POSIX volume (e.g. an NFS / EFS PVC mounted by every replica). It is the
// Redis-free, SQL-free option for deployments that already share a filesystem but
// have no object store.
//
// Each lease is a JSON file under dir; its CAS version is the SHA-256 of the file
// content, so an update/remove only proceeds when the file still holds exactly
// the bytes the caller last read. Cross-process atomicity of the read-modify-write
// is provided by an advisory file lock (flock) on a per-lease lock file, which is
// honored on local filesystems and NFSv4. First acquisition uses O_CREATE|O_EXCL
// so only one creator wins.
//
// Note: advisory locking semantics on some networked filesystems are weaker than
// local ones; the lease TTL and fencing token remain the ultimate guard against
// split-brain regardless.
type fileBackend struct {
	dir string

	mu    sync.Mutex
	locks map[string]*sync.Mutex // intra-process serialization per lease name
}

func newFileBackend(dir string) (*fileBackend, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("coord: file backend requires a directory (coordination.dir)")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("coord: creating lease dir %q: %w", dir, err)
	}
	return &fileBackend{dir: dir, locks: make(map[string]*sync.Mutex)}, nil
}

// sanitizeName maps a lease name to a safe single path segment. Job names are
// simple identifiers ("backup", "malfeed-refresh"); this just defends against an
// unexpected separator escaping the lease dir.
func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, name)
}

func (b *fileBackend) path(name string) string {
	return filepath.Join(b.dir, sanitizeName(name)+".lease.json")
}

func (b *fileBackend) lockPath(name string) string {
	return filepath.Join(b.dir, sanitizeName(name)+".lock")
}

// nameMutex returns the per-name process-local mutex, creating it on first use,
// so concurrent goroutines in this process serialize before contending on flock.
func (b *fileBackend) nameMutex(name string) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.locks[name]
	if !ok {
		m = &sync.Mutex{}
		b.locks[name] = m
	}
	return m
}

// withLock runs fn while holding both the process-local mutex and an exclusive
// flock on the lease's lock file, serializing the read-modify-write across all
// replicas sharing the volume.
func (b *fileBackend) withLock(name string, fn func() error) error {
	m := b.nameMutex(name)
	m.Lock()
	defer m.Unlock()

	f, err := os.OpenFile(b.lockPath(name), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("coord: opening lock file for %q: %w", name, err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("coord: locking lease %q: %w", name, err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (b *fileBackend) load(_ context.Context, name string) (record, string, bool, error) {
	var (
		rec   record
		ver   string
		found bool
	)
	err := b.withLock(name, func() error {
		r, v, ok, e := b.readUnlocked(name)
		rec, ver, found = r, v, ok
		return e
	})
	return rec, ver, found, err
}

// readUnlocked reads and decodes the lease file, returning its content-hash
// version. The caller must hold the lock.
func (b *fileBackend) readUnlocked(name string) (record, string, bool, error) {
	data, err := os.ReadFile(b.path(name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return record{}, "", false, nil
		}
		return record{}, "", false, fmt.Errorf("coord: reading lease %q: %w", name, err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return record{}, "", false, fmt.Errorf("coord: decoding lease %q: %w", name, err)
	}
	return rec, hashVersion(data), true, nil
}

func (b *fileBackend) create(_ context.Context, name string, rec record) (string, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	var version string
	err = b.withLock(name, func() error {
		f, oerr := os.OpenFile(b.path(name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if oerr != nil {
			if errors.Is(oerr, os.ErrExist) {
				return ErrConflict
			}
			return fmt.Errorf("coord: creating lease %q: %w", name, oerr)
		}
		defer f.Close()
		if _, werr := f.Write(data); werr != nil {
			return fmt.Errorf("coord: writing lease %q: %w", name, werr)
		}
		version = hashVersion(data)
		return nil
	})
	return version, err
}

func (b *fileBackend) update(_ context.Context, name, expectedVersion string, rec record) (string, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	var version string
	err = b.withLock(name, func() error {
		_, ver, ok, rerr := b.readUnlocked(name)
		if rerr != nil {
			return rerr
		}
		if !ok || ver != expectedVersion {
			return ErrConflict
		}
		if werr := b.writeAtomic(name, data); werr != nil {
			return werr
		}
		version = hashVersion(data)
		return nil
	})
	return version, err
}

func (b *fileBackend) remove(_ context.Context, name, expectedVersion string) error {
	return b.withLock(name, func() error {
		_, ver, ok, rerr := b.readUnlocked(name)
		if rerr != nil {
			return rerr
		}
		if !ok {
			return nil
		}
		if ver != expectedVersion {
			return ErrConflict
		}
		if err := os.Remove(b.path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("coord: removing lease %q: %w", name, err)
		}
		return nil
	})
}

// writeAtomic replaces the lease file by writing a temp file and renaming it, so
// a concurrent reader never observes a partial write. The caller holds the lock.
func (b *fileBackend) writeAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(b.dir, sanitizeName(name)+".tmp-*")
	if err != nil {
		return fmt.Errorf("coord: staging lease %q: %w", name, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("coord: writing lease %q: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, b.path(name)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("coord: committing lease %q: %w", name, err)
	}
	return nil
}

func (b *fileBackend) close() error { return nil }

// hashVersion is the content-hash CAS token for a lease file's bytes.
func hashVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
