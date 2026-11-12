package userlinks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned by a Store for an object that does not exist.
var ErrNotFound = errors.New("userlinks: object not found")

// maxObjectBytes bounds the size of one stored object. Every object is a small
// JSON record; only a usage object grows with the number of links, and even
// that stays far below this.
const maxObjectBytes = 8 << 20

// Object describes one stored object.
type Object struct {
	// Name is the object's name, "<kind>/<key>".
	Name string
	// Version changes whenever the object's content changes. It is opaque: a
	// modification time and size for a file, an ETag for an object store.
	Version string
}

// Store is where the registry keeps its records: a flat namespace of small,
// named objects that every replica of the proxy can read and write.
//
// The registry asks little of it. Put replaces an object as a whole and is
// atomic — a reader sees the old content or the new, never a mix. There is no
// compare-and-swap and no locking: the registry is laid out so that it needs
// neither (see the package documentation).
//
// Implementations are safe for concurrent use.
type Store interface {
	// List returns every object.
	List(ctx context.Context) ([]Object, error)
	// Get returns an object's content, or ErrNotFound.
	Get(ctx context.Context, name string) ([]byte, error)
	// Put creates or replaces an object.
	Put(ctx context.Context, name string, data []byte) error
	// Delete removes an object. Removing one that does not exist is not an error.
	Delete(ctx context.Context, name string) error
	// Close releases the store's resources.
	Close() error
}

// validObjectName reports whether name is one the registry uses: a kind made of
// lower-case letters, a slash, and a key made of the characters of hashes and
// node names. Stores refuse anything else, so that no object name — whatever
// produced it — can address a file outside the store's directory.
func validObjectName(name string) bool {
	kind, key, ok := strings.Cut(name, "/")
	if !ok || kind == "" || key == "" || len(name) > 200 {
		return false
	}
	for i := 0; i < len(kind); i++ {
		if c := kind[i]; c < 'a' || c > 'z' {
			return false
		}
	}
	if key[0] == '.' || key[0] == '-' {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// --- in memory --------------------------------------------------------------

// MemoryStore keeps the registry in memory. Links do not survive a restart and
// are not shared with other replicas: it is for tests and for trying the
// feature out.
type MemoryStore struct {
	mu      sync.Mutex
	objects map[string]memObject
	gen     uint64
}

type memObject struct {
	data []byte
	gen  uint64
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{objects: map[string]memObject{}}
}

// List implements Store.
func (m *MemoryStore) List(ctx context.Context) ([]Object, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Object, 0, len(m.objects))
	for name, obj := range m.objects {
		out = append(out, Object{Name: name, Version: strconv.FormatUint(obj.gen, 10)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get implements Store.
func (m *MemoryStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	obj, ok := m.objects[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), obj.data...), nil
}

// Put implements Store.
func (m *MemoryStore) Put(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validObjectName(name) {
		return fmt.Errorf("userlinks: invalid object name %q", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++
	m.objects[name] = memObject{data: append([]byte(nil), data...), gen: m.gen}
	return nil
}

// Delete implements Store.
func (m *MemoryStore) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, name)
	return nil
}

// Close implements Store.
func (m *MemoryStore) Close() error { return nil }

// --- a directory ------------------------------------------------------------

// DirStore keeps the registry in a directory: one file per object,
// "<dir>/<kind>/<key>.json". On a single host that is a local directory; for
// several replicas it is a directory on a volume they all mount.
//
// A file is written to a temporary name and renamed into place, so a reader —
// in this process or in another replica — never sees one half-written. Files
// are created private (0600, in 0700 directories): they hold who the users are.
type DirStore struct {
	dir string
}

// objectFileSuffix is the extension of an object's file.
const objectFileSuffix = ".json"

// NewDirStore opens (creating it if need be) the directory store at dir. It
// fails when the directory cannot be created or written to: a registry that
// silently could not remember a link would be worse than one that refuses to
// start.
func NewDirStore(dir string) (*DirStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("userlinks: the store directory is not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("userlinks: creating the store directory: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("userlinks: the store directory %q is not writable: %w", dir, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	d := &DirStore{dir: dir}
	d.sweepTemporaries()
	return d, nil
}

// staleTemporaryAge is how old a temporary file must be before it is taken for
// the leftover of a write that never finished (a crash, a full disk) rather
// than a write in progress — by this process or by another replica.
const staleTemporaryAge = time.Hour

// sweepTemporaries removes the leftovers of writes that never finished.
func (d *DirStore) sweepTemporaries() {
	kinds, err := os.ReadDir(d.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTemporaryAge)
	for _, kind := range kinds {
		if !kind.IsDir() {
			continue
		}
		sub := filepath.Join(d.dir, kind.Name())
		entries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasPrefix(e.Name(), ".tmp-") {
				continue
			}
			if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
				_ = os.Remove(filepath.Join(sub, e.Name()))
			}
		}
	}
}

func (d *DirStore) path(name string) (string, error) {
	if !validObjectName(name) {
		return "", fmt.Errorf("userlinks: invalid object name %q", name)
	}
	kind, key, _ := strings.Cut(name, "/")
	return filepath.Join(d.dir, kind, key+objectFileSuffix), nil
}

// List implements Store. It walks the two levels of the layout and ignores
// everything that is not an object file: temporary files of writes in progress,
// and whatever else was put in the directory.
func (d *DirStore) List(ctx context.Context) ([]Object, error) {
	kinds, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, fmt.Errorf("userlinks: reading the store directory: %w", err)
	}
	var out []Object
	for _, kind := range kinds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !kind.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(d.dir, kind.Name()))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("userlinks: reading the store directory: %w", err)
		}
		for _, e := range entries {
			key, ok := strings.CutSuffix(e.Name(), objectFileSuffix)
			if !ok || e.IsDir() {
				continue
			}
			name := kind.Name() + "/" + key
			if !validObjectName(name) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					// Removed between the listing and the stat: it is gone.
					continue
				}
				// Anything else would leave the object out of the listing, and
				// an object left out reads as one that was deleted.
				return nil, fmt.Errorf("userlinks: reading the store directory: %w", err)
			}
			out = append(out, Object{
				Name:    name,
				Version: strconv.FormatInt(info.ModTime().UnixNano(), 10) + "-" + strconv.FormatInt(info.Size(), 10),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get implements Store.
func (d *DirStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("userlinks: reading %s: %w", name, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("userlinks: reading %s: %w", name, err)
	}
	if len(data) > maxObjectBytes {
		return nil, fmt.Errorf("userlinks: %s is larger than an object can be", name)
	}
	return data, nil
}

// Put implements Store.
func (d *DirStore) Put(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	// The temporary file starts with a dot and does not end in the object
	// suffix, so a listing never takes it for an object.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	// The record must be on disk before the rename makes it the truth: a link
	// that exists only in the page cache is lost with the power.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		cleanup()
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	// The rename itself is a change of the directory: until the directory is
	// on disk, a write that was acknowledged — a revocation — can be undone by
	// a power failure.
	if err := syncDir(filepath.Dir(p)); err != nil {
		return fmt.Errorf("userlinks: writing %s: %w", name, err)
	}
	return nil
}

// syncDir flushes a directory's entries to disk.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// Delete implements Store.
func (d *DirStore) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("userlinks: deleting %s: %w", name, err)
	}
	return nil
}

// Close implements Store.
func (d *DirStore) Close() error { return nil }
