package repos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store keeps the registry's state: small named objects in a flat namespace
// of "<kind>/<key>" or "<kind>/<group>/<key>" names.
//
// The layout (see the objects named in service.go):
//
//	repos/<repo>                 registrations made through the API
//	history/<repo>/<seq>         the append-only tag history, one record each
//	manifests/<repo>/<commit>    release manifests
//	live/<repo>                  what the tracker last saw (volatile)
//
// History records are created with Create, which never replaces an object:
// the history is append-only by construction, not only by convention.
type Store interface {
	// Get returns an object's content, or ErrNotFound.
	Get(ctx context.Context, name string) ([]byte, error)
	// Put creates or replaces an object atomically: a reader sees the old
	// content or the new.
	Put(ctx context.Context, name string, data []byte) error
	// Create creates an object that must not exist yet; ErrExists otherwise.
	Create(ctx context.Context, name string, data []byte) error
	// List returns the names beneath prefix ("history/acme/"), sorted.
	List(ctx context.Context, prefix string) ([]string, error)
	// Delete removes an object; removing a missing one is not an error.
	Delete(ctx context.Context, name string) error
}

// Errors of a Store.
var (
	ErrNotFound = errors.New("repos: not found")
	ErrExists   = errors.New("repos: object exists")
)

// maxObjectBytes bounds one stored object. A manifest of a release with
// thousands of dependencies stays far below.
const maxObjectBytes = 256 << 20

// validObjectName reports whether name is one the registry writes: two or
// three segments of lower-case letters, digits, '.', '_' and '-', none starting
// with '.' — so no name can address a file outside the store's directory.
func validObjectName(name string) bool {
	segs := strings.Split(name, "/")
	if len(segs) < 2 || len(segs) > 3 || len(name) > 400 {
		return false
	}
	for _, s := range segs {
		if s == "" || s[0] == '.' || s[0] == '-' {
			return false
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			default:
				return false
			}
		}
	}
	return true
}

// --- memory -----------------------------------------------------------------

// MemoryStore keeps the state in memory: for tests, and for trying the
// feature out. Nothing survives a restart.
type MemoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{objects: map[string][]byte{}} }

func (m *MemoryStore) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.objects[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), d...), nil
}

func (m *MemoryStore) Put(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validObjectName(name) {
		return fmt.Errorf("repos: invalid object name %q", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[name] = append([]byte(nil), data...)
	return nil
}

func (m *MemoryStore) Create(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validObjectName(name) {
		return fmt.Errorf("repos: invalid object name %q", name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[name]; ok {
		return ErrExists
	}
	m.objects[name] = append([]byte(nil), data...)
	return nil
}

func (m *MemoryStore) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for name := range m.objects {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *MemoryStore) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, name)
	return nil
}

// --- directory --------------------------------------------------------------

// DirStore keeps the state in a directory, one file per object
// ("<dir>/<name>.json"). Writes go to a temporary file that is renamed (Put) or
// hard-linked (Create, which fails if the name exists) into place, so a reader
// never sees a half-written object and a history record is never replaced.
// Files are private (0600 in 0700 directories).
type DirStore struct {
	dir string
}

// NewDirStore opens (creating it if need be) the store at dir and checks that
// it can be written to: a tracker that silently could not record a tag or a
// pin would be worse than one that refuses to start.
func NewDirStore(dir string) (*DirStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("repos: the state directory is not set")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("repos: creating the state directory: %w", err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return nil, fmt.Errorf("repos: the state directory %q is not writable: %w", dir, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	d := &DirStore{dir: dir}
	d.sweepTemporaries()
	return d, nil
}

// Dir returns the store's directory.
func (d *DirStore) Dir() string { return d.dir }

const objectSuffix = ".json"

func (d *DirStore) path(name string) (string, error) {
	if !validObjectName(name) {
		return "", fmt.Errorf("repos: invalid object name %q", name)
	}
	return filepath.Join(d.dir, filepath.FromSlash(name)+objectSuffix), nil
}

// sweepTemporaries removes what writes that never finished left behind.
func (d *DirStore) sweepTemporaries() {
	cutoff := time.Now().Add(-time.Hour)
	_ = filepath.WalkDir(d.dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasPrefix(e.Name(), ".tmp-") {
			return nil
		}
		if info, ierr := e.Info(); ierr == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(p)
		}
		return nil
	})
}

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
		return nil, fmt.Errorf("repos: reading %s: %w", name, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("repos: reading %s: %w", name, err)
	}
	if info.Size() > maxObjectBytes {
		return nil, fmt.Errorf("repos: %s is larger than %d bytes", name, maxObjectBytes)
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, fmt.Errorf("repos: reading %s: %w", name, err)
	}
	return data, nil
}

// stage writes data to a temporary file in the directory of p.
func (d *DirStore) stage(p string, data []byte) (string, error) {
	if len(data) > maxObjectBytes {
		return "", fmt.Errorf("repos: object of %d bytes is larger than %d", len(data), maxObjectBytes)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func (d *DirStore) Put(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := d.path(name)
	if err != nil {
		return err
	}
	tmp, err := d.stage(p, data)
	if err != nil {
		return fmt.Errorf("repos: writing %s: %w", name, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("repos: writing %s: %w", name, err)
	}
	syncDir(filepath.Dir(p))
	return nil
}

func (d *DirStore) Create(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := d.path(name)
	if err != nil {
		return err
	}
	tmp, err := d.stage(p, data)
	if err != nil {
		return fmt.Errorf("repos: writing %s: %w", name, err)
	}
	defer os.Remove(tmp)
	// link(2) fails when the target exists: the record is created whole or
	// not at all, and never replaces one.
	if err := os.Link(tmp, p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return fmt.Errorf("repos: writing %s: %w", name, err)
	}
	syncDir(filepath.Dir(p))
	return nil
}

func (d *DirStore) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The prefix names a directory ("history/acme/") or a kind ("repos/").
	dir := strings.TrimSuffix(prefix, "/")
	root := filepath.Join(d.dir, filepath.FromSlash(dir))
	var out []string
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") || !strings.HasSuffix(e.Name(), objectSuffix) {
			return nil
		}
		rel, rerr := filepath.Rel(d.dir, p)
		if rerr != nil {
			return nil
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), objectSuffix)
		if validObjectName(name) && strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("repos: listing %s: %w", prefix, err)
	}
	sort.Strings(out)
	return out, nil
}

func (d *DirStore) Delete(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("repos: deleting %s: %w", name, err)
	}
	return nil
}

// syncDir makes a rename or link in dir durable.
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}
