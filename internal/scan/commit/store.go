package commit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// ErrNotFound is returned by a VerdictStore when no verdict is stored for a key.
var ErrNotFound = errors.New("commit: verdict not found")

// VerdictStore persists scan verdicts keyed by a deterministic cache key (commit
// SHA folded with the model set, prompt version, and ruleset hash) so an
// identical analysis is performed at most once. Implementations must be safe for
// concurrent use.
type VerdictStore interface {
	// Get returns the stored verdict for key, or ErrNotFound.
	Get(ctx context.Context, key string) (*Verdict, error)
	// Put stores (or overwrites) the verdict under v.CacheKey (falling back to
	// v.SHA when CacheKey is empty, e.g. legacy callers).
	Put(ctx context.Context, v *Verdict) error
	// List returns every stored verdict, for administrative inspection. The
	// order is unspecified.
	List(ctx context.Context) ([]*Verdict, error)
	// Prune removes every verdict whose ScannedAt is before olderThan and returns
	// the number removed. It wires the verdict cache into the retention engine
	// (Task 39/78) so it does not grow unbounded.
	Prune(ctx context.Context, olderThan time.Time) (int, error)
	// Close releases any resources.
	Close() error
}

// storeKey returns the key a verdict is stored under: its CacheKey, or its SHA
// when CacheKey is unset.
func storeKey(v *Verdict) string {
	if v.CacheKey != "" {
		return v.CacheKey
	}
	return v.SHA
}

// MemoryStore is an in-memory VerdictStore, suitable for tests and ephemeral
// deployments. Verdicts are lost on restart.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[string]*Verdict
}

// NewMemoryStore constructs an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: make(map[string]*Verdict)}
}

// Get implements VerdictStore.
func (s *MemoryStore) Get(_ context.Context, key string) (*Verdict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *v // defensive copy so callers cannot mutate the stored value
	return &cp, nil
}

// Put implements VerdictStore.
func (s *MemoryStore) Put(_ context.Context, v *Verdict) error {
	if v == nil || v.SHA == "" {
		return errors.New("commit: cannot store verdict without a SHA")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *v
	s.m[storeKey(v)] = &cp
	return nil
}

// Prune implements VerdictStore.
func (s *MemoryStore) Prune(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if v.ScannedAt.Before(olderThan) {
			delete(s.m, k)
			n++
		}
	}
	return n, nil
}

// List implements VerdictStore.
func (s *MemoryStore) List(_ context.Context) ([]*Verdict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Verdict, 0, len(s.m))
	for _, v := range s.m {
		cp := *v // defensive copy
		out = append(out, &cp)
	}
	return out, nil
}

// Close implements VerdictStore.
func (s *MemoryStore) Close() error { return nil }

// keyPattern validates a verdict cache key before it is used to derive a
// filesystem path. A key is a hex commit SHA, optionally suffixed with a "-" and
// a hex signature (the model/prompt/ruleset fold). Restricting to hex and a
// single dash makes path traversal impossible by construction.
var keyPattern = regexp.MustCompile(`^[0-9a-fA-F]{7,64}(-[0-9a-f]{8,64})?$`)

// FileStore is a durable, filesystem-backed VerdictStore. Each verdict is one
// JSON file named "<sha>.json"; writes are atomic (write-temp-then-rename) so a
// concurrent or interrupted read never observes a partial file.
type FileStore struct {
	dir string
	mu  sync.Mutex // serializes writes to the same directory
}

// NewFileStore creates (if needed) and opens a filesystem verdict store rooted
// at dir.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("commit: file store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("commit: creating verdict store %q: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

// path returns the on-disk path for a cache key after validating it.
func (s *FileStore) path(key string) (string, error) {
	if !keyPattern.MatchString(key) {
		return "", fmt.Errorf("commit: invalid verdict key %q", key)
	}
	return filepath.Join(s.dir, key+".json"), nil
}

// Get implements VerdictStore.
func (s *FileStore) Get(_ context.Context, key string) (*Verdict, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("commit: reading verdict %q: %w", key, err)
	}
	var v Verdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("commit: decoding verdict %q: %w", key, err)
	}
	return &v, nil
}

// Put implements VerdictStore.
func (s *FileStore) Put(_ context.Context, v *Verdict) error {
	if v == nil || v.SHA == "" {
		return errors.New("commit: cannot store verdict without a SHA")
	}
	key := storeKey(v)
	p, err := s.path(key)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("commit: encoding verdict %q: %w", v.SHA, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(s.dir, "."+v.SHA+".*.tmp")
	if err != nil {
		return fmt.Errorf("commit: creating temp verdict file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("commit: writing verdict %q: %w", v.SHA, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("commit: syncing verdict %q: %w", v.SHA, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("commit: closing verdict %q: %w", v.SHA, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("commit: committing verdict %q: %w", v.SHA, err)
	}
	return nil
}

// List implements VerdictStore by reading every "<sha>.json" verdict file in
// the store directory. Unreadable or corrupt files are skipped rather than
// failing the whole listing.
func (s *FileStore) List(_ context.Context) ([]*Verdict, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("commit: listing verdict store: %w", err)
	}
	var out []*Verdict
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(s.dir, name))
		if rerr != nil {
			continue
		}
		var v Verdict
		if json.Unmarshal(data, &v) != nil || v.SHA == "" {
			continue
		}
		cp := v
		out = append(out, &cp)
	}
	return out, nil
}

// Prune implements VerdictStore by removing every "<key>.json" verdict file whose
// stored ScannedAt is before olderThan. Unreadable or corrupt files are skipped.
func (s *FileStore) Prune(_ context.Context, olderThan time.Time) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("commit: listing verdict store for prune: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		full := filepath.Join(s.dir, name)
		data, rerr := os.ReadFile(full)
		if rerr != nil {
			continue
		}
		var v Verdict
		if json.Unmarshal(data, &v) != nil {
			continue
		}
		if v.ScannedAt.Before(olderThan) {
			if os.Remove(full) == nil {
				n++
			}
		}
	}
	return n, nil
}

// Close implements VerdictStore.
func (s *FileStore) Close() error { return nil }
