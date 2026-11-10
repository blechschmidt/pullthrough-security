package watch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Cursor is the persisted per-repository scan state. It records the ref tips the
// watcher has scanned up to and the scanning signature they were scanned under,
// so a restart resumes incrementally and a configuration change triggers a
// re-scan.
type Cursor struct {
	// Repo is the watched repository's stable name (the StateStore key).
	Repo string `json:"repo"`
	// Tips maps a fully-qualified ref (e.g. "refs/heads/main") to the last commit
	// SHA scanned on it. The next cycle scans the range Tips[ref]..<new head>.
	Tips map[string]string `json:"tips,omitempty"`
	// Signature is the scanner cache signature (model/prompt/ruleset fold) under
	// which the commits up to Tips were scanned. When it no longer matches the
	// scanner's current signature, the watcher re-scans the history.
	Signature string `json:"signature,omitempty"`
	// ScannedCount is the cumulative number of commits scanned for this repo.
	ScannedCount int `json:"scannedCount,omitempty"`
	// BaselinedAt is when the cursor was first established from the current tips
	// without scanning history (non-backfill first sighting).
	BaselinedAt time.Time `json:"baselinedAt,omitempty"`
	// LastScanAt is when the cursor was last advanced by a scan.
	LastScanAt time.Time `json:"lastScanAt,omitempty"`
}

// StateStore persists per-repository scan cursors. Implementations must be safe
// for concurrent use; the Service additionally serializes per-repo access.
type StateStore interface {
	// Load returns the cursor for repo, or a zero Cursor (and nil error) when
	// none is stored yet.
	Load(ctx context.Context, repo string) (Cursor, error)
	// Save persists (overwrites) the cursor for c.Repo.
	Save(ctx context.Context, c Cursor) error
	// List returns every stored cursor, ordered by repo name.
	List(ctx context.Context) ([]Cursor, error)
	// Close releases any resources.
	Close() error
}

// MemoryStateStore is an in-memory StateStore for tests and ephemeral
// deployments. Cursors are lost on restart (the watcher then re-baselines or
// re-backfills each repo).
type MemoryStateStore struct {
	mu sync.RWMutex
	m  map[string]Cursor
}

// NewMemoryStateStore constructs an empty in-memory store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{m: make(map[string]Cursor)}
}

func (s *MemoryStateStore) Load(_ context.Context, repo string) (Cursor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[repo]
	if !ok {
		return Cursor{}, nil
	}
	return c.clone(), nil
}

func (s *MemoryStateStore) Save(_ context.Context, c Cursor) error {
	if c.Repo == "" {
		return errors.New("watch: cannot save a cursor without a repo name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[c.Repo] = c.clone()
	return nil
}

func (s *MemoryStateStore) List(_ context.Context) ([]Cursor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Cursor, 0, len(s.m))
	for _, c := range s.m {
		out = append(out, c.clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

func (s *MemoryStateStore) Close() error { return nil }

// clone deep-copies a cursor so stored values cannot be mutated by callers.
func (c Cursor) clone() Cursor {
	cp := c
	if c.Tips != nil {
		cp.Tips = make(map[string]string, len(c.Tips))
		for k, v := range c.Tips {
			cp.Tips[k] = v
		}
	}
	return cp
}

// repoFilePattern restricts a repo name to characters safe in a filename before
// it is used to derive a cursor path, making path traversal impossible by
// construction.
var repoFilePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)

// FileStateStore is a durable, filesystem-backed StateStore. Each cursor is one
// JSON file "<repo>.json"; writes are atomic (write-temp-then-rename).
type FileStateStore struct {
	dir string
	mu  sync.Mutex
}

// NewFileStateStore creates (if needed) and opens a cursor store rooted at dir.
func NewFileStateStore(dir string) (*FileStateStore, error) {
	if dir == "" {
		return nil, errors.New("watch: file state store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("watch: creating cursor store %q: %w", dir, err)
	}
	return &FileStateStore{dir: dir}, nil
}

func (s *FileStateStore) path(repo string) (string, error) {
	if !repoFilePattern.MatchString(repo) {
		return "", fmt.Errorf("watch: invalid repo name %q for cursor storage", repo)
	}
	return filepath.Join(s.dir, repo+".json"), nil
}

func (s *FileStateStore) Load(_ context.Context, repo string) (Cursor, error) {
	p, err := s.path(repo)
	if err != nil {
		return Cursor{}, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Cursor{}, nil
		}
		return Cursor{}, fmt.Errorf("watch: reading cursor %q: %w", repo, err)
	}
	var c Cursor
	if err := json.Unmarshal(data, &c); err != nil {
		return Cursor{}, fmt.Errorf("watch: decoding cursor %q: %w", repo, err)
	}
	return c, nil
}

func (s *FileStateStore) Save(_ context.Context, c Cursor) error {
	if c.Repo == "" {
		return errors.New("watch: cannot save a cursor without a repo name")
	}
	p, err := s.path(c.Repo)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("watch: encoding cursor %q: %w", c.Repo, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(s.dir, "."+c.Repo+".*.tmp")
	if err != nil {
		return fmt.Errorf("watch: creating temp cursor file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("watch: writing cursor %q: %w", c.Repo, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("watch: syncing cursor %q: %w", c.Repo, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("watch: closing cursor %q: %w", c.Repo, err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("watch: committing cursor %q: %w", c.Repo, err)
	}
	return nil
}

func (s *FileStateStore) List(_ context.Context) ([]Cursor, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("watch: listing cursor store: %w", err)
	}
	var out []Cursor
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(s.dir, name))
		if rerr != nil {
			continue
		}
		var c Cursor
		if json.Unmarshal(data, &c) != nil || c.Repo == "" {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, nil
}

func (s *FileStateStore) Close() error { return nil }

// keyedMutex provides per-key locking with reference counting so unused keys are
// reclaimed. It mirrors the pattern used by the git mirror manager.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*refLock
}

type refLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() keyedMutex {
	return keyedMutex{locks: make(map[string]*refLock)}
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	rl, ok := k.locks[key]
	if !ok {
		rl = &refLock{}
		k.locks[key] = rl
	}
	rl.refs++
	k.mu.Unlock()

	rl.mu.Lock()
	return func() {
		rl.mu.Unlock()
		k.mu.Lock()
		rl.refs--
		if rl.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
