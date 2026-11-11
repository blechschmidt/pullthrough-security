package llmpkgscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The verdict cache.
//
// A verdict is stored under the artifact's sha256 digest, the model that
// produced it and the prompt version. The digest makes the verdict a property
// of the bytes, not of a coordinate: the same tarball pulled as two names, by
// two tenants, through two upstreams, is scanned once. The model and prompt
// version make a change to either re-scan instead of serving an answer the
// current configuration never gave.

// ErrNotFound is returned by a VerdictStore when no verdict is stored for a key.
var ErrNotFound = errors.New("llmpkgscan: verdict not found")

// VerdictStore persists verdicts by cache key. Implementations must be safe for
// concurrent use.
type VerdictStore interface {
	// Get returns the verdict stored under key, or ErrNotFound.
	Get(ctx context.Context, key string) (*Verdict, error)
	// Put stores v under v.Key, replacing any previous verdict.
	Put(ctx context.Context, v *Verdict) error
	// List returns every stored verdict, in unspecified order.
	List(ctx context.Context) ([]*Verdict, error)
	// Prune removes verdicts scanned before olderThan and returns how many.
	Prune(ctx context.Context, olderThan time.Time) (int, error)
	// Close releases resources.
	Close() error
}

// digestPattern is a bare sha256: 64 lower-case hex characters.
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NormalizeDigest returns the bare lower-case hex of a sha256 digest given as
// "sha256:<hex>" or bare hex. ok is false for anything else — another
// algorithm, a truncated value, a logical cache key — so a caller never keys a
// verdict on something that is not a content digest.
func NormalizeDigest(d string) (hexDigest string, ok bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "sha256:")
	if !digestPattern.MatchString(d) {
		return "", false
	}
	return d, true
}

// signature folds everything other than the digest that a verdict depends on.
func signature(model string, promptVersion int) string {
	h := sha256.New()
	h.Write([]byte("llmpkgscan\x00pv=" + strconv.Itoa(promptVersion) + "\x00model=" + strings.TrimSpace(model)))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// CacheKey is the storage key for an artifact's verdict: "<sha256>-<signature>".
func CacheKey(hexDigest, model string, promptVersion int) string {
	return hexDigest + "-" + signature(model, promptVersion)
}

// keyPattern validates a cache key before it is used to derive a file name.
// Restricting it to hex and one dash makes path traversal impossible by
// construction.
var keyPattern = regexp.MustCompile(`^[0-9a-f]{64}-[0-9a-f]{16}$`)

// defaultMemoryStoreEntries bounds the in-memory store.
const defaultMemoryStoreEntries = 50000

// MemoryStore is a bounded in-memory VerdictStore. When full it evicts the
// oldest-scanned verdicts; a verdict evicted this way is simply scanned again.
type MemoryStore struct {
	mu  sync.RWMutex
	m   map[string]*Verdict
	max int
}

// NewMemoryStore constructs an in-memory store holding at most max verdicts
// (0 => a built-in default).
func NewMemoryStore(max int) *MemoryStore {
	if max <= 0 {
		max = defaultMemoryStoreEntries
	}
	return &MemoryStore{m: make(map[string]*Verdict), max: max}
}

// Get implements VerdictStore.
func (s *MemoryStore) Get(_ context.Context, key string) (*Verdict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	return v.clone(), nil
}

// Put implements VerdictStore.
func (s *MemoryStore) Put(_ context.Context, v *Verdict) error {
	if v == nil || !keyPattern.MatchString(v.Key) {
		return errors.New("llmpkgscan: cannot store a verdict without a valid key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[v.Key]; !exists && len(s.m) >= s.max {
		s.evictOldestLocked(len(s.m) - s.max + 1 + s.max/20)
	}
	s.m[v.Key] = v.clone()
	return nil
}

// evictOldestLocked drops the n oldest-scanned verdicts.
func (s *MemoryStore) evictOldestLocked(n int) {
	if n <= 0 {
		return
	}
	type aged struct {
		key string
		at  time.Time
	}
	all := make([]aged, 0, len(s.m))
	for k, v := range s.m {
		all = append(all, aged{k, v.ScannedAt})
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].at.Equal(all[j].at) {
			return all[i].at.Before(all[j].at)
		}
		return all[i].key < all[j].key
	})
	if n > len(all) {
		n = len(all)
	}
	for _, a := range all[:n] {
		delete(s.m, a.key)
	}
}

// List implements VerdictStore.
func (s *MemoryStore) List(_ context.Context) ([]*Verdict, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Verdict, 0, len(s.m))
	for _, v := range s.m {
		out = append(out, v.clone())
	}
	return out, nil
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

// Close implements VerdictStore.
func (s *MemoryStore) Close() error { return nil }

// maxVerdictFileBytes bounds a verdict file read back from disk.
const maxVerdictFileBytes = 1 << 20

// FileStore is a durable VerdictStore: one JSON file per verdict, named after
// its cache key, written atomically (temp file + rename) with owner-only
// permissions. A verdict names a package's malicious behaviour and quotes its
// code; it is not secret, but it is not for other local users either.
type FileStore struct {
	dir string
	mu  sync.Mutex // serializes writes
}

// NewFileStore creates (if needed) and opens a verdict store rooted at dir.
func NewFileStore(dir string) (*FileStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("llmpkgscan: file store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("llmpkgscan: creating verdict store %q: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) path(key string) (string, error) {
	if !keyPattern.MatchString(key) {
		return "", fmt.Errorf("llmpkgscan: invalid verdict key %q", key)
	}
	return filepath.Join(s.dir, key+".json"), nil
}

// Get implements VerdictStore.
func (s *FileStore) Get(_ context.Context, key string) (*Verdict, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	v, err := readVerdictFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	// A file whose content does not belong under its name is not trusted: the
	// name is the lookup key, and a verdict answering for another digest must not
	// be returned for this one.
	if v.Key != key {
		return nil, fmt.Errorf("llmpkgscan: verdict file %q holds key %q", filepath.Base(p), v.Key)
	}
	return v, nil
}

func readVerdictFile(p string) (*Verdict, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxVerdictFileBytes {
		return nil, fmt.Errorf("llmpkgscan: verdict file %q is implausibly large", filepath.Base(p))
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var v Verdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("llmpkgscan: decoding verdict %q: %w", filepath.Base(p), err)
	}
	return &v, nil
}

// Put implements VerdictStore.
func (s *FileStore) Put(_ context.Context, v *Verdict) error {
	if v == nil {
		return errors.New("llmpkgscan: cannot store a nil verdict")
	}
	p, err := s.path(v.Key)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("llmpkgscan: encoding verdict: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.CreateTemp(s.dir, ".verdict-*.tmp")
	if err != nil {
		return fmt.Errorf("llmpkgscan: creating temp verdict file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("llmpkgscan: writing verdict: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("llmpkgscan: syncing verdict: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("llmpkgscan: closing verdict: %w", err)
	}
	if err := os.Rename(tmpName, p); err != nil {
		return fmt.Errorf("llmpkgscan: committing verdict: %w", err)
	}
	return nil
}

// List implements VerdictStore. Unreadable or corrupt files are skipped.
func (s *FileStore) List(_ context.Context) ([]*Verdict, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("llmpkgscan: listing verdict store: %w", err)
	}
	var out []*Verdict
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		key := strings.TrimSuffix(name, ".json")
		if !keyPattern.MatchString(key) {
			continue
		}
		v, rerr := readVerdictFile(filepath.Join(s.dir, name))
		if rerr != nil || v.Key != key {
			continue
		}
		out = append(out, v)
	}
	return out, nil
}

// Prune implements VerdictStore.
func (s *FileStore) Prune(_ context.Context, olderThan time.Time) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, fmt.Errorf("llmpkgscan: listing verdict store for prune: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" || !keyPattern.MatchString(strings.TrimSuffix(name, ".json")) {
			continue
		}
		full := filepath.Join(s.dir, name)
		v, rerr := readVerdictFile(full)
		if rerr != nil {
			continue
		}
		if v.ScannedAt.Before(olderThan) && os.Remove(full) == nil {
			n++
		}
	}
	return n, nil
}

// Close implements VerdictStore.
func (s *FileStore) Close() error { return nil }
