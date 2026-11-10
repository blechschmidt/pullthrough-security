package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LinkStore persists resolved package->commit associations so a given artifact's
// provenance is established once and then served from cache. Implementations must
// be safe for concurrent use.
//
// The store is keyed by the artifact's stable identity (ecosystem/name/version,
// preferring the content digest when present), so the same artifact consumed
// repeatedly reuses the persisted link rather than re-fetching and re-verifying
// attestations on every pull.
type LinkStore interface {
	// Get returns the stored link for the artifact, or ErrNoProvenance.
	Get(ctx context.Context, art Artifact) (*Link, error)
	// Put stores (or overwrites) the link for link.Artifact.
	Put(ctx context.Context, link *Link) error
	// List returns every stored link, for administrative inspection. Order is
	// unspecified.
	List(ctx context.Context) ([]*Link, error)
	// Close releases any resources.
	Close() error
}

// ArtifactKey derives a stable, collision-resistant identity for an artifact.
// The content digest is the strongest identity (immutable, unambiguous); when it
// is absent the ecosystem/name/version coordinate is used. Keys are lower-cased
// so case differences in coordinates do not fragment the store.
func ArtifactKey(a Artifact) string {
	if a.Digest != "" {
		return "digest:" + strings.ToLower(a.Digest)
	}
	return "coord:" + strings.ToLower(strings.Join([]string{a.Ecosystem, a.Name, a.Version}, "|"))
}

// MemoryLinkStore is an in-memory LinkStore for tests and ephemeral deployments.
type MemoryLinkStore struct {
	mu sync.RWMutex
	m  map[string]*Link
}

// NewMemoryLinkStore constructs an empty in-memory link store.
func NewMemoryLinkStore() *MemoryLinkStore {
	return &MemoryLinkStore{m: make(map[string]*Link)}
}

// Get implements LinkStore.
func (s *MemoryLinkStore) Get(_ context.Context, art Artifact) (*Link, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.m[ArtifactKey(art)]
	if !ok {
		return nil, ErrNoProvenance
	}
	return cloneLink(l), nil
}

// Put implements LinkStore.
func (s *MemoryLinkStore) Put(_ context.Context, link *Link) error {
	if link == nil {
		return errors.New("provenance: cannot store nil link")
	}
	key := ArtifactKey(link.Artifact)
	if key == "coord:||" {
		return errors.New("provenance: cannot store link for an empty artifact")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = cloneLink(link)
	return nil
}

// List implements LinkStore.
func (s *MemoryLinkStore) List(_ context.Context) ([]*Link, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Link, 0, len(s.m))
	for _, l := range s.m {
		out = append(out, cloneLink(l))
	}
	sortLinks(out)
	return out, nil
}

// Close implements LinkStore.
func (s *MemoryLinkStore) Close() error { return nil }

// FileLinkStore is a durable, filesystem-backed LinkStore. Each link is one JSON
// file named "<sha256(key)>.json"; writes are atomic (temp-then-rename). Hashing
// the key to a fixed-length hex filename makes path traversal impossible by
// construction regardless of the artifact name's contents.
type FileLinkStore struct {
	dir string
	mu  sync.Mutex
}

// NewFileLinkStore creates (if needed) and opens a filesystem link store at dir.
func NewFileLinkStore(dir string) (*FileLinkStore, error) {
	if dir == "" {
		return nil, errors.New("provenance: file link store requires a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("provenance: creating link store %q: %w", dir, err)
	}
	return &FileLinkStore{dir: dir}, nil
}

// fileName hashes the artifact key to a fixed hex filename, neutralizing any
// path-significant characters in the artifact coordinate.
func (s *FileLinkStore) fileName(art Artifact) string {
	sum := sha256.Sum256([]byte(ArtifactKey(art)))
	return hex.EncodeToString(sum[:]) + ".json"
}

// Get implements LinkStore.
func (s *FileLinkStore) Get(_ context.Context, art Artifact) (*Link, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, s.fileName(art)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoProvenance
		}
		return nil, fmt.Errorf("provenance: reading link: %w", err)
	}
	var l Link
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("provenance: decoding link: %w", err)
	}
	return &l, nil
}

// Put implements LinkStore.
func (s *FileLinkStore) Put(_ context.Context, link *Link) error {
	if link == nil {
		return errors.New("provenance: cannot store nil link")
	}
	key := ArtifactKey(link.Artifact)
	if key == "coord:||" {
		return errors.New("provenance: cannot store link for an empty artifact")
	}
	data, err := json.MarshalIndent(link, "", "  ")
	if err != nil {
		return fmt.Errorf("provenance: encoding link: %w", err)
	}
	name := s.fileName(link.Artifact)

	s.mu.Lock()
	defer s.mu.Unlock()

	tmp, err := os.CreateTemp(s.dir, ".link.*.tmp")
	if err != nil {
		return fmt.Errorf("provenance: creating temp link file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("provenance: writing link: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("provenance: syncing link: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("provenance: closing link: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(s.dir, name)); err != nil {
		return fmt.Errorf("provenance: committing link: %w", err)
	}
	return nil
}

// List implements LinkStore. Unreadable or corrupt files are skipped.
func (s *FileLinkStore) List(_ context.Context) ([]*Link, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("provenance: listing link store: %w", err)
	}
	var out []*Link
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if rerr != nil {
			continue
		}
		var l Link
		if json.Unmarshal(data, &l) != nil {
			continue
		}
		out = append(out, &l)
	}
	sortLinks(out)
	return out, nil
}

// Close implements LinkStore.
func (s *FileLinkStore) Close() error { return nil }

// cloneLink deep-copies a Link so stored values cannot be mutated by callers.
func cloneLink(l *Link) *Link {
	cp := *l
	if l.Attestation != nil {
		cp.Attestation = append([]byte(nil), l.Attestation...)
	}
	return &cp
}

// sortLinks orders links by ecosystem, name, version for stable listings.
func sortLinks(ls []*Link) {
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i].Artifact, ls[j].Artifact
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
}

// stampNow records resolution time on a link when unset.
func stampNow(l *Link, now func() time.Time) {
	if l != nil && l.ResolvedAt.IsZero() {
		l.ResolvedAt = now()
	}
}
