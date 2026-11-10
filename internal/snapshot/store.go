package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// store is the durable JSON-on-disk persistence layer. Each manifest is one file
// under <dir>/snapshots/<safeID>.json; the active freeze state is <dir>/freeze.json.
// Writes are atomic (temp file + rename). An empty dir keeps everything in memory
// (every method is a no-op / returns nothing), which the test suite relies on.
type store struct {
	dir string
}

func newStore(dir string) *store { return &store{dir: strings.TrimSpace(dir)} }

func (s *store) enabled() bool { return s.dir != "" }

func (s *store) snapshotsDir() string { return filepath.Join(s.dir, "snapshots") }

func (s *store) freezePath() string { return filepath.Join(s.dir, "freeze.json") }

// safeFileName derives a filesystem-safe name from a content-addressed id like
// "sha256:abcd...". The algorithm prefix's colon and any stray separators are
// replaced so the id maps to exactly one file.
func safeFileName(id string) string {
	repl := strings.NewReplacer(":", "_", "/", "_", "\\", "_", "..", "_")
	return repl.Replace(id) + ".json"
}

func (s *store) manifestPath(id string) string {
	return filepath.Join(s.snapshotsDir(), safeFileName(id))
}

// loadAll reads every persisted manifest. A missing directory yields no
// manifests (not an error): a fresh deployment has none.
func (s *store) loadAll() ([]*Manifest, error) {
	if !s.enabled() {
		return nil, nil
	}
	dir := s.snapshotsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("snapshot: reading store dir: %w", err)
	}
	var out []*Manifest
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			return nil, fmt.Errorf("snapshot: reading manifest %s: %w", de.Name(), err)
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("snapshot: parsing manifest %s: %w", de.Name(), err)
		}
		if m.ID == "" {
			continue
		}
		out = append(out, &m)
	}
	return out, nil
}

func (s *store) saveManifest(m *Manifest) error {
	if !s.enabled() {
		return nil
	}
	if err := os.MkdirAll(s.snapshotsDir(), 0o755); err != nil {
		return fmt.Errorf("snapshot: creating store dir: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot: marshaling manifest: %w", err)
	}
	return atomicWrite(s.manifestPath(m.ID), data)
}

func (s *store) deleteManifest(id string) error {
	if !s.enabled() {
		return nil
	}
	err := os.Remove(s.manifestPath(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("snapshot: deleting manifest: %w", err)
	}
	return nil
}

func (s *store) loadFreeze() (FreezeState, bool, error) {
	if !s.enabled() {
		return FreezeState{}, false, nil
	}
	data, err := os.ReadFile(s.freezePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return FreezeState{}, false, nil
		}
		return FreezeState{}, false, fmt.Errorf("snapshot: reading freeze state: %w", err)
	}
	if len(data) == 0 {
		return FreezeState{}, false, nil
	}
	var fs FreezeState
	if err := json.Unmarshal(data, &fs); err != nil {
		return FreezeState{}, false, fmt.Errorf("snapshot: parsing freeze state: %w", err)
	}
	return fs, true, nil
}

func (s *store) saveFreeze(fs FreezeState) error {
	if !s.enabled() {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("snapshot: creating store dir: %w", err)
	}
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return fmt.Errorf("snapshot: marshaling freeze state: %w", err)
	}
	return atomicWrite(s.freezePath(), data)
}

// atomicWrite writes data to path via a temp file in the same directory followed
// by a rename, so a reader never observes a partially-written file.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".snapshot-*.tmp")
	if err != nil {
		return fmt.Errorf("snapshot: creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("snapshot: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("snapshot: closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("snapshot: renaming temp file: %w", err)
	}
	return nil
}
