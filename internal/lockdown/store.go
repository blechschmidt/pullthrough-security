package lockdown

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// store is the durable persistence layer for the single active lockdown State.
// An empty path keeps everything in memory (tests / ephemeral deployments).
type store interface {
	load() (State, bool, error)
	save(State) error
}

// newStore returns a file-backed store when path is set, else an in-memory one.
func newStore(path string) store {
	if strings.TrimSpace(path) == "" {
		return &memStore{}
	}
	return &fileStore{path: strings.TrimSpace(path)}
}

// memStore keeps state in memory only.
type memStore struct {
	mu  sync.Mutex
	st  State
	set bool
}

func (m *memStore) load() (State, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st, m.set, nil
}

func (m *memStore) save(st State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st = st
	m.set = st.active()
	return nil
}

// fileStore persists the active state as a single JSON file. Writes are atomic
// (temp file + rename) so a concurrent reader never observes a partial write. An
// inactive (cleared) state removes the file so a missing file reads as "no
// lockdown".
type fileStore struct {
	path string
}

func (f *fileStore) load() (State, bool, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, false, nil
		}
		return State{}, false, fmt.Errorf("reading lockdown state: %w", err)
	}
	if len(data) == 0 {
		return State{}, false, nil
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, false, fmt.Errorf("parsing lockdown state: %w", err)
	}
	return st, st.active(), nil
}

func (f *fileStore) save(st State) error {
	if !st.active() {
		// A cleared state removes the file (atomic absence == no lockdown).
		if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clearing lockdown state: %w", err)
		}
		return nil
	}
	if dir := filepath.Dir(f.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating lockdown state dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling lockdown state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), ".lockdown-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, f.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}
