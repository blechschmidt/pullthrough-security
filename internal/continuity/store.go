package continuity

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// store persists the durable known-maintainer set and cumulative counters to a
// single JSON file with atomic (temp-file + rename) writes, mirroring the
// approvals/snapshot durable-store pattern. An empty path keeps state in memory
// only.
type store struct {
	path string
}

// persistedState is the on-disk representation of the continuity Service.
type persistedState struct {
	Records     []*record `json:"records"`
	Checks      uint64    `json:"checks"`
	FirstUse    uint64    `json:"firstUse"`
	Drifts      uint64    `json:"drifts"`
	Blocks      uint64    `json:"blocks"`
	Warns       uint64    `json:"warns"`
	Unknown     uint64    `json:"unknown"`
	Allowlisted uint64    `json:"allowlisted"`
}

// load reads the persisted state (if any) into the service, rebuilding the
// in-memory record index and restoring cumulative counters. A missing file is not
// an error (first run). The caller holds no lock (New is single-threaded).
func (st *store) load(s *Service) error {
	if st.path == "" {
		return nil
	}
	data, err := os.ReadFile(st.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var ps persistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		return err
	}
	for _, r := range ps.Records {
		if r == nil || r.Name == "" {
			continue
		}
		if len(r.Pending) == 0 {
			r.Pending = nil
		}
		s.records[recordKey(r.Ecosystem, r.Name)] = r
	}
	s.checks.Store(ps.Checks)
	s.firstUse.Store(ps.FirstUse)
	s.drifts.Store(ps.Drifts)
	s.blocks.Store(ps.Blocks)
	s.warns.Store(ps.Warns)
	s.unknown.Store(ps.Unknown)
	s.allowlists.Store(ps.Allowlisted)
	return nil
}

// persistLocked atomically writes the current state to disk. The caller holds
// s.mu. Write errors are logged and swallowed (best-effort durability): a
// persistence failure must never break the pull path.
func (s *Service) persistLocked() {
	if s.store == nil || s.store.path == "" {
		return
	}
	ps := persistedState{
		Records:     make([]*record, 0, len(s.records)),
		Checks:      s.checks.Load(),
		FirstUse:    s.firstUse.Load(),
		Drifts:      s.drifts.Load(),
		Blocks:      s.blocks.Load(),
		Warns:       s.warns.Load(),
		Unknown:     s.unknown.Load(),
		Allowlisted: s.allowlists.Load(),
	}
	for _, r := range s.records {
		ps.Records = append(ps.Records, r)
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		s.log.Warn("continuity: marshaling store failed", "error", err)
		return
	}
	if err := atomicWrite(s.store.path, data); err != nil {
		s.log.Warn("continuity: persisting store failed", "path", s.store.path, "error", err)
	}
}

// atomicWrite writes data to path via a temp file in the same directory followed
// by a rename, so a concurrent reader never observes a partially-written file.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".continuity-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
