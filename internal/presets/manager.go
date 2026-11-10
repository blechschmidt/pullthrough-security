package presets

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
)

// sha256Hex returns the hex-encoded SHA-256 digest of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Manager wires the preset library to a running process: the live configuration
// (for dry-run diffs) and the config file backing it (for apply). It is the
// single object the admin API and the metrics bridge consume. A Manager with an
// empty path can still list and diff presets; apply requires a backing file.
type Manager struct {
	mu   sync.Mutex
	path string
	live *config.Config
}

// NewManager captures the running configuration and the file it was loaded from
// (empty for a defaults-only process).
func NewManager(path string, live *config.Config) *Manager {
	return &Manager{path: path, live: live}
}

// Path returns the config file backing the running process ("" when none).
func (m *Manager) Path() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.path
}

// List returns the compact summaries of every registered preset.
func (m *Manager) List() []Summary { return List() }

// Diff dry-runs the named preset against the running configuration.
func (m *Manager) Diff(name string) (Diff, error) {
	p, err := Get(name)
	if err != nil {
		return Diff{}, err
	}
	m.mu.Lock()
	live := m.live
	m.mu.Unlock()
	return p.Diff(live)
}

// ApplyResult reports the outcome of applying a preset to the on-disk config.
type ApplyResult struct {
	Preset      string    `json:"preset"`
	Version     string    `json:"version"`
	Path        string    `json:"path"`
	BackupPath  string    `json:"backupPath,omitempty"`
	AppliedAt   time.Time `json:"appliedAt"`
	Changed     int       `json:"changed"`
	Controls    []string  `json:"controls"`
	Diff        Diff      `json:"diff"`
	NewFileHash string    `json:"newFileHash"`
	// Note explains how the applied configuration takes effect.
	Note string `json:"note"`
}

// Apply patches the on-disk configuration file with the named preset's settings,
// preserving comments, encrypted secrets, and unrelated settings. It validates
// the patched document before writing and snapshots the previous file to a
// timestamped .bak. Apply refuses when the projected configuration would be
// invalid (so a preset cannot break the running deployment) or when no file
// backs the process.
//
// The patched configuration is durable; it takes effect on the next config
// reload/restart. The caller (admin handler) is responsible for the audit/event
// trail, since it holds the authenticated identity.
func (m *Manager) Apply(name string) (ApplyResult, error) {
	p, err := Get(name)
	if err != nil {
		return ApplyResult{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.path == "" {
		return ApplyResult{}, fmt.Errorf("presets: cannot apply %q: the process is running from defaults with no config file (start it with -config <path>)", name)
	}

	// Dry-run diff first so the result carries the full preview and we fail early
	// on an invalid projection.
	diff, err := p.Diff(m.live)
	if err != nil {
		return ApplyResult{}, err
	}
	if diff.Validation != nil && !diff.Validation.OK {
		return ApplyResult{}, fmt.Errorf("presets: refusing to apply %q: projected configuration is invalid (%d error(s)); run `verify-config preset diff %s` for details", name, diff.Validation.Errors, name)
	}

	raw, err := os.ReadFile(m.path)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("presets: reading %q: %w", m.path, err)
	}
	patched, err := p.PatchOnDisk(raw)
	if err != nil {
		return ApplyResult{}, err
	}

	// Validate the patched bytes (the on-disk form, which keeps secrets templated)
	// independently of the in-memory projection.
	if rep := config.CheckBytes(patched); !rep.OK {
		return ApplyResult{}, fmt.Errorf("presets: refusing to apply %q: patched config failed validation (%d error(s))", name, rep.Errors)
	}

	// Snapshot the previous file before overwriting.
	backup := fmt.Sprintf("%s.bak.%s", m.path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, raw, 0o600); err != nil {
		return ApplyResult{}, fmt.Errorf("presets: writing backup %q: %w", backup, err)
	}

	info, statErr := os.Stat(m.path)
	mode := os.FileMode(0o600)
	if statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := writeFileAtomic(m.path, patched, mode); err != nil {
		return ApplyResult{}, fmt.Errorf("presets: writing %q: %w", m.path, err)
	}

	return ApplyResult{
		Preset:      p.Name,
		Version:     p.Version,
		Path:        m.path,
		BackupPath:  backup,
		AppliedAt:   time.Now().UTC(),
		Changed:     diff.Changed,
		Controls:    diff.Controls,
		Diff:        diff,
		NewFileHash: sha256Hex(patched),
		Note:        "configuration written to disk; takes effect on the next reload/restart",
	}, nil
}

// writeFileAtomic writes data to path via a temp file + rename so a crash mid-
// write cannot leave a truncated config.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".preset-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
