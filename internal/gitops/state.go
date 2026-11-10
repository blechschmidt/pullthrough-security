package gitops

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AppliedEntry records one successful apply of a desired-state bundle to the
// on-disk configuration. The BackupPath holds the configuration as it was *before*
// this apply, so rolling the apply back restores the prior (last-known-good) state.
type AppliedEntry struct {
	// Revision is the source-of-truth revision applied (Git commit SHA / digest).
	Revision string `json:"revision"`
	// Origin describes where the bundle came from.
	Origin string `json:"origin,omitempty"`
	// FromFingerprint / ToFingerprint are the effective-config SHA-256 digests
	// before and after the apply (config.Fingerprint).
	FromFingerprint string `json:"fromFingerprint"`
	ToFingerprint   string `json:"toFingerprint"`
	// BundleDigest is the SHA-256 of the applied bundle document.
	BundleDigest string `json:"bundleDigest"`
	// Changed is the number of config settings the apply changed.
	Changed int `json:"changed"`
	// Paths are the config paths the bundle governs.
	Paths []string `json:"paths,omitempty"`
	// BackupPath is the timestamped copy of the pre-apply config file.
	BackupPath string `json:"backupPath,omitempty"`
	// By identifies who/what triggered the apply ("scheduler", an operator, an
	// approver subject).
	By string `json:"by,omitempty"`
	// AppliedAt is when the apply was written.
	AppliedAt time.Time `json:"appliedAt"`
	// Approved marks an apply that went through the dual-control suggest workflow.
	Approved bool `json:"approved,omitempty"`
	// RequestID is the approvals request that authorised a suggest-mode apply.
	RequestID string `json:"requestId,omitempty"`
}

// PendingChange describes a desired-state change awaiting human approval in suggest
// mode (or one that could not be applied because verification/validation failed).
type PendingChange struct {
	Revision     string    `json:"revision"`
	Origin       string    `json:"origin,omitempty"`
	BundleDigest string    `json:"bundleDigest"`
	Changed      int       `json:"changed"`
	Paths        []string  `json:"paths,omitempty"`
	RequestID    string    `json:"requestId,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	DetectedAt   time.Time `json:"detectedAt"`
}

// state is the durable reconciliation state persisted to StorePath. It survives a
// restart so the proxy remembers the last applied revision, the rollback history,
// and any pending suggested change.
type state struct {
	LastSyncAt     time.Time      `json:"lastSyncAt,omitempty"`
	LastRevision   string         `json:"lastRevision,omitempty"`
	LastOutcome    string         `json:"lastOutcome,omitempty"`
	LastError      string         `json:"lastError,omitempty"`
	LastBundleHash string         `json:"lastBundleHash,omitempty"`
	InSync         bool           `json:"inSync"`
	Drift          bool           `json:"drift"`
	Pending        *PendingChange `json:"pending,omitempty"`
	// History is the apply log, oldest first. The last entry is the current applied
	// revision; rolling back pops it and restores its BackupPath.
	History []AppliedEntry `json:"history,omitempty"`
}

// head returns the most recent applied entry (the current applied revision), or nil
// when nothing has been applied.
func (s *state) head() *AppliedEntry {
	if len(s.History) == 0 {
		return nil
	}
	return &s.History[len(s.History)-1]
}

// lastKnownGood returns the entry one before the head — the revision the proxy
// would roll back to. When only one apply exists, the pre-apply backup of that
// single entry is the last-known-good baseline, signalled by a nil return with a
// non-nil head.
func (s *state) lastKnownGood() *AppliedEntry {
	if len(s.History) < 2 {
		return nil
	}
	return &s.History[len(s.History)-2]
}

const maxHistory = 50

// append records an apply, trimming the history to the most recent maxHistory.
func (s *state) append(e AppliedEntry) {
	s.History = append(s.History, e)
	if len(s.History) > maxHistory {
		s.History = s.History[len(s.History)-maxHistory:]
	}
}

// loadState reads the durable state from path. A missing file yields an empty
// state; a corrupt file is an error so we never silently lose the apply history.
func loadState(path string) (*state, error) {
	if path == "" {
		return &state{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &state{}, nil
		}
		return nil, fmt.Errorf("gitops: reading state %q: %w", path, err)
	}
	var st state
	if len(data) > 0 {
		if err := json.Unmarshal(data, &st); err != nil {
			return nil, fmt.Errorf("gitops: parsing state %q: %w", path, err)
		}
	}
	return &st, nil
}

// saveState writes the durable state to path atomically (temp + rename), 0600. A
// nil path is a no-op (in-memory mode).
func saveState(path string, st *state) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("gitops: encoding state: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("gitops: preparing state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".gitops-state-*.tmp")
	if err != nil {
		return fmt.Errorf("gitops: creating temp state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("gitops: writing temp state: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
