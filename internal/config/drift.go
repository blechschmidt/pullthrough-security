package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"

	"gopkg.in/yaml.v3"
)

// Fingerprint returns a deterministic SHA-256 hex digest of the effective
// configuration. It marshals the resolved config to canonical YAML (struct
// fields in declaration order, map keys sorted) and hashes the bytes, so two
// processes that loaded equivalent effective configurations produce the same
// fingerprint regardless of the original file's comments, key order, or
// whitespace. An (unexpected) marshal failure yields the empty string.
//
// Credential fields are redacted to a fixed marker before hashing (Task 133):
// no resolved secret value ever enters the digest, and — crucially — a secretRef
// that resolves differently over time (a rotated Vault lease, a changed env
// var) does not make the running process appear to have drifted from its own
// on-disk config. Adding or removing a secret (empty vs. set) still changes the
// fingerprint, so structural drift remains detectable.
func Fingerprint(c *Config) string {
	red := redactedClone(c)
	data, err := yaml.Marshal(red)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// redactedClone returns a deep copy of c with every credential field scrubbed.
// The copy is produced via a YAML round-trip so the original config is never
// mutated. A marshal/unmarshal failure falls back to the original config
// (fingerprinting then degrades to the pre-redaction behavior rather than
// panicking); in practice Config always round-trips.
func redactedClone(c *Config) *Config {
	data, err := yaml.Marshal(c)
	if err != nil {
		return c
	}
	var clone Config
	if err := yaml.Unmarshal(data, &clone); err != nil {
		return c
	}
	redactCredentials(&clone)
	return &clone
}

// hashBytes is the SHA-256 hex digest of raw bytes (used for the on-disk file
// hash, which detects any textual change including comments/whitespace).
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DriftStatus describes whether the on-disk configuration has diverged from the
// configuration the process is currently running. It is exposed verbatim over
// the admin /api/config/drift endpoint.
type DriftStatus struct {
	// Path is the config file backing the running process ("" when the process
	// was started with no config file — pure defaults plus environment).
	Path string `json:"path"`
	// Drifted is true when the current on-disk effective configuration differs
	// from the running one, or when the on-disk file can no longer be loaded
	// (Error is set in that case).
	Drifted bool `json:"drifted"`
	// RunningConfigHash is the effective fingerprint captured at process start.
	RunningConfigHash string `json:"runningConfigHash"`
	// CurrentConfigHash is the effective fingerprint recomputed from disk now.
	// Empty when the on-disk file could not be loaded.
	CurrentConfigHash string `json:"currentConfigHash,omitempty"`
	// RunningFileHash / CurrentFileHash are raw-byte digests of the file; they
	// detect textual changes (including comments) that may not alter the
	// effective configuration. Empty when there is no backing file.
	RunningFileHash string `json:"runningFileHash,omitempty"`
	CurrentFileHash string `json:"currentFileHash,omitempty"`
	// Error is set when the on-disk file could not be read/parsed/validated; the
	// status is reported as drifted so operators are alerted to the broken file.
	Error string `json:"error,omitempty"`
}

// Detector compares the effective configuration captured at process start
// against the current on-disk file on demand. It pairs with the hot-reload
// subsystems: when an operator edits config on disk but the running process has
// not reloaded it, the detector reports drift over the admin endpoint and the
// pullthrough_config_drift metric. The detector is immutable and safe for
// concurrent use (Status only reads disk).
type Detector struct {
	path            string
	runningHash     string
	runningFileHash string
}

// NewDetector captures the boot configuration's effective fingerprint (and, when
// a file backs it, the raw-file digest) so later Status calls can detect drift.
// boot must be the configuration the process is actually running.
func NewDetector(path string, boot *Config) *Detector {
	d := &Detector{path: path, runningHash: Fingerprint(boot)}
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			d.runningFileHash = hashBytes(data)
		}
	}
	return d
}

// RunningHash returns the effective fingerprint captured at process start.
func (d *Detector) RunningHash() string { return d.runningHash }

// Status recomputes the effective configuration from the on-disk file and
// reports whether it has drifted from the running configuration. A file that no
// longer reads, parses, or validates is reported as drifted with Error set.
func (d *Detector) Status() DriftStatus {
	st := DriftStatus{
		Path:              d.path,
		RunningConfigHash: d.runningHash,
		RunningFileHash:   d.runningFileHash,
	}

	if d.path == "" {
		// No file backs the running config; the effective config can still drift
		// if the environment (PTS_* / ${ENV}) changed under it.
		cur, err := loadEffective("")
		if err != nil {
			st.Error = err.Error()
			st.Drifted = true
			return st
		}
		st.CurrentConfigHash = Fingerprint(cur)
		st.Drifted = st.CurrentConfigHash != d.runningHash
		return st
	}

	data, err := os.ReadFile(d.path)
	if err != nil {
		st.Error = err.Error()
		st.Drifted = true
		return st
	}
	st.CurrentFileHash = hashBytes(data)

	cur, err := loadEffective(d.path)
	if err != nil {
		// The file changed into something that no longer loads — definitely drift,
		// and an operator must be alerted.
		st.Error = err.Error()
		st.Drifted = true
		return st
	}
	st.CurrentConfigHash = Fingerprint(cur)
	st.Drifted = st.CurrentConfigHash != d.runningHash
	return st
}

// Drifted is a convenience that reports only whether drift is present (used by
// the Prometheus gauge bridge).
func (d *Detector) Drifted() bool { return d.Status().Drifted }
