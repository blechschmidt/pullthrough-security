package contentscan

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
)

// Action is the gate's response when a finding meets the configured fail
// threshold. It is intentionally observe-friendly: the default is annotate, so a
// new, heuristic-heavy gate never blocks a pull until an operator opts in.
type Action string

const (
	// ActionAnnotate records findings and always serves the artifact (observe
	// mode). This is the default.
	ActionAnnotate Action = "annotate"
	// ActionDowngrade records findings but lowers each one's severity by a single
	// rank before it reaches the risk/SARIF/policy layers, and always serves. It
	// turns a noisy heuristic advisory without discarding the signal.
	ActionDowngrade Action = "downgrade"
	// ActionBlock refuses (403) and evicts the artifact when a finding meets the
	// fail-severity threshold.
	ActionBlock Action = "block"
)

// Refuses reports whether the action can prevent an artifact from being served.
func (a Action) Refuses() bool { return a == ActionBlock }

// Default scan budget bounds. The gate unpacks an untrusted upstream archive, so
// every dimension (total bytes, per-file bytes, entry count, scanned text,
// findings, wall-clock) is bounded to keep a hostile or accidentally-huge
// artifact from exhausting memory or stalling the pull path.
const (
	defaultMaxArchiveBytes     int64         = 128 << 20 // decompressed bytes read overall
	defaultMaxFileBytes        int64         = 8 << 20   // bytes read per archive entry
	defaultMaxFiles            int           = 20000     // entry-count guard (tar/zip bomb)
	defaultMaxScanBytesPerFile int64         = 1 << 20   // text bytes scanned per file by the line rules
	defaultMaxFindings         int           = 500       // overall finding cap per artifact
	defaultMaxFindingsPerFile  int           = 25        // finding cap per file
	defaultTimeout             time.Duration = 20 * time.Second
)

// Config configures the package-payload static content-analysis gate.
type Config struct {
	// Enabled gates whether the service is built and wired into the pull path.
	Enabled bool
	// Action is applied when a finding meets FailSeverity: "annotate" (record +
	// serve), "downgrade" (record + serve, findings downgraded one rank) or
	// "block" (refuse + evict). Default "annotate".
	Action Action
	// FailSeverity is the minimum finding severity that triggers Action under the
	// block action. Default "high".
	FailSeverity Severity
	// Ecosystems restricts scanning to these (canonicalized) ecosystems. Empty
	// selects the built-in source-package default set.
	Ecosystems []string

	// Heuristic toggles. Each defaults on; an operator can turn one off to quiet a
	// dimension that is noisy for their corpus.
	DetectEntropy bool // high-entropy embedded blobs
	DetectBinary  bool // embedded native binaries in a source package
	DetectJS      bool // obfuscated / minified-plus-eval JavaScript
	DetectExec    bool // dynamic code-execution sinks
	DetectSecrets bool // in-source credentials/secrets (reuses Task 29 detectors)

	// EntropyThreshold is the byte-level Shannon entropy (bits/byte, 0..8) at or
	// above which a blob is flagged. Default 7.2.
	EntropyThreshold float64
	// MinEntropyBlobBytes is the smallest file size considered for the entropy
	// heuristic (short files are not reliable). Default 1024.
	MinEntropyBlobBytes int64

	// Budget bounds (0 => the package default for each).
	MaxArchiveBytes     int64
	MaxFileBytes        int64
	MaxFiles            int
	MaxScanBytesPerFile int64
	MaxFindings         int
	MaxFindingsPerFile  int
	Timeout             time.Duration

	// SecretDetector is the Task 29 deterministic secret detector reused against
	// package files. When nil and DetectSecrets is true, a default detector (the
	// built-in ruleset + entropy heuristic) is constructed.
	SecretDetector *secretscan.Detector

	// Logger is used for non-fatal diagnostics; nil uses slog.Default().
	Logger *slog.Logger
}

// defaultEcosystems is the built-in source-package set the gate inspects: the
// ecosystems whose published artifact is nominally source (so an embedded native
// binary or packed blob is a supply-chain tell).
var defaultEcosystems = []string{"npm", "pip", "cargo", "rubygems", "composer", "nuget"}

// DefaultConfig returns the built-in defaults: on, observe-only (annotate),
// block-threshold high, all heuristics active, conservative budget.
func DefaultConfig() Config {
	return Config{
		Enabled:             true,
		Action:              ActionAnnotate,
		FailSeverity:        SeverityHigh,
		DetectEntropy:       true,
		DetectBinary:        true,
		DetectJS:            true,
		DetectExec:          true,
		DetectSecrets:       true,
		EntropyThreshold:    7.2,
		MinEntropyBlobBytes: 1024,
		MaxArchiveBytes:     defaultMaxArchiveBytes,
		MaxFileBytes:        defaultMaxFileBytes,
		MaxFiles:            defaultMaxFiles,
		MaxScanBytesPerFile: defaultMaxScanBytesPerFile,
		MaxFindings:         defaultMaxFindings,
		MaxFindingsPerFile:  defaultMaxFindingsPerFile,
		Timeout:             defaultTimeout,
	}
}

// withDefaults fills zero-valued fields from the built-in defaults. The heuristic
// toggles are NOT defaulted here (a deliberately-false value must be preserved);
// the config/wiring layer establishes their true default.
func (c Config) withDefaults() Config {
	if c.Action == "" {
		c.Action = ActionAnnotate
	}
	c.Action = Action(strings.ToLower(strings.TrimSpace(string(c.Action))))
	if c.FailSeverity == "" {
		c.FailSeverity = SeverityHigh
	}
	c.FailSeverity = Severity(strings.ToLower(strings.TrimSpace(string(c.FailSeverity))))
	if c.EntropyThreshold == 0 {
		c.EntropyThreshold = 7.2
	}
	if c.MinEntropyBlobBytes == 0 {
		c.MinEntropyBlobBytes = 1024
	}
	if c.MaxArchiveBytes == 0 {
		c.MaxArchiveBytes = defaultMaxArchiveBytes
	}
	if c.MaxFileBytes == 0 {
		c.MaxFileBytes = defaultMaxFileBytes
	}
	if c.MaxFiles == 0 {
		c.MaxFiles = defaultMaxFiles
	}
	if c.MaxScanBytesPerFile == 0 {
		c.MaxScanBytesPerFile = defaultMaxScanBytesPerFile
	}
	if c.MaxFindings == 0 {
		c.MaxFindings = defaultMaxFindings
	}
	if c.MaxFindingsPerFile == 0 {
		c.MaxFindingsPerFile = defaultMaxFindingsPerFile
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
	// Normalize the ecosystem allowlist; empty falls back to the default set.
	if len(c.Ecosystems) == 0 {
		c.Ecosystems = append([]string(nil), defaultEcosystems...)
	} else {
		norm := make([]string, 0, len(c.Ecosystems))
		for _, e := range c.Ecosystems {
			if ce := canonEco(e); ce != "" {
				norm = append(norm, ce)
			}
		}
		c.Ecosystems = norm
	}
	return c
}

// validate checks the (defaults-applied) config for self-consistency.
func (c Config) validate() error {
	switch c.Action {
	case ActionAnnotate, ActionDowngrade, ActionBlock:
	default:
		return fmt.Errorf("contentscan: invalid action %q (want annotate|downgrade|block)", c.Action)
	}
	if _, ok := ParseSeverity(string(c.FailSeverity)); !ok {
		return fmt.Errorf("contentscan: invalid failSeverity %q", c.FailSeverity)
	}
	if c.EntropyThreshold < 0 || c.EntropyThreshold > 8 {
		return fmt.Errorf("contentscan: entropyThreshold %.3f out of range [0,8]", c.EntropyThreshold)
	}
	if c.MinEntropyBlobBytes < 0 {
		return fmt.Errorf("contentscan: minEntropyBlobBytes must not be negative")
	}
	if c.MaxArchiveBytes < 0 || c.MaxFileBytes < 0 || c.MaxScanBytesPerFile < 0 {
		return fmt.Errorf("contentscan: byte bounds must not be negative")
	}
	if c.MaxFiles < 0 || c.MaxFindings < 0 || c.MaxFindingsPerFile < 0 {
		return fmt.Errorf("contentscan: count bounds must not be negative")
	}
	if c.Timeout < 0 {
		return fmt.Errorf("contentscan: timeout must not be negative")
	}
	return nil
}

// ecosystemAllowed reports whether an ecosystem is in the configured allowlist.
func (c Config) ecosystemAllowed(eco string) bool {
	ce := canonEco(eco)
	for _, e := range c.Ecosystems {
		if e == ce {
			return true
		}
	}
	return false
}
