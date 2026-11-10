// Package avscan implements a pluggable antivirus content-scanning admission
// gate. It streams a fetched artifact's bytes (package archives, wheels, jars,
// container layer blobs, ML weight files, Git LFS objects) through a configured
// malware engine and, on a positive detection, annotates / quarantines / blocks
// the artifact and emits a finding into the unified dossier/risk/SARIF/
// notification pipeline.
//
// The primary engine is ClamAV, driven over the clamd INSTREAM protocol on a
// TCP or UNIX socket (see clamd.go), so the proxy scans an in-flight,
// cache-staged blob without handing the daemon a filesystem path. The Engine
// interface (engine.go) lets an operator substitute an alternative scanner.
//
// This complements the signature-list OSV malware feed (Task 48), which blocks
// known-malicious coordinates by name/version, with real byte-level detection of
// the payload actually served. Unlike the coordinate feed, avscan is
// ecosystem-agnostic: it inspects any cacheable binary artifact.
//
// When the engine is unreachable or errors, the gate degrades gracefully per the
// fail-open / fail-closed policy rather than failing the pull hard. All exported
// methods are safe for concurrent use and safe on a nil receiver.
package avscan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Stable rule identifier for an antivirus detection finding.
const RuleMalwareDetected = "avscan/malware-detected"

// Artifact identifies the cached blob being scanned.
type Artifact struct {
	Ecosystem string
	// Name is the package/image coordinate (empty for a bare blob).
	Name string
	// Version is the version/tag/revision.
	Version string
	// Filename is the artifact filename, used for reporting (not for gating).
	Filename string
	// Digest is the content digest when known (e.g. "sha256:...").
	Digest string
	// MediaType is the artifact content type when known.
	MediaType string
}

// Coordinate renders a "name@version" coordinate, falling back to the filename
// or digest for a bare blob.
func (a Artifact) Coordinate() string {
	switch {
	case a.Name != "" && a.Version != "":
		return a.Name + "@" + a.Version
	case a.Name != "":
		return a.Name
	case a.Filename != "":
		return a.Filename
	default:
		return a.Digest
	}
}

// Finding is a single antivirus detection.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	Signature string   `json:"signature"`
}

// Report is the deterministic result of scanning one artifact.
type Report struct {
	Artifact Artifact `json:"artifact"`
	// Engine is the scanner that produced the verdict.
	Engine string `json:"engine,omitempty"`
	// Scanned reports that the engine returned a completed verdict (clean or
	// infected).
	Scanned bool `json:"scanned"`
	// Infected reports a positive malware detection.
	Infected bool `json:"infected"`
	// Signature is the matched malware signature when Infected.
	Signature string `json:"signature,omitempty"`
	// Bytes is the number of payload bytes streamed to the engine.
	Bytes int64 `json:"bytes"`
	// Truncated reports that the artifact exceeded MaxScanBytes and only a prefix
	// was scanned.
	Truncated bool `json:"truncated,omitempty"`
	// Unavailable reports that the engine could not be reached / errored, so no
	// verdict was obtained. The gate applies the fail-open/fail-closed policy.
	Unavailable bool `json:"unavailable,omitempty"`
	// Error records the non-fatal engine error, when Unavailable.
	Error string `json:"error,omitempty"`
	// Risk is the ordinal 0..100 risk contribution (0 unless infected).
	Risk int `json:"risk"`
	// Findings holds the detection finding (at most one per scan).
	Findings []Finding `json:"findings,omitempty"`
}

// HasFindings reports whether the report carries a detection.
func (r *Report) HasFindings() bool { return r != nil && len(r.Findings) > 0 }

// Service is the antivirus content-scanning gate. Construct one with NewService.
type Service struct {
	cfg    Config
	engine Engine
	log    *slog.Logger

	scanned     atomic.Uint64 // artifacts that got a completed verdict
	clean       atomic.Uint64
	infected    atomic.Uint64
	truncated   atomic.Uint64
	unavailable atomic.Uint64 // scans where the engine could not be reached
	bytesTotal  atomic.Uint64

	quarantined atomic.Uint64
	blocked     atomic.Uint64
	annotated   atomic.Uint64
	degraded    atomic.Uint64 // fail-open admissions without a verdict

	mu          sync.Mutex
	bySignature map[string]uint64
}

// NewService validates cfg, constructs the configured engine, and returns the
// gate.
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	engine, err := newEngine(cfg)
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:         cfg,
		engine:      engine,
		log:         log,
		bySignature: make(map[string]uint64),
	}, nil
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// EngineName returns the configured engine's identifier.
func (s *Service) EngineName() string {
	if s == nil || s.engine == nil {
		return ""
	}
	return s.engine.Name()
}

// Ping checks engine reachability for status/health reporting. Safe on a nil
// receiver (returns nil).
func (s *Service) Ping(ctx context.Context) error {
	if s == nil || s.engine == nil {
		return nil
	}
	return s.engine.Ping(ctx)
}

// Assess streams the artifact's bytes through the malware engine and returns a
// deterministic report. open lazily yields a fresh content stream, read at most
// once (up to MaxScanBytes) and closed by Assess. A failure to reach the engine
// yields a report with Unavailable=true (and a nil error) so the gate can apply
// the fail-open/fail-closed policy; a hard I/O error on the content stream is
// returned as an error.
func (s *Service) Assess(ctx context.Context, art Artifact, open func() (io.ReadCloser, error)) (*Report, error) {
	report := &Report{Artifact: art, Engine: s.engine.Name()}

	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Bound the bytes streamed to the engine. A probe byte beyond the limit lets
	// us flag truncation without buffering the whole artifact.
	limited := io.LimitReader(rc, s.cfg.MaxScanBytes)
	verdict, scanErr := s.engine.Scan(ctx, limited)
	if scanErr != nil {
		if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
			// A cancelled request is not an engine fault; surface it to the caller.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		report.Unavailable = true
		report.Error = scanErr.Error()
		s.unavailable.Add(1)
		s.log.Warn("avscan: engine scan failed; applying degradation policy",
			"engine", s.engine.Name(), "artifact", art.Coordinate(), "error", scanErr)
		return report, nil
	}

	report.Scanned = true
	report.Bytes = verdict.Bytes
	s.scanned.Add(1)
	s.bytesTotal.Add(uint64(verdict.Bytes))

	// Truncation: if we streamed exactly the limit, probe one more byte to learn
	// whether the artifact continued beyond the scanned prefix.
	if verdict.Bytes >= s.cfg.MaxScanBytes {
		var probe [1]byte
		if n, _ := rc.Read(probe[:]); n > 0 {
			report.Truncated = true
			s.truncated.Add(1)
		}
	}

	if verdict.Infected {
		report.Infected = true
		report.Signature = verdict.Signature
		report.Risk = detectionRisk
		report.Findings = []Finding{{
			RuleID:    RuleMalwareDetected,
			Title:     "Malware detected in artifact payload",
			Severity:  SeverityCritical,
			Signature: verdict.Signature,
		}}
		s.infected.Add(1)
		s.bumpSignature(verdict.Signature)
	} else {
		s.clean.Add(1)
	}
	return report, nil
}

func (s *Service) bumpSignature(sig string) {
	if sig == "" {
		sig = "unknown"
	}
	s.mu.Lock()
	s.bySignature[sig]++
	s.mu.Unlock()
}

// Action returns the configured detection action.
func (s *Service) Action() Action {
	if s == nil {
		return ActionQuarantine
	}
	return s.cfg.Action
}

// FailOpen reports the configured engine-unavailable policy.
func (s *Service) FailOpen() bool { return s != nil && s.cfg.FailOpen }
