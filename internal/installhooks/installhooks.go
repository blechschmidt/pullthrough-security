// Package installhooks implements a deterministic, no-execution admission gate
// that statically extracts and scores a package's install / lifecycle scripts
// (Task 62).
//
// Modern supply-chain attacks frequently weaponize the install-time hooks a
// package manager runs automatically on `npm install`, `pip install`, `gem
// install`, or a `cargo build`: an npm preinstall/install/postinstall script, a
// Python setup.py build hook, a RubyGems native extension or post-install
// message, or a Cargo build.rs. Because these run before any code is imported,
// they are the earliest — and stealthiest — place to drop a crypto-miner,
// credential stealer, or reverse shell.
//
// This gate never executes anything. It extracts the relevant manifest/script
// files straight from the cached artifact archive and runs a fixed set of
// deterministic regex + heuristic rules over the script text, mirroring the
// secretscan subsystem's "no execution, fully reproducible" approach. The rules
// flag the patterns that distinguish a malicious install hook from a benign one:
// network egress in an install step (curl/wget/fetch), base64-decoded eval,
// shell/process spawning, writes outside the package directory, environment-
// variable exfiltration, and obfuscated one-liners.
//
// The result is a stable, ordered finding set with a composite risk contribution
// that is folded into the same aggregated admission document
// (policyengine.Input) the policy-as-code and risk-scoring engines evaluate, and
// surfaced through the unified SARIF findings layer so a CI pipeline can decorate
// a pull request. A configurable severity threshold (per-tenant) decides whether
// a flagged artifact is merely warned on or blocked.
//
// All exported methods are safe for concurrent use.
package installhooks

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
)

// Artifact identifies the package whose install hooks are being assessed.
type Artifact struct {
	Ecosystem string
	Name      string
	Version   string
	Digest    string
	Filename  string
	MediaType string
}

// Coordinate renders a "name@version" coordinate, falling back to the digest.
func (a Artifact) Coordinate() string {
	switch {
	case a.Name != "" && a.Version != "":
		return a.Name + "@" + a.Version
	case a.Name != "":
		return a.Name
	default:
		return a.Digest
	}
}

// Hook is one extracted lifecycle script or build hook. Script holds the raw
// command/source text that the rules are run over (bounded during extraction);
// Label is a stable, human- and metric-friendly identifier such as
// "npm:postinstall" or "cargo:build.rs".
type Hook struct {
	Ecosystem string `json:"ecosystem"`
	// Kind is the lifecycle phase / hook category, e.g. "postinstall",
	// "setup.py", "build.rs", "extension", "post_install_message".
	Kind string `json:"kind"`
	// Label is "<ecosystem>:<kind>", the stable key used in findings and metrics.
	Label string `json:"label"`
	// File is the path of the hook within the package archive.
	File string `json:"file"`
	// Script is the (bounded) hook source/command text scanned by the rules.
	Script string `json:"script,omitempty"`
}

// Finding is one matched high-risk pattern in an install hook. The match is
// rendered as a short, whitespace-collapsed, length-bounded Excerpt so a finding
// is legible without leaking a large blob into logs/SARIF.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Title     string   `json:"title"`
	Severity  Severity `json:"severity"`
	HookLabel string   `json:"hookLabel"`
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
	Excerpt   string   `json:"excerpt,omitempty"`
}

// Report is the deterministic result of assessing one artifact's install hooks.
type Report struct {
	Artifact    Artifact  `json:"artifact"`
	Hooks       []Hook    `json:"hooks,omitempty"`
	Findings    []Finding `json:"findings,omitempty"`
	MaxSeverity Severity  `json:"maxSeverity,omitempty"`
	// Risk is the composite ordinal risk contribution (0..100) derived from the
	// findings, fed into the unified risk-scoring / policy engines.
	Risk int `json:"risk"`
	// Inspected reports that the artifact was an install-hook-bearing format the
	// gate understands and actually extracted (false for an index/listing or an
	// ecosystem with no install-time hooks).
	Inspected bool `json:"inspected"`
	// Truncated reports that extraction hit a size/entry bound and some content
	// was not scanned.
	Truncated bool `json:"truncated,omitempty"`
	// Error records a non-fatal extraction problem (a corrupt archive); the gate
	// fails open on it.
	Error string `json:"error,omitempty"`
}

// HasFindings reports whether the report carries at least one finding.
func (r *Report) HasFindings() bool { return r != nil && len(r.Findings) > 0 }

// Service is the install-hook risk-analysis gate. The zero value is not usable;
// construct one with NewService.
type Service struct {
	cfg   Config
	rules []Rule
	log   *slog.Logger

	scanned       atomic.Uint64
	hooksFound    atomic.Uint64
	findingsTotal atomic.Uint64
	flaggedArts   atomic.Uint64
	blocked       atomic.Uint64
	warned        atomic.Uint64

	mu     sync.Mutex
	byRule map[string]uint64
	byEco  map[string]uint64
}

// NewService validates cfg, compiles the active rule set, and constructs a
// Service. It returns an error only for an invalid configuration (a bad rule
// pattern or an invalid severity threshold).
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	rules, err := cfg.compileRules()
	if err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:    cfg,
		rules:  rules,
		log:    log,
		byRule: make(map[string]uint64),
		byEco:  make(map[string]uint64),
	}, nil
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Assess extracts the artifact's install/lifecycle hooks and scores them against
// the active rule set. It never executes anything and is deterministic: the same
// archive bytes always produce the same ordered finding set.
//
// open lazily yields a fresh content stream so the caller need not buffer the
// artifact; it is read at most once and closed by Assess. A nil/empty result for
// an ecosystem the gate does not understand (or a non-hook-bearing resource) is a
// clean, inspected=false report rather than an error.
func (s *Service) Assess(art Artifact, open func() (io.ReadCloser, error)) (*Report, error) {
	report := &Report{Artifact: art}
	if !supportedEcosystem(art.Ecosystem) || !applicableArtifact(art) {
		return report, nil
	}

	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	hooks, truncated, exErr := extractHooks(art, rc)
	report.Truncated = truncated
	if exErr != nil {
		// A corrupt or unexpected archive is not a finding; record it and fail open.
		report.Error = exErr.Error()
		s.log.Debug("installhooks: extraction failed; serving without scan",
			"artifact", art.Coordinate(), "ecosystem", art.Ecosystem, "error", exErr)
		return report, nil
	}

	s.scanned.Add(1)
	s.bumpEco(art.Ecosystem)
	if len(hooks) == 0 {
		// The archive parsed cleanly but declared no install hooks: the common,
		// benign case. Mark it inspected so the signal is recorded as "scanned, no
		// hooks" rather than absent.
		report.Inspected = true
		return report, nil
	}
	report.Inspected = true
	report.Hooks = hooks
	s.hooksFound.Add(uint64(len(hooks)))

	report.Findings = s.scanHooks(hooks)
	report.MaxSeverity = maxSeverity(report.Findings)
	report.Risk = riskScore(report.MaxSeverity, len(report.Findings))
	if len(report.Findings) > 0 {
		s.flaggedArts.Add(1)
		s.findingsTotal.Add(uint64(len(report.Findings)))
		s.bumpRules(report.Findings)
	}
	return report, nil
}

// scanHooks runs every active rule over every hook, deduplicating identical
// (rule, hook, line) matches and returning findings in a stable order: by hook
// (extraction order), then by rule (catalog order), then by line.
func (s *Service) scanHooks(hooks []Hook) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})
	maxPer := s.cfg.MaxFindingsPerHook
	for hi := range hooks {
		h := hooks[hi]
		perHook := 0
		for ri := range s.rules {
			rule := &s.rules[ri]
			matches := rule.match(h.Script)
			for _, m := range matches {
				key := fmt.Sprintf("%s|%s|%d", rule.ID, h.Label, m.line)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					RuleID:    rule.ID,
					Title:     rule.Title,
					Severity:  rule.Severity,
					HookLabel: h.Label,
					File:      h.File,
					Line:      m.line,
					Excerpt:   m.excerpt,
				})
				perHook++
				if maxPer > 0 && perHook >= maxPer {
					break
				}
			}
			if maxPer > 0 && perHook >= maxPer {
				break
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		hi, hj := hookOrder(hooks, findings[i].HookLabel), hookOrder(hooks, findings[j].HookLabel)
		if hi != hj {
			return hi < hj
		}
		ri, rj := s.ruleOrder(findings[i].RuleID), s.ruleOrder(findings[j].RuleID)
		if ri != rj {
			return ri < rj
		}
		return findings[i].Line < findings[j].Line
	})
	return findings
}

func hookOrder(hooks []Hook, label string) int {
	for i := range hooks {
		if hooks[i].Label == label {
			return i
		}
	}
	return len(hooks)
}

func (s *Service) ruleOrder(id string) int {
	for i := range s.rules {
		if s.rules[i].ID == id {
			return i
		}
	}
	return len(s.rules)
}

func (s *Service) bumpEco(eco string) {
	s.mu.Lock()
	s.byEco[eco]++
	s.mu.Unlock()
}

func (s *Service) bumpRules(findings []Finding) {
	s.mu.Lock()
	for i := range findings {
		s.byRule[findings[i].RuleID]++
	}
	s.mu.Unlock()
}
