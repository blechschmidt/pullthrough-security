// Package mlguard implements a deterministic, no-execution admission gate for
// machine-learning model weights (the ML analogue of the install-hook static
// scanner).
//
// The dominant ML supply-chain attack is the malicious pickle: a model "weight"
// file (.bin/.pkl/.pt/.pth/.ckpt) is, under the hood, a Python pickle — a
// stack-based program the deserializer executes on load. An attacker embeds a
// GLOBAL import of a code-execution primitive (os.system, subprocess.Popen,
// builtins.eval/exec, a socket) and invokes it via __reduce__ (the REDUCE
// opcode), so merely loading the model runs attacker code. Safetensors, by
// contrast, is a tensor-only format with no executable opcodes.
//
// This gate never unpickles anything. It statically disassembles the pickle
// opcode stream (unwrapping the PyTorch ZIP container when present), extracts
// every imported callable, and flags imports of code-execution / network /
// filesystem primitives — the same approach as picklescan / fickling. A finding
// whose severity meets the tenant's threshold warns on or blocks (and evicts) the
// weight file. The gate also recognizes and prefers safetensors: a safetensors
// file is always admitted and surfaced as the safe format, and a pickle served
// when a safer format exists is flagged.
//
// The result is a stable, ordered finding set with a composite risk contribution
// folded into the same aggregated admission document (policyengine.Input) the
// policy-as-code and risk-scoring engines evaluate, and surfaced through the
// unified SARIF findings layer. All exported methods are safe for concurrent use.
package mlguard

import (
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Stable rule identifiers for the pickle-scanner findings.
const (
	// RuleCodeExecImport — the pickle imports a code-execution / shell / network /
	// filesystem primitive (os.system, subprocess, builtins.eval, socket, ...).
	RuleCodeExecImport = "pickle-code-execution-import"
	// RuleSuspiciousImport — the pickle imports a module that is abnormal in a
	// weight file and is a pickle-exploit building block (importlib, base64,
	// codecs, marshal, operator, ...).
	RuleSuspiciousImport = "pickle-suspicious-import"
	// RuleReduce — the pickle invokes an imported callable via __reduce__ (REDUCE),
	// the execution mechanism; recorded as supporting evidence alongside an unsafe
	// import.
	RuleReduce = "pickle-reduce-opcode"
)

// Artifact identifies the model/dataset file being assessed.
type Artifact struct {
	Ecosystem string
	// Name is the repository coordinate (e.g. "bigscience/bloom").
	Name string
	// Version is the revision (branch, tag, or commit SHA).
	Version string
	// Filename is the repository-relative filename, used for format classification.
	Filename string
	Digest   string
}

// Coordinate renders a "name@version" coordinate.
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

// Finding is one flagged pickle import (or the REDUCE mechanism).
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Stream is the pickle stream the finding came from (e.g. "archive/data.pkl"
	// or "<root>" for a bare pickle).
	Stream string `json:"stream,omitempty"`
	// Import is the offending "module.name" (empty for a REDUCE-mechanism finding).
	Import string `json:"import,omitempty"`
	// Opcode names the pickle opcode that raised the finding.
	Opcode string `json:"opcode,omitempty"`
}

// Report is the deterministic result of assessing one weight file.
type Report struct {
	Artifact Artifact `json:"artifact"`
	Format   Format   `json:"format,omitempty"`
	// Inspected reports that the file was a pickle format whose opcode stream the
	// gate actually disassembled.
	Inspected bool `json:"inspected"`
	// SafeFormat reports that the file is safetensors (preferred, never flagged).
	SafeFormat bool `json:"safeFormat"`
	// Streams / Opcodes summarize the disassembly scope.
	Streams     int       `json:"streams,omitempty"`
	Opcodes     int       `json:"opcodes,omitempty"`
	Imports     []string  `json:"imports,omitempty"` // distinct flagged "module.name"
	Findings    []Finding `json:"findings,omitempty"`
	MaxSeverity Severity  `json:"maxSeverity,omitempty"`
	// Risk is the composite ordinal risk contribution (0..100).
	Risk int `json:"risk"`
	// Truncated reports that extraction/scan hit a size/entry bound and some
	// content was not scanned (the gate fails open on it, but flags it).
	Truncated bool `json:"truncated,omitempty"`
	// Error records a non-fatal extraction problem; the gate fails open on it.
	Error string `json:"error,omitempty"`
}

// HasFindings reports whether the report carries at least one finding.
func (r *Report) HasFindings() bool { return r != nil && len(r.Findings) > 0 }

// Service is the ML weight-scanning gate. Construct one with NewService.
type Service struct {
	cfg Config
	log *slog.Logger

	scanned       atomic.Uint64 // pickle files whose opcode stream was disassembled
	safetensors   atomic.Uint64 // safetensors files recognized and preferred
	flaggedArts   atomic.Uint64
	findingsTotal atomic.Uint64
	blocked       atomic.Uint64
	warned        atomic.Uint64

	mu     sync.Mutex
	byRule map[string]uint64
}

// NewService validates cfg and constructs a Service.
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		cfg:    cfg,
		log:    log,
		byRule: make(map[string]uint64),
	}, nil
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// supportedEcosystem reports whether the gate applies to an ecosystem.
func supportedEcosystem(eco string) bool {
	switch strings.ToLower(eco) {
	case "huggingface", "hf":
		return true
	default:
		return false
	}
}

// Assess classifies the artifact's weight format and, for a pickle-based file,
// statically disassembles its opcode stream and flags unsafe imports. It never
// executes anything and is deterministic. open lazily yields a fresh content
// stream, read at most once and closed by Assess. A non-weight resource (config/
// tokenizer/metadata) or a non-ML ecosystem yields a clean, inspected=false
// report rather than an error.
func (s *Service) Assess(art Artifact, open func() (io.ReadCloser, error)) (*Report, error) {
	report := &Report{Artifact: art}
	if !supportedEcosystem(art.Ecosystem) {
		return report, nil
	}
	format := classifyFormat(art.Filename)
	report.Format = format

	switch format {
	case FormatOther:
		// Not a weight file (config.json, tokenizer, README): the gate does not apply.
		return report, nil
	case FormatSafetensors:
		report.SafeFormat = true
		s.safetensors.Add(1)
		return report, nil
	case FormatGGUF, FormatOtherWeights:
		// A non-pickle binary weight format: no arbitrary-callable execution on load,
		// so it is recorded but not opcode-scanned.
		return report, nil
	}

	// Pickle-based weight file: extract and disassemble.
	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf, sourceTruncated, rerr := readBounded(rc, s.cfg.MaxScanBytes)
	if rerr != nil {
		report.Error = rerr.Error()
		s.log.Debug("mlguard: reading weight file failed; serving without scan",
			"artifact", art.Coordinate(), "error", rerr)
		return report, nil
	}

	streams, truncated := extractPickleStreams(buf, sourceTruncated, s.cfg.MaxZipEntries, s.cfg.MaxScanBytes)
	report.Truncated = truncated
	report.Streams = len(streams)
	if len(streams) == 0 {
		// An oversize/opaque container we could not open: fail open but flagged.
		if truncated {
			report.Error = "weight file exceeded the scan limit or could not be opened"
		}
		return report, nil
	}

	s.scanned.Add(1)
	report.Inspected = true
	report.Findings = s.scanStreams(streams, report)
	report.MaxSeverity = maxSeverity(report.Findings)
	report.Risk = riskScore(report.MaxSeverity, len(report.Findings))
	if len(report.Findings) > 0 {
		s.flaggedArts.Add(1)
		s.findingsTotal.Add(uint64(len(report.Findings)))
		s.bumpRules(report.Findings)
	}
	return report, nil
}

// scanStreams disassembles every extracted pickle stream and returns the flagged
// imports in a stable order (by stream, then severity-desc, then import name).
func (s *Service) scanStreams(streams []namedStream, report *Report) []Finding {
	var findings []Finding
	seen := make(map[string]struct{})
	importSet := make(map[string]struct{})
	for si := range streams {
		st := streams[si]
		sc := scanPickle(st.data)
		report.Opcodes += sc.OpcodeCount
		if sc.Truncated {
			report.Truncated = true
		}
		dangerousInStream := false
		for _, g := range sc.Globals {
			sev, rule, ok := classifyGlobal(g)
			if !ok {
				continue
			}
			dangerousInStream = true
			imp := g.qualified()
			if _, dup := importSet[imp]; !dup {
				importSet[imp] = struct{}{}
				report.Imports = append(report.Imports, imp)
			}
			key := st.name + "|" + rule + "|" + imp
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, Finding{
				RuleID:   rule,
				Title:    ruleTitle(rule),
				Severity: sev,
				Stream:   st.name,
				Import:   imp,
				Opcode:   "GLOBAL",
			})
		}
		// Record the REDUCE mechanism as supporting evidence only when an unsafe
		// import is present in the same stream (legitimate weights use REDUCE
		// pervasively via torch rebuild helpers, so REDUCE alone is not a finding).
		if sc.HasReduce && dangerousInStream {
			key := st.name + "|" + RuleReduce
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					RuleID:   RuleReduce,
					Title:    ruleTitle(RuleReduce),
					Severity: SeverityMedium,
					Stream:   st.name,
					Opcode:   "REDUCE",
				})
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Stream != findings[j].Stream {
			return findings[i].Stream < findings[j].Stream
		}
		if ri, rj := severityRank(findings[i].Severity), severityRank(findings[j].Severity); ri != rj {
			return ri > rj
		}
		return findings[i].Import < findings[j].Import
	})
	sort.Strings(report.Imports)
	return findings
}

func ruleTitle(rule string) string {
	switch rule {
	case RuleCodeExecImport:
		return "Pickle imports a code-execution primitive"
	case RuleSuspiciousImport:
		return "Pickle imports a suspicious module"
	case RuleReduce:
		return "Pickle invokes an imported callable via __reduce__"
	default:
		return rule
	}
}

func (s *Service) bumpRules(findings []Finding) {
	s.mu.Lock()
	for i := range findings {
		s.byRule[findings[i].RuleID]++
	}
	s.mu.Unlock()
}

// readBounded reads up to max+ bytes from rc, reporting whether the source
// exceeded max (so an oversize file is flagged). It bounds memory to ~max.
func readBounded(rc io.Reader, max int) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(rc, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(buf) > max {
		return buf[:max], true, nil
	}
	return buf, false, nil
}
