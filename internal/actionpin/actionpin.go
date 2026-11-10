package actionpin

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Artifact identifies the Git content being inspected (a repository + optional
// commit), for finding attribution and metrics.
type Artifact struct {
	// Repository is the source repository URL or name.
	Repository string
	// CommitSHA is the commit the inspected content came from, when known.
	CommitSHA string
}

// FileInput is one workflow / composite-action file handed to the gate. Lines
// carry their (new-file, 1-based) line numbers so findings localize precisely;
// callers holding full file text can build them with Lines.
type FileInput struct {
	Path  string
	Lines []Line
}

// Finding is one pinning-hygiene / allowlist violation on a `uses:` reference.
type Finding struct {
	// RuleID is one of RuleMutableRef, RuleUnpinned, RuleDisallowedOwner.
	RuleID string `json:"ruleId"`
	// Title is a short, human-readable summary.
	Title string `json:"title"`
	// Severity is the finding severity.
	Severity Severity `json:"severity"`
	// Reference is the offending (length-bounded) `uses:` value.
	Reference string `json:"reference"`
	// Owner is the action owner/org the reference targets (when applicable).
	Owner string `json:"owner,omitempty"`
	// Pinning records how the reference was pinned.
	Pinning Pinning `json:"pinning"`
	// File and Line locate the reference within the inspected content.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	// Detail explains the finding and the remediation.
	Detail string `json:"detail,omitempty"`
}

// Report is the deterministic result of inspecting one content set.
type Report struct {
	Artifact Artifact  `json:"artifact"`
	Findings []Finding `json:"findings,omitempty"`
	// References is the total number of `uses:` references inspected.
	References int `json:"references"`
	// Files is the number of workflow/action files inspected.
	Files int `json:"files"`
	// MaxSeverity is the highest finding severity (empty for none).
	MaxSeverity Severity `json:"maxSeverity,omitempty"`
	// Risk is the composite ordinal risk contribution (0..100) derived from the
	// findings, fed into the unified risk-scoring / policy engines.
	Risk int `json:"risk"`
	// Inspected reports that at least one workflow/composite-action file was seen
	// (false when the content carried none).
	Inspected bool `json:"inspected"`
}

// HasFindings reports whether the report carries at least one finding.
func (r *Report) HasFindings() bool { return r != nil && len(r.Findings) > 0 }

// Service is the GitHub Actions pinning gate. The zero value is not usable;
// construct one with NewService.
type Service struct {
	cfg         Config
	allowOwners map[string]struct{}
	log         *slog.Logger

	scanned       atomic.Uint64 // content sets inspected
	filesScanned  atomic.Uint64
	refsScanned   atomic.Uint64
	findingsTotal atomic.Uint64
	flaggedSets   atomic.Uint64
	blocked       atomic.Uint64
	warned        atomic.Uint64

	mu     sync.Mutex
	byRule map[string]uint64
}

// NewService validates cfg and constructs a Service. It returns an error only
// for an invalid configuration.
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
		cfg:         cfg,
		allowOwners: ownerSet(cfg.AllowedOwners),
		log:         log,
		byRule:      make(map[string]uint64),
	}, nil
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// CacheSignature returns a deterministic, order-independent fingerprint of the
// policy inputs that affect which findings are produced (thresholds, action,
// pinning toggle, and the owner allowlist). It is folded into the commit-scan
// verdict cache key so a policy change forces a re-scan rather than a stale hit.
func (s *Service) CacheSignature() string {
	if s == nil {
		return ""
	}
	owners := make([]string, 0, len(s.allowOwners))
	for o := range s.allowOwners {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	return fmt.Sprintf("fail=%s;warn=%s;action=%s;pin=%t;owners=%s;max=%d",
		s.cfg.FailSeverity, s.cfg.WarnSeverity, s.cfg.Action, s.cfg.RequirePinning,
		strings.Join(owners, ","), s.cfg.MaxFindings)
}

// Assess inspects the workflow / composite-action files for `uses:` references
// and classifies each against the active policy. It is deterministic: the same
// inputs always produce the same ordered finding set. A content set with no
// Actions files yields a clean, Inspected=false report. The per-tenant allowlist
// and thresholds are resolved by Gate, not here, so the report is tenant-neutral.
func (s *Service) Assess(art Artifact, files []FileInput) *Report {
	report := &Report{Artifact: art}
	if s == nil {
		return report
	}

	// The owner allowlist is global; it governs which disallowed-owner findings
	// are produced here. Per-tenant block/warn thresholds are applied later by
	// Gate against the resulting report's severity.
	allow := s.allowOwners

	var findings []Finding
	for fi := range files {
		f := files[fi]
		if !IsActionsFile(f.Path) {
			continue
		}
		report.Files++
		s.filesScanned.Add(1)
		refs := ParseLines(f.Lines)
		report.References += len(refs)
		s.refsScanned.Add(uint64(len(refs)))
		for ri := range refs {
			if len(findings) >= s.cfg.MaxFindings {
				break
			}
			if fnd, ok := s.evaluate(refs[ri], f.Path, allow); ok {
				findings = append(findings, fnd)
			}
		}
	}

	if report.Files == 0 {
		return report
	}
	report.Inspected = true
	s.scanned.Add(1)

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return ruleOrder(findings[i].RuleID) < ruleOrder(findings[j].RuleID)
	})
	report.Findings = findings
	report.MaxSeverity = maxSeverity(findings)
	report.Risk = riskScore(report.MaxSeverity, len(findings))
	if len(findings) > 0 {
		s.flaggedSets.Add(1)
		s.findingsTotal.Add(uint64(len(findings)))
		s.bumpRules(findings)
	}
	return report
}

// evaluate classifies a single reference and, if it violates policy, returns the
// finding. A disallowed owner (against a non-empty allowlist) always wins over a
// pinning finding for the same reference, since it is the more severe signal.
func (s *Service) evaluate(ref Reference, file string, allow map[string]struct{}) (Finding, bool) {
	// Owner allowlist (remote references only; local and docker references do not
	// carry a GitHub owner/org).
	if ref.Kind == KindRemote && len(allow) > 0 && ref.Owner != "" {
		if _, ok := allow[strings.ToLower(ref.Owner)]; !ok {
			return Finding{
				RuleID:    RuleDisallowedOwner,
				Title:     fmt.Sprintf("Action owner %q is not in the allowlist", ref.Owner),
				Severity:  SeverityHigh,
				Reference: ref.Raw,
				Owner:     ref.Owner,
				Pinning:   ref.pinningOf(),
				File:      file,
				Line:      ref.Line,
				Detail: fmt.Sprintf("the workflow references %q, whose owner %q is not among the permitted action owners; "+
					"restrict workflows to vetted owners or add %q to the allowlist if it is trusted", ref.Raw, ref.Owner, ref.Owner),
			}, true
		}
	}

	if !s.cfg.RequirePinning {
		return Finding{}, false
	}

	pin := ref.pinningOf()
	if pin.OK() {
		return Finding{}, false
	}

	switch pin {
	case PinNone:
		return Finding{
			RuleID:    RuleUnpinned,
			Title:     fmt.Sprintf("Action %q is not pinned to a commit SHA", displayTarget(ref)),
			Severity:  SeverityMedium,
			Reference: ref.Raw,
			Owner:     ref.Owner,
			Pinning:   pin,
			File:      file,
			Line:      ref.Line,
			Detail: fmt.Sprintf("the reference %q carries no ref and resolves to the default branch's latest commit; "+
				"pin it to a full 40-character commit SHA", ref.Raw),
		}, true
	case PinMutable:
		kind := "mutable ref"
		if ref.Kind == KindDocker {
			kind = "mutable image tag"
		} else if looksLikeVersionTag(ref.Ref) {
			kind = "floating version tag"
		} else {
			kind = "branch or tag"
		}
		return Finding{
			RuleID:    RuleMutableRef,
			Title:     fmt.Sprintf("Action %q is pinned to a %s, not a commit SHA", displayTarget(ref), kind),
			Severity:  SeverityMedium,
			Reference: ref.Raw,
			Owner:     ref.Owner,
			Pinning:   pin,
			File:      file,
			Line:      ref.Line,
			Detail: fmt.Sprintf("the reference %q is pinned to the %s %q, which is mutable — whoever controls it can change the "+
				"code that runs; pin it to a full 40-character commit SHA instead", ref.Raw, kind, ref.Ref),
		}, true
	default:
		return Finding{}, false
	}
}

// displayTarget renders a reference's "owner/repo" (or raw value) for a title.
func displayTarget(ref Reference) string {
	switch ref.Kind {
	case KindRemote:
		if ref.Owner != "" && ref.Repo != "" {
			return ref.Owner + "/" + ref.Repo
		}
	case KindDocker:
		return ref.Raw
	}
	if ref.Raw != "" {
		return ref.Raw
	}
	return "(reference)"
}

// ruleOrder gives a stable ordering to the finding rules (most severe first).
func ruleOrder(id string) int {
	switch id {
	case RuleDisallowedOwner:
		return 0
	case RuleUnpinned:
		return 1
	case RuleMutableRef:
		return 2
	default:
		return 3
	}
}

// maxSeverity returns the highest severity across the findings (or "" for none).
func maxSeverity(findings []Finding) Severity {
	var worst Severity
	for i := range findings {
		if severityRank(findings[i].Severity) > severityRank(worst) {
			worst = findings[i].Severity
		}
	}
	return worst
}

// riskScore maps the worst severity (and finding volume) onto a 0..100 ordinal
// risk contribution, mirroring the installhooks gate so the signals compose on a
// common scale.
func riskScore(worst Severity, count int) int {
	base := 0
	switch worst {
	case SeverityCritical:
		base = 95
	case SeverityHigh:
		base = 80
	case SeverityMedium:
		base = 55
	case SeverityLow:
		base = 30
	case SeverityInfo:
		base = 12
	default:
		return 0
	}
	if count > 1 {
		extra := (count - 1) * 3
		headroom := 100 - base
		if extra > headroom {
			extra = headroom
		}
		base += extra
	}
	if base > 100 {
		base = 100
	}
	return base
}

func (s *Service) bumpRules(findings []Finding) {
	s.mu.Lock()
	for i := range findings {
		s.byRule[findings[i].RuleID]++
	}
	s.mu.Unlock()
}
