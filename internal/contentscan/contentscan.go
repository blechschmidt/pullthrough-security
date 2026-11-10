// Package contentscan implements a deterministic, no-execution admission gate
// that statically analyzes the *contents* of a served source package (Task 138).
//
// The install-script gate (Task 62) inspects a package's declared lifecycle
// hooks, and the antivirus gate (Task 136) streams the raw payload through a
// signature engine. This gate complements both by unpacking a cached source
// artifact — an npm tarball, a pip sdist/wheel, a gem/composer/cargo/nuget
// archive — and applying a fixed set of content heuristics to every file inside:
//
//   - high-entropy embedded blobs (packed / encrypted payloads hiding under a
//     source/text/data extension),
//   - unexpectedly embedded native binaries in a nominally-source package
//     (ELF/PE/Mach-O/.so/.dll/.node/...),
//   - obfuscated or minified-plus-eval JavaScript,
//   - dynamic code-execution sinks (eval/exec, base64-decode-then-run, remote
//     script piped into a shell),
//   - in-source credentials/secrets, by reusing the Task 29 deterministic secret
//     detectors against the package files rather than a commit diff.
//
// It never executes anything and is fully deterministic: the same archive bytes
// always produce the same ordered finding set. Every dimension of work (total
// bytes, per-file bytes, entry count, scanned text, findings, wall-clock) is
// bounded by a configurable budget so a hostile or accidentally-huge artifact
// cannot exhaust memory or stall the pull path. The result folds into the same
// unified dossier / risk / SARIF / notification pipeline as the other gates,
// honoring annotate|downgrade|block actions. It runs only on cacheable artifacts
// per the existing content-gate wiring.
//
// All exported methods are safe for concurrent use and safe on a nil receiver.
package contentscan

import (
	"context"
	"io"
	"log/slog"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
)

// Artifact identifies the cached package whose contents are being analyzed.
type Artifact struct {
	Ecosystem string
	Name      string
	Version   string
	Digest    string
	Filename  string
	MediaType string
}

// Coordinate renders a "name@version" coordinate, falling back to the filename
// or digest.
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

// Finding is one flagged content pattern in a package file. The match is rendered
// as a short, whitespace-collapsed, length-bounded Excerpt so a finding is
// legible without leaking a large blob into logs/SARIF. For a secret finding the
// Excerpt is the detector's redacted match (never the raw credential).
type Finding struct {
	RuleID   string   `json:"ruleId"`
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Excerpt  string   `json:"excerpt,omitempty"`
}

// Report is the deterministic result of analyzing one artifact's contents.
type Report struct {
	Artifact Artifact  `json:"artifact"`
	Findings []Finding `json:"findings,omitempty"`
	// MaxSeverity is the worst finding severity after any configured downgrade.
	MaxSeverity Severity `json:"maxSeverity,omitempty"`
	// Risk is the ordinal 0..100 risk contribution for the risk-scoring engine.
	Risk int `json:"risk"`
	// Action is the configured action this report was finalized under.
	Action Action `json:"action"`
	// Inspected reports that the artifact was a recognized archive the gate
	// unpacked and scanned (false for an index/listing, an unsupported ecosystem,
	// or an unrecognized archive format).
	Inspected bool `json:"inspected"`
	// FilesScanned counts the archive entries examined.
	FilesScanned int `json:"filesScanned"`
	// Truncated reports that extraction hit a size/entry/finding bound and some
	// content was not scanned.
	Truncated bool `json:"truncated,omitempty"`
	// TimedOut reports that the scan budget (Timeout) elapsed before the whole
	// archive was examined.
	TimedOut bool `json:"timedOut,omitempty"`
	// Error records a non-fatal extraction problem (a corrupt archive); the gate
	// fails open on it.
	Error string `json:"error,omitempty"`
}

// HasFindings reports whether the report carries at least one finding.
func (r *Report) HasFindings() bool { return r != nil && len(r.Findings) > 0 }

// budget is the resolved set of scan bounds, passed to the archive walker.
type budget struct {
	maxArchiveBytes int64
	maxFileBytes    int64
	maxFiles        int
}

// Service is the package-payload static content-analysis gate. The zero value is
// not usable; construct one with NewService.
type Service struct {
	cfg     Config
	secrets *secretscan.Detector
	log     *slog.Logger

	scanned      atomic.Uint64 // artifacts inspected
	filesTotal   atomic.Uint64
	flaggedArts  atomic.Uint64
	findingTotal atomic.Uint64
	blocked      atomic.Uint64
	downgraded   atomic.Uint64
	annotated    atomic.Uint64
	truncated    atomic.Uint64
	timedOut     atomic.Uint64

	mu    sync.Mutex
	byCat map[string]uint64
	byEco map[string]uint64
}

// NewService validates cfg and constructs the gate, wiring the secret detector
// (reused or default-built) when secret scanning is enabled.
func NewService(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	var det *secretscan.Detector
	if cfg.DetectSecrets {
		det = cfg.SecretDetector
		if det == nil {
			// A wholly-zero secretscan.Config yields the built-in ruleset plus the
			// default entropy heuristic — exactly the Task 29 detectors, reused here.
			det = secretscan.New(secretscan.Config{})
		}
	}
	return &Service{
		cfg:     cfg,
		secrets: det,
		log:     log,
		byCat:   make(map[string]uint64),
		byEco:   make(map[string]uint64),
	}, nil
}

// Enabled reports whether the gate is configured on. Safe on a nil receiver.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Action returns the configured action. Safe on a nil receiver.
func (s *Service) Action() Action {
	if s == nil {
		return ActionAnnotate
	}
	return s.cfg.Action
}

// Applies reports whether the gate inspects the given ecosystem. Safe on a nil
// receiver.
func (s *Service) Applies(ecosystem string) bool {
	return s.Enabled() && s.cfg.ecosystemAllowed(ecosystem)
}

// Assess unpacks the artifact and scans every file against the content
// heuristics, returning a deterministic report. open lazily yields a fresh
// content stream (read at most once, closed by Assess). The whole scan is bounded
// by the configured budget and by ctx. A nil/unsupported/unrecognized input is a
// clean, inspected=false report rather than an error; a hard I/O error on the
// content stream is returned as an error.
func (s *Service) Assess(ctx context.Context, art Artifact, open func() (io.ReadCloser, error)) (*Report, error) {
	report := &Report{Artifact: art, Action: s.cfg.Action}
	if !s.cfg.ecosystemAllowed(art.Ecosystem) {
		return report, nil
	}

	rc, err := open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	if s.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}

	b := budget{
		maxArchiveBytes: s.cfg.MaxArchiveBytes,
		maxFileBytes:    s.cfg.MaxFileBytes,
		maxFiles:        s.cfg.MaxFiles,
	}
	expectBin := expectsBinaries(art)

	var findings []Finding
	files := 0
	visit := func(wf walkedFile) bool {
		files++
		findings = append(findings, s.scanFile(wf, expectBin)...)
		// Stop early once the overall finding budget is reached.
		return len(findings) < s.cfg.MaxFindings
	}

	truncated, werr := walkArchive(ctx, rc, b, visit)
	if werr != nil {
		// An unrecognized or corrupt archive is not a finding; record it and fail
		// open (served unscanned).
		report.Error = werr.Error()
		s.log.Debug("contentscan: archive not scanned; serving without content gate",
			"artifact", art.Coordinate(), "ecosystem", art.Ecosystem, "error", werr)
		return report, nil
	}

	report.Inspected = true
	report.FilesScanned = files
	report.Truncated = truncated || len(findings) >= s.cfg.MaxFindings
	report.TimedOut = ctx.Err() != nil
	s.scanned.Add(1)
	s.filesTotal.Add(uint64(files))
	s.bumpEco(art.Ecosystem)

	findings = s.finalize(findings)
	report.Findings = findings
	report.MaxSeverity = maxSeverity(findings)
	report.Risk = riskScore(report.MaxSeverity, len(findings))

	if len(findings) > 0 {
		s.flaggedArts.Add(1)
		s.findingTotal.Add(uint64(len(findings)))
		s.bumpCategories(findings)
	}
	if report.Truncated {
		s.truncated.Add(1)
	}
	if report.TimedOut {
		s.timedOut.Add(1)
	}
	return report, nil
}

// scanFile applies the content heuristics to one extracted file and returns its
// findings (bounded per file). expectBin suppresses the embedded-binary and
// high-entropy-blob heuristics for a binary distribution whose payload
// legitimately contains compiled objects.
func (s *Service) scanFile(wf walkedFile, expectBin bool) []Finding {
	ext := strings.ToLower(path.Ext(wf.name))
	perFile := newFindingBudget(s.cfg.MaxFindingsPerFile)

	// 1) Embedded native binary. A binary file is not scanned further as text.
	if s.cfg.DetectBinary {
		if desc, ok := classifyBinary(wf.name, wf.data); ok {
			if !expectBin {
				perFile.add(Finding{
					RuleID:   RuleEmbeddedBinary,
					Category: "embedded-binary",
					Title:    "Embedded native binary in a source package",
					Severity: SeverityHigh,
					File:     wf.name,
					Excerpt:  excerpt(desc + " (" + humanBytes(len(wf.data)) + ")"),
				})
			}
			return perFile.findings
		}
	}

	textual := looksTextual(wf.data)

	// 2) High-entropy blob (non-native binary content under an unexpected extension).
	if !textual {
		if s.cfg.DetectEntropy && !expectBin && !expectedBinaryExtensions[ext] &&
			int64(len(wf.data)) >= s.cfg.MinEntropyBlobBytes {
			if ent := byteEntropy(wf.data); ent >= s.cfg.EntropyThreshold {
				perFile.add(Finding{
					RuleID:   RuleHighEntropyBlob,
					Category: "high-entropy-blob",
					Title:    "High-entropy embedded blob in a source package",
					Severity: SeverityMedium,
					File:     wf.name,
					Excerpt:  excerpt(humanBytes(len(wf.data)) + ", entropy " + formatEntropy(ent) + " bits/byte"),
				})
			}
		}
		return perFile.findings
	}

	// Text content: bound how much is scanned by the line rules.
	text := string(wf.data)
	if int64(len(text)) > s.cfg.MaxScanBytesPerFile {
		text = text[:s.cfg.MaxScanBytesPerFile]
	}

	// 3) Obfuscated / minified-plus-eval JavaScript.
	if s.cfg.DetectJS && jsExtensions[ext] {
		if detail, sev, ok := obfuscatedJS(text); ok {
			perFile.add(Finding{
				RuleID:   RuleObfuscatedCode,
				Category: "obfuscated-code",
				Title:    "Obfuscated JavaScript in a package file",
				Severity: sev,
				File:     wf.name,
				Excerpt:  excerpt(detail),
			})
		}
	}

	// 4) Dynamic code-execution sinks, scanned per line so findings localize.
	if s.cfg.DetectExec {
		seen := make(map[string]struct{})
		for ln, raw := range splitLines(text) {
			if perFile.full() {
				break
			}
			for _, rule := range scanExecLine(ext, raw) {
				key := rule.id
				if _, dup := seen[key]; dup {
					continue // one finding per sink kind per file keeps output bounded
				}
				seen[key] = struct{}{}
				perFile.add(Finding{
					RuleID:   RuleDynamicExec,
					Category: "dynamic-exec",
					Title:    rule.title,
					Severity: rule.severity,
					File:     wf.name,
					Line:     ln + 1,
					Excerpt:  excerpt(raw),
				})
			}
		}
	}

	// 5) In-source secrets (reused Task 29 detectors).
	if s.cfg.DetectSecrets && !perFile.full() {
		for _, f := range s.scanSecrets(wf.name, text) {
			if perFile.full() {
				break
			}
			perFile.add(Finding{
				RuleID:   RuleEmbeddedSecret,
				Category: "embedded-secret",
				Title:    "In-source credential/secret in a package file",
				Severity: coerceSeverity(f.Severity),
				File:     wf.name,
				Line:     f.Line,
				Excerpt:  excerpt(f.RuleID + ": " + f.Match),
			})
		}
	}

	return perFile.findings
}

// finalize deduplicates, sorts for determinism, and applies the downgrade action.
func (s *Service) finalize(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	out := findings[:0]
	for _, f := range findings {
		key := f.RuleID + "\x00" + f.File + "\x00" + itoa(f.Line) + "\x00" + f.Excerpt
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	if s.cfg.Action == ActionDowngrade {
		for i := range out {
			out[i].Severity = downgradeOne(out[i].Severity)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if ri, rj := categoryOrder(out[i].Category), categoryOrder(out[j].Category); ri != rj {
			return ri < rj
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// findingBudget caps findings per file.
type findingBudget struct {
	findings []Finding
	max      int
}

func newFindingBudget(max int) *findingBudget { return &findingBudget{max: max} }

func (b *findingBudget) full() bool { return b.max > 0 && len(b.findings) >= b.max }

func (b *findingBudget) add(f Finding) {
	if b.full() {
		return
	}
	b.findings = append(b.findings, f)
}

func (s *Service) bumpEco(eco string) {
	s.mu.Lock()
	s.byEco[canonEco(eco)]++
	s.mu.Unlock()
}

func (s *Service) bumpCategories(findings []Finding) {
	s.mu.Lock()
	for i := range findings {
		s.byCat[findings[i].Category]++
	}
	s.mu.Unlock()
}

// categoryOrder gives a stable catalog ordering for findings of the same file.
func categoryOrder(cat string) int {
	switch cat {
	case "embedded-binary":
		return 0
	case "obfuscated-code":
		return 1
	case "dynamic-exec":
		return 2
	case "high-entropy-blob":
		return 3
	case "embedded-secret":
		return 4
	default:
		return 5
	}
}

// coerceSeverity maps a secretscan severity string onto this package's Severity.
func coerceSeverity(s string) Severity {
	if sev, ok := ParseSeverity(s); ok {
		return sev
	}
	return SeverityMedium
}
