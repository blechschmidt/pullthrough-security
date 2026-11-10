package muttest

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

// Status is the terminal classification of a single mutant.
type Status string

const (
	// StatusKilled means the test suite failed (or timed out) with the mutant
	// applied — the fault was detected. Good.
	StatusKilled Status = "killed"
	// StatusSurvived means the suite still passed with the mutant applied — a
	// fault the tests do not detect. This is what triage targets.
	StatusSurvived Status = "survived"
	// StatusInvalid means the mutant did not compile (not type-safe). Invalid
	// mutants are excluded from the mutation score.
	StatusInvalid Status = "invalid"
)

// MutantResult is a mutant plus its terminal status and the reason/timing.
type MutantResult struct {
	Mutant
	Status   Status        `json:"status"`
	TimedOut bool          `json:"timedOut,omitempty"`
	Elapsed  time.Duration `json:"elapsedNs"`
}

// PackageRun is the full per-package result: aggregate tallies plus every
// mutant result (so survivors can be listed for triage).
type PackageRun struct {
	Package  string         `json:"package"`
	Dir      string         `json:"dir"`
	Total    int            `json:"totalEnumerated"`
	Sampled  int            `json:"sampled"`
	Killed   int            `json:"killed"`
	Survived int            `json:"survived"`
	Invalid  int            `json:"invalid"`
	Ignored  int            `json:"ignored"`
	ScorePct float64        `json:"scorePct"`
	Mutants  []MutantResult `json:"mutants,omitempty"`
}

// scored is killed+survived: the mutants that count toward the score.
func (p PackageRun) scored() int { return p.Killed + p.Survived }

// RunResult aggregates every package run in one invocation.
type RunResult struct {
	StartedAt time.Time     `json:"startedAt"`
	Elapsed   time.Duration `json:"elapsedNs"`
	Seed      int64         `json:"seed"`
	Operators []string      `json:"operators"`
	Packages  []PackageRun  `json:"packages"`
}

// Options configures an Engine.
type Options struct {
	// GoBin is the go binary (default "go").
	GoBin string
	// ModuleDir is the repository root the `go` commands run from. Package
	// patterns and relative file paths are resolved against it.
	ModuleDir string
	// ModulePath is the module's import path (from go.mod), used to turn a
	// package directory into a full import path for the report/baseline.
	ModulePath string
	// Operators is the set of enabled operator keys; empty means DefaultOperators.
	Operators []string
	// MaxPerPackage caps the number of mutants run per package (0 = unbounded).
	// When the cap is below the enumerated count a seeded sample is taken.
	MaxPerPackage int
	// Seed makes the sampling deterministic.
	Seed int64
	// TestTimeout bounds each mutant's test run (default 2m).
	TestTimeout time.Duration
	// BuildTimeout bounds each mutant's compile (default 3m).
	BuildTimeout time.Duration
	// Short passes -test.short to each mutant run.
	Short bool
	// Ignore is the set of mutant IDs to treat as known-equivalent/accepted and
	// exclude from both execution and the score.
	Ignore map[string]bool
	// Logf receives human-readable progress (nil discards).
	Logf func(format string, args ...any)
	// KeepMutantResults, when false, drops killed/invalid mutants from the
	// per-package result to keep the report small; survivors are always kept.
	KeepMutantResults bool
}

func (o *Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Engine runs mutation testing. It mutates source files in place, one at a
// time, and guarantees each file is restored after its mutants run — including
// on SIGINT/SIGTERM — so an interrupted run never leaves mutated source behind.
type Engine struct {
	opts Options

	mu        sync.Mutex
	originals map[string][]byte // absPath -> original bytes (lazily captured)
	dirty     map[string]bool   // absPath currently holding a mutation
}

// New constructs an Engine, filling in defaults.
func New(opts Options) *Engine {
	if opts.GoBin == "" {
		opts.GoBin = "go"
	}
	if opts.TestTimeout <= 0 {
		opts.TestTimeout = 2 * time.Minute
	}
	if opts.BuildTimeout <= 0 {
		opts.BuildTimeout = 3 * time.Minute
	}
	if len(opts.Operators) == 0 {
		opts.Operators = DefaultOperators()
	}
	return &Engine{
		opts:      opts,
		originals: map[string][]byte{},
		dirty:     map[string]bool{},
	}
}

// enabledSet builds the operator lookup.
func (e *Engine) enabledSet() map[string]bool {
	set := map[string]bool{}
	for _, op := range e.opts.Operators {
		set[op] = true
	}
	return set
}

// Run mutation-tests each package (given as module-relative slash paths such as
// "internal/vulnscan"). It returns the aggregated result. A package whose
// unmutated test binary fails to build or fails its tests is a hard error: a
// red or non-compiling suite cannot be mutation-tested meaningfully.
func (e *Engine) Run(ctx context.Context, packages []string) (*RunResult, error) {
	// Install a best-effort restorer so an interrupt restores mutated files.
	stop := e.installSignalRestore()
	defer stop()
	defer e.restoreAll()

	res := &RunResult{
		StartedAt: time.Now().UTC(),
		Seed:      e.opts.Seed,
		Operators: append([]string(nil), e.opts.Operators...),
	}
	sort.Strings(res.Operators)
	start := time.Now()

	enabled := e.enabledSet()
	work := make([]string, len(packages))
	copy(work, packages)
	sort.Strings(work)

	for _, rel := range work {
		pr, err := e.runPackage(ctx, rel, enabled)
		if err != nil {
			return nil, err
		}
		res.Packages = append(res.Packages, *pr)
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// runPackage mutation-tests a single package.
func (e *Engine) runPackage(ctx context.Context, rel string, enabled map[string]bool) (*PackageRun, error) {
	rel = filepath.ToSlash(rel)
	pkgDir := filepath.Join(e.opts.ModuleDir, filepath.FromSlash(rel))
	importPath := e.opts.ModulePath + "/" + rel
	pattern := "./" + rel

	pr := &PackageRun{Package: importPath, Dir: rel}

	// Enumerate candidate mutants across the package's non-test source files.
	files, err := goSourceFiles(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("list sources for %s: %w", rel, err)
	}
	var mutants []Mutant
	for _, abs := range files {
		relFile, _ := filepath.Rel(e.opts.ModuleDir, abs)
		relFile = filepath.ToSlash(relFile)
		ms, err := EnumerateFile(abs, importPath, relFile, enabled)
		if err != nil {
			return nil, err
		}
		mutants = append(mutants, ms...)
	}
	sortMutants(mutants)

	// Drop ignored (known-equivalent) mutants before sampling so the committed
	// ignore list deterministically removes them from the denominator.
	if len(e.opts.Ignore) > 0 {
		kept := mutants[:0]
		for _, m := range mutants {
			if e.opts.Ignore[m.ID] {
				pr.Ignored++
				continue
			}
			kept = append(kept, m)
		}
		mutants = kept
	}
	pr.Total = len(mutants)

	// Seeded sampling to a per-package cap.
	mutants = e.sample(mutants, rel)
	pr.Sampled = len(mutants)

	e.opts.logf(">> %s: %d mutant(s) after ignore, running %d (cap %d, seed %d)\n",
		importPath, pr.Total, pr.Sampled, e.opts.MaxPerPackage, e.opts.Seed)

	// Establish a green baseline: the unmutated test binary must build and pass.
	binPath := filepath.Join(os.TempDir(), fmt.Sprintf("muttest-%s.test", sanitize(rel)))
	defer os.Remove(binPath)
	cr, err := compileTestBinary(ctx, e.opts.GoBin, e.opts.ModuleDir, pattern, binPath, e.opts.BuildTimeout)
	if err != nil {
		return nil, fmt.Errorf("baseline build failed for %s: %w\n%s", rel, err, cr.output)
	}
	if !cr.hasTest {
		return nil, fmt.Errorf("package %s has no test files; cannot mutation-test it", rel)
	}
	if outcome := runTestBinary(ctx, binPath, pkgDir, e.opts.TestTimeout, e.opts.Short); outcome != outcomePass {
		return nil, fmt.Errorf("baseline tests for %s are not green (status %v); fix the suite before mutation testing", rel, outcome)
	}

	for i := range mutants {
		m := mutants[i]
		mr := e.evaluate(ctx, m, pattern, pkgDir, binPath)
		switch mr.Status {
		case StatusKilled:
			pr.Killed++
		case StatusSurvived:
			pr.Survived++
		case StatusInvalid:
			pr.Invalid++
		}
		if e.opts.KeepMutantResults || mr.Status == StatusSurvived {
			pr.Mutants = append(pr.Mutants, mr)
		}
	}

	pr.ScorePct = score(pr.Killed, pr.scored())
	e.opts.logf(">> %s: killed=%d survived=%d invalid=%d score=%.1f%%\n",
		importPath, pr.Killed, pr.Survived, pr.Invalid, pr.ScorePct)
	return pr, nil
}

// evaluate applies one mutant, rebuilds the test binary, runs it, classifies
// the outcome, and restores the file — always.
func (e *Engine) evaluate(ctx context.Context, m Mutant, pattern, pkgDir, binPath string) MutantResult {
	start := time.Now()
	mr := MutantResult{Mutant: m}

	if err := e.writeMutant(m); err != nil {
		// If we cannot even write the mutation, score it conservatively as invalid.
		mr.Status = StatusInvalid
		mr.Elapsed = time.Since(start)
		return mr
	}
	defer e.restoreFile(m.absFile)

	cr, err := compileTestBinary(ctx, e.opts.GoBin, e.opts.ModuleDir, pattern, binPath, e.opts.BuildTimeout)
	if err != nil || !cr.built {
		// Did not type-check (or build timed out): an invalid mutant.
		mr.Status = StatusInvalid
		mr.Elapsed = time.Since(start)
		return mr
	}
	switch runTestBinary(ctx, binPath, pkgDir, e.opts.TestTimeout, e.opts.Short) {
	case outcomePass:
		mr.Status = StatusSurvived
	case outcomeTimeout:
		mr.Status = StatusKilled
		mr.TimedOut = true
	default:
		mr.Status = StatusKilled
	}
	mr.Elapsed = time.Since(start)
	return mr
}

// sample deterministically reduces mutants to MaxPerPackage using a per-package
// seeded shuffle, then restores stable order for execution and reporting.
func (e *Engine) sample(mutants []Mutant, pkgKey string) []Mutant {
	if e.opts.MaxPerPackage <= 0 || len(mutants) <= e.opts.MaxPerPackage {
		return mutants
	}
	// Derive a per-package seed so each package samples independently yet
	// reproducibly for a given global seed.
	r := rand.New(rand.NewSource(e.opts.Seed ^ int64(fnv(pkgKey))))
	idx := r.Perm(len(mutants))[:e.opts.MaxPerPackage]
	sort.Ints(idx)
	out := make([]Mutant, 0, len(idx))
	for _, i := range idx {
		out = append(out, mutants[i])
	}
	return out
}

// --- in-place mutation with guaranteed restore --------------------------- //

func (e *Engine) writeMutant(m Mutant) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	orig, ok := e.originals[m.absFile]
	if !ok {
		b, err := os.ReadFile(m.absFile)
		if err != nil {
			return err
		}
		orig = b
		e.originals[m.absFile] = b
	}
	mutated := Apply(orig, m)
	if err := os.WriteFile(m.absFile, mutated, 0o644); err != nil {
		return err
	}
	e.dirty[m.absFile] = true
	return nil
}

func (e *Engine) restoreFile(abs string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.dirty[abs] {
		return
	}
	if orig, ok := e.originals[abs]; ok {
		_ = os.WriteFile(abs, orig, 0o644)
	}
	e.dirty[abs] = false
}

func (e *Engine) restoreAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for abs, dirty := range e.dirty {
		if !dirty {
			continue
		}
		if orig, ok := e.originals[abs]; ok {
			_ = os.WriteFile(abs, orig, 0o644)
		}
		e.dirty[abs] = false
	}
}

// installSignalRestore restores mutated files on SIGINT/SIGTERM then re-raises
// the default disposition, so Ctrl-C during a long run never leaves the tree
// mutated. The returned func uninstalls the handler.
func (e *Engine) installSignalRestore() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			e.restoreAll()
			// Exit with the conventional 128+signal status for an interrupt.
			os.Exit(130)
		case <-done:
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// --- small helpers -------------------------------------------------------- //

// score returns killed/scored as a percentage; a package with no scored mutants
// is defined as 100% (there is nothing that could have survived).
func score(killed, scored int) float64 {
	if scored <= 0 {
		return 100
	}
	return float64(killed) / float64(scored) * 100
}

// sanitize turns a package path into a filesystem-safe binary name fragment.
func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b = append(b, byte(r))
		default:
			b = append(b, '_')
		}
	}
	return string(b)
}

// fnv is a tiny FNV-1a hash of a string, used to derive a per-package sampling
// seed from the global seed.
func fnv(s string) uint64 {
	const (
		offset = 1469598103934665603
		prime  = 1099511628211
	)
	h := uint64(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}
