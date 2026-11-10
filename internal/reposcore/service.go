package reposcore

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RepoRef identifies the repository to score for one request: its URL (from the
// provenance association), the optional source commit, and the tenant whose
// weighting model applies.
type RepoRef struct {
	RepositoryURL string
	CommitSHA     string
	Tenant        string
}

// Service computes and caches OpenSSF Scorecard-style repository-health reports.
// It caches the offline facts per repository (tenant-independent) and re-scores
// them per tenant on each call, so per-tenant weights are honored without
// re-cloning. All methods are safe for concurrent use.
type Service struct {
	cfg Config

	mu      sync.Mutex
	cache   map[string]*factsEntry
	history []Report

	// counters (cumulative) for the metrics bridge.
	evaluated  uint64
	resolved   uint64
	unresolved uint64
	cacheHits  uint64
	online     uint64
	errors     uint64
	byGrade    map[string]uint64
	healthSum  uint64 // sum of resolved health scores, for an average gauge
}

// factsEntry is a cached, tenant-independent extraction for one repository.
type factsEntry struct {
	facts     RepoFacts
	resolved  bool
	online    bool
	commitSHA string
	errText   string
	expires   time.Time
}

// New constructs a Service, applying built-in defaults and validating the config.
func New(cfg Config) (*Service, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("reposcore: %w", err)
	}
	return &Service{
		cfg:     cfg,
		cache:   make(map[string]*factsEntry),
		byGrade: make(map[string]uint64),
	}, nil
}

// Enabled reports whether repository-health scoring is enabled.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Score computes (or reuses a cached extraction for) the repository's health
// report for the given reference. It never returns an error: a repository that
// cannot be reached or analyzed yields an unresolved report that contributes
// nothing to risk, so a degraded signal never blocks a pull. The result is
// recorded in the recent-report history and folded into the metrics counters.
func (s *Service) Score(ctx context.Context, ref RepoRef) Report {
	if s == nil || !s.cfg.Enabled {
		return Report{}
	}
	norm := normalizeRepoURL(ref.RepositoryURL)
	now := s.cfg.Now()

	if norm == "" {
		r := s.unresolvedReport(ref, "no repository URL associated")
		s.record(r, true)
		return r
	}

	entry, hit := s.cachedFacts(norm, now)
	if !hit {
		entry = s.extract(ctx, norm, ref)
		s.storeFacts(norm, entry)
	}

	r := s.buildReport(ref, entry, now)
	s.record(r, hit)
	return r
}

// cachedFacts returns a fresh cached extraction for norm, if any.
func (s *Service) cachedFacts(norm string, now time.Time) (*factsEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.cache[norm]
	if !ok || now.After(e.expires) {
		return nil, false
	}
	return e, true
}

func (s *Service) storeFacts(norm string, e *factsEntry) {
	s.mu.Lock()
	s.cache[norm] = e
	s.mu.Unlock()
}

// extract performs the offline (and optional online) derivation for one
// repository, returning a cache entry with the right TTL.
func (s *Service) extract(ctx context.Context, norm string, ref RepoRef) *factsEntry {
	now := s.cfg.Now()
	e := &factsEntry{commitSHA: ref.CommitSHA, expires: now.Add(s.cfg.NegativeTTL)}

	if s.cfg.Locator == nil {
		e.errText = "no repository locator configured"
		return e
	}

	actx := ctx
	if s.cfg.AnalyzeTimeout > 0 {
		var cancel context.CancelFunc
		actx, cancel = context.WithTimeout(ctx, s.cfg.AnalyzeTimeout)
		defer cancel()
	}

	dir, resolved, online, err := s.cfg.Locator.Locate(actx, ref.RepositoryURL)
	e.online = online
	if err != nil {
		e.errText = err.Error()
		return e
	}
	if !resolved {
		e.errText = "no local clone available"
		return e
	}

	runner, err := newGitRunner(s.cfg.GitBinary, dir)
	if err != nil {
		e.errText = err.Error()
		return e
	}
	facts, err := gatherFacts(actx, runner, now, s.cfg.Window)
	if err != nil {
		e.errText = err.Error()
		return e
	}

	// Optional online enrichment (e.g. authoritative branch protection). A failure
	// degrades to the offline heuristics rather than failing the report.
	if s.cfg.Enricher != nil {
		if enr, eerr := s.cfg.Enricher.Enrich(actx, ref.RepositoryURL); eerr == nil {
			if enr.BranchProtectionKnown {
				facts.BranchProtectionKnown = true
				facts.BranchProtected = enr.BranchProtected
			}
			e.online = true
		}
	}

	e.facts = facts
	e.resolved = true
	e.expires = now.Add(s.cfg.CacheTTL)
	return e
}

// buildReport scores a cached extraction with the tenant's effective weights.
func (s *Service) buildReport(ref RepoRef, e *factsEntry, now time.Time) Report {
	r := Report{
		RepositoryURL: ref.RepositoryURL,
		CommitSHA:     orStr(ref.CommitSHA, e.commitSHA),
		Evaluated:     true,
		Online:        e.online,
		Error:         e.errText,
		EvaluatedAt:   now,
	}
	if !e.resolved {
		r.Summary = summarize(r)
		return r
	}

	weights := s.cfg.resolveWeights(ref.Tenant)
	health, signals, weak, grade := scoreFacts(e.facts, weights)
	r.Resolved = true
	r.Facts = e.facts
	r.Health = health
	r.Risk = 100 - health
	r.Grade = grade
	r.Signals = signals
	r.Weak = weak
	r.Summary = summarize(r)
	return r
}

func (s *Service) unresolvedReport(ref RepoRef, reason string) Report {
	r := Report{
		RepositoryURL: ref.RepositoryURL,
		CommitSHA:     ref.CommitSHA,
		Evaluated:     true,
		Error:         reason,
		EvaluatedAt:   s.cfg.Now(),
	}
	r.Summary = summarize(r)
	return r
}

// record folds a report into the metrics counters and the recent-report ring.
func (s *Service) record(r Report, cacheHit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluated++
	if cacheHit {
		s.cacheHits++
	}
	if r.Online {
		s.online++
	}
	if r.Error != "" {
		s.errors++
	}
	if r.Resolved {
		s.resolved++
		s.byGrade[r.Grade]++
		s.healthSum += uint64(r.Health)
	} else {
		s.unresolved++
	}
	s.history = append(s.history, r)
	if len(s.history) > s.cfg.HistorySize {
		s.history = append(s.history[:0], s.history[len(s.history)-s.cfg.HistorySize:]...)
	}
}

// Recent returns up to limit most-recently-scored reports, most-recent-first. A
// non-positive limit returns the full retained history.
func (s *Service) Recent(limit int) []Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recentLocked(limit)
}

func (s *Service) recentLocked(limit int) []Report {
	n := len(s.history)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Report, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s.history[len(s.history)-1-i])
	}
	return out
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
