package malfeed

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaliciousPackagesURL is the OpenSSF/OSV malicious-packages exported
// dataset. The repository (github.com/ossf/malicious-packages) publishes the
// curated advisories; an operator typically points FeedURLs at a periodically
// built aggregate (a single JSON array of OSV records) served internally or by a
// mirror. It is left unset by default so the subsystem never reaches out
// unexpectedly; an operator opts in by configuring feed URLs.
const DefaultMaliciousPackagesURL = "https://github.com/ossf/malicious-packages"

// maxFeedBytes bounds a single feed response so a hostile or misconfigured
// endpoint cannot exhaust memory.
const maxFeedBytes = 256 << 20 // 256 MiB

// Doer is the subset of *http.Client the feed refresher depends on, so a fake
// transport can be injected in tests and the proxy's shared upstream client can
// be reused in production.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// FeedSource describes one upstream feed to ingest. Each source tracks its own
// ETag/Last-Modified so a conditional refresh that returns 304 Not Modified is
// cheap and leaves the loaded data untouched.
type FeedSource struct {
	// URL is the HTTP(S) endpoint serving a single OSV record or a JSON array of
	// OSV records (the malicious-packages / GHSA export shapes).
	URL string
	// Name labels the source for entry provenance and logging. Defaults to the URL.
	Name string
}

// Config configures the malicious-package admission gate.
type Config struct {
	// Sources are the upstream feeds to ingest on refresh. May be empty when the
	// only data comes from an imported offline bundle.
	Sources []FeedSource
	// RefreshInterval is the period between background refreshes (0 disables the
	// background loop; refresh can still be triggered on demand).
	RefreshInterval time.Duration
	// StaleAfter is how long after the last successful refresh the loaded data is
	// considered stale. 0 disables staleness checking entirely (the gate then
	// always fails open on freshness, blocking only on a concrete match).
	StaleAfter time.Duration
	// FailClosedWhenStale makes the gate block pulls while the feed is stale,
	// trading availability for safety when the known-malicious list cannot be
	// confirmed current. The default (false) fails open: a stale feed still blocks
	// concrete matches but never blocks an unmatched pull.
	FailClosedWhenStale bool
	// Timeout bounds a single feed fetch. Defaults to 30s.
	Timeout time.Duration
	// HTTPClient performs feed fetches. Defaults to a client with Timeout.
	HTTPClient Doer
	// InitialEntries seeds the matcher at construction (e.g. from an imported
	// offline bundle or static config) before any network refresh.
	InitialEntries []Entry
	// InitialLoaded marks the seed data as a successful load for freshness, so an
	// air-gapped deployment importing a bundle is not immediately "stale".
	InitialLoaded bool
	// Logger receives refresh diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// Decision is the gate's verdict for a coordinate. Blocked is the only field the
// pull path must honor; the rest explain why for the response, audit, and alert.
type Decision struct {
	// Blocked reports whether the pull must be refused.
	Blocked bool
	// Code is a short machine code: "malicious" for a concrete match, "feed-stale"
	// for a fail-closed staleness block, or "" when allowed.
	Code string
	// Reason is a human-readable explanation suitable for the block response.
	Reason string
	// Entry is the matched record when Code is "malicious"; nil otherwise.
	Entry *Entry
	// Stale reports whether the feed was stale at decision time (informational
	// even when the gate fails open).
	Stale bool
}

// AdvisoryID returns the advisory id driving a block, or "" when none applies.
func (d Decision) AdvisoryID() string {
	if d.Entry != nil {
		return d.Entry.ID
	}
	return ""
}

// Service is the live known-malicious gate: it holds the current matcher, tracks
// freshness, applies the fail-open/closed staleness policy, and runs the
// background refresh loop. A nil *Service is a valid no-op gate (Check always
// allows), so the gateway needs no nil checks at the call site.
type Service struct {
	cfg    Config
	logger *slog.Logger
	client Doer

	mu           sync.RWMutex
	matcher      *Matcher
	lastRefresh  time.Time
	lastErr      string
	conditionals map[string]conditional // per-source-URL ETag/Last-Modified

	// counters (atomic; read by the metrics bridge at scrape time).
	checks       atomic.Uint64
	blocks       atomic.Uint64
	staleServes  atomic.Uint64 // unmatched pulls served while stale (fail-open)
	staleBlocks  atomic.Uint64 // pulls blocked solely due to staleness (fail-closed)
	refreshes    atomic.Uint64
	refreshFails atomic.Uint64

	blocksByEco struct {
		mu sync.Mutex
		m  map[string]uint64
	}

	done   chan struct{}
	closed atomic.Bool
}

// conditional is the cache-validation state retained per source for conditional
// refresh.
type conditional struct {
	etag         string
	lastModified string
}

// NewService constructs the gate from cfg. It seeds the matcher from
// InitialEntries (which may be nil) and starts empty otherwise. The background
// refresh loop is not started here; call Start.
func NewService(cfg Config) *Service {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	s := &Service{
		cfg:          cfg,
		logger:       cfg.Logger,
		client:       client,
		matcher:      NewMatcher(cfg.InitialEntries),
		conditionals: make(map[string]conditional),
		done:         make(chan struct{}),
	}
	s.blocksByEco.m = make(map[string]uint64)
	if cfg.InitialLoaded && len(cfg.InitialEntries) > 0 {
		s.lastRefresh = time.Now()
	}
	return s
}

// Check evaluates a coordinate against the loaded feed and the staleness policy,
// returning the gate Decision. It is safe for concurrent use and never blocks on
// I/O. A nil Service allows everything.
func (s *Service) Check(c Coordinate) Decision {
	if s == nil {
		return Decision{}
	}
	s.checks.Add(1)

	s.mu.RLock()
	matcher := s.matcher
	stale := s.staleLocked()
	s.mu.RUnlock()

	if m := matcher.Match(c); m.Matched {
		s.recordBlock(m.Entry.Ecosystem)
		return Decision{
			Blocked: true,
			Code:    "malicious",
			Reason:  blockReason(m.Entry),
			Entry:   m.Entry,
			Stale:   stale,
		}
	}

	if stale {
		if s.cfg.FailClosedWhenStale {
			s.staleBlocks.Add(1)
			return Decision{
				Blocked: true,
				Code:    "feed-stale",
				Reason:  "known-malicious feed is stale and the gate is configured fail-closed; pull refused until the feed is refreshed",
				Stale:   true,
			}
		}
		s.staleServes.Add(1)
	}
	return Decision{Stale: stale}
}

// recordBlock bumps the global and per-ecosystem block counters.
func (s *Service) recordBlock(eco string) {
	s.blocks.Add(1)
	s.blocksByEco.mu.Lock()
	s.blocksByEco.m[eco]++
	s.blocksByEco.mu.Unlock()
}

// blockReason renders an actionable reason for a matched entry.
func blockReason(e *Entry) string {
	if e == nil {
		return "package is listed as known-malicious"
	}
	reason := e.Summary
	if reason == "" {
		reason = "package is listed as known-malicious"
	}
	if e.ID != "" {
		reason = fmt.Sprintf("%s (advisory %s)", reason, e.ID)
	}
	return reason
}

// staleLocked reports whether the loaded data is stale per the configured
// StaleAfter. The caller must hold at least the read lock.
func (s *Service) staleLocked() bool {
	if s.cfg.StaleAfter <= 0 {
		return false
	}
	if s.lastRefresh.IsZero() {
		// Never successfully loaded: treat as stale so a fail-closed deployment
		// refuses to serve until the feed is established.
		return true
	}
	return time.Since(s.lastRefresh) > s.cfg.StaleAfter
}

// Stale reports the current staleness of the loaded feed.
func (s *Service) Stale() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.staleLocked()
}

// Start launches the background refresh loop. It performs one immediate refresh
// (so the gate is populated as soon as possible) and then refreshes every
// RefreshInterval until ctx is cancelled or Close is called. It is a no-op when
// no sources are configured or RefreshInterval is non-positive (the gate then
// relies on InitialEntries / on-demand Refresh only).
func (s *Service) Start(ctx context.Context) {
	if s == nil || len(s.cfg.Sources) == 0 {
		return
	}
	// Prime once in the background so startup is not blocked on the network.
	go func() {
		if err := s.Refresh(ctx); err != nil {
			s.logger.Warn("malfeed initial refresh failed", "error", err)
		}
	}()
	if s.cfg.RefreshInterval <= 0 {
		return
	}
	go s.loop(ctx)
}

// loop drives the periodic refresh until shutdown.
func (s *Service) loop(ctx context.Context) {
	t := time.NewTicker(s.cfg.RefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil {
				s.logger.Warn("malfeed refresh failed", "error", err)
			}
		}
	}
}

// Close stops the background refresh loop. It is idempotent and safe to call on
// a nil Service.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	if s.closed.CompareAndSwap(false, true) {
		close(s.done)
	}
	return nil
}

// Refresh fetches every configured source (conditionally, honoring ETag /
// Last-Modified), rebuilds the matcher from the union of all fetched entries,
// and updates the freshness timestamp. A source returning 304 Not Modified
// contributes its previously-loaded entries unchanged. Refresh is safe to call
// concurrently with Check; the matcher swap is atomic.
//
// It returns an error only when *every* source fails and nothing could be
// loaded; a partial failure logs and proceeds with whatever was fetched, so one
// unreachable mirror does not blank the whole list.
func (s *Service) Refresh(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if len(s.cfg.Sources) == 0 {
		// Nothing to fetch; still mark a successful "load" so an InitialEntries-only
		// deployment is considered fresh after an explicit refresh.
		s.mu.Lock()
		s.lastRefresh = time.Now()
		s.lastErr = ""
		s.mu.Unlock()
		s.refreshes.Add(1)
		return nil
	}

	s.refreshes.Add(1)

	// Snapshot the per-source previously-loaded entries so a 304 keeps them.
	prevBySource := s.entriesBySource()

	var (
		all        []Entry
		anyOK      bool
		anyChanged bool
		errs       []string
	)
	for _, src := range s.cfg.Sources {
		name := src.Name
		if name == "" {
			name = src.URL
		}
		entries, notModified, err := s.fetchSource(ctx, src)
		switch {
		case err != nil:
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			// Retain whatever this source last contributed so a transient failure
			// does not drop its entries.
			all = append(all, prevBySource[name]...)
		case notModified:
			anyOK = true
			all = append(all, prevBySource[name]...)
		default:
			anyOK = true
			anyChanged = true
			all = append(all, entries...)
		}
	}

	if !anyOK {
		errMsg := joinErrs(errs)
		s.mu.Lock()
		s.lastErr = errMsg
		s.mu.Unlock()
		s.refreshFails.Add(1)
		return fmt.Errorf("malfeed: all feed sources failed: %s", errMsg)
	}

	matcher := NewMatcher(all)
	s.mu.Lock()
	s.matcher = matcher
	s.lastRefresh = time.Now()
	s.lastErr = joinErrs(errs)
	s.mu.Unlock()

	if anyChanged {
		s.logger.Info("malfeed refreshed",
			"entries", matcher.Len(),
			"sources", len(s.cfg.Sources),
			"partialErrors", len(errs))
	}
	return nil
}

// fetchSource performs a single conditional GET. It returns the parsed entries
// on a 200, notModified=true on a 304, and an error otherwise. On a successful
// 200 it records the new ETag/Last-Modified for the next conditional fetch.
func (s *Service) fetchSource(ctx context.Context, src FeedSource) (entries []Entry, notModified bool, err error) {
	name := src.Name
	if name == "" {
		name = src.URL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	s.mu.RLock()
	cond := s.conditionals[src.URL]
	s.mu.RUnlock()
	if cond.etag != "" {
		req.Header.Set("If-None-Match", cond.etag)
	}
	if cond.lastModified != "" {
		req.Header.Set("If-Modified-Since", cond.lastModified)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("fetch: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, true, nil
	case http.StatusOK:
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
		if rerr != nil {
			return nil, false, fmt.Errorf("read body: %w", rerr)
		}
		parsed, perr := ParseOSVStream(body, name)
		if perr != nil {
			return nil, false, perr
		}
		// Record validators for the next conditional fetch.
		s.mu.Lock()
		s.conditionals[src.URL] = conditional{
			etag:         resp.Header.Get("ETag"),
			lastModified: resp.Header.Get("Last-Modified"),
		}
		s.mu.Unlock()
		return parsed, false, nil
	default:
		return nil, false, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
}

// entriesBySource groups the currently-loaded entries by their source label so a
// 304/failed refresh can retain a source's contribution.
func (s *Service) entriesBySource() map[string][]Entry {
	s.mu.RLock()
	matcher := s.matcher
	s.mu.RUnlock()
	out := make(map[string][]Entry)
	for _, e := range matcher.Entries() {
		out[e.Source] = append(out[e.Source], e)
	}
	return out
}

// Search returns up to limit loaded entries (0 = no limit) matching query
// across id/name/alias/summary/category, optionally restricted to a canonical
// ecosystem. It is the admin list/search surface. Safe on a nil Service.
func (s *Service) Search(query, ecosystem string, limit int) []Entry {
	if s == nil {
		return nil
	}
	return s.Matcher().Search(query, ecosystem, limit)
}

// Matcher returns the current matcher for read-only queries (listing, search).
func (s *Service) Matcher() *Matcher {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.matcher
}

// Status is a point-in-time view of the gate for the admin surface.
type Status struct {
	Enabled             bool           `json:"enabled"`
	Entries             int            `json:"entries"`
	EntriesByEcosystem  map[string]int `json:"entriesByEcosystem"`
	Sources             []string       `json:"sources"`
	LastRefresh         *time.Time     `json:"lastRefresh,omitempty"`
	RefreshAgeSeconds   float64        `json:"refreshAgeSeconds"`
	Stale               bool           `json:"stale"`
	FailClosedWhenStale bool           `json:"failClosedWhenStale"`
	StaleAfterSeconds   float64        `json:"staleAfterSeconds"`
	LastError           string         `json:"lastError,omitempty"`
	TotalChecks         uint64         `json:"totalChecks"`
	TotalBlocks         uint64         `json:"totalBlocks"`
}

// Status returns the current status snapshot.
func (s *Service) Status() Status {
	if s == nil {
		return Status{Enabled: false, EntriesByEcosystem: map[string]int{}}
	}
	s.mu.RLock()
	matcher := s.matcher
	last := s.lastRefresh
	lastErr := s.lastErr
	stale := s.staleLocked()
	s.mu.RUnlock()

	srcs := make([]string, 0, len(s.cfg.Sources))
	for _, src := range s.cfg.Sources {
		if src.URL != "" {
			srcs = append(srcs, src.URL)
		}
	}
	sort.Strings(srcs)

	st := Status{
		Enabled:             true,
		Entries:             matcher.Len(),
		EntriesByEcosystem:  matcher.CountsByEcosystem(),
		Sources:             srcs,
		Stale:               stale,
		FailClosedWhenStale: s.cfg.FailClosedWhenStale,
		StaleAfterSeconds:   s.cfg.StaleAfter.Seconds(),
		LastError:           lastErr,
		TotalChecks:         s.checks.Load(),
		TotalBlocks:         s.blocks.Load(),
	}
	if !last.IsZero() {
		lr := last
		st.LastRefresh = &lr
		st.RefreshAgeSeconds = time.Since(last).Seconds()
	}
	return st
}

// joinErrs concatenates source errors for a compact diagnostic.
func joinErrs(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	out := errs[0]
	for _, e := range errs[1:] {
		out += "; " + e
	}
	return out
}
