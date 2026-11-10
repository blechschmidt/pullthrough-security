// Package watch turns the on-demand LLM Git commit-scanning pipeline
// (internal/scan/commit) into a continuous, incremental scanner (Task 108).
//
// The commit pipeline scans a single commit when one flows through the Git
// backend. This package drives it proactively for a configured set of watched
// repositories: it detects new commits — either reactively from a push webhook
// or by polling the upstream — and scans only the commits it has not already
// scanned, persisting a per-repository cursor so progress survives restarts and
// is never duplicated.
//
// The design is a small set of collaborating seams so the orchestration is
// unit-testable without a live Git host or LLM provider:
//
//   - Scanner:      the commit pipeline (commit.Pipeline satisfies it). Its
//     verdict cache is keyed by the commit SHA folded with the model/prompt/
//     ruleset signature, so re-scanning an already-scanned commit under the same
//     configuration is free, and a configuration change automatically produces a
//     fresh scan (the rescan-on-new-version requirement).
//   - CommitSource: enumerates the commits in a repository that are new relative
//     to the persisted cursor (gitsource.go is the git-binary implementation).
//   - StateStore:   durable per-repo cursor persistence (state.go).
//   - Observer:     the integration hook invoked once per scanned commit, which
//     main.go wires into the findings store, risk engine, and audit log.
//
// The Service exposes three entry points: a push-webhook HTTP handler
// (webhook.go, with GitHub-style HMAC signature verification), a polling loop
// (Start), and an on-demand backfill (Backfill). All three converge on
// processRepo, which does the incremental cursor diff + scan + persist exactly
// once regardless of what triggered it.
package watch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/scan/commit"
)

// Scanner is the commit-scanning capability the watcher drives. *commit.Pipeline
// satisfies it. Scan is idempotent per (commit, configuration): a repeated scan
// of an already-scanned commit is served from the verdict cache, and a change to
// the scanning configuration (model, prompt, ruleset) changes Signature and
// forces a fresh scan.
type Scanner interface {
	// Scan returns the verdict for a commit, scanning it if not already cached.
	Scan(ctx context.Context, c *commit.Commit) (*commit.Verdict, error)
	// Signature is the current cache signature: it folds the model set, prompt
	// version, and ruleset hash. The watcher records it in each repo's cursor so a
	// configuration change (a new detector/model version) is detected and the
	// already-scanned commits are re-enumerated and re-scanned under the new key.
	Signature() string
}

// RepoRef identifies a watched repository.
type RepoRef struct {
	// Name is the stable identifier for the repo in cursors, findings, logs, and
	// webhook routing. It must be unique and non-empty.
	Name string
	// URL is the clone URL (HTTPS or SSH) the CommitSource fetches from.
	URL string
	// Branches restricts scanning to these branch short-names (e.g. "main"). When
	// empty, the repository's default branch is tracked.
	Branches []string
	// FullName, when set, is the "owner/repo" slug used to route an inbound GitHub
	// webhook to this repo (matched against the payload's repository.full_name) in
	// addition to the clone URL. Optional.
	FullName string
	// Username and Token are optional HTTPS credentials injected when fetching.
	// They are never logged or sent to the model.
	Username string
	Token    string
}

// Batch is the set of new commits a CommitSource discovered for a repository,
// together with the ref tips that should be persisted once they are scanned.
type Batch struct {
	// Commits are the new commits ordered oldest → newest so a cursor advanced
	// incrementally never skips a commit if scanning is interrupted midway.
	Commits []*commit.Commit
	// Tips is the ref → head-SHA map representing the repository state these
	// commits bring the cursor up to. It replaces the cursor's tips on success.
	Tips map[string]string
	// Truncated reports that the discovered set was capped at the limit, so more
	// history remains to be scanned on a later cycle.
	Truncated bool
}

// RefUpdate is one ref's before/after SHAs from a push event.
type RefUpdate struct {
	// Ref is the fully-qualified ref name, e.g. "refs/heads/main".
	Ref string
	// Before is the SHA the ref pointed at before the push ("0"*40 for a newly
	// created ref); After is the SHA it points at now ("0"*40 for a deletion).
	Before string
	After  string
}

// UpdateHint carries the ref movements reported by a push webhook so the
// CommitSource can scope enumeration to exactly the pushed range rather than
// re-deriving it from the cursor. It is nil for a poll-driven cycle.
type UpdateHint struct {
	Refs []RefUpdate
}

// CommitSource enumerates the commits in a repository that are new relative to
// the already-scanned ref tips. Implementations fetch from the upstream as
// needed. A nil hint means "poll": derive the new commits from the difference
// between the current upstream ref tips and known. A non-nil hint scopes
// enumeration to the pushed ranges.
type CommitSource interface {
	NewCommits(ctx context.Context, repo RepoRef, known map[string]string, hint *UpdateHint, limit int) (*Batch, error)
}

// ScanEvent is handed to the Observer once per commit the watcher scanned. It
// bundles the repository context the verdict itself does not carry so downstream
// consumers can key findings by repo+commit.
type ScanEvent struct {
	Repo    RepoRef
	Commit  *commit.Commit
	Verdict *commit.Verdict
	// Fresh reports whether this scan produced a new verdict (false on a cache
	// hit, e.g. a commit already scanned under the same configuration).
	Fresh bool
	// Backfill reports that the scan was part of a history backfill rather than a
	// live (webhook/poll) update.
	Backfill bool
}

// Observer is the integration hook invoked synchronously after each commit is
// scanned. main.go implements it to persist findings keyed by repo+commit, feed
// the risk engine, and record an audit event. It must not block for long; a
// slow consumer should hand off to its own queue. A nil Observer is ignored.
type Observer interface {
	ObserveScan(ctx context.Context, ev ScanEvent)
}

// Config tunes the watcher.
type Config struct {
	// Repos is the set of watched repositories. A repo not listed here is ignored
	// by both the poller and the webhook (unknown webhook deliveries are rejected)
	// unless AllowUnconfiguredWebhooks is set.
	Repos []RepoRef
	// PollInterval is the period between polling sweeps of every watched repo.
	// Zero disables polling (webhook-only operation).
	PollInterval time.Duration
	// MaxCommitsPerScan caps the commits scanned for one repo in one cycle, so a
	// large push or an initial sighting cannot stall the pipeline. Zero defaults
	// to 500. Remaining history is picked up on subsequent cycles.
	MaxCommitsPerScan int
	// Backfill, when true, scans history on a repo's first sighting (bounded by
	// MaxCommitsPerScan per cycle) rather than starting the cursor at the current
	// tip. When false, a first sighting records the current tips without scanning
	// historical commits (only commits pushed afterward are scanned).
	Backfill bool
	// WebhookSecret is the shared secret for GitHub-style HMAC-SHA256 payload
	// signature verification (the X-Hub-Signature-256 header). Empty disables
	// signature verification, which is strongly discouraged outside a trusted
	// network; the handler then accepts any well-formed payload.
	WebhookSecret string
	// AllowUnconfiguredWebhooks, when true, lets a push webhook for a repository
	// not in Repos be scanned ad hoc (the repo is derived from the payload). Off
	// by default so the watcher only ever touches an explicitly allowed set.
	AllowUnconfiguredWebhooks bool
	// Logger is the structured logger; defaults to slog.Default when nil.
	Logger *slog.Logger
	// Metrics receives watcher observations; a nil Metrics is a no-op.
	Metrics MetricsRecorder
}

func (c Config) withDefaults() Config {
	if c.MaxCommitsPerScan <= 0 {
		c.MaxCommitsPerScan = 500
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Metrics == nil {
		c.Metrics = nopMetrics{}
	}
	return c
}

// Service is the continuous commit-scanning orchestrator. It is safe for
// concurrent use; per-repo processing is serialized so a webhook and a poll
// cannot race the same cursor.
type Service struct {
	scanner Scanner
	source  CommitSource
	state   StateStore
	obs     Observer
	cfg     Config
	logger  *slog.Logger
	metrics MetricsRecorder

	// repos indexes the configured repositories for webhook routing.
	repos map[string]RepoRef // keyed by Name

	// locks serializes processing per repository (by name).
	locks keyedMutex

	// leaderGate, when set, gates the polling loop so only the HA leader polls.
	leaderGate func() bool

	// webhookSync, when true, makes the webhook handler process the delivery
	// synchronously and return the scan result. It is off in production (the
	// handler schedules the scan and returns 202 promptly); tests set it so the
	// handler's response reflects the completed scan.
	webhookSync bool

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup

	mu    sync.Mutex
	stats Stats
}

// Stats is a point-in-time snapshot of watcher activity, for the admin/status
// surface.
type Stats struct {
	ReposWatched     int       `json:"reposWatched"`
	Cycles           int64     `json:"cycles"`
	CommitsScanned   int64     `json:"commitsScanned"`
	CommitsFlagged   int64     `json:"commitsFlagged"` // malicious or above-threshold verdicts
	WebhooksTotal    int64     `json:"webhooksTotal"`
	WebhooksRejected int64     `json:"webhooksRejected"`
	Errors           int64     `json:"errors"`
	LastCycleAt      time.Time `json:"lastCycleAt,omitempty"`
	PollInterval     string    `json:"pollInterval,omitempty"`
	Signature        string    `json:"signature,omitempty"`
}

// NewService constructs a watcher. scanner, source, and state are required.
func NewService(scanner Scanner, source CommitSource, state StateStore, obs Observer, cfg Config) (*Service, error) {
	if scanner == nil {
		return nil, errors.New("watch: a scanner is required")
	}
	if source == nil {
		return nil, errors.New("watch: a commit source is required")
	}
	if state == nil {
		return nil, errors.New("watch: a state store is required")
	}
	cfg = cfg.withDefaults()

	repos := make(map[string]RepoRef, len(cfg.Repos))
	for _, r := range cfg.Repos {
		if strings.TrimSpace(r.Name) == "" {
			return nil, errors.New("watch: every watched repo requires a name")
		}
		if strings.TrimSpace(r.URL) == "" {
			return nil, fmt.Errorf("watch: repo %q requires a url", r.Name)
		}
		if _, dup := repos[r.Name]; dup {
			return nil, fmt.Errorf("watch: duplicate repo name %q", r.Name)
		}
		repos[r.Name] = r
	}

	return &Service{
		scanner: scanner,
		source:  source,
		state:   state,
		obs:     obs,
		cfg:     cfg,
		logger:  cfg.Logger,
		metrics: cfg.Metrics,
		repos:   repos,
		locks:   newKeyedMutex(),
		stop:    make(chan struct{}),
	}, nil
}

// SetMetrics swaps the metrics recorder. It must be called before Start (the
// observability registry is built after the service), so there is no concurrent
// access with the poll loop / webhook goroutines. A nil recorder is replaced
// with a no-op.
func (s *Service) SetMetrics(m MetricsRecorder) {
	if m == nil {
		m = nopMetrics{}
	}
	s.metrics = m
}

// SetLeaderGate installs an HA leader gate consulted before each poll sweep so
// that in a multi-replica deployment only the lease-holder polls (and mutates
// the shared cursor state). Webhook-driven and on-demand processing are not
// gated — they are naturally idempotent via the cursor — but the gate keeps N
// replicas from each polling the same upstreams. A nil gate means always poll.
func (s *Service) SetLeaderGate(isLeader func() bool) { s.leaderGate = isLeader }

func (s *Service) isLeader() bool {
	return s.leaderGate == nil || s.leaderGate()
}

// SetWebhookSync makes the webhook handler process deliveries synchronously
// (returning the scan result) instead of scheduling them in the background. It
// exists for deterministic testing; production leaves it off.
func (s *Service) SetWebhookSync(sync bool) { s.webhookSync = sync }

// Start launches the polling loop when PollInterval > 0. It is idempotent and
// returns immediately; the loop runs until ctx is canceled or Close is called.
func (s *Service) Start(ctx context.Context) {
	if s.cfg.PollInterval <= 0 {
		s.logger.Info("commit-watch polling disabled (webhook-only)", "repos", len(s.repos))
		return
	}
	s.wg.Add(1)
	go s.pollLoop(ctx)
	s.logger.Info("commit-watch polling started",
		"repos", len(s.repos), "interval", s.cfg.PollInterval, "backfill", s.cfg.Backfill)
}

func (s *Service) pollLoop(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			if !s.isLeader() {
				continue
			}
			s.PollOnce(ctx)
		}
	}
}

// PollOnce runs a single polling sweep across every watched repository. Errors
// on one repo are logged and do not abort the sweep. It is exported so the admin
// API and tests can trigger a sweep on demand.
func (s *Service) PollOnce(ctx context.Context) {
	for _, r := range s.cfg.Repos {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := s.processRepo(ctx, r, nil, false); err != nil {
			s.logger.Error("commit-watch poll failed", "repo", r.Name, "error", err)
			s.incErrors()
		}
	}
}

// Backfill scans a repository's reachable history (bounded by
// MaxCommitsPerScan per invocation) regardless of the Backfill config flag. It
// resets the repo's cursor tips so enumeration starts from scratch and returns a
// Result summary. Call it repeatedly until Result.Truncated is false to walk the
// whole history in bounded chunks.
func (s *Service) Backfill(ctx context.Context, repoName string) (Result, error) {
	r, ok := s.repos[repoName]
	if !ok {
		return Result{}, fmt.Errorf("watch: repo %q is not watched", repoName)
	}
	return s.processRepo(ctx, r, nil, true)
}

// Result summarizes a single processRepo cycle.
type Result struct {
	Repo      string `json:"repo"`
	Scanned   int    `json:"scanned"`
	Flagged   int    `json:"flagged"`
	Truncated bool   `json:"truncated"`
	Rescan    bool   `json:"rescan"`
}

// processRepo is the single incremental scan cycle shared by the webhook,
// poller, and backfill. It loads the cursor, enumerates new commits (resetting
// the known tips when a backfill is requested or the scanning signature changed
// since the cursor was written), scans each commit, invokes the observer, and
// advances the cursor — persisting progress after each commit so an interruption
// never loses or re-scans work.
func (s *Service) processRepo(ctx context.Context, repo RepoRef, hint *UpdateHint, backfill bool) (Result, error) {
	unlock := s.locks.lock(repo.Name)
	defer unlock()

	res := Result{Repo: repo.Name}

	cursor, err := s.state.Load(ctx, repo.Name)
	if err != nil {
		return res, fmt.Errorf("watch: loading cursor for %q: %w", repo.Name, err)
	}

	sig := s.scanner.Signature()
	known := cursor.Tips
	firstSight := len(cursor.Tips) == 0 && cursor.Signature == ""

	// Rescan-on-new-version: when the scanning signature changed since this repo
	// was last processed, the already-scanned commits must be re-scanned under the
	// new configuration. Re-enumerate from scratch (known=nil) so the source
	// returns the reachable history again; the pipeline serves a fresh scan for
	// each because its cache key now differs.
	rescan := !firstSight && cursor.Signature != "" && cursor.Signature != sig
	if rescan {
		s.logger.Info("commit-watch scanning signature changed; re-scanning repo history",
			"repo", repo.Name, "old", cursor.Signature, "new", sig)
		known = nil
	}
	res.Rescan = rescan

	// On a first sighting without backfill, record the current tips and do not
	// scan historical commits — only commits that arrive afterward are scanned.
	if firstSight && !backfill && !s.cfg.Backfill && hint == nil {
		batch, berr := s.source.NewCommits(ctx, repo, map[string]string{"__skip__": ""}, nil, 0)
		if berr != nil {
			return res, fmt.Errorf("watch: establishing baseline for %q: %w", repo.Name, berr)
		}
		cursor.Repo = repo.Name
		cursor.Tips = batch.Tips
		cursor.Signature = sig
		cursor.BaselinedAt = time.Now().UTC()
		if err := s.state.Save(ctx, cursor); err != nil {
			return res, fmt.Errorf("watch: saving baseline cursor for %q: %w", repo.Name, err)
		}
		s.logger.Info("commit-watch baselined repo (history not scanned; set backfill to scan it)",
			"repo", repo.Name, "tips", len(batch.Tips))
		return res, nil
	}

	batch, err := s.source.NewCommits(ctx, repo, known, hint, s.cfg.MaxCommitsPerScan)
	if err != nil {
		return res, fmt.Errorf("watch: enumerating new commits for %q: %w", repo.Name, err)
	}
	res.Truncated = batch.Truncated

	for _, c := range batch.Commits {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if c == nil || c.SHA == "" {
			continue
		}
		// Stamp the repository on the commit so the verdict/findings carry it; the
		// pipeline never sends RepositoryURL to the model, it is metadata only.
		if c.RepositoryURL == "" {
			c.RepositoryURL = repo.URL
		}

		verdict, serr := s.scanner.Scan(ctx, c)
		if serr != nil {
			// A single failed commit scan must not abort the whole batch or lose the
			// cursor progress already made. Log, count, and stop advancing the cursor
			// at this point so the commit is retried next cycle.
			s.logger.Error("commit-watch scan failed", "repo", repo.Name, "sha", c.SHA, "error", serr)
			s.incErrors()
			res.Truncated = true
			if err := s.persistCursor(ctx, &cursor, repo.Name, sig); err != nil {
				return res, err
			}
			return res, nil
		}

		fresh := verdict != nil && verdict.CacheKey == cacheKeyOf(c.SHA, sig)
		res.Scanned++
		flagged := verdict != nil && (verdict.Malicious || isFlagged(verdict))
		if flagged {
			res.Flagged++
		}
		s.metrics.ObserveScan(repo.Name, fresh, flagged)

		if s.obs != nil {
			s.obs.ObserveScan(ctx, ScanEvent{
				Repo:     repo,
				Commit:   c,
				Verdict:  verdict,
				Fresh:    fresh,
				Backfill: backfill || rescan,
			})
		}
	}

	// Advance the cursor to the tips this batch brought us to. On a truncated
	// batch the source reports tips only for fully-consumed ranges, so the next
	// cycle resumes correctly.
	if batch.Tips != nil {
		cursor.Tips = batch.Tips
	}
	cursor.ScannedCount += res.Scanned
	if err := s.persistCursor(ctx, &cursor, repo.Name, sig); err != nil {
		return res, err
	}

	s.recordCycle(res)
	if res.Scanned > 0 {
		s.logger.Info("commit-watch scanned new commits",
			"repo", repo.Name, "scanned", res.Scanned, "flagged", res.Flagged,
			"truncated", res.Truncated, "rescan", rescan)
	}
	return res, nil
}

func (s *Service) persistCursor(ctx context.Context, cursor *Cursor, name, sig string) error {
	cursor.Repo = name
	cursor.Signature = sig
	cursor.LastScanAt = time.Now().UTC()
	if err := s.state.Save(ctx, *cursor); err != nil {
		return fmt.Errorf("watch: saving cursor for %q: %w", name, err)
	}
	return nil
}

// Cursors returns every persisted cursor, for the admin/status surface.
func (s *Service) Cursors(ctx context.Context) ([]Cursor, error) {
	return s.state.List(ctx)
}

// Repos returns the configured watched repositories (sorted by name), for admin
// reporting. Credentials are stripped.
func (s *Service) Repos() []RepoRef {
	out := make([]RepoRef, 0, len(s.cfg.Repos))
	for _, r := range s.cfg.Repos {
		r.Token = ""
		r.Username = ""
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Snapshot returns a copy of the current activity stats.
func (s *Service) Snapshot() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.ReposWatched = len(s.repos)
	st.Signature = s.scanner.Signature()
	if s.cfg.PollInterval > 0 {
		st.PollInterval = s.cfg.PollInterval.String()
	}
	return st
}

func (s *Service) recordCycle(res Result) {
	s.mu.Lock()
	s.stats.Cycles++
	s.stats.CommitsScanned += int64(res.Scanned)
	s.stats.CommitsFlagged += int64(res.Flagged)
	s.stats.LastCycleAt = time.Now().UTC()
	s.mu.Unlock()
}

func (s *Service) incErrors() {
	s.mu.Lock()
	s.stats.Errors++
	s.mu.Unlock()
}

func (s *Service) incWebhook(rejected bool) {
	s.mu.Lock()
	s.stats.WebhooksTotal++
	if rejected {
		s.stats.WebhooksRejected++
	}
	s.mu.Unlock()
}

// Close stops the polling loop and waits for it to exit. It does not close the
// state store (the owner does that).
func (s *Service) Close() error {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
	return nil
}

// isFlagged reports whether a verdict carries at least one medium-or-higher
// finding, the threshold at which the watcher counts a commit as "flagged" for
// its activity stats (independent of the admission failOn severity).
func isFlagged(v *commit.Verdict) bool {
	switch v.HighestSeverity() {
	case "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// cacheKeyOf mirrors the pipeline's cache-key derivation so the watcher can tell
// a fresh scan from a cache hit by comparing the verdict's recorded CacheKey. It
// must stay in sync with commit.cacheKey (sha + "-" + signature).
func cacheKeyOf(sha, sig string) string {
	sha = strings.TrimSpace(sha)
	if sig == "" {
		return sha
	}
	return sha + "-" + sig
}
