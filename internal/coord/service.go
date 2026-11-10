package coord

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures the coordination Service. When Enabled is false the Service
// is in single-node fallback: every Guard reports leader unconditionally and no
// backend or campaign goroutines are created, preserving the original
// single-replica behavior with zero overhead.
type Config struct {
	Enabled bool
	// Mode selects the lease backend: "memory" (single-node default), "s3", or
	// "file". Empty defaults to "memory".
	Mode string
	// NodeID uniquely identifies this replica in lease records. Empty defaults to
	// "<hostname>-<pid>".
	NodeID string
	// LeaseTTL is how long an acquired lease is valid before it must be renewed;
	// after this without a heartbeat another replica may take over. Empty defaults
	// to 30s.
	LeaseTTL time.Duration
	// RenewInterval is how often the holder heartbeats to extend its lease. It must
	// be comfortably below LeaseTTL. Empty defaults to LeaseTTL/3.
	RenewInterval time.Duration
	// RetryInterval is how often a follower re-attempts acquisition. Empty defaults
	// to RenewInterval.
	RetryInterval time.Duration
	// JobTTLs optionally overrides LeaseTTL for specific named jobs.
	JobTTLs map[string]time.Duration

	// S3 configures the "s3" backend. Prefix isolates lease objects in the bucket.
	S3       S3Config
	S3Prefix string
	// Dir configures the "file" backend's shared lease directory.
	Dir string
}

// S3Config holds the S3-compatible object-store connection settings for the s3
// coordination backend. It mirrors the cache S3 backend so an HA deployment can
// reuse the same bucket and credentials.
type S3Config struct {
	Endpoint           string
	Region             string
	Bucket             string
	AccessKeyID        string
	SecretAccessKey    string
	SessionToken       string
	UsePathStyle       bool
	InsecureSkipVerify bool
	MaxRetries         int
}

// Service is the configured top-level coordination object. It owns the lease
// backend and the per-job campaign goroutines, hands out Guards that schedulers
// gate their work on, and exposes status for metrics and the admin API.
type Service struct {
	cfg     Config
	logger  *slog.Logger
	now     func() time.Time
	coord   *coordinator
	backend backend

	mu      sync.Mutex
	guards  map[string]*Guard
	started bool
	rootCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// Option customizes a Service (used by tests to inject a clock or backend).
type Option func(*Service)

// WithClock overrides the Service clock for deterministic tests.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// withBackend injects a pre-built backend, bypassing Mode selection (tests).
func withBackend(b backend) Option {
	return func(s *Service) { s.backend = b }
}

// New constructs a coordination Service from cfg. When coordination is disabled
// it returns a Service that hands out always-leader Guards. Otherwise it builds
// the configured backend and a coordinator over it.
func New(cfg Config, logger *slog.Logger, opts ...Option) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = withDefaults(cfg)
	s := &Service{
		cfg:    cfg,
		logger: logger,
		now:    time.Now,
		guards: make(map[string]*Guard),
	}
	for _, o := range opts {
		o(s)
	}
	if !cfg.Enabled {
		return s, nil
	}
	if s.backend == nil {
		b, err := buildBackend(cfg)
		if err != nil {
			return nil, err
		}
		s.backend = b
	}
	s.coord = newCoordinator(s.backend, cfg.NodeID, s.now)
	return s, nil
}

// withDefaults fills unset Config fields with their defaults.
func withDefaults(cfg Config) Config {
	if strings.TrimSpace(cfg.Mode) == "" {
		cfg.Mode = "memory"
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		cfg.NodeID = defaultNodeID()
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.RenewInterval <= 0 {
		cfg.RenewInterval = cfg.LeaseTTL / 3
	}
	if cfg.RenewInterval <= 0 {
		cfg.RenewInterval = cfg.LeaseTTL
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = cfg.RenewInterval
	}
	return cfg
}

// buildBackend constructs the backend selected by cfg.Mode.
func buildBackend(cfg Config) (backend, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "", "memory":
		return newMemoryBackend(), nil
	case "s3":
		return newS3Backend(cfg.S3, cfg.S3Prefix)
	case "file":
		return newFileBackend(cfg.Dir)
	default:
		return nil, fmt.Errorf("coord: unknown coordination mode %q (want memory|s3|file)", cfg.Mode)
	}
}

// defaultNodeID derives a stable-per-process identity from the hostname and PID.
func defaultNodeID() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "node"
	}
	return host + "-" + strconv.Itoa(os.Getpid())
}

// Enabled reports whether distributed coordination is active (false ⇒ single-node
// fallback where every Guard is permanently leader).
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// NodeID returns this replica's identity in lease records.
func (s *Service) NodeID() string {
	if s == nil {
		return ""
	}
	return s.cfg.NodeID
}

// Coordinator exposes the underlying lease primitive for callers that want to
// drive leases directly rather than through a Guard. It is nil when coordination
// is disabled.
func (s *Service) Coordinator() Coordinator {
	if s == nil || s.coord == nil {
		return nil
	}
	return s.coord
}

// Guard returns (creating on first use) the leadership guard for a named job. The
// returned Guard's IsLeader gates the job's scheduled work. When coordination is
// disabled the Guard is permanently leader. If the Service has already started,
// the new Guard's campaign goroutine launches immediately.
func (s *Service) Guard(job string) *Guard {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.guards[job]; ok {
		return g
	}
	ttl := s.cfg.LeaseTTL
	if v, ok := s.cfg.JobTTLs[job]; ok && v > 0 {
		ttl = v
	}
	g := &Guard{svc: s, job: job, ttl: ttl, always: !s.cfg.Enabled}
	if g.always {
		g.leader.Store(true)
	}
	s.guards[job] = g
	if s.started && s.cfg.Enabled {
		s.wg.Add(1)
		go s.campaign(s.rootCtx, g)
	}
	return g
}

// Start launches the campaign goroutines for all registered guards. It is a no-op
// when coordination is disabled or already started. Guards registered after Start
// launch their campaign immediately from Guard.
func (s *Service) Start(ctx context.Context) {
	if s == nil || !s.cfg.Enabled {
		return
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	cctx, cancel := context.WithCancel(ctx)
	s.rootCtx = cctx
	s.cancel = cancel
	guards := make([]*Guard, 0, len(s.guards))
	for _, g := range s.guards {
		guards = append(guards, g)
	}
	s.mu.Unlock()

	s.logger.Info("coordination started",
		"mode", s.cfg.Mode, "node", s.cfg.NodeID,
		"leaseTtl", s.cfg.LeaseTTL, "renewInterval", s.cfg.RenewInterval)
	for _, g := range guards {
		s.wg.Add(1)
		go s.campaign(cctx, g)
	}
}

// Close stops all campaign goroutines (each resigns its held lease so another
// replica can take over immediately) and closes the backend. It is idempotent.
func (s *Service) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	started := s.started
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if started {
		s.wg.Wait()
	}
	if s.backend != nil {
		return s.backend.close()
	}
	return nil
}

// campaign continuously acquires and renews the guard's lease until ctx is
// cancelled, then resigns. Renewals heartbeat every RenewInterval while leader;
// a follower retries acquisition every RetryInterval.
func (s *Service) campaign(ctx context.Context, g *Guard) {
	defer s.wg.Done()

	// Attempt an immediate acquisition so leadership is established promptly at
	// startup rather than after one full interval.
	s.tick(ctx, g)

	timer := time.NewTimer(s.waitFor(g))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			s.relinquish(g)
			return
		case <-timer.C:
			s.tick(ctx, g)
			timer.Reset(s.waitFor(g))
		}
	}
}

// waitFor returns the delay until the guard's next campaign action: the renew
// heartbeat when leader, else the follower retry interval.
func (s *Service) waitFor(g *Guard) time.Duration {
	if g.IsLeader() {
		return s.cfg.RenewInterval
	}
	return s.cfg.RetryInterval
}

// tick performs a single campaign action for the guard: acquire when not leader,
// renew when leader, updating leadership state and counters. It is also the unit
// exercised directly (with a fake clock) by the deterministic tests.
func (s *Service) tick(ctx context.Context, g *Guard) {
	g.mu.Lock()
	lease := g.lease
	g.mu.Unlock()

	if lease == nil {
		nl, err := s.coord.AcquireLease(ctx, g.job, g.ttl)
		if err != nil {
			if errors.Is(err, ErrLeaseHeld) {
				g.stats.acquireContended.Add(1)
				return
			}
			if ctx.Err() == nil {
				s.logger.Debug("coordination: lease acquisition error", "job", g.job, "error", err)
			}
			g.stats.errors.Add(1)
			return
		}
		g.setLease(nl, s.now())
		g.stats.acquisitions.Add(1)
		s.logger.Info("coordination: acquired leadership",
			"job", g.job, "node", s.cfg.NodeID, "fencingToken", nl.FencingToken)
		return
	}

	nl, err := s.coord.RenewLease(ctx, lease, g.ttl)
	if err != nil {
		if errors.Is(err, ErrLeaseLost) {
			g.clearLease(s.now())
			g.stats.losses.Add(1)
			s.logger.Warn("coordination: lost leadership", "job", g.job, "node", s.cfg.NodeID)
			return
		}
		// Transient backend error: keep leadership for now, but step down if the
		// lease has already expired locally so we never act past our grant.
		g.stats.errors.Add(1)
		if ctx.Err() == nil {
			s.logger.Warn("coordination: lease renewal error", "job", g.job, "error", err)
		}
		if lease.expired(s.now()) {
			g.clearLease(s.now())
			g.stats.losses.Add(1)
			s.logger.Warn("coordination: lease expired during renewal failures; stepping down", "job", g.job)
		}
		return
	}
	g.setLease(nl, s.now())
	g.stats.renewals.Add(1)
}

// relinquish resigns the guard's held lease on shutdown so a surviving replica
// can take over without waiting for expiry. Best-effort with a bounded context.
func (s *Service) relinquish(g *Guard) {
	g.mu.Lock()
	lease := g.lease
	g.mu.Unlock()
	if lease == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.coord.Resign(ctx, lease); err != nil {
		s.logger.Debug("coordination: resign on shutdown failed", "job", g.job, "error", err)
	}
	g.clearLease(s.now())
}

// Snapshot returns the local coordination state for the metrics bridge and the
// admin overview. It performs no I/O.
func (s *Service) Snapshot() Snapshot {
	snap := Snapshot{Enabled: s.cfg.Enabled, Mode: s.cfg.Mode, NodeID: s.cfg.NodeID}
	s.mu.Lock()
	guards := make([]*Guard, 0, len(s.guards))
	for _, g := range s.guards {
		guards = append(guards, g)
	}
	s.mu.Unlock()
	now := s.now()
	for _, g := range guards {
		snap.Jobs = append(snap.Jobs, g.status(now))
	}
	sort.Slice(snap.Jobs, func(i, j int) bool { return snap.Jobs[i].Job < snap.Jobs[j].Job })
	return snap
}

// Leaseholders reads the coordination backend for every registered job and
// reports the observed cluster-wide leaseholder. Any replica (leader or follower)
// can answer it; it is the basis for the admin "who holds each lease" view.
func (s *Service) Leaseholders(ctx context.Context) []Leaseholder {
	s.mu.Lock()
	jobs := make([]string, 0, len(s.guards))
	for name := range s.guards {
		jobs = append(jobs, name)
	}
	s.mu.Unlock()
	sort.Strings(jobs)

	now := s.now()
	out := make([]Leaseholder, 0, len(jobs))
	for _, job := range jobs {
		lh := Leaseholder{Job: job}
		if s.backend != nil {
			rec, _, found, err := s.backend.load(ctx, job)
			if err == nil && found {
				lh.Held = true
				lh.Holder = rec.Holder
				lh.FencingToken = rec.FencingToken
				lh.AcquiredAt = rec.AcquiredAt
				lh.ExpiresAt = rec.ExpiresAt
				lh.Expired = !now.Before(rec.ExpiresAt)
				lh.Self = rec.Holder == s.cfg.NodeID
			}
		}
		out = append(out, lh)
	}
	return out
}

// Guard is a per-job leadership guard. A scheduler calls IsLeader before each
// scheduled run and only proceeds when it returns true. When coordination is
// disabled the guard is permanently leader.
type Guard struct {
	svc    *Service
	job    string
	ttl    time.Duration
	always bool

	leader atomic.Bool
	stats  jobStats

	mu                 sync.Mutex
	lease              *Lease
	leaderSince        time.Time
	accumLeaderSeconds float64
}

// IsLeader reports whether this node should run the guard's scheduled work now.
// It is safe on a nil guard (treated as leader, i.e. coordination not wired).
func (g *Guard) IsLeader() bool {
	if g == nil || g.always {
		return true
	}
	return g.leader.Load()
}

// FencingToken returns the fencing token of the currently held lease (0 when not
// leader or coordination is disabled). Thread it into downstream writes that need
// to fence off a stale former leader.
func (g *Guard) FencingToken() uint64 {
	if g == nil || g.always {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lease == nil {
		return 0
	}
	return g.lease.FencingToken
}

// Job returns the guard's job name.
func (g *Guard) Job() string {
	if g == nil {
		return ""
	}
	return g.job
}

// setLease records a freshly acquired/renewed lease and marks leadership, opening
// the time-as-leader accounting window on the first acquisition.
func (g *Guard) setLease(l *Lease, now time.Time) {
	g.mu.Lock()
	if g.lease == nil {
		g.leaderSince = now
	}
	g.lease = l
	g.mu.Unlock()
	g.leader.Store(true)
}

// clearLease drops leadership and closes the current time-as-leader window.
func (g *Guard) clearLease(now time.Time) {
	g.mu.Lock()
	if g.lease != nil && !g.leaderSince.IsZero() {
		if d := now.Sub(g.leaderSince).Seconds(); d > 0 {
			g.accumLeaderSeconds += d
		}
	}
	g.lease = nil
	g.leaderSince = time.Time{}
	g.mu.Unlock()
	g.leader.Store(false)
}

// status builds the JobStatus snapshot for this guard as of now.
func (g *Guard) status(now time.Time) JobStatus {
	g.mu.Lock()
	st := JobStatus{
		Job:                 g.job,
		Acquisitions:        g.stats.acquisitions.Load(),
		Renewals:            g.stats.renewals.Load(),
		Losses:              g.stats.losses.Load(),
		AcquireContended:    g.stats.acquireContended.Load(),
		Errors:              g.stats.errors.Load(),
		TimeAsLeaderSeconds: g.accumLeaderSeconds,
	}
	if g.always {
		st.IsLeader = true
	} else if g.lease != nil {
		st.IsLeader = !g.lease.expired(now)
		st.FencingToken = g.lease.FencingToken
		st.AcquiredAt = g.lease.AcquiredAt
		st.ExpiresAt = g.lease.ExpiresAt
		if !g.leaderSince.IsZero() {
			if d := now.Sub(g.leaderSince).Seconds(); d > 0 {
				st.TimeAsLeaderSeconds += d
			}
		}
	}
	g.mu.Unlock()
	return st
}
