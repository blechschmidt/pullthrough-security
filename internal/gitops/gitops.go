package gitops

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/simreplay"
)

// Mode selects how a detected desired-state change is applied.
type Mode string

const (
	// ModeApply reconciles automatically: a verified, valid change is patched onto
	// the on-disk config and recorded to the audit log without human intervention.
	ModeApply Mode = "apply"
	// ModeSuggest reconciles through the dual-control approvals workflow: a change is
	// surfaced as a pending review and applied only once approved.
	ModeSuggest Mode = "suggest"
)

// DefaultInterval is the reconcile cadence applied when the configured interval is
// non-positive.
const DefaultInterval = 5 * time.Minute

// Config configures the GitOps reconciler.
type Config struct {
	// Enabled turns on reconciliation, the admin surface, the scheduler, and metrics.
	Enabled bool
	// Mode is "apply" (auto) or "suggest" (dual-control). Defaults to suggest.
	Mode Mode
	// Interval is the reconcile cadence. Non-positive uses DefaultInterval.
	Interval time.Duration
	// ConfigPath is the live config file the reconciler patches on apply. Empty
	// means the process runs from defaults with no backing file; apply is then
	// refused (diff/suggest still work).
	ConfigPath string
	// StorePath is the JSON file the durable reconciliation state (last revision,
	// apply history, pending change) is persisted to. Empty keeps it in memory.
	StorePath string
	// FailClosed refuses to apply when verification is configured but the bundle
	// does not verify (bad signature / digest mismatch / missing signature). When
	// false the verification failure is recorded but the change still reconciles
	// (observe-the-signature mode).
	FailClosed bool
}

// ApprovalConsulter is the slice of the approvals workflow the reconciler needs in
// suggest mode. *approvals.Service satisfies it.
type ApprovalConsulter interface {
	Enabled() bool
	Consult(ctx context.Context, sc approvals.Scope) approvals.Disposition
}

// Option configures optional dependencies.
type Option func(*Service)

// WithAudit wires the Merkle-chained audit logger; apply/rollback events are
// recorded to it.
func WithAudit(l *audit.Logger) Option { return func(s *Service) { s.audit = l } }

// WithNotifier wires the event-notification emitter; apply/drift/rollback events
// are emitted to it.
func WithNotifier(n notify.Emitter) Option { return func(s *Service) { s.notify = n } }

// WithApprovals wires the dual-control approvals workflow used by suggest mode.
func WithApprovals(a ApprovalConsulter) Option { return func(s *Service) { s.approvals = a } }

// WithRecords wires a provider of captured admission records so the reconcile
// preview can include a simreplay blast-radius what-if.
func WithRecords(fn func() []simreplay.Record) Option {
	return func(s *Service) { s.records = fn }
}

// WithClock overrides the clock (for tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// Service reconciles the proxy's policy/config bundles toward a Git/OCI/local
// source of truth.
type Service struct {
	cfg      Config
	src      Source
	verifier *Verifier
	logger   *slog.Logger
	now      func() time.Time

	audit     *audit.Logger
	notify    notify.Emitter
	approvals ApprovalConsulter
	records   func() []simreplay.Record

	mu         sync.Mutex
	live       *config.Config
	detector   *config.Detector
	st         *state
	preview    *Preview
	leaderGate func() bool

	// metrics counters
	reconciles     uint64
	applies        uint64
	rollbacks      uint64
	verifyFailures uint64
	errs           uint64

	// scheduler
	schedMu sync.Mutex
	stop    chan struct{}
	done    chan struct{}
}

// New constructs the reconciler. live is the running configuration (used for
// projecting/validating desired-state changes); src is the source of truth;
// verifier checks bundle integrity/authenticity (pass a Verifier with no key/digest
// to skip verification).
func New(cfg Config, live *config.Config, src Source, verifier *Verifier, logger *slog.Logger, opts ...Option) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeSuggest
	}
	switch cfg.Mode {
	case ModeApply, ModeSuggest:
	default:
		return nil, fmt.Errorf("gitops: invalid mode %q (want apply|suggest)", cfg.Mode)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Enabled && src == nil {
		return nil, fmt.Errorf("gitops: a source of truth is required when enabled")
	}
	if verifier == nil {
		verifier, _ = NewVerifier(nil, "")
	}
	st, err := loadState(cfg.StorePath)
	if err != nil {
		return nil, err
	}
	s := &Service{
		cfg:      cfg,
		src:      src,
		verifier: verifier,
		logger:   logger,
		now:      time.Now,
		live:     live,
		st:       st,
	}
	for _, opt := range opts {
		opt(s)
	}
	if cfg.ConfigPath != "" && live != nil {
		s.detector = config.NewDetector(cfg.ConfigPath, live)
	}
	return s, nil
}

// Enabled reports whether the reconciler is active. Safe on a nil Service.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Mode returns the configured reconcile mode.
func (s *Service) Mode() Mode {
	if s == nil {
		return ModeSuggest
	}
	return s.cfg.Mode
}

// SourceDescription returns a description of the source of truth.
func (s *Service) SourceDescription() string {
	if s == nil || s.src == nil {
		return ""
	}
	return s.src.Describe()
}

// SetLeaderGate installs the HA leader predicate consulted before each *scheduled*
// reconcile, so across N replicas only the lease-holder reconciles and mutates the
// shared config/state. Manual syncs (admin/ptctl) are never gated. A nil gate
// reconciles unconditionally. Call before Start.
func (s *Service) SetLeaderGate(fn func() bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.leaderGate = fn
	s.mu.Unlock()
}

func (s *Service) isLeader() bool {
	s.mu.Lock()
	gate := s.leaderGate
	s.mu.Unlock()
	return gate == nil || gate()
}

// Start launches the background reconcile loop. It is a no-op when the service is
// disabled or already started.
func (s *Service) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.schedMu.Lock()
	if s.stop != nil {
		s.schedMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	s.stop = stop
	s.done = done
	s.schedMu.Unlock()

	go s.loop(ctx, stop, done)
}

// Stop halts the background reconcile loop and waits for it to exit.
func (s *Service) Stop() {
	if s == nil {
		return
	}
	s.schedMu.Lock()
	stop, done := s.stop, s.done
	s.stop, s.done = nil, nil
	s.schedMu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
}

func (s *Service) loop(ctx context.Context, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	s.logger.Info("gitops reconciler started",
		"mode", s.cfg.Mode, "interval", s.cfg.Interval, "source", s.SourceDescription())
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			if !s.isLeader() {
				continue
			}
			rctx, cancel := context.WithTimeout(ctx, s.cfg.Interval)
			if _, err := s.Reconcile(rctx, "scheduler", "scheduler"); err != nil {
				s.logger.Warn("gitops scheduled reconcile failed", "error", err)
			}
			cancel()
		}
	}
}

// Sync forces an immediate reconcile (the manual admin/ptctl path). It is not
// leader-gated: the operator invoking it chose this replica.
func (s *Service) Sync(ctx context.Context, by string) (Outcome, error) {
	if by == "" {
		by = "manual"
	}
	return s.Reconcile(ctx, "manual", by)
}

// --- status / metrics types ------------------------------------------------

// SettingChange is one path's before/after in a reconcile preview.
type SettingChange struct {
	Path     string `json:"path"`
	Desc     string `json:"desc,omitempty"`
	Current  string `json:"current"`
	Proposed string `json:"proposed"`
	Changed  bool   `json:"changed"`
}

// BlastSummary is the simreplay what-if summary for a desired-state change: how
// many captured pulls would flip admit↔block, shift risk band, or gain new policy
// violations under the proposed configuration.
type BlastSummary struct {
	Total         int `json:"total"`
	Changed       int `json:"changed"`
	Flips         int `json:"flips"`
	NowBlocked    int `json:"nowBlocked"`
	NowAdmitted   int `json:"nowAdmitted"`
	BandShifts    int `json:"bandShifts"`
	NewViolations int `json:"newViolations"`
}

func blastFrom(sum simreplay.Summary) *BlastSummary {
	return &BlastSummary{
		Total:         sum.Total,
		Changed:       sum.Changed,
		Flips:         sum.Flips,
		NowBlocked:    sum.NowBlocked,
		NowAdmitted:   sum.NowAdmitted,
		BandShifts:    sum.BandShifts,
		NewViolations: sum.NewViolations,
	}
}

// Preview is the latest computed view of the desired-state-vs-live delta.
type Preview struct {
	Revision            string          `json:"revision"`
	Origin              string          `json:"origin,omitempty"`
	BundleDigest        string          `json:"bundleDigest"`
	Changed             int             `json:"changed"`
	Settings            []SettingChange `json:"settings"`
	RunningFingerprint  string          `json:"runningFingerprint"`
	ProposedFingerprint string          `json:"proposedFingerprint"`
	Valid               bool            `json:"valid"`
	ValidationErrors    int             `json:"validationErrors"`
	BlastRadius         *BlastSummary   `json:"blastRadius,omitempty"`
	ComputedAt          time.Time       `json:"computedAt"`
}

// Status is the operator-facing reconciliation status surfaced to the admin UI/CLI.
type Status struct {
	Enabled       bool                `json:"enabled"`
	Mode          Mode                `json:"mode"`
	Source        string              `json:"source"`
	Interval      string              `json:"interval"`
	InSync        bool                `json:"inSync"`
	DriftDetected bool                `json:"driftDetected"`
	LastSyncAt    time.Time           `json:"lastSyncAt,omitempty"`
	LastRevision  string              `json:"lastRevision,omitempty"`
	LastOutcome   string              `json:"lastOutcome,omitempty"`
	LastError     string              `json:"lastError,omitempty"`
	Verified      bool                `json:"verified"`
	KeyID         string              `json:"keyId,omitempty"`
	LastApplied   *AppliedEntry       `json:"lastApplied,omitempty"`
	LastKnownGood *AppliedEntry       `json:"lastKnownGood,omitempty"`
	Pending       *PendingChange      `json:"pending,omitempty"`
	Preview       *Preview            `json:"preview,omitempty"`
	History       []AppliedEntry      `json:"history,omitempty"`
	ConfigDrift   *config.DriftStatus `json:"configDrift,omitempty"`
}

// Status returns the current reconciliation status. Safe on a nil/disabled service.
func (s *Service) Status() Status {
	if s == nil {
		return Status{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		Enabled:       s.cfg.Enabled,
		Mode:          s.cfg.Mode,
		Source:        s.SourceDescription(),
		Interval:      s.cfg.Interval.String(),
		InSync:        s.st.InSync,
		DriftDetected: s.st.Drift,
		LastSyncAt:    s.st.LastSyncAt,
		LastRevision:  s.st.LastRevision,
		LastOutcome:   s.st.LastOutcome,
		LastError:     s.st.LastError,
		KeyID:         s.verifier.KeyID(),
		Pending:       s.st.Pending,
		Preview:       s.preview,
	}
	if head := s.st.head(); head != nil {
		e := *head
		st.LastApplied = &e
	}
	if lkg := s.st.lastKnownGood(); lkg != nil {
		e := *lkg
		st.LastKnownGood = &e
	}
	if n := len(s.st.History); n > 0 {
		hist := make([]AppliedEntry, n)
		copy(hist, s.st.History)
		st.History = hist
	}
	if s.detector != nil {
		ds := s.detector.Status()
		st.ConfigDrift = &ds
	}
	return st
}

// Snapshot is the point-in-time metrics view consumed by the Prometheus bridge.
type Snapshot struct {
	Enabled        bool
	Mode           string
	InSync         bool
	DriftDetected  bool
	PendingChange  bool
	Reconciles     uint64
	Applies        uint64
	Rollbacks      uint64
	VerifyFailures uint64
	Errors         uint64
	HistoryLen     int
	LastSyncUnix   int64
}

// Metrics returns the current metrics snapshot. Safe on a nil/disabled service.
func (s *Service) Metrics() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{
		Enabled:        s.cfg.Enabled,
		Mode:           string(s.cfg.Mode),
		InSync:         s.st.InSync,
		DriftDetected:  s.st.Drift,
		PendingChange:  s.st.Pending != nil,
		Reconciles:     s.reconciles,
		Applies:        s.applies,
		Rollbacks:      s.rollbacks,
		VerifyFailures: s.verifyFailures,
		Errors:         s.errs,
		HistoryLen:     len(s.st.History),
	}
	if !s.st.LastSyncAt.IsZero() {
		snap.LastSyncUnix = s.st.LastSyncAt.Unix()
	}
	return snap
}

// persistLocked writes the durable state; callers hold s.mu.
func (s *Service) persistLocked() {
	if err := saveState(s.cfg.StorePath, s.st); err != nil {
		s.logger.Warn("gitops state persist failed", "error", err)
	}
}

// emit sends a notification event when a notifier is wired.
func (s *Service) emit(ctx context.Context, ev notify.Event) {
	if s.notify == nil {
		return
	}
	s.notify.Emit(ctx, ev)
}

// normRevision shortens a revision for display while keeping full-length SHAs in
// records.
func shortRev(rev string) string {
	rev = strings.TrimPrefix(rev, "sha256:")
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
