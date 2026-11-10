package keyrotation

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Rotation-driver errors returned by Service.Rotate.
var (
	// ErrUnknownMaterial is returned when no material with the given id is
	// registered.
	ErrUnknownMaterial = errors.New("keyrotation: unknown material")
	// ErrRotationUnsupported is returned when a material is known but has no
	// automated in-place rotation path (it must be rotated out-of-band).
	ErrRotationUnsupported = errors.New("keyrotation: material does not support automated in-place rotation")
)

// Config is the key-rotation subsystem's static configuration.
type Config struct {
	Enabled bool
	// ScanInterval is how often the leader-gated scanner runs. Non-positive uses
	// the default.
	ScanInterval time.Duration
	// WarnThreshold / CriticalThreshold grade remaining lifetime; material within
	// WarnThreshold of expiry warns, within CriticalThreshold is critical.
	WarnThreshold     time.Duration
	CriticalThreshold time.Duration
	// OverlapWindow is the default dual-key overlap window applied to staged
	// rotations the subsystem drives.
	OverlapWindow time.Duration
}

const (
	defaultScanInterval      = 6 * time.Hour
	defaultWarnThreshold     = 14 * 24 * time.Hour
	defaultCriticalThreshold = 3 * 24 * time.Hour
	defaultOverlapWindow     = 24 * time.Hour
)

func (c *Config) applyDefaults() {
	if c.ScanInterval <= 0 {
		c.ScanInterval = defaultScanInterval
	}
	if c.WarnThreshold <= 0 {
		c.WarnThreshold = defaultWarnThreshold
	}
	if c.CriticalThreshold <= 0 {
		c.CriticalThreshold = defaultCriticalThreshold
	}
	if c.OverlapWindow < 0 {
		c.OverlapWindow = defaultOverlapWindow
	}
}

// Deps carries the subsystem's injected collaborators.
type Deps struct {
	// Notifier receives expiry warnings and rotation events. A nil Notifier (or a
	// nil *notify.Notifier) is a valid no-op.
	Notifier notify.Emitter
	Logger   *slog.Logger
	// Now is the clock; nil uses time.Now. Tests inject a fake.
	Now func() time.Time
}

type namedSource struct {
	name string
	src  Source
}

// Service is the key-rotation/expiry orchestrator. It aggregates registered
// Sources, grades each material on a leader-gated schedule, emits notifications
// and metrics, and drives the rotations that register a Rotator through the
// dual-key overlap state machine. It is safe for concurrent use.
type Service struct {
	cfg      Config
	notifier notify.Emitter
	logger   *slog.Logger
	now      func() time.Time
	metrics  *Metrics

	mu       sync.Mutex
	sources  []namedSource
	rotators map[string]Rotator
	overlaps map[string]*OverlapState
	last     []MaterialStatus
	lastScan time.Time
	notified map[string]Status // per-material last-notified band, for de-dup

	leaderFn func() bool
	cancel   context.CancelFunc
	doneCh   chan struct{}
}

// New constructs the service. It is always safe to construct (even when
// disabled) so the metrics/admin layers can bind unconditionally; Start is a
// no-op when disabled.
func New(cfg Config, deps Deps) *Service {
	cfg.applyDefaults()
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		cfg:      cfg,
		notifier: deps.Notifier,
		logger:   logger,
		now:      now,
		metrics:  NewMetrics(),
		rotators: make(map[string]Rotator),
		overlaps: make(map[string]*OverlapState),
		notified: make(map[string]Status),
	}
}

// Enabled reports whether the subsystem is active.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Metrics returns the shared metrics handle for the observability layer.
func (s *Service) Metrics() *Metrics {
	if s == nil {
		return nil
	}
	return s.metrics
}

// AddSource registers a material source. name is used only for log/metric
// attribution of source errors.
func (s *Service) AddSource(name string, src Source) {
	if s == nil || src == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, namedSource{name: name, src: src})
}

// AddRotator registers an automated in-place rotator for a material id and seeds
// its overlap-state tracker with the current primary key id.
func (s *Service) AddRotator(materialID, currentKeyID string, r Rotator) {
	if s == nil || r == nil || materialID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotators[materialID] = r
	if s.overlaps[materialID] == nil {
		s.overlaps[materialID] = NewOverlapState(currentKeyID, s.cfg.OverlapWindow)
	}
}

// SetLeaderGate installs the HA leader predicate (Task 56). The scheduled scan
// still runs on every replica so each node's gauge is populated, but
// notifications are emitted only by the leader so an N-replica deployment alerts
// once. A nil gate (the default) treats this node as leader. Call before Start.
func (s *Service) SetLeaderGate(fn func() bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaderFn = fn
}

func (s *Service) isLeader() bool {
	s.mu.Lock()
	fn := s.leaderFn
	s.mu.Unlock()
	return fn == nil || fn()
}

func (s *Service) thresholds() Thresholds {
	return Thresholds{Warn: s.cfg.WarnThreshold, Critical: s.cfg.CriticalThreshold}
}

// ScanResult is the full point-in-time expiry read-model returned by Status and
// the admin API.
type ScanResult struct {
	GeneratedAt       time.Time        `json:"generatedAt"`
	Enabled           bool             `json:"enabled"`
	WarnThreshold     string           `json:"warnThreshold"`
	CriticalThreshold string           `json:"criticalThreshold"`
	Counts            StatusCounts     `json:"counts"`
	Materials         []MaterialStatus `json:"materials"`
}

// StatusCounts tallies materials by band.
type StatusCounts struct {
	Total    int `json:"total"`
	OK       int `json:"ok"`
	Warning  int `json:"warning"`
	Critical int `json:"critical"`
	Expired  int `json:"expired"`
	Unknown  int `json:"unknown"`
}

// Status runs a fresh, read-only evaluation (no notifications emitted) and
// returns the current expiry read-model. It also refreshes the stored scan so
// the live expiry gauge reflects the latest observation.
func (s *Service) Status(ctx context.Context) ScanResult {
	return s.scan(ctx, false)
}

// Expiries returns just the current per-material statuses (read-only), sorted
// soonest-expiring first.
func (s *Service) Expiries(ctx context.Context) []MaterialStatus {
	return s.scan(ctx, false).Materials
}

// UpcomingExpiries is the ctx-free seam the SOC posture surface reads; it runs a
// fresh read-only evaluation and returns the per-material statuses.
func (s *Service) UpcomingExpiries() []MaterialStatus {
	if !s.Enabled() {
		return nil
	}
	return s.scan(context.Background(), false).Materials
}

// scan consults every source, grades each material, updates stored state and
// metrics, and (when emit is true) sends notifications for materials that have
// entered a more-severe band since the last emitting scan.
func (s *Service) scan(ctx context.Context, emit bool) ScanResult {
	now := s.now()
	th := s.thresholds()

	s.mu.Lock()
	sources := append([]namedSource(nil), s.sources...)
	rotators := s.rotators
	s.mu.Unlock()

	var statuses []MaterialStatus
	for _, ns := range sources {
		mats, err := ns.src.Scan(ctx)
		if err != nil {
			s.metrics.recordSourceError()
			s.logger.Warn("keyrotation: source scan failed", "source", ns.name, "error", err)
			continue
		}
		for _, m := range mats {
			if _, ok := rotators[m.ID]; ok {
				m.RotationSupported = true
			}
			// Merge any subsystem-driven overlap we are tracking for this slot so a
			// staged rotation suppresses expiry false-positives on the retiring key.
			if st := s.overlapFor(m.ID); st != nil && st.InOverlap(now) {
				m.Overlap = true
				m.PreviousKeyIDs = mergeKeyIDs(m.PreviousKeyIDs, st.LivePreviousKeyIDs(now))
			}
			statuses = append(statuses, Evaluate(now, m, th))
		}
	}

	sortStatuses(statuses)
	counts := tally(statuses)
	s.metrics.recordScan(now.Unix(), counts.Warning, counts.Critical, counts.Expired)

	s.mu.Lock()
	s.last = statuses
	s.lastScan = now
	s.mu.Unlock()

	if emit {
		s.emitTransitions(ctx, statuses)
	}

	return ScanResult{
		GeneratedAt:       now,
		Enabled:           s.cfg.Enabled,
		WarnThreshold:     s.cfg.WarnThreshold.String(),
		CriticalThreshold: s.cfg.CriticalThreshold.String(),
		Counts:            counts,
		Materials:         statuses,
	}
}

// emitTransitions sends a notification for each material whose band has worsened
// since the last emitting scan (so a steady-state warning is not re-alerted every
// tick, but an escalation always is), and clears the de-dup record when a
// material returns to OK so a future re-entry alerts again.
func (s *Service) emitTransitions(ctx context.Context, statuses []MaterialStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ms := range statuses {
		prev, seen := s.notified[ms.ID]
		if !ms.Status.alerting() {
			if seen {
				delete(s.notified, ms.ID)
			}
			continue
		}
		if seen && !ms.Status.worseThan(prev) {
			continue
		}
		s.notified[ms.ID] = ms.Status
		s.metrics.recordBandEntry(ms.Status)
		if s.notifier != nil {
			s.notifier.Emit(ctx, keyExpiryEvent(ms, s.now()))
		}
		s.logger.Warn("keyrotation: material approaching expiry",
			"material", ms.ID, "kind", string(ms.Kind), "status", string(ms.Status),
			"expiresAt", ms.EffectiveExpiry, "secondsRemaining", int64(ms.SecondsRemaining))
	}
}

// keyExpiryEvent builds the notification for a material in an alerting band.
func keyExpiryEvent(ms MaterialStatus, now time.Time) notify.Event {
	sev := notify.SeverityMedium
	switch ms.Status {
	case StatusCritical:
		sev = notify.SeverityHigh
	case StatusExpired:
		sev = notify.SeverityCritical
	}
	days := int(ms.EffectiveExpiry.Sub(now).Hours() / 24)
	return notify.KeyExpiryEvent(sev, ms.ID, string(ms.Kind), ms.KeyID, string(ms.Status), days, ms.EffectiveExpiry)
}

func (s *Service) overlapFor(id string) *OverlapState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.overlaps[id]
}

// Rotate drives an in-place rotation of the named material. When force is false
// and a prior rotation of the same slot is still within its overlap window, it is
// refused with ErrRotationInFlight (the safe default). A material with no
// registered rotator returns an informative, Supported=false outcome alongside
// ErrRotationUnsupported.
func (s *Service) Rotate(ctx context.Context, materialID string, force bool) (RotationOutcome, error) {
	s.mu.Lock()
	r := s.rotators[materialID]
	st := s.overlaps[materialID]
	s.mu.Unlock()

	if r == nil {
		return RotationOutcome{
			MaterialID: materialID,
			Supported:  false,
			Detail: "no automated in-place rotation for this material; rotate it out-of-band: " +
				"install the new key, stage a dual-key overlap window so in-flight artifacts still verify, then retire the old key",
		}, ErrRotationUnsupported
	}

	now := s.now()
	if !force && st != nil && !st.CanBegin(now) {
		return RotationOutcome{MaterialID: materialID, Supported: true, Detail: "rotation refused: a prior rotation is still within its overlap window"},
			ErrRotationInFlight
	}

	out, err := r.Rotate(ctx)
	out.MaterialID = materialID
	out.Supported = true
	if err != nil {
		s.metrics.recordRotation(false)
		s.logger.Error("keyrotation: rotation failed", "material", materialID, "error", err)
		return out, err
	}
	out.Performed = true
	s.metrics.recordRotation(true)

	if out.NewPrimaryKeyID != "" {
		s.mu.Lock()
		if s.overlaps[materialID] == nil {
			s.overlaps[materialID] = NewOverlapState("", s.cfg.OverlapWindow)
		}
		pruned, berr := s.overlaps[materialID].Begin(out.NewPrimaryKeyID, now)
		s.mu.Unlock()
		if berr != nil && !errors.Is(berr, ErrSameKey) {
			s.logger.Warn("keyrotation: overlap bookkeeping", "material", materialID, "error", berr)
		}
		if len(pruned) > 0 {
			s.logger.Info("keyrotation: retired previous keys past overlap window",
				"material", materialID, "retired", pruned)
		}
	}

	if s.notifier != nil {
		s.notifier.Emit(ctx, notify.KeyRotatedEvent(materialID, out.NewPrimaryKeyID, out.Rewrapped))
	}
	s.logger.Info("keyrotation: rotation complete",
		"material", materialID, "newPrimaryKeyId", out.NewPrimaryKeyID,
		"rewrapped", out.Rewrapped, "scanned", out.Scanned)
	return out, nil
}

// OverlapStatus returns a copy of the overlap state tracked for a material, and
// whether one exists. It lets the admin surface show where a staged rotation sits.
func (s *Service) OverlapStatus(materialID string) (OverlapState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.overlaps[materialID]
	if st == nil {
		return OverlapState{}, false
	}
	cp := *st
	cp.PreviousKeys = append([]PreviousKey(nil), st.PreviousKeys...)
	return cp, true
}

// ExpirySeconds returns, for each material that has an effective expiry, the live
// seconds remaining until that expiry at call time. It backs the
// pullthrough_key_expiry_seconds gauge and is recomputed from the last scan's
// expiry timestamps against the current clock, so the gauge decreases smoothly
// between scans.
func (s *Service) ExpirySeconds() map[string]float64 {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]float64, len(s.last))
	for _, ms := range s.last {
		if !ms.HasExpiry {
			continue
		}
		out[ms.ID] = ms.EffectiveExpiry.Sub(now).Seconds()
	}
	return out
}

// Start launches the periodic scan loop. It is a no-op when disabled. An initial
// scan runs immediately so the gauge and SOC view are populated at startup.
func (s *Service) Start(ctx context.Context) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	s.scan(loopCtx, s.isLeader())
	go s.loop(loopCtx, s.doneCh)
}

func (s *Service) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(s.cfg.ScanInterval)
	defer ticker.Stop()
	s.logger.Info("keyrotation: expiry scanner started",
		"interval", s.cfg.ScanInterval, "warn", s.cfg.WarnThreshold, "critical", s.cfg.CriticalThreshold)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scan(ctx, s.isLeader())
		}
	}
}

// Stop halts the scan loop and waits for it to exit.
func (s *Service) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.cancel
	done := s.doneCh
	s.cancel = nil
	s.doneCh = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Close implements the io.Closer-style lifecycle used by the wiring layer.
func (s *Service) Close() error {
	s.Stop()
	return nil
}

func sortStatuses(st []MaterialStatus) {
	sort.SliceStable(st, func(i, j int) bool {
		// Materials with an expiry sort first (soonest first); those without go
		// last, ordered by id for determinism.
		a, b := st[i], st[j]
		if a.HasExpiry != b.HasExpiry {
			return a.HasExpiry
		}
		if a.HasExpiry && a.SecondsRemaining != b.SecondsRemaining {
			return a.SecondsRemaining < b.SecondsRemaining
		}
		return a.ID < b.ID
	})
}

func tally(st []MaterialStatus) StatusCounts {
	c := StatusCounts{Total: len(st)}
	for _, ms := range st {
		switch ms.Status {
		case StatusOK:
			c.OK++
		case StatusWarning:
			c.Warning++
		case StatusCritical:
			c.Critical++
		case StatusExpired:
			c.Expired++
		case StatusUnknown:
			c.Unknown++
		}
	}
	return c
}

// mergeKeyIDs unions two key-id slices, preserving order and dropping empties
// and duplicates.
func mergeKeyIDs(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
