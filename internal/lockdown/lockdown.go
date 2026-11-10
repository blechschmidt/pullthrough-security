// Package lockdown implements the emergency lockdown / global kill-switch
// incident-response control (Task 74).
//
// During an active supply-chain incident an operator needs to tighten the
// proxy's posture *instantly* — without redeploying or hand-editing dozens of
// individual gate configs. This subsystem is that single, org-wide lever. It
// holds one durable, coordinated (Task 56 coord-guarded) piece of state — the
// active incident mode — that the pull path consults as its very FIRST check,
// ahead of every other admission gate.
//
// Three modes:
//
//   - freeze  Serve only already-cached, last-known-good artifacts and block all
//     new upstream fetches. Combined with an organization snapshot freeze
//     (Task 70) this pins the whole org to known-good digests while the
//     incident is investigated. Cache hits still serve; a cache miss (which
//     would require an upstream fetch) is refused.
//   - strict  Flip every observe-mode gate to enforce and harden the risk /
//     maturity / firewall thresholds. Surfaced as an admission signal the
//     aggregating policy and risk engines consume, so the hardened posture
//     applies without touching each gate's own config.
//   - block   Immediately deny a specific (eco,name) or (eco,name,version)
//     coordinate everywhere — e.g. a freshly-disclosed malicious package, ahead
//     of the malfeed feed's next refresh.
//
// Every transition carries a mandatory operator-supplied reason and incident ID,
// is recorded to the Merkle audit log (Task 31), raises an EventLockdown
// notification (Task 21), and carries a TTL with automatic expiry so a forgotten
// lockdown self-heals. The break-glass workflow (Task 50) still composes on top,
// so an individual exception can be granted under dual control while the
// lockdown stands.
package lockdown

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Mode is the active incident-response posture.
type Mode string

const (
	// ModeOff is the normal posture: no lockdown is engaged.
	ModeOff Mode = ""
	// ModeFreeze serves only already-cached artifacts and blocks new upstream fetches.
	ModeFreeze Mode = "freeze"
	// ModeStrict hardens every gate to enforce and lowers risk/maturity/firewall thresholds.
	ModeStrict Mode = "strict"
	// ModeBlock denies a targeted set of coordinates everywhere.
	ModeBlock Mode = "block"
)

// Decision codes returned by the pull-path consult.
const (
	// CodeBlocked is a targeted-block coordinate denial.
	CodeBlocked = "lockdown-block"
	// CodeFreeze is an upstream fetch refused under a freeze.
	CodeFreeze = "lockdown-freeze"
)

// ParseMode normalizes a mode string. It returns (ModeOff, error) for an
// unrecognized value so callers can reject bad operator input.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeFreeze:
		return ModeFreeze, nil
	case ModeStrict:
		return ModeStrict, nil
	case ModeBlock:
		return ModeBlock, nil
	default:
		return ModeOff, fmt.Errorf("lockdown: unknown mode %q (want freeze|strict|block)", s)
	}
}

// Coordinate is a targeted-block target. An empty Version blocks the entire
// package (every version) for the (Ecosystem, Name) pair.
type Coordinate struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

func (c Coordinate) normalized() Coordinate {
	return Coordinate{
		Ecosystem: strings.ToLower(strings.TrimSpace(c.Ecosystem)),
		Name:      strings.TrimSpace(c.Name),
		Version:   strings.TrimSpace(c.Version),
	}
}

// String renders a human-readable coordinate.
func (c Coordinate) String() string {
	out := c.Name
	if c.Version != "" {
		out += "@" + c.Version
	}
	if c.Ecosystem != "" {
		out = c.Ecosystem + ":" + out
	}
	return out
}

// State is the durable lockdown state, persisted to the store so it survives a
// restart and (on a shared store) is the same record every replica reads.
type State struct {
	Mode         Mode         `json:"mode"`
	Reason       string       `json:"reason"`
	IncidentID   string       `json:"incidentId"`
	Operator     string       `json:"operator,omitempty"`
	EngagedAt    time.Time    `json:"engagedAt"`
	ExpiresAt    time.Time    `json:"expiresAt,omitempty"`
	Targets      []Coordinate `json:"targets,omitempty"`
	FencingToken uint64       `json:"fencingToken,omitempty"`
}

func (s State) active() bool { return s.Mode != ModeOff }

// Status is the read-model projection returned by the admin/CLI/UI surfaces. It
// reflects the *effective* state (an expired engagement reads as inactive).
type Status struct {
	Active           bool         `json:"active"`
	Mode             Mode         `json:"mode"`
	Reason           string       `json:"reason,omitempty"`
	IncidentID       string       `json:"incidentId,omitempty"`
	Operator         string       `json:"operator,omitempty"`
	EngagedAt        time.Time    `json:"engagedAt,omitempty"`
	ExpiresAt        time.Time    `json:"expiresAt,omitempty"`
	SecondsRemaining float64      `json:"secondsRemaining"`
	Targets          []Coordinate `json:"targets,omitempty"`
	FencingToken     uint64       `json:"fencingToken,omitempty"`
}

// Decision is what the pull-path FIRST-check consult returns.
type Decision struct {
	Blocked    bool
	Code       string
	Reason     string
	Mode       Mode
	IncidentID string
	// Coordinate is the matched block target (for an actionable refusal body).
	Coordinate Coordinate
}

// Coordinator is the minimal slice of the distributed-coordination Service (Task
// 56) the lockdown subsystem needs. A *coord.Guard satisfies it. It is consulted
// for two things: the fencing token recorded with each transition (so incident-
// mode changes are monotonically ordered across an HA cluster) and the leader
// gate for the auto-expiry persistence sweep (so only one replica writes the
// auto-clear to the shared store). When nil the subsystem behaves as a single
// node.
type Coordinator interface {
	IsLeader() bool
	FencingToken() uint64
}

// Config configures the subsystem.
type Config struct {
	// Enabled turns the subsystem (the FIRST-check gate, admin surface, metrics) on.
	Enabled bool
	// StorePath is the JSON file the active state is persisted to so a lockdown
	// survives a restart. Empty keeps state in memory only (tests / ephemeral).
	StorePath string
	// DefaultTTL is applied when an engagement omits a TTL. A lockdown ALWAYS has a
	// TTL so a forgotten incident self-heals; 0 falls back to defaultTTL.
	DefaultTTL time.Duration
	// MaxTTL caps an operator-supplied TTL. 0 means no cap.
	MaxTTL time.Duration
}

const defaultTTL = time.Hour

// Service is the emergency-lockdown subsystem.
type Service struct {
	cfg    Config
	logger *slog.Logger
	store  store
	now    func() time.Time
	coord  Coordinator

	audit    *audit.Logger
	notifier notify.Emitter

	mu             sync.RWMutex
	state          State
	expiredHandled bool // guards a single expiry audit/notify emission

	// counters (cumulative; read by the metrics bridge).
	checks       atomic.Uint64
	blocks       atomic.Uint64
	freezeBlocks atomic.Uint64
	engagements  atomic.Uint64
	clears       atomic.Uint64
	expirations  atomic.Uint64
}

// Option customizes a Service at construction.
type Option func(*Service)

// WithAudit attaches the Merkle audit logger so every lockdown transition is
// recorded to the tamper-evident chain. A nil logger is a no-op.
func WithAudit(l *audit.Logger) Option { return func(s *Service) { s.audit = l } }

// WithNotifier attaches the notification emitter so transitions raise
// EventLockdown alerts. A nil emitter is a no-op.
func WithNotifier(n notify.Emitter) Option { return func(s *Service) { s.notifier = n } }

// WithCoordinator attaches the distributed-coordination guard (Task 56). A nil
// coordinator yields single-node behavior.
func WithCoordinator(c Coordinator) Option {
	return func(s *Service) {
		if c != nil {
			s.coord = c
		}
	}
}

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New constructs the subsystem and loads any persisted state. It returns nil,nil
// when disabled so the wiring can leave every consumer's pointer nil.
func New(cfg Config, logger *slog.Logger, opts ...Option) (*Service, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		cfg:    cfg,
		logger: logger,
		store:  newStore(cfg.StorePath),
		now:    time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	loaded, ok, err := s.store.load()
	if err != nil {
		return nil, fmt.Errorf("lockdown: loading persisted state: %w", err)
	}
	if ok {
		s.state = loaded
		// A persisted lockdown that already expired during downtime starts cleared.
		if s.isExpired(loaded) {
			s.state = State{}
		}
	}
	return s, nil
}

// Enabled reports whether the subsystem is active (a non-nil Service). It
// satisfies the admin inspector contract.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Service) isExpired(st State) bool {
	return st.active() && !st.ExpiresAt.IsZero() && !s.clock().Before(st.ExpiresAt)
}

// EngageInput parameterizes engaging a lockdown.
type EngageInput struct {
	Mode       Mode
	Reason     string
	IncidentID string
	Operator   string
	TTL        time.Duration
	// Targets are required for ModeBlock and ignored otherwise.
	Targets []Coordinate
}

// Engage activates (or replaces) the lockdown. The reason and incident ID are
// mandatory; ModeBlock requires at least one named target. The new state is
// persisted, audited, and notified. It is idempotent in effect: re-engaging the
// same mode just refreshes the metadata and TTL.
func (s *Service) Engage(ctx context.Context, in EngageInput) (Status, error) {
	if !s.Enabled() {
		return Status{}, errors.New("lockdown: subsystem is disabled")
	}
	mode, err := ParseMode(string(in.Mode))
	if err != nil {
		return Status{}, err
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return Status{}, errors.New("lockdown: a reason is required")
	}
	incident := strings.TrimSpace(in.IncidentID)
	if incident == "" {
		return Status{}, errors.New("lockdown: an incident ID is required")
	}

	var targets []Coordinate
	if mode == ModeBlock {
		targets = normalizeTargets(in.Targets)
		if len(targets) == 0 {
			return Status{}, errors.New("lockdown: block mode requires at least one target coordinate with a name")
		}
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.cfg.DefaultTTL
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}
	if s.cfg.MaxTTL > 0 && ttl > s.cfg.MaxTTL {
		ttl = s.cfg.MaxTTL
	}

	now := s.clock().UTC()
	st := State{
		Mode:       mode,
		Reason:     reason,
		IncidentID: incident,
		Operator:   strings.TrimSpace(in.Operator),
		EngagedAt:  now,
		ExpiresAt:  now.Add(ttl),
		Targets:    targets,
	}
	if s.coord != nil {
		st.FencingToken = s.coord.FencingToken()
	}

	s.mu.Lock()
	prev := s.state
	s.state = st
	s.expiredHandled = false
	if err := s.store.save(st); err != nil {
		s.state = prev // roll back the in-memory change so it matches the store
		s.mu.Unlock()
		return Status{}, fmt.Errorf("lockdown: persisting state: %w", err)
	}
	s.mu.Unlock()

	s.engagements.Add(1)
	s.logger.Warn("emergency lockdown engaged",
		"mode", mode, "incident", incident, "operator", st.Operator,
		"reason", reason, "expiresAt", st.ExpiresAt, "targets", len(targets),
		"fencingToken", st.FencingToken)
	s.recordAudit(ctx, "engaged", st, nil)
	s.emit(ctx, lockdownEvent("engaged", st, prev.Mode))
	return s.statusOf(st), nil
}

// ClearInput parameterizes clearing a lockdown.
type ClearInput struct {
	Reason   string
	Operator string
}

// Clear lifts the active lockdown. A reason is required (the all-clear is itself
// an auditable incident action). It is a no-op (no error) when nothing is
// engaged.
func (s *Service) Clear(ctx context.Context, in ClearInput) (Status, error) {
	if !s.Enabled() {
		return Status{}, errors.New("lockdown: subsystem is disabled")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return Status{}, errors.New("lockdown: a reason is required to clear a lockdown")
	}
	s.mu.Lock()
	prev := s.state
	if !prev.active() {
		s.mu.Unlock()
		return Status{}, nil
	}
	s.state = State{}
	s.expiredHandled = false
	if err := s.store.save(State{}); err != nil {
		s.state = prev
		s.mu.Unlock()
		return Status{}, fmt.Errorf("lockdown: persisting cleared state: %w", err)
	}
	s.mu.Unlock()

	s.clears.Add(1)
	op := strings.TrimSpace(in.Operator)
	s.logger.Warn("emergency lockdown cleared",
		"previousMode", prev.Mode, "incident", prev.IncidentID, "operator", op, "reason", reason)
	cleared := prev
	cleared.Reason = reason
	cleared.Operator = op
	s.recordAudit(ctx, "cleared", cleared, map[string]any{"previousMode": string(prev.Mode)})
	s.emit(ctx, lockdownEvent("cleared", cleared, prev.Mode))
	return Status{Active: false, SecondsRemaining: -1}, nil
}

// current returns the effective state, applying auto-expiry. When an active
// engagement has passed its TTL it is treated as cleared; the leader (or a
// single node) additionally persists the auto-clear and emits the expiry event
// exactly once. Followers compute the same effective state without writing.
func (s *Service) current() State {
	s.mu.RLock()
	st := s.state
	expiredHandled := s.expiredHandled
	s.mu.RUnlock()
	if !s.isExpired(st) {
		return st
	}
	// Expired: surface as inactive everywhere. Persist + emit once, leader-only.
	if (s.coord == nil || s.coord.IsLeader()) && !expiredHandled {
		s.mu.Lock()
		// Re-check under the write lock (another goroutine may have handled it).
		if s.isExpired(s.state) && !s.expiredHandled {
			expired := s.state
			s.state = State{}
			s.expiredHandled = true
			if err := s.store.save(State{}); err != nil {
				s.logger.Error("lockdown: persisting auto-expiry failed", "error", err)
			}
			s.mu.Unlock()
			s.expirations.Add(1)
			s.logger.Warn("emergency lockdown auto-expired",
				"mode", expired.Mode, "incident", expired.IncidentID, "expiresAt", expired.ExpiresAt)
			ctx := context.Background()
			s.recordAudit(ctx, "expired", expired, map[string]any{"expiresAt": expired.ExpiresAt.Format(time.RFC3339)})
			s.emit(ctx, lockdownEvent("expired", expired, expired.Mode))
			return State{}
		}
		s.mu.Unlock()
	}
	return State{}
}

// Status returns the effective lockdown status.
func (s *Service) Status() Status {
	if !s.Enabled() {
		return Status{Active: false, SecondsRemaining: -1}
	}
	return s.statusOf(s.current())
}

func (s *Service) statusOf(st State) Status {
	if !st.active() {
		return Status{Active: false, SecondsRemaining: -1}
	}
	remaining := -1.0
	if !st.ExpiresAt.IsZero() {
		remaining = st.ExpiresAt.Sub(s.clock()).Seconds()
		if remaining < 0 {
			remaining = 0
		}
	}
	return Status{
		Active:           true,
		Mode:             st.Mode,
		Reason:           st.Reason,
		IncidentID:       st.IncidentID,
		Operator:         st.Operator,
		EngagedAt:        st.EngagedAt,
		ExpiresAt:        st.ExpiresAt,
		SecondsRemaining: remaining,
		Targets:          st.Targets,
		FencingToken:     st.FencingToken,
	}
}

// Check is the pull-path FIRST-check consult on a resolved coordinate. It blocks
// only for a targeted-block match (ModeBlock); freeze is enforced at the
// upstream-fetch boundary (see FreezeActive) and strict via the admission
// signal, neither of which refuses the coordinate outright here. Safe on nil.
func (s *Service) Check(c Coordinate) Decision {
	if !s.Enabled() {
		return Decision{}
	}
	st := s.current()
	if !st.active() {
		return Decision{}
	}
	s.checks.Add(1)
	if st.Mode != ModeBlock {
		return Decision{Mode: st.Mode, IncidentID: st.IncidentID}
	}
	target := c.normalized()
	if target.Name == "" {
		return Decision{Mode: st.Mode, IncidentID: st.IncidentID}
	}
	for _, t := range st.Targets {
		if !strings.EqualFold(t.Name, target.Name) {
			continue
		}
		if t.Ecosystem != "" && target.Ecosystem != "" && t.Ecosystem != target.Ecosystem {
			continue
		}
		// An empty target version matches the whole package; otherwise the version
		// must match exactly.
		if t.Version != "" && !strings.EqualFold(t.Version, target.Version) {
			continue
		}
		s.blocks.Add(1)
		reason := fmt.Sprintf("coordinate %s is denied by an active emergency lockdown (incident %s)", t.String(), st.IncidentID)
		return Decision{
			Blocked:    true,
			Code:       CodeBlocked,
			Reason:     reason,
			Mode:       st.Mode,
			IncidentID: st.IncidentID,
			Coordinate: t,
		}
	}
	return Decision{Mode: st.Mode, IncidentID: st.IncidentID}
}

// FreezeActive reports whether a freeze lockdown is in effect — the proxy must
// then serve only already-cached artifacts and refuse any upstream fetch. Safe
// on nil.
func (s *Service) FreezeActive() bool {
	if !s.Enabled() {
		return false
	}
	return s.current().Mode == ModeFreeze
}

// RecordFreezeFetchBlock counts an upstream fetch refused because a freeze
// lockdown is active. The proxy calls it from the fetch boundary.
func (s *Service) RecordFreezeFetchBlock() {
	if s.Enabled() {
		s.freezeBlocks.Add(1)
	}
}

// StrictActive reports whether a strict lockdown is in effect — every observe-
// mode gate should enforce and the risk/maturity/firewall thresholds should use
// their hardened presets. Surfaced as an admission signal. Safe on nil.
func (s *Service) StrictActive() bool {
	if !s.Enabled() {
		return false
	}
	return s.current().Mode == ModeStrict
}

// Mode returns the effective active mode (ModeOff when none). Safe on nil.
func (s *Service) Mode() Mode {
	if !s.Enabled() {
		return ModeOff
	}
	return s.current().Mode
}

// IncidentID returns the active incident identifier (empty when none). Safe on nil.
func (s *Service) IncidentID() string {
	if !s.Enabled() {
		return ""
	}
	return s.current().IncidentID
}

func normalizeTargets(in []Coordinate) []Coordinate {
	out := make([]Coordinate, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		n := c.normalized()
		if n.Name == "" {
			continue
		}
		key := n.Ecosystem + "\x00" + strings.ToLower(n.Name) + "\x00" + n.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}
	return out
}

// recordAudit appends a lockdown transition to the Merkle audit log.
func (s *Service) recordAudit(ctx context.Context, action string, st State, extra map[string]any) {
	if s == nil || s.audit == nil {
		return
	}
	detail := map[string]any{
		"action":     action,
		"mode":       string(st.Mode),
		"incidentId": st.IncidentID,
		"reason":     st.Reason,
	}
	if !st.ExpiresAt.IsZero() {
		detail["expiresAt"] = st.ExpiresAt.Format(time.RFC3339)
	}
	if st.FencingToken != 0 {
		detail["fencingToken"] = st.FencingToken
	}
	if len(st.Targets) > 0 {
		coords := make([]string, 0, len(st.Targets))
		for _, t := range st.Targets {
			coords = append(coords, t.String())
		}
		detail["targets"] = strings.Join(coords, ",")
	}
	for k, v := range extra {
		detail[k] = v
	}
	ev := audit.Event{
		Type:     audit.EventAdmin,
		Subject:  st.Operator,
		Decision: audit.DecisionAllow,
		Reason:   "lockdown:" + action,
		Detail:   detail,
	}
	if err := s.audit.Log(ctx, ev); err != nil {
		s.logger.Warn("lockdown: recording audit event failed", "action", action, "error", err)
	}
}

func (s *Service) emit(ctx context.Context, ev notify.Event) {
	if s == nil || s.notifier == nil {
		return
	}
	s.notifier.Emit(ctx, ev)
}
