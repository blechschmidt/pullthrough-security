// Package approvals implements a stateful, human-in-the-loop quarantine-review
// and break-glass approval workflow (Task 50).
//
// When an admission gate blocks or quarantines an artifact — a vulnerability
// re-scan quarantine, a known-malicious (malfeed) match, a signature-verification
// failure, a hard policy block, or a CVE-drift quarantine — the pull path
// consults this subsystem before returning the block. An operator can review the
// pending decision and either:
//
//   - grant a time-boxed, tenant+coordinate+gate-scoped exception ("break-glass")
//     that lets the artifact be served until the grant's TTL expires, at which
//     point it auto-revokes and the artifact is re-quarantined; or
//   - confirm the block (deny), so the artifact stays refused.
//
// A grant may require N distinct approver identities (dual control). Every state
// change is written to the tamper-evident audit log (who/why/duration, linked
// into the Merkle chain) and surfaced as a notification event. The request store
// is durable: it is persisted to disk so pending reviews and active grants
// survive a restart.
//
// The Service is safe for concurrent use. A nil *Service is NOT valid; callers
// gate on Enabled instead, and the gateway holds a possibly-nil *Service and
// checks for nil at the call site.
package approvals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Status is the lifecycle state of an approval request.
type Status string

const (
	// StatusPending is a request awaiting an operator decision (it may already
	// carry some — but not yet enough — dual-control approvals).
	StatusPending Status = "pending"
	// StatusApproved is a granted, currently-active break-glass exception.
	StatusApproved Status = "approved"
	// StatusDenied is a request an operator confirmed the block on; the artifact
	// stays refused and no fresh review is auto-opened.
	StatusDenied Status = "denied"
	// StatusExpired is a grant whose TTL elapsed; the artifact is re-quarantined.
	StatusExpired Status = "expired"
)

// Errors returned by the decision methods.
var (
	// ErrNotFound is returned when no request matches the given id.
	ErrNotFound = errors.New("approvals: request not found")
	// ErrNotPending is returned when a decision targets a request that is not
	// awaiting one (already granted, denied, or expired).
	ErrNotPending = errors.New("approvals: request is not pending")
	// ErrDuplicateApprover is returned when an approver tries to vote twice on the
	// same request (dual control requires DISTINCT identities).
	ErrDuplicateApprover = errors.New("approvals: approver has already voted on this request")
	// ErrNoApprover is returned when an approve/deny call omits the approver
	// identity.
	ErrNoApprover = errors.New("approvals: an approver identity is required")
	// ErrNoJustification is returned when a decision omits the required
	// justification.
	ErrNoJustification = errors.New("approvals: a justification is required")
)

// Approver records one identity's vote toward a dual-control grant.
type Approver struct {
	Subject string    `json:"subject"`
	At      time.Time `json:"at"`
}

// Request is one durable quarantine-review record, keyed by
// (tenant, ecosystem, coordinate, gate, reason).
type Request struct {
	ID string `json:"id"`

	// Scope of the block under review.
	Tenant     string `json:"tenant"`
	Ecosystem  string `json:"ecosystem"`
	Coordinate string `json:"coordinate"`
	Gate       string `json:"gate"`
	Reason     string `json:"reason"`
	Backend    string `json:"backend,omitempty"`

	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Requester is the identity whose pull first triggered the review.
	Requester string `json:"requester,omitempty"`
	// Hits counts how many blocked pulls this request has absorbed while pending
	// (a backlog signal for operators).
	Hits int `json:"hits"`

	// Dual-control voting and the resulting grant.
	Approvers     []Approver `json:"approvers,omitempty"`
	Justification string     `json:"justification,omitempty"`
	GrantedAt     time.Time  `json:"grantedAt,omitempty"`
	ExpiresAt     time.Time  `json:"expiresAt,omitempty"`

	// Denial bookkeeping.
	DecidedBy string    `json:"decidedBy,omitempty"`
	DecidedAt time.Time `json:"decidedAt,omitempty"`

	// ServeCount counts break-glass serves this grant has authorized.
	ServeCount int `json:"serveCount"`
}

// active reports whether the request is an approved grant that is still within
// its TTL as of now.
func (r *Request) active(now time.Time) bool {
	return r.Status == StatusApproved && now.Before(r.ExpiresAt)
}

// key is the canonical scope key for a request.
func (r *Request) key() string {
	return scopeKey(r.Tenant, r.Ecosystem, r.Coordinate, r.Gate, r.Reason)
}

// Scope identifies the block a pull-path gate is about to return, so the Service
// can find a matching grant or open a review. It is the input to Consult.
type Scope struct {
	Tenant     string
	Ecosystem  string
	Coordinate string
	Gate       string
	Reason     string
	Backend    string
	Requester  string
}

// Disposition is the result of consulting the workflow for a blocked pull.
type Disposition struct {
	// Allow is true when an active break-glass grant covers the block, so the
	// gate should serve the artifact instead of refusing it.
	Allow bool
	// RequestID is the id of the matched grant (when Allow) or of the pending
	// review the consult opened/updated (when blocked).
	RequestID string
	// ExpiresAt is the active grant's expiry (zero when blocked).
	ExpiresAt time.Time
}

// ApproveInput carries one approver's vote toward a grant.
type ApproveInput struct {
	// Approver is the deciding operator's identity (required).
	Approver string
	// Justification explains why the exception is warranted (required).
	Justification string
	// Duration overrides the configured grant TTL for this exception. Zero uses
	// the configured default.
	Duration time.Duration
}

// Config configures the approval workflow.
type Config struct {
	// Enabled turns the workflow on. When false, Consult always blocks (no
	// pending requests are recorded) and the admin surface reports disabled.
	Enabled bool
	// RequiredApprovers is the number of DISTINCT approver identities a grant
	// needs (dual control). Values < 1 are treated as 1 (single approver).
	RequiredApprovers int
	// GrantTTL is how long a break-glass grant stays active before it auto-revokes
	// and the artifact is re-quarantined. Zero uses DefaultGrantTTL.
	GrantTTL time.Duration
	// RequestTTL is how long a pending review lives before it auto-expires
	// (unreviewed). Zero uses DefaultRequestTTL.
	RequestTTL time.Duration
	// MaxRequests bounds the retained request set; the oldest terminal (denied/
	// expired) records are trimmed first. Zero uses DefaultMaxRequests.
	MaxRequests int
	// StorePath is an optional JSON file the request set is persisted to so
	// pending reviews and active grants survive a restart. Empty keeps the store
	// in memory only.
	StorePath string
}

// Defaults applied when a field is left zero.
const (
	DefaultGrantTTL    = time.Hour
	DefaultRequestTTL  = 72 * time.Hour
	DefaultMaxRequests = 1000
)

func (c Config) requiredApprovers() int {
	if c.RequiredApprovers < 1 {
		return 1
	}
	return c.RequiredApprovers
}

func (c Config) grantTTL() time.Duration {
	if c.GrantTTL <= 0 {
		return DefaultGrantTTL
	}
	return c.GrantTTL
}

func (c Config) requestTTL() time.Duration {
	if c.RequestTTL <= 0 {
		return DefaultRequestTTL
	}
	return c.RequestTTL
}

func (c Config) maxRequests() int {
	if c.MaxRequests <= 0 {
		return DefaultMaxRequests
	}
	return c.MaxRequests
}

// Snapshot is a point-in-time view of the workflow's state for the admin and
// metrics surfaces.
type Snapshot struct {
	Enabled                  bool    `json:"enabled"`
	RequiredApprovers        int     `json:"requiredApprovers"`
	GrantTTLSeconds          float64 `json:"grantTtlSeconds"`
	RequestTTLSeconds        float64 `json:"requestTtlSeconds"`
	Open                     int     `json:"open"`          // pending reviews
	ActiveGrants             int     `json:"activeGrants"`  // approved & unexpired
	RequestsTotal            int64   `json:"requestsTotal"` // reviews ever opened
	ApprovedTotal            int64   `json:"approvedTotal"`
	DeniedTotal              int64   `json:"deniedTotal"`
	ExpiredTotal             int64   `json:"expiredTotal"`
	BreakGlassServesTotal    int64   `json:"breakGlassServesTotal"`
	TimeToApprovalSumSeconds float64 `json:"timeToApprovalSumSeconds"`
	TimeToApprovalCount      int64   `json:"timeToApprovalCount"`
	AvgTimeToApprovalSeconds float64 `json:"avgTimeToApprovalSeconds"`
}

// Service is the durable, concurrent quarantine-review/break-glass workflow.
type Service struct {
	cfg    Config
	logger *slog.Logger
	audit  *audit.Logger
	notify notify.Emitter
	now    func() time.Time

	mu    sync.Mutex
	byID  map[string]*Request
	byKey map[string]*Request // canonical scope key -> the governing (pending|approved|denied) request
	order []string            // ids in creation order, for stable listing and trimming
	seq   uint64              // monotonic id counter (deterministic ids)

	// cumulative counters (read under mu).
	requestsTotal int64
	approvedTotal int64
	deniedTotal   int64
	expiredTotal  int64
	servesTotal   int64
	ttSum         float64
	ttCount       int64
}

// Option configures a Service at construction.
type Option func(*Service)

// WithAudit sets the tamper-evident audit logger every state change is recorded
// to (linked into the Merkle chain). A nil logger disables audit recording.
func WithAudit(l *audit.Logger) Option { return func(s *Service) { s.audit = l } }

// WithNotifier sets the notification emitter for grant/expiry/deny/request
// events. A nil emitter disables notifications.
func WithNotifier(n notify.Emitter) Option { return func(s *Service) { s.notify = n } }

// WithClock overrides the time source (for deterministic tests).
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// New constructs a Service. When cfg.StorePath is set and the file exists, the
// request set and counters are restored from it.
func New(cfg Config, logger *slog.Logger, opts ...Option) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		cfg:    cfg,
		logger: logger,
		now:    time.Now,
		byID:   make(map[string]*Request),
		byKey:  make(map[string]*Request),
	}
	for _, o := range opts {
		o(s)
	}
	if cfg.StorePath != "" {
		if err := s.load(); err != nil {
			return nil, fmt.Errorf("approvals: loading store: %w", err)
		}
	}
	return s, nil
}

// Enabled reports whether the workflow is active.
func (s *Service) Enabled() bool { return s != nil && s.cfg.Enabled }

// Consult is the pull-path entry point. It is called by an admission gate that is
// about to block an artifact. It returns Allow=true when an active break-glass
// grant covers the block (the gate then serves); otherwise it records (or
// updates) a pending review and returns Allow=false (the gate then blocks).
//
// A grant that has expired since it was issued is revoked here (re-quarantine)
// and a fresh pending review is opened, so the next pull blocks again.
func (s *Service) Consult(ctx context.Context, sc Scope) Disposition {
	if !s.Enabled() {
		return Disposition{Allow: false}
	}
	now := s.now()
	k := scopeKey(sc.Tenant, sc.Ecosystem, sc.Coordinate, sc.Gate, sc.Reason)

	var expiredSnap *Request

	s.mu.Lock()
	if r, ok := s.byKey[k]; ok {
		switch {
		case r.active(now):
			r.ServeCount++
			r.UpdatedAt = now
			s.servesTotal++
			s.persistLocked()
			disp := Disposition{Allow: true, RequestID: r.ID, ExpiresAt: r.ExpiresAt}
			s.mu.Unlock()
			s.logger.Warn("approvals: break-glass grant served blocked artifact",
				"requestId", r.ID, "gate", sc.Gate, "ecosystem", sc.Ecosystem,
				"coordinate", sc.Coordinate, "expiresAt", r.ExpiresAt)
			return disp
		case r.Status == StatusApproved:
			// Grant exists but its TTL elapsed: revoke and re-quarantine, then fall
			// through to open a fresh review. Notify/audit the expiry after unlock.
			s.expireLocked(r, now)
			expiredSnap = cloneRequest(r)
		case r.Status == StatusDenied:
			// Operator confirmed the block; keep refusing without re-opening review.
			r.Hits++
			r.UpdatedAt = now
			s.persistLocked()
			s.mu.Unlock()
			return Disposition{Allow: false, RequestID: r.ID}
		case r.Status == StatusPending:
			r.Hits++
			r.UpdatedAt = now
			s.persistLocked()
			s.mu.Unlock()
			return Disposition{Allow: false, RequestID: r.ID}
		}
	}

	// No governing request (or the prior grant just expired): open a fresh review.
	r := s.openLocked(sc, now)
	s.persistLocked()
	s.mu.Unlock()

	if expiredSnap != nil {
		s.logger.Warn("approvals: break-glass grant expired on access (re-quarantined)",
			"requestId", expiredSnap.ID, "gate", expiredSnap.Gate, "coordinate", expiredSnap.Coordinate)
		s.auditState(ctx, expiredSnap, "expired", "", "", 0)
		s.emit(ctx, "expired", expiredSnap, "")
	}
	s.logger.Info("approvals: opened pending quarantine review",
		"requestId", r.ID, "gate", sc.Gate, "ecosystem", sc.Ecosystem, "coordinate", sc.Coordinate)
	s.auditState(ctx, r, "requested", r.Requester, "", 0)
	s.emit(ctx, "requested", r, r.Requester)
	return Disposition{Allow: false, RequestID: r.ID}
}

// openLocked creates and registers a new pending review for the scope. Caller
// holds the mutex.
func (s *Service) openLocked(sc Scope, now time.Time) *Request {
	s.seq++
	r := &Request{
		ID:         s.newID(sc, now),
		Tenant:     sc.Tenant,
		Ecosystem:  sc.Ecosystem,
		Coordinate: sc.Coordinate,
		Gate:       sc.Gate,
		Reason:     sc.Reason,
		Backend:    sc.Backend,
		Status:     StatusPending,
		CreatedAt:  now,
		UpdatedAt:  now,
		Requester:  sc.Requester,
		Hits:       1,
	}
	s.byID[r.ID] = r
	s.byKey[r.key()] = r
	s.order = append(s.order, r.ID)
	s.requestsTotal++
	s.trimLocked()
	return r
}

// Approve records one approver's vote toward a grant. When the request reaches
// the configured number of distinct approvers it transitions to an active grant
// (StatusApproved) with a TTL. Returns the updated request.
func (s *Service) Approve(ctx context.Context, id string, in ApproveInput) (Request, error) {
	approver := strings.TrimSpace(in.Approver)
	if approver == "" {
		return Request{}, ErrNoApprover
	}
	if strings.TrimSpace(in.Justification) == "" {
		return Request{}, ErrNoJustification
	}
	now := s.now()

	s.mu.Lock()
	r, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return Request{}, ErrNotFound
	}
	if r.Status != StatusPending {
		s.mu.Unlock()
		return Request{}, ErrNotPending
	}
	for _, a := range r.Approvers {
		if strings.EqualFold(a.Subject, approver) {
			s.mu.Unlock()
			return Request{}, ErrDuplicateApprover
		}
	}
	r.Approvers = append(r.Approvers, Approver{Subject: approver, At: now})
	r.Justification = strings.TrimSpace(in.Justification)
	r.UpdatedAt = now

	granted := len(r.Approvers) >= s.cfg.requiredApprovers()
	var (
		dur   time.Duration
		ttSec float64
	)
	if granted {
		dur = in.Duration
		if dur <= 0 {
			dur = s.cfg.grantTTL()
		}
		r.Status = StatusApproved
		r.GrantedAt = now
		r.ExpiresAt = now.Add(dur)
		s.approvedTotal++
		ttSec = now.Sub(r.CreatedAt).Seconds()
		s.ttSum += ttSec
		s.ttCount++
	}
	snap := *r
	s.persistLocked()
	s.mu.Unlock()

	if granted {
		s.logger.Warn("approvals: break-glass grant issued",
			"requestId", snap.ID, "gate", snap.Gate, "coordinate", snap.Coordinate,
			"approver", approver, "approvers", len(snap.Approvers), "expiresAt", snap.ExpiresAt)
		s.auditState(ctx, &snap, "granted", approver, snap.Justification, dur)
		s.emit(ctx, "granted", &snap, approver)
	} else {
		s.logger.Info("approvals: approval vote recorded (more approvers required)",
			"requestId", snap.ID, "approver", approver,
			"have", len(snap.Approvers), "need", s.cfg.requiredApprovers())
		s.auditState(ctx, &snap, "vote", approver, snap.Justification, 0)
	}
	return snap, nil
}

// Deny confirms the block on a pending request: the artifact stays refused and no
// fresh review is auto-opened. Returns the updated request.
func (s *Service) Deny(ctx context.Context, id, approver, justification string) (Request, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return Request{}, ErrNoApprover
	}
	if strings.TrimSpace(justification) == "" {
		return Request{}, ErrNoJustification
	}
	now := s.now()

	s.mu.Lock()
	r, ok := s.byID[id]
	if !ok {
		s.mu.Unlock()
		return Request{}, ErrNotFound
	}
	if r.Status != StatusPending {
		s.mu.Unlock()
		return Request{}, ErrNotPending
	}
	r.Status = StatusDenied
	r.DecidedBy = approver
	r.DecidedAt = now
	r.UpdatedAt = now
	r.Justification = strings.TrimSpace(justification)
	s.deniedTotal++
	snap := *r
	s.persistLocked()
	s.mu.Unlock()

	s.logger.Info("approvals: quarantine review denied (block confirmed)",
		"requestId", snap.ID, "gate", snap.Gate, "coordinate", snap.Coordinate, "approver", approver)
	s.auditState(ctx, &snap, "denied", approver, snap.Justification, 0)
	s.emit(ctx, "denied", &snap, approver)
	return snap, nil
}

// Sweep revokes every grant whose TTL has elapsed (re-quarantine) and expires
// pending reviews older than the request TTL. It is safe to call periodically
// from a background loop and is also exercised directly by tests. It returns the
// number of records that changed state.
func (s *Service) Sweep(ctx context.Context) int {
	if !s.Enabled() {
		return 0
	}
	now := s.now()
	var expired []*Request

	s.mu.Lock()
	reqTTL := s.cfg.requestTTL()
	for _, id := range s.order {
		r := s.byID[id]
		if r == nil {
			continue
		}
		switch r.Status {
		case StatusApproved:
			if !now.Before(r.ExpiresAt) {
				s.expireLocked(r, now)
				expired = append(expired, cloneRequest(r))
			}
		case StatusPending:
			if now.Sub(r.CreatedAt) >= reqTTL {
				r.Status = StatusExpired
				r.UpdatedAt = now
				s.expiredTotal++
				delete(s.byKey, r.key())
				expired = append(expired, cloneRequest(r))
			}
		}
	}
	if len(expired) > 0 {
		s.persistLocked()
	}
	s.mu.Unlock()

	for _, r := range expired {
		s.logger.Warn("approvals: grant/review expired",
			"requestId", r.ID, "gate", r.Gate, "coordinate", r.Coordinate, "status", string(r.Status))
		s.auditState(ctx, r, "expired", "", "", 0)
		s.emit(ctx, "expired", r, "")
	}
	return len(expired)
}

// expireLocked transitions an active grant to expired and drops it from the key
// index so the next pull re-blocks. It is pure state mutation; the caller is
// responsible for the audit/notify side effects (so they run outside the lock and
// are emitted exactly once). Caller holds the mutex.
func (s *Service) expireLocked(r *Request, now time.Time) {
	r.Status = StatusExpired
	r.UpdatedAt = now
	s.expiredTotal++
	delete(s.byKey, r.key())
}

// Get returns a copy of the request with the given id.
func (s *Service) Get(id string) (Request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok {
		return Request{}, false
	}
	return *cloneRequest(r), true
}

// List returns the requests matching status (empty = all), most-recent first,
// capped at limit (<= 0 = no cap). Grants whose TTL has elapsed but that have not
// yet been swept are reported with their stored (approved) status; callers that
// need live status should Sweep first.
func (s *Service) List(status string, limit int) []Request {
	want := Status(strings.ToLower(strings.TrimSpace(status)))
	s.mu.Lock()
	out := make([]Request, 0, len(s.order))
	for _, id := range s.order {
		r := s.byID[id]
		if r == nil {
			continue
		}
		if want != "" && r.Status != want {
			continue
		}
		out = append(out, *cloneRequest(r))
	}
	s.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Pending returns the open (awaiting-decision) reviews, most-recent first.
func (s *Service) Pending() []Request { return s.List(string(StatusPending), 0) }

// Snapshot returns the cumulative counters and live gauges.
func (s *Service) Snapshot() Snapshot {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var open, grants int
	for _, id := range s.order {
		r := s.byID[id]
		if r == nil {
			continue
		}
		switch {
		case r.Status == StatusPending:
			open++
		case r.active(now):
			grants++
		}
	}
	snap := Snapshot{
		Enabled:                  s.cfg.Enabled,
		RequiredApprovers:        s.cfg.requiredApprovers(),
		GrantTTLSeconds:          s.cfg.grantTTL().Seconds(),
		RequestTTLSeconds:        s.cfg.requestTTL().Seconds(),
		Open:                     open,
		ActiveGrants:             grants,
		RequestsTotal:            s.requestsTotal,
		ApprovedTotal:            s.approvedTotal,
		DeniedTotal:              s.deniedTotal,
		ExpiredTotal:             s.expiredTotal,
		BreakGlassServesTotal:    s.servesTotal,
		TimeToApprovalSumSeconds: s.ttSum,
		TimeToApprovalCount:      s.ttCount,
	}
	if s.ttCount > 0 {
		snap.AvgTimeToApprovalSeconds = s.ttSum / float64(s.ttCount)
	}
	return snap
}

// trimLocked bounds the retained request set, dropping the oldest terminal
// (denied/expired) records first and never an active grant or pending review
// unless the cap is exceeded entirely by them. Caller holds the mutex.
func (s *Service) trimLocked() {
	max := s.cfg.maxRequests()
	if len(s.order) <= max {
		return
	}
	now := s.now()
	// First pass: drop terminal records oldest-first.
	keep := s.order[:0:0]
	terminal := make([]string, 0)
	for _, id := range s.order {
		r := s.byID[id]
		if r == nil {
			continue
		}
		if r.Status == StatusDenied || r.Status == StatusExpired || (r.Status == StatusApproved && !r.active(now)) {
			terminal = append(terminal, id)
		}
	}
	drop := len(s.order) - max
	dropSet := make(map[string]struct{}, drop)
	for _, id := range terminal {
		if len(dropSet) >= drop {
			break
		}
		dropSet[id] = struct{}{}
	}
	// If still over cap (all remaining are active/pending), drop oldest overall.
	if len(dropSet) < drop {
		for _, id := range s.order {
			if len(dropSet) >= drop {
				break
			}
			if _, ok := dropSet[id]; ok {
				continue
			}
			dropSet[id] = struct{}{}
		}
	}
	for _, id := range s.order {
		if _, dropIt := dropSet[id]; dropIt {
			if r := s.byID[id]; r != nil {
				if cur, ok := s.byKey[r.key()]; ok && cur.ID == id {
					delete(s.byKey, r.key())
				}
			}
			delete(s.byID, id)
			continue
		}
		keep = append(keep, id)
	}
	s.order = keep
}

// newID derives a short, deterministic id from the scope and creation time so
// ids are stable for a given (scope, clock) — important for reproducible tests.
func (s *Service) newID(sc Scope, now time.Time) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%d",
		s.seq, sc.Tenant, sc.Ecosystem, sc.Coordinate, sc.Gate, sc.Reason, now.UnixNano())
	return "apr_" + hex.EncodeToString(h.Sum(nil))[:16]
}

// scopeKey is the canonical (tenant, ecosystem, coordinate, gate, reason) key.
func scopeKey(tenant, ecosystem, coordinate, gate, reason string) string {
	return strings.Join([]string{tenant, ecosystem, coordinate, gate, reason}, "\x00")
}

func cloneRequest(r *Request) *Request {
	c := *r
	if len(r.Approvers) > 0 {
		c.Approvers = append([]Approver(nil), r.Approvers...)
	}
	return &c
}

// --- audit + notify ---------------------------------------------------------

// auditState writes a tamper-evident audit entry for a workflow state change. The
// entry is linked into the Merkle chain by the audit logger. who is the deciding
// operator (empty for an automatic expiry); dur is the grant duration on a grant.
func (s *Service) auditState(ctx context.Context, r *Request, action, who, justification string, dur time.Duration) {
	if s.audit == nil {
		return
	}
	decision := audit.DecisionAllow
	switch action {
	case "denied", "expired", "requested":
		decision = audit.DecisionDeny
	}
	detail := map[string]any{
		"event":      "approval",
		"action":     action,
		"requestId":  r.ID,
		"gate":       r.Gate,
		"coordinate": r.Coordinate,
		"status":     string(r.Status),
		"tenant":     r.Tenant,
		"approvers":  approverSubjects(r.Approvers),
	}
	if justification != "" {
		detail["justification"] = justification
	}
	if dur > 0 {
		detail["durationSeconds"] = int64(dur / time.Second)
	}
	if !r.ExpiresAt.IsZero() {
		detail["expiresAt"] = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	ev := audit.Event{
		Type:      audit.EventAdmin,
		Ecosystem: r.Ecosystem,
		Backend:   r.Backend,
		Resource:  r.Coordinate,
		Decision:  decision,
		Reason:    "approvals:" + action,
		Subject:   who,
		Team:      r.Tenant,
		Detail:    detail,
	}
	if err := s.audit.Log(ctx, ev); err != nil {
		s.logger.Error("approvals: audit log write failed", "action", action, "requestId", r.ID, "error", err)
	}
}

func (s *Service) emit(ctx context.Context, action string, r *Request, who string) {
	if s.notify == nil {
		return
	}
	summary := r.Reason
	switch action {
	case "granted":
		summary = fmt.Sprintf("break-glass exception granted for %s (gate %s); expires %s",
			r.Coordinate, r.Gate, r.ExpiresAt.UTC().Format(time.RFC3339))
	case "expired":
		summary = fmt.Sprintf("break-glass exception for %s (gate %s) expired; artifact re-quarantined",
			r.Coordinate, r.Gate)
	case "denied":
		summary = fmt.Sprintf("quarantine review for %s (gate %s) denied; block confirmed", r.Coordinate, r.Gate)
	case "requested":
		summary = fmt.Sprintf("quarantine review opened for %s (gate %s): %s", r.Coordinate, r.Gate, r.Reason)
	}
	ev := notify.ApprovalEvent(action, r.Gate, r.Ecosystem, r.Coordinate, who, summary)
	if r.Tenant != "" {
		ev = ev.WithField("tenant", r.Tenant)
	}
	ev = ev.WithField("requestId", r.ID)
	s.notify.Emit(ctx, ev)
}

func approverSubjects(as []Approver) string {
	if len(as) == 0 {
		return ""
	}
	subs := make([]string, 0, len(as))
	for _, a := range as {
		subs = append(subs, a.Subject)
	}
	return strings.Join(subs, ",")
}

// --- durable store ----------------------------------------------------------

// persistedState is the on-disk representation of the store.
type persistedState struct {
	Requests      []*Request `json:"requests"`
	Seq           uint64     `json:"seq"`
	RequestsTotal int64      `json:"requestsTotal"`
	ApprovedTotal int64      `json:"approvedTotal"`
	DeniedTotal   int64      `json:"deniedTotal"`
	ExpiredTotal  int64      `json:"expiredTotal"`
	ServesTotal   int64      `json:"servesTotal"`
	TTSum         float64    `json:"timeToApprovalSum"`
	TTCount       int64      `json:"timeToApprovalCount"`
}

// load restores the store from StorePath. A missing file is not an error.
func (s *Service) load() error {
	data, err := os.ReadFile(s.cfg.StorePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}
	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	s.byID = make(map[string]*Request, len(st.Requests))
	s.byKey = make(map[string]*Request)
	s.order = s.order[:0]
	for _, r := range st.Requests {
		if r == nil || r.ID == "" {
			continue
		}
		s.byID[r.ID] = r
		s.order = append(s.order, r.ID)
		// Only the latest governing record per key is indexed; later records in the
		// slice (created later) win.
		if r.Status == StatusPending || r.Status == StatusApproved || r.Status == StatusDenied {
			s.byKey[r.key()] = r
		}
	}
	s.seq = st.Seq
	s.requestsTotal = st.RequestsTotal
	s.approvedTotal = st.ApprovedTotal
	s.deniedTotal = st.DeniedTotal
	s.expiredTotal = st.ExpiredTotal
	s.servesTotal = st.ServesTotal
	s.ttSum = st.TTSum
	s.ttCount = st.TTCount
	return nil
}

// persistLocked atomically writes the store to StorePath. Best-effort: a write
// failure is logged, never propagated (the in-memory state remains authoritative
// for the running process). Caller holds the mutex.
func (s *Service) persistLocked() {
	if s.cfg.StorePath == "" {
		return
	}
	st := persistedState{
		Seq:           s.seq,
		RequestsTotal: s.requestsTotal,
		ApprovedTotal: s.approvedTotal,
		DeniedTotal:   s.deniedTotal,
		ExpiredTotal:  s.expiredTotal,
		ServesTotal:   s.servesTotal,
		TTSum:         s.ttSum,
		TTCount:       s.ttCount,
	}
	st.Requests = make([]*Request, 0, len(s.order))
	for _, id := range s.order {
		if r := s.byID[id]; r != nil {
			st.Requests = append(st.Requests, r)
		}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		s.logger.Error("approvals: marshaling store failed", "error", err)
		return
	}
	dir := filepath.Dir(s.cfg.StorePath)
	tmp, err := os.CreateTemp(dir, ".approvals-*.tmp")
	if err != nil {
		s.logger.Error("approvals: creating store temp file failed", "error", err)
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		s.logger.Error("approvals: writing store temp file failed", "error", err)
		return
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		s.logger.Error("approvals: closing store temp file failed", "error", err)
		return
	}
	if err := os.Rename(tmpName, s.cfg.StorePath); err != nil {
		os.Remove(tmpName)
		s.logger.Error("approvals: renaming store file failed", "error", err)
	}
}
