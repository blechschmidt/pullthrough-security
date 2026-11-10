package approvals

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// fakeClock is a deterministic, advanceable time source for the tests.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestService(t *testing.T, cfg Config, clk *fakeClock) *Service {
	t.Helper()
	cfg.Enabled = true
	s, err := New(cfg, nil, WithClock(clk.now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func scope() Scope {
	return Scope{
		Tenant:     "acme",
		Ecosystem:  "npm",
		Coordinate: "left-pad@1.0.0",
		Gate:       "vulnscan",
		Reason:     "critical CVE-2024-0001",
		Backend:    "npm",
		Requester:  "alice",
	}
}

// TestGrantServeExpireReblock is the canonical lifecycle: a block opens a pending
// review, an approval grants a time-boxed exception, the artifact serves under
// the grant, the grant expires, and the artifact is re-blocked.
func TestGrantServeExpireReblock(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestService(t, Config{GrantTTL: time.Hour, RequiredApprovers: 1}, clk)
	ctx := context.Background()

	// 1. First block: no grant -> blocked, pending review opened.
	d := s.Consult(ctx, scope())
	if d.Allow {
		t.Fatal("first consult should block (no grant)")
	}
	if d.RequestID == "" {
		t.Fatal("a pending review should have been opened")
	}
	if got := s.Snapshot().Open; got != 1 {
		t.Fatalf("Open = %d, want 1", got)
	}

	// 2. A second blocked pull while pending bumps hits, no new request.
	d2 := s.Consult(ctx, scope())
	if d2.Allow || d2.RequestID != d.RequestID {
		t.Fatalf("second consult should reuse pending review %s, got %+v", d.RequestID, d2)
	}
	if r, _ := s.Get(d.RequestID); r.Hits != 2 {
		t.Fatalf("hits = %d, want 2", r.Hits)
	}

	// 3. Approve -> active grant.
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "ops-bob", Justification: "triaged, false positive"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	snap := s.Snapshot()
	if snap.ApprovedTotal != 1 || snap.ActiveGrants != 1 || snap.Open != 0 {
		t.Fatalf("after approve snapshot = %+v", snap)
	}

	// 4. Serve under the grant.
	d3 := s.Consult(ctx, scope())
	if !d3.Allow {
		t.Fatal("consult should allow under active grant")
	}
	if r, _ := s.Get(d.RequestID); r.ServeCount != 1 {
		t.Fatalf("serveCount = %d, want 1", r.ServeCount)
	}

	// 5. Advance past the TTL and re-consult: lazy expiry -> re-block, fresh review.
	clk.advance(time.Hour + time.Minute)
	d4 := s.Consult(ctx, scope())
	if d4.Allow {
		t.Fatal("consult after expiry should re-block")
	}
	if d4.RequestID == d.RequestID {
		t.Fatal("a fresh pending review should be opened after expiry")
	}
	snap = s.Snapshot()
	if snap.ExpiredTotal != 1 {
		t.Fatalf("expiredTotal = %d, want 1", snap.ExpiredTotal)
	}
	if snap.Open != 1 {
		t.Fatalf("Open = %d, want 1 (re-opened review)", snap.Open)
	}
	if snap.BreakGlassServesTotal != 1 {
		t.Fatalf("breakGlassServes = %d, want 1", snap.BreakGlassServesTotal)
	}
}

// TestDualControl requires N distinct approvers before a grant is issued, and
// rejects a duplicate approver.
func TestDualControl(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestService(t, Config{RequiredApprovers: 2}, clk)
	ctx := context.Background()

	d := s.Consult(ctx, scope())
	if d.Allow {
		t.Fatal("should block initially")
	}

	// First approver: still pending.
	r1, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "bob", Justification: "ok"})
	if err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if r1.Status != StatusPending {
		t.Fatalf("after 1/2 approvers status = %s, want pending", r1.Status)
	}
	if s.Consult(ctx, scope()).Allow {
		t.Fatal("should still block with only 1/2 approvers")
	}

	// Same approver again: rejected.
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "bob", Justification: "again"}); err != ErrDuplicateApprover {
		t.Fatalf("duplicate approver err = %v, want ErrDuplicateApprover", err)
	}

	// Second distinct approver: granted.
	r2, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "carol", Justification: "confirmed"})
	if err != nil {
		t.Fatalf("second approve: %v", err)
	}
	if r2.Status != StatusApproved {
		t.Fatalf("after 2/2 approvers status = %s, want approved", r2.Status)
	}
	if !s.Consult(ctx, scope()).Allow {
		t.Fatal("should allow after dual-control grant")
	}
}

// TestDeny confirms the block and keeps re-blocking without re-opening a review.
func TestDeny(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestService(t, Config{RequiredApprovers: 1}, clk)
	ctx := context.Background()

	d := s.Consult(ctx, scope())
	if _, err := s.Deny(ctx, d.RequestID, "bob", "genuinely malicious"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	// Approving a denied request must fail.
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "carol", Justification: "x"}); err != ErrNotPending {
		t.Fatalf("approve-after-deny err = %v, want ErrNotPending", err)
	}
	// Re-consult: still blocked, same request, no new pending.
	d2 := s.Consult(ctx, scope())
	if d2.Allow || d2.RequestID != d.RequestID {
		t.Fatalf("denied request should keep blocking; got %+v", d2)
	}
	if s.Snapshot().Open != 0 {
		t.Fatal("a denied request must not leave an open review")
	}
}

// TestSweepExpiresGrantsAndStaleRequests checks the background sweep transitions
// due grants and stale pending reviews.
func TestSweepExpiresGrantsAndStaleRequests(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestService(t, Config{GrantTTL: 30 * time.Minute, RequestTTL: time.Hour, RequiredApprovers: 1}, clk)
	ctx := context.Background()

	d := s.Consult(ctx, scope())
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "bob", Justification: "ok"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// A separate, never-reviewed pending request.
	other := scope()
	other.Coordinate = "evil@2.0.0"
	other.Reason = "malware"
	s.Consult(ctx, other)

	clk.advance(90 * time.Minute) // past both TTLs
	changed := s.Sweep(ctx)
	if changed != 2 {
		t.Fatalf("sweep changed %d, want 2 (grant expired + stale pending expired)", changed)
	}
	snap := s.Snapshot()
	if snap.ActiveGrants != 0 || snap.Open != 0 {
		t.Fatalf("after sweep snapshot = %+v, want no active grants or open reviews", snap)
	}
	if snap.ExpiredTotal != 2 {
		t.Fatalf("expiredTotal = %d, want 2", snap.ExpiredTotal)
	}
}

// TestValidation rejects empty approver/justification.
func TestValidation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	s := newTestService(t, Config{RequiredApprovers: 1}, clk)
	ctx := context.Background()
	d := s.Consult(ctx, scope())
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Justification: "x"}); err != ErrNoApprover {
		t.Fatalf("err = %v, want ErrNoApprover", err)
	}
	if _, err := s.Approve(ctx, d.RequestID, ApproveInput{Approver: "bob"}); err != ErrNoJustification {
		t.Fatalf("err = %v, want ErrNoJustification", err)
	}
	if _, err := s.Approve(ctx, "nope", ApproveInput{Approver: "bob", Justification: "x"}); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestDurablePersistence verifies pending reviews and active grants survive a
// reload from the on-disk store.
func TestDurablePersistence(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	path := filepath.Join(t.TempDir(), "approvals.json")
	cfg := Config{GrantTTL: time.Hour, RequiredApprovers: 1, StorePath: path}
	ctx := context.Background()

	s1 := newTestService(t, cfg, clk)
	d := s1.Consult(ctx, scope())
	if _, err := s1.Approve(ctx, d.RequestID, ApproveInput{Approver: "bob", Justification: "ok"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Reload into a fresh service from the same file and same clock.
	s2 := newTestService(t, cfg, clk)
	snap := s2.Snapshot()
	if snap.ActiveGrants != 1 || snap.ApprovedTotal != 1 {
		t.Fatalf("reloaded snapshot = %+v, want 1 active grant", snap)
	}
	if !s2.Consult(ctx, scope()).Allow {
		t.Fatal("reloaded grant should still serve")
	}
}
