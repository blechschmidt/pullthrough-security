package webauthn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
)

const (
	testRPID   = "example.com"
	testOrigin = "https://admin.example.com"
)

func testCtx() context.Context { return context.Background() }

// fakeClock is a mutable clock for TTL tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestService(t *testing.T, opts ...Option) (*Service, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	cfg := Config{
		Enabled:      true,
		Enforce:      true,
		RPID:         testRPID,
		RPName:       "Pullthrough Admin",
		Origins:      []string{testOrigin},
		ChallengeTTL: 2 * time.Minute,
		StepUpTTL:    5 * time.Minute,
	}
	all := append([]Option{WithClock(clk.now), WithMetrics(NewMetrics())}, opts...)
	svc, err := New(cfg, all...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, clk
}

func TestRegistrationAndAssertionES256(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)

	view, err := fa.register(svc, "alice", "YubiKey", testOrigin, true, 1)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if view.Label != "YubiKey" || view.AttestationFormat != "none" {
		t.Fatalf("unexpected credential view: %+v", view)
	}
	if !svc.HasCredentials("alice") {
		t.Fatal("expected alice to have credentials")
	}

	res, err := fa.assert(svc, "alice", "/api/keys/rotate", testOrigin, true, 2)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	if res.Token == "" {
		t.Fatal("expected a step-up token")
	}
	// The token verifies for the bound action and is single-use.
	if err := svc.VerifyStepUp(testCtx(), "alice", "/api/keys/rotate", res.Token, "1.2.3.4"); err != nil {
		t.Fatalf("VerifyStepUp: %v", err)
	}
	if err := svc.VerifyStepUp(testCtx(), "alice", "/api/keys/rotate", res.Token, "1.2.3.4"); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("expected replayed token to be invalid, got %v", err)
	}
}

func TestRegistrationAndAssertionEd25519(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algEdDSA)
	if _, err := fa.register(svc, "bob", "Phone", testOrigin, true, 0); err != nil {
		t.Fatalf("register: %v", err)
	}
	// A zero sign count on both sides is allowed (authenticators that never
	// increment the counter).
	res, err := fa.assert(svc, "bob", "", testOrigin, true, 0)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	// An unbound ("") token works for any action.
	if err := svc.VerifyStepUp(testCtx(), "bob", "/api/lockdown/engage", res.Token, ""); err != nil {
		t.Fatalf("VerifyStepUp any-action: %v", err)
	}
}

func TestChallengeExpiry(t *testing.T) {
	svc, clk := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "carol", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Begin an assertion, then let the challenge expire before finishing.
	ch, err := svc.BeginAssertion("carol", "/api/presets/apply")
	if err != nil {
		t.Fatalf("BeginAssertion: %v", err)
	}
	clk.advance(3 * time.Minute) // past the 2m challenge TTL

	ad := fa.authData(ch.RPID, true, 5, false)
	cdj := fa.clientDataJSON("webauthn.get", ch.Challenge, testOrigin)
	sig := fa.sign(ad, cdj)
	_, err = svc.FinishAssertion(testCtx(), "carol", AssertionResponse{
		CredentialID:      b64urlEncode(fa.credID),
		ClientDataJSON:    b64urlEncode(cdj),
		AuthenticatorData: b64urlEncode(ad),
		Signature:         b64urlEncode(sig),
	})
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected ErrChallengeExpired, got %v", err)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "dave", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	ch, err := svc.BeginAssertion("dave", "")
	if err != nil {
		t.Fatalf("BeginAssertion: %v", err)
	}
	ad := fa.authData(ch.RPID, true, 2, false)
	cdj := fa.clientDataJSON("webauthn.get", ch.Challenge, testOrigin)
	sig := fa.sign(ad, cdj)
	resp := AssertionResponse{
		CredentialID:      b64urlEncode(fa.credID),
		ClientDataJSON:    b64urlEncode(cdj),
		AuthenticatorData: b64urlEncode(ad),
		Signature:         b64urlEncode(sig),
	}
	if _, err := svc.FinishAssertion(testCtx(), "dave", resp); err != nil {
		t.Fatalf("first assertion: %v", err)
	}
	// Replaying the identical response (same challenge) must fail: the challenge
	// was consumed.
	if _, err := svc.FinishAssertion(testCtx(), "dave", resp); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expected replay to fail with ErrChallengeExpired, got %v", err)
	}
}

func TestSignatureCounterRollback(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "erin", "key", testOrigin, true, 5); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Advance the counter legitimately.
	if _, err := fa.assert(svc, "erin", "", testOrigin, true, 10); err != nil {
		t.Fatalf("assert 10: %v", err)
	}
	// A cloned authenticator replays a lower/equal counter → rollback detected.
	if _, err := fa.assert(svc, "erin", "", testOrigin, true, 10); !errors.Is(err, ErrCounterRollback) {
		t.Fatalf("expected ErrCounterRollback at equal counter, got %v", err)
	}
	if _, err := fa.assert(svc, "erin", "", testOrigin, true, 7); !errors.Is(err, ErrCounterRollback) {
		t.Fatalf("expected ErrCounterRollback at lower counter, got %v", err)
	}
	if svc.Snapshot().CounterRollbacks != 2 {
		t.Fatalf("expected 2 recorded rollbacks, got %d", svc.Snapshot().CounterRollbacks)
	}
}

func TestOriginMismatchRejected(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	ch, err := svc.BeginRegistration("frank", "frank")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	ad := fa.authData(ch.RPID, true, 1, true)
	cdj := fa.clientDataJSON("webauthn.create", ch.Challenge, "https://evil.example.com")
	_, err = svc.FinishRegistration(testCtx(), "frank", RegistrationResponse{
		ClientDataJSON:    b64urlEncode(cdj),
		AttestationObject: b64urlEncode(fa.attestationObject(ad)),
	})
	if !errors.Is(err, ErrBadOrigin) {
		t.Fatalf("expected ErrBadOrigin, got %v", err)
	}
}

func TestRPIDHashMismatchRejected(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	ch, err := svc.BeginRegistration("grace", "grace")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	// Build authData against the WRONG rp id.
	ad := fa.authData("attacker.example", true, 1, true)
	cdj := fa.clientDataJSON("webauthn.create", ch.Challenge, testOrigin)
	_, err = svc.FinishRegistration(testCtx(), "grace", RegistrationResponse{
		ClientDataJSON:    b64urlEncode(cdj),
		AttestationObject: b64urlEncode(fa.attestationObject(ad)),
	})
	if err == nil || !contains(err.Error(), "RP ID hash mismatch") {
		t.Fatalf("expected RP ID hash mismatch, got %v", err)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "heidi", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	ch, err := svc.BeginAssertion("heidi", "")
	if err != nil {
		t.Fatalf("BeginAssertion: %v", err)
	}
	ad := fa.authData(ch.RPID, true, 2, false)
	cdj := fa.clientDataJSON("webauthn.get", ch.Challenge, testOrigin)
	badSig := make([]byte, 70) // nonsense ASN.1
	_, err = svc.FinishAssertion(testCtx(), "heidi", AssertionResponse{
		CredentialID:      b64urlEncode(fa.credID),
		ClientDataJSON:    b64urlEncode(cdj),
		AuthenticatorData: b64urlEncode(ad),
		Signature:         b64urlEncode(badSig),
	})
	if err == nil {
		t.Fatal("expected forged signature to be rejected")
	}
}

func TestStepUpTokenExpiry(t *testing.T) {
	svc, clk := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "ivan", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := fa.assert(svc, "ivan", "/api/lockdown/engage", testOrigin, true, 2)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	clk.advance(6 * time.Minute) // past the 5m step-up TTL
	if err := svc.VerifyStepUp(testCtx(), "ivan", "/api/lockdown/engage", res.Token, ""); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("expected expired step-up token, got %v", err)
	}
}

func TestStepUpBoundToSubject(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "judy", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := fa.assert(svc, "judy", "/api/presets/apply", testOrigin, true, 2)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	// Another identity cannot use judy's token.
	if err := svc.VerifyStepUp(testCtx(), "mallory", "/api/presets/apply", res.Token, ""); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("expected subject-bound rejection, got %v", err)
	}
}

func TestStepUpBoundToAction(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "ken", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := fa.assert(svc, "ken", "/api/presets/apply", testOrigin, true, 2)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	// Token minted for presets/apply must not authorize lockdown/engage.
	if err := svc.VerifyStepUp(testCtx(), "ken", "/api/lockdown/engage", res.Token, ""); !errors.Is(err, ErrStepUpInvalid) {
		t.Fatalf("expected action-bound rejection, got %v", err)
	}
}

func TestAssertionRequiresEnrollment(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.BeginAssertion("nobody", ""); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("expected ErrNoCredentials, got %v", err)
	}
}

func TestStepUpRequiredPaths(t *testing.T) {
	svc, _ := newTestService(t)
	for _, p := range defaultProtectedActions {
		if !svc.StepUpRequired(p) {
			t.Errorf("expected %q to require step-up", p)
		}
	}
	if svc.StepUpRequired("/api/overview") {
		t.Error("overview must not require step-up")
	}
}

func TestEnforcementDisabledSkipsVerification(t *testing.T) {
	clk := &fakeClock{t: time.Now()}
	svc, err := New(Config{
		Enabled: true,
		Enforce: false, // ceremonies work but endpoints are not gated
		RPID:    testRPID,
		Origins: []string{testOrigin},
	}, WithClock(clk.now), WithMetrics(NewMetrics()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.StepUpRequired("/api/keys/rotate") {
		t.Fatal("non-enforcing service must not require step-up")
	}
	// VerifyStepUp is a no-op (nil) when not enforcing.
	if err := svc.VerifyStepUp(testCtx(), "x", "/api/keys/rotate", "", ""); err != nil {
		t.Fatalf("expected no-op verify, got %v", err)
	}
}

func TestRemoveCredential(t *testing.T) {
	svc, _ := newTestService(t)
	fa := newFakeAuthenticator(t, algES256)
	view, err := fa.register(svc, "olivia", "key", testOrigin, true, 1)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	ok, err := svc.RemoveCredential(testCtx(), "olivia", view.ID)
	if err != nil || !ok {
		t.Fatalf("RemoveCredential: ok=%v err=%v", ok, err)
	}
	if svc.HasCredentials("olivia") {
		t.Fatal("expected no credentials after removal")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/webauthn.json"
	clk := &fakeClock{t: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	cfg := Config{Enabled: true, Enforce: true, RPID: testRPID, Origins: []string{testOrigin}, StorePath: path}

	svc1, err := New(cfg, WithClock(clk.now), WithMetrics(NewMetrics()))
	if err != nil {
		t.Fatalf("New svc1: %v", err)
	}
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc1, "pat", "key", testOrigin, true, 3); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := fa.assert(svc1, "pat", "", testOrigin, true, 9); err != nil {
		t.Fatalf("assert: %v", err)
	}

	// Reload from disk; the credential and its advanced counter must survive.
	svc2, err := New(cfg, WithClock(clk.now), WithMetrics(NewMetrics()))
	if err != nil {
		t.Fatalf("New svc2: %v", err)
	}
	if !svc2.HasCredentials("pat") {
		t.Fatal("expected reloaded credential")
	}
	// A replayed-counter assertion must be rejected after reload (counter=9 stored).
	if _, err := fa.assert(svc2, "pat", "", testOrigin, true, 9); !errors.Is(err, ErrCounterRollback) {
		t.Fatalf("expected rollback after reload, got %v", err)
	}
}

// auditCapture is a test AuditLogger.
type auditCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (a *auditCapture) Log(_ context.Context, ev audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *auditCapture) count(decision audit.Decision) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.events {
		if e.Type == audit.EventStepUpAuth && e.Decision == decision {
			n++
		}
	}
	return n
}

func TestAuditEventsRecorded(t *testing.T) {
	cap := &auditCapture{}
	clk := &fakeClock{t: time.Now()}
	svc, err := New(Config{Enabled: true, Enforce: true, RPID: testRPID, Origins: []string{testOrigin}},
		WithClock(clk.now), WithMetrics(NewMetrics()), WithAudit(cap))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fa := newFakeAuthenticator(t, algES256)
	if _, err := fa.register(svc, "quinn", "key", testOrigin, true, 1); err != nil {
		t.Fatalf("register: %v", err)
	}
	res, err := fa.assert(svc, "quinn", "/api/keys/rotate", testOrigin, true, 2)
	if err != nil {
		t.Fatalf("assert: %v", err)
	}
	if err := svc.VerifyStepUp(testCtx(), "quinn", "/api/keys/rotate", res.Token, "9.9.9.9"); err != nil {
		t.Fatalf("VerifyStepUp: %v", err)
	}
	// A denied enforcement (no token) must also be audited.
	_ = svc.VerifyStepUp(testCtx(), "quinn", "/api/keys/rotate", "", "9.9.9.9")

	if cap.count(audit.DecisionAllow) < 3 { // register + assert + verify
		t.Fatalf("expected >=3 allow events, got %d", cap.count(audit.DecisionAllow))
	}
	if cap.count(audit.DecisionDeny) < 1 {
		t.Fatalf("expected >=1 deny event, got %d", cap.count(audit.DecisionDeny))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
