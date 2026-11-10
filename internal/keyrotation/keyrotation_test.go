package keyrotation

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// captureEmitter records every emitted event for assertions.
type captureEmitter struct {
	mu     sync.Mutex
	events []notify.Event
}

func (c *captureEmitter) Emit(_ context.Context, ev notify.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureEmitter) byType(t notify.EventType) []notify.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []notify.Event
	for _, e := range c.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

func newTestService(em notify.Emitter, clk *fakeClock) *Service {
	return New(Config{
		Enabled:           true,
		ScanInterval:      time.Hour,
		WarnThreshold:     14 * 24 * time.Hour,
		CriticalThreshold: 3 * 24 * time.Hour,
		OverlapWindow:     24 * time.Hour,
	}, Deps{Notifier: em, Now: clk.now})
}

func TestService_StatusGradesMaterials(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := newTestService(nil, clk)
	svc.AddSource("certs", SourceFunc(func(_ context.Context) ([]Material, error) {
		return []Material{
			{ID: "healthy", Kind: KindTLSCert, NotAfter: clk.now().Add(90 * 24 * time.Hour)},
			{ID: "soon", Kind: KindTLSCert, NotAfter: clk.now().Add(2 * 24 * time.Hour)},
			{ID: "nokey", Kind: KindAttestSigner},
		}, nil
	}))

	res := svc.Status(context.Background())
	if res.Counts.Total != 3 {
		t.Fatalf("total = %d, want 3", res.Counts.Total)
	}
	if res.Counts.Critical != 1 || res.Counts.OK != 1 || res.Counts.Unknown != 1 {
		t.Fatalf("counts = %+v, want 1 critical / 1 ok / 1 unknown", res.Counts)
	}
	// Soonest-expiring sorts first.
	if res.Materials[0].ID != "soon" {
		t.Fatalf("first material = %q, want soon (soonest expiry first)", res.Materials[0].ID)
	}
	// The no-expiry material sorts last.
	if res.Materials[len(res.Materials)-1].ID != "nokey" {
		t.Fatalf("last material = %q, want nokey", res.Materials[len(res.Materials)-1].ID)
	}
}

func TestService_EmitsAndDedupesNotifications(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	em := &captureEmitter{}
	svc := newTestService(em, clk)

	expiry := clk.now().Add(10 * 24 * time.Hour) // warning band
	svc.AddSource("certs", SourceFunc(func(_ context.Context) ([]Material, error) {
		return []Material{{ID: "cert", Kind: KindTLSCert, NotAfter: expiry}}, nil
	}))

	// First emitting scan: one warning notification.
	svc.scan(context.Background(), true)
	if n := len(em.byType(notify.EventKeyExpiry)); n != 1 {
		t.Fatalf("after first scan: %d expiry events, want 1", n)
	}
	// Second scan, same band: de-duplicated (no new notification).
	svc.scan(context.Background(), true)
	if n := len(em.byType(notify.EventKeyExpiry)); n != 1 {
		t.Fatalf("steady-state re-scan should not re-alert; got %d events", n)
	}

	// Advance so the cert enters the critical band: escalation re-alerts.
	clk.advance(8 * 24 * time.Hour) // now ~2 days left
	svc.scan(context.Background(), true)
	ev := em.byType(notify.EventKeyExpiry)
	if len(ev) != 2 {
		t.Fatalf("escalation should re-alert; got %d events", len(ev))
	}
	if ev[1].Severity != notify.SeverityHigh {
		t.Fatalf("critical event severity = %q, want high", ev[1].Severity)
	}
	if ev[1].Fields["status"] != "critical" {
		t.Fatalf("event status field = %q, want critical", ev[1].Fields["status"])
	}
}

func TestService_FollowerDoesNotNotify(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	em := &captureEmitter{}
	svc := newTestService(em, clk)
	svc.SetLeaderGate(func() bool { return false }) // this node is a follower
	svc.AddSource("certs", SourceFunc(func(_ context.Context) ([]Material, error) {
		return []Material{{ID: "cert", Kind: KindTLSCert, NotAfter: clk.now().Add(time.Hour)}}, nil
	}))

	// A follower scan (emit=false) still populates the gauge but emits nothing.
	svc.scan(context.Background(), svc.isLeader())
	if n := len(em.byType(notify.EventKeyExpiry)); n != 0 {
		t.Fatalf("follower emitted %d notifications, want 0", n)
	}
	if got := svc.ExpirySeconds()["cert"]; got <= 0 {
		t.Fatalf("gauge should still be populated on a follower; got %v", got)
	}
}

func TestService_SourceErrorDoesNotFailScan(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := newTestService(nil, clk)
	svc.AddSource("broken", SourceFunc(func(_ context.Context) ([]Material, error) {
		return nil, context.DeadlineExceeded
	}))
	svc.AddSource("good", SourceFunc(func(_ context.Context) ([]Material, error) {
		return []Material{{ID: "ok", Kind: KindTLSCert, NotAfter: clk.now().Add(365 * 24 * time.Hour)}}, nil
	}))
	res := svc.Status(context.Background())
	if res.Counts.Total != 1 || res.Materials[0].ID != "ok" {
		t.Fatalf("a broken source must not blind the scan; got %+v", res.Counts)
	}
	if svc.Metrics().Snapshot().SourceErrors != 1 {
		t.Fatalf("source error not counted; snapshot=%+v", svc.Metrics().Snapshot())
	}
}

func TestService_RotateUnsupported(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := newTestService(nil, clk)
	svc.AddSource("audit", SourceFunc(func(_ context.Context) ([]Material, error) {
		return []Material{{ID: "audit.hmac", Kind: KindAuditHMAC}}, nil
	}))
	out, err := svc.Rotate(context.Background(), "audit.hmac", false)
	if err != ErrRotationUnsupported {
		t.Fatalf("err = %v, want ErrRotationUnsupported", err)
	}
	if out.Supported {
		t.Fatal("unsupported material must report Supported=false")
	}
	if out.Detail == "" {
		t.Fatal("unsupported rotation should describe the out-of-band procedure")
	}
}

func TestService_RotateDrivesOverlapAndGuards(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	em := &captureEmitter{}
	svc := newTestService(em, clk)

	// A rotator that mints a fresh primary key id on each call.
	gen := 0
	svc.AddRotator("cache.kek", "kek-0", RotatorFunc(func(_ context.Context) (RotationOutcome, error) {
		gen++
		return RotationOutcome{NewPrimaryKeyID: keyName(gen), Rewrapped: 5, Scanned: 7}, nil
	}))

	out, err := svc.Rotate(context.Background(), "cache.kek", false)
	if err != nil {
		t.Fatalf("first rotation: unexpected error %v", err)
	}
	if !out.Performed || out.NewPrimaryKeyID != "kek-1" || out.Rewrapped != 5 {
		t.Fatalf("rotation outcome = %+v", out)
	}
	if n := len(em.byType(notify.EventKeyRotated)); n != 1 {
		t.Fatalf("rotation should emit one key_rotated event, got %d", n)
	}

	// Overlap window is now open; a second rotation without force is refused.
	if _, err := svc.Rotate(context.Background(), "cache.kek", false); err != ErrRotationInFlight {
		t.Fatalf("stacked rotation err = %v, want ErrRotationInFlight", err)
	}
	// force overrides the guard.
	if _, err := svc.Rotate(context.Background(), "cache.kek", true); err != nil {
		t.Fatalf("forced rotation: unexpected error %v", err)
	}
	if svc.Metrics().Snapshot().Rotations != 2 {
		t.Fatalf("rotations counter = %d, want 2", svc.Metrics().Snapshot().Rotations)
	}

	// After the overlap window elapses an unforced rotation is allowed again.
	clk.advance(25 * time.Hour)
	if _, err := svc.Rotate(context.Background(), "cache.kek", false); err != nil {
		t.Fatalf("rotation after window: unexpected error %v", err)
	}
}

func TestService_UnknownMaterialRotation(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	svc := newTestService(nil, clk)
	if _, err := svc.Rotate(context.Background(), "does.not.exist", false); err != ErrRotationUnsupported {
		t.Fatalf("err = %v, want ErrRotationUnsupported for unknown material", err)
	}
}

func TestService_DisabledIsInert(t *testing.T) {
	svc := New(Config{Enabled: false}, Deps{})
	if svc.Enabled() {
		t.Fatal("disabled service reports enabled")
	}
	if got := svc.UpcomingExpiries(); got != nil {
		t.Fatalf("disabled service should report no expiries, got %v", got)
	}
	// Start/Stop are no-ops when disabled.
	svc.Start(context.Background())
	svc.Stop()
}

func keyName(n int) string {
	return "kek-" + string(rune('0'+n))
}
