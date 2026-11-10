package secops

import (
	"testing"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// fixedClock returns a deterministic clock for stable window math.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestObserveClassifiesAndTallies(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	h := NewHub(Options{Now: fixedClock(now)})

	// A policy block, a vulnerability warn, and a granted approval (an admit).
	h.Observe(notify.Event{Type: notify.EventPolicyBlock, Severity: notify.SeverityHigh, Time: now, Subject: "team-a", Artifact: "npm evil@1"})
	h.Observe(notify.VulnerabilityEvent(notify.SeverityMedium, "npm", "b", "left-pad@1", "adv", "warn", "vulnerable").WithField("action", "warn"))
	h.Observe(notify.ApprovalEvent("granted", "vulnscan", "npm", "left-pad@1", "op", "exception"))
	// The synthetic test event must be ignored.
	h.Observe(notify.TestEvent())

	// Stamp times on the events that lacked one so they land in-window.
	sum := h.Summary()
	if sum.Window.Total != 3 {
		t.Fatalf("window total = %d, want 3", sum.Window.Total)
	}
	if sum.Window.Blocks != 1 || sum.Window.Warns != 1 || sum.Window.Admits != 1 {
		t.Fatalf("outcome split = b%d/w%d/a%d, want 1/1/1", sum.Window.Blocks, sum.Window.Warns, sum.Window.Admits)
	}
	if len(sum.Recent) != 3 {
		t.Fatalf("recent feed = %d, want 3", len(sum.Recent))
	}
	// Newest-first: the granted approval was observed last.
	if sum.Recent[0].Type != string(notify.EventApproval) || sum.Recent[0].Outcome != OutcomeAdmit {
		t.Fatalf("newest feed entry = %+v, want approval/admit", sum.Recent[0])
	}
	// Gate mapping: a policy block is owned by the policyengine gate.
	gotGate := false
	for _, c := range sum.Window.ByGate {
		if c.Key == "policyengine" && c.Value == 1 {
			gotGate = true
		}
	}
	if !gotGate {
		t.Fatalf("byGate missing policyengine: %+v", sum.Window.ByGate)
	}
}

func TestWindowDecay(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	clk := now
	h := NewHub(Options{Window: time.Hour, Now: func() time.Time { return clk }})

	old := notify.Event{Type: notify.EventPolicyBlock, Severity: notify.SeverityHigh, Time: now.Add(-2 * time.Hour)}
	h.Observe(old)
	if got := h.Summary().Window.Total; got != 0 {
		t.Fatalf("event older than the window counted: total=%d, want 0", got)
	}

	fresh := notify.Event{Type: notify.EventPolicyBlock, Severity: notify.SeverityHigh, Time: now.Add(-1 * time.Minute)}
	h.Observe(fresh)
	if got := h.Summary().Window.Total; got != 1 {
		t.Fatalf("in-window event missed: total=%d, want 1", got)
	}
}

func TestSubscribeFanout(t *testing.T) {
	h := NewHub(Options{})
	ch, cancel := h.Subscribe()
	defer cancel()

	h.Observe(notify.Event{Type: notify.EventMaliciousBlock, Severity: notify.SeverityCritical, Time: time.Now()})
	select {
	case ev := <-ch:
		if ev.Outcome != OutcomeBlock || ev.Gate != "malfeed" {
			t.Fatalf("streamed event = %+v, want block/malfeed", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("did not receive streamed event")
	}

	// After cancel, the channel closes and no further events are delivered.
	cancel()
	if _, open := <-ch; open {
		t.Fatal("channel should be closed after cancel")
	}
	if got := h.MetricsSnapshot().ActiveStreams; got != 0 {
		t.Fatalf("active streams after cancel = %d, want 0", got)
	}
}

func TestSummaryGracefulWithoutProviders(t *testing.T) {
	h := NewHub(Options{})
	sum := h.Summary()
	if sum.Posture.Approvals != nil || sum.Posture.Risk != nil {
		t.Fatal("posture sections should be nil when no providers are wired")
	}
	for name, on := range sum.Subsystems {
		if on {
			t.Fatalf("subsystem %q reported enabled with no provider", name)
		}
	}
}

func TestPostureFromProviders(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	// Real subsystem engines so the posture summary reads through the same
	// interfaces the production wiring uses.
	risk, err := riskscore.New(riskscore.Config{Enabled: true})
	if err != nil {
		t.Fatalf("riskscore.New: %v", err)
	}
	anom, err := anomaly.New(anomaly.Config{Enabled: true})
	if err != nil {
		t.Fatalf("anomaly.New: %v", err)
	}
	appr, err := approvals.New(approvals.Config{Enabled: true, RequiredApprovers: 1}, nil)
	if err != nil {
		t.Fatalf("approvals.New: %v", err)
	}
	store := findings.NewStore(findings.StoreOptions{})

	h := NewHub(Options{
		Now: fixedClock(now),
		Providers: Providers{
			Risk:      risk,
			Anomaly:   anom,
			Approvals: appr,
			Findings:  store,
		},
	})

	sum := h.Summary()
	if sum.Posture.Risk == nil || sum.Posture.Anomaly == nil || sum.Posture.Approvals == nil || sum.Posture.Findings == nil {
		t.Fatalf("expected all posture sections present, got %+v", sum.Posture)
	}
	if len(sum.Posture.Risk.ByBand) != 4 {
		t.Fatalf("risk byBand = %d bands, want 4 (low..critical)", len(sum.Posture.Risk.ByBand))
	}
	if !sum.Subsystems["riskscore"] || !sum.Subsystems["anomaly"] || !sum.Subsystems["approvals"] || !sum.Subsystems["findings"] {
		t.Fatalf("subsystems flags = %+v, want all enabled", sum.Subsystems)
	}
}
