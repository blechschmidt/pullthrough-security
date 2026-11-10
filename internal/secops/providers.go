package secops

import (
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/keyrotation"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// The provider interfaces are the narrow read-only seams the posture summary
// reads through. The concrete subsystem types satisfy them directly, and any
// provider left nil (subsystem disabled) is skipped — the source of truth always
// stays in the owning subsystem.

// ApprovalsProvider exposes the quarantine-review / break-glass backlog (Task 50).
type ApprovalsProvider interface {
	Enabled() bool
	Snapshot() approvals.Snapshot
	Pending() []approvals.Request
}

// AnomalyProvider exposes the behavioral-anomaly standings (Task 43).
type AnomalyProvider interface {
	Enabled() bool
	Snapshot() anomaly.Snapshot
}

// RiskProvider exposes the unified risk-band distribution (Task 37).
type RiskProvider interface {
	Enabled() bool
	Snapshot() riskscore.Snapshot
}

// FindingsProvider exposes the aggregated findings store (Task 42).
type FindingsProvider interface {
	Documents(tenant, q string) []findings.Document
}

// KeyRotationProvider exposes the credential & signing-key expiry standings
// (Task 148), so the SOC view can foreground material approaching expiry.
type KeyRotationProvider interface {
	Enabled() bool
	UpcomingExpiries() []keyrotation.MaterialStatus
}

// Providers bundles the optional subsystem read-models the posture summary taps.
// A nil field means the subsystem is disabled or unwired.
type Providers struct {
	Approvals   ApprovalsProvider
	Anomaly     AnomalyProvider
	Risk        RiskProvider
	Findings    FindingsProvider
	KeyRotation KeyRotationProvider
}

// Posture is the point-in-time cross-subsystem security posture. Each section is
// omitted when its subsystem is disabled, so the dashboard degrades gracefully.
type Posture struct {
	Approvals *ApprovalsPosture `json:"approvals,omitempty"`
	Anomaly   *AnomalyPosture   `json:"anomaly,omitempty"`
	Risk      *RiskPosture      `json:"risk,omitempty"`
	Findings  *FindingsPosture  `json:"findings,omitempty"`
	Keys      *KeysPosture      `json:"keys,omitempty"`
}

// KeysPosture summarizes the credential/signing-key expiry standings: how many
// pieces of trust material are in each alerting band, and the soonest few to
// expire so the SOC view can foreground them for rotation.
type KeysPosture struct {
	Total    int             `json:"total"`
	Warning  int             `json:"warning"`
	Critical int             `json:"critical"`
	Expired  int             `json:"expired"`
	Soonest  []KeyExpiryItem `json:"soonest,omitempty"`
}

// KeyExpiryItem is one piece of trust material approaching expiry.
type KeyExpiryItem struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	DaysLeft  int       `json:"daysLeft"`
}

// ApprovalsPosture summarizes the human-in-the-loop backlog.
type ApprovalsPosture struct {
	Open         int           `json:"open"`         // pending reviews (the backlog)
	ActiveGrants int           `json:"activeGrants"` // unexpired break-glass exceptions
	Oldest       []BacklogItem `json:"oldest,omitempty"`
}

// BacklogItem is one pending review, surfaced so the SOC view can show the queue.
type BacklogItem struct {
	ID         string `json:"id"`
	Tenant     string `json:"tenant,omitempty"`
	Gate       string `json:"gate,omitempty"`
	Coordinate string `json:"coordinate,omitempty"`
	Reason     string `json:"reason,omitempty"`
	WaitingSec int64  `json:"waitingSec"`
}

// AnomalyPosture summarizes currently-active behavioral anomalies.
type AnomalyPosture struct {
	Active  int            `json:"active"`  // scopes above the observe floor
	Blocked int            `json:"blocked"` // scopes currently soft-blocked
	ByLevel []Count        `json:"byLevel,omitempty"`
	Top     []AnomalyScope `json:"top,omitempty"`
}

// AnomalyScope is one anomalous tenant/identity scope.
type AnomalyScope struct {
	Scope    string  `json:"scope"`
	Tenant   string  `json:"tenant,omitempty"`
	Identity string  `json:"identity,omitempty"`
	Level    string  `json:"level"`
	Action   string  `json:"action"`
	Score    float64 `json:"score"`
}

// RiskPosture is the risk-band distribution plus the admission funnel.
type RiskPosture struct {
	TotalScored int64   `json:"totalScored"`
	Blocked     int64   `json:"blocked"`
	Warned      int64   `json:"warned"`
	ByBand      []Count `json:"byBand"`
}

// FindingsPosture summarizes the aggregated findings store.
type FindingsPosture struct {
	Artifacts    int     `json:"artifacts"`    // documents retained
	WithBlocking int     `json:"withBlocking"` // artifacts with a blocking finding
	BySeverity   []Count `json:"bySeverity"`
	ByGate       []Count `json:"byGate"`
}

// enabled reports which subsystems are contributing, so the dashboard can show
// what is and is not wired (graceful degradation is explicit, not silent).
func (p Providers) enabled() map[string]bool {
	return map[string]bool{
		"approvals":   p.Approvals != nil && p.Approvals.Enabled(),
		"anomaly":     p.Anomaly != nil && p.Anomaly.Enabled(),
		"riskscore":   p.Risk != nil && p.Risk.Enabled(),
		"findings":    p.Findings != nil,
		"keyrotation": p.KeyRotation != nil && p.KeyRotation.Enabled(),
	}
}

// posture reads the current posture from every wired, enabled provider.
func (p Providers) posture(now time.Time) Posture {
	var out Posture
	if p.Approvals != nil && p.Approvals.Enabled() {
		out.Approvals = approvalsPosture(p.Approvals, now)
	}
	if p.Anomaly != nil && p.Anomaly.Enabled() {
		out.Anomaly = anomalyPosture(p.Anomaly)
	}
	if p.Risk != nil && p.Risk.Enabled() {
		out.Risk = riskPosture(p.Risk)
	}
	if p.Findings != nil {
		out.Findings = findingsPosture(p.Findings)
	}
	if p.KeyRotation != nil && p.KeyRotation.Enabled() {
		out.Keys = keysPosture(p.KeyRotation, now)
	}
	return out
}

func keysPosture(kp KeyRotationProvider, now time.Time) *KeysPosture {
	mats := kp.UpcomingExpiries()
	out := &KeysPosture{Total: len(mats)}
	for _, m := range mats {
		switch m.Status {
		case keyrotation.StatusWarning:
			out.Warning++
		case keyrotation.StatusCritical:
			out.Critical++
		case keyrotation.StatusExpired:
			out.Expired++
		}
		// Surface the soonest-expiring material (the scanner already sorts
		// soonest-first), capped so the panel stays compact.
		if m.HasExpiry && len(out.Soonest) < 8 {
			out.Soonest = append(out.Soonest, KeyExpiryItem{
				ID:        m.ID,
				Kind:      string(m.Kind),
				Status:    string(m.Status),
				ExpiresAt: m.EffectiveExpiry,
				DaysLeft:  int(m.EffectiveExpiry.Sub(now).Hours() / 24),
			})
		}
	}
	return out
}

func approvalsPosture(a ApprovalsProvider, now time.Time) *ApprovalsPosture {
	snap := a.Snapshot()
	out := &ApprovalsPosture{Open: snap.Open, ActiveGrants: snap.ActiveGrants}
	pending := a.Pending()
	// Surface the oldest few (the longest waiting), since those are the backlog
	// risk the SOC view should foreground.
	sort.SliceStable(pending, func(i, j int) bool {
		return pending[i].CreatedAt.Before(pending[j].CreatedAt)
	})
	limit := 5
	for i := range pending {
		if i >= limit {
			break
		}
		r := pending[i]
		out.Oldest = append(out.Oldest, BacklogItem{
			ID:         r.ID,
			Tenant:     r.Tenant,
			Gate:       r.Gate,
			Coordinate: r.Coordinate,
			Reason:     r.Reason,
			WaitingSec: waitingSeconds(r, now),
		})
	}
	return out
}

func waitingSeconds(r approvals.Request, now time.Time) int64 {
	if r.CreatedAt.IsZero() {
		return 0
	}
	d := now.Sub(r.CreatedAt).Seconds()
	if d < 0 {
		return 0
	}
	return int64(d)
}

func anomalyPosture(a AnomalyProvider) *AnomalyPosture {
	snap := a.Snapshot()
	out := &AnomalyPosture{ByLevel: levelCounts(snap.ByLevel)}
	for _, sc := range snap.Scopes {
		level := strings.ToLower(string(sc.Level))
		if level == "" || level == "none" {
			continue
		}
		out.Active++
		if strings.EqualFold(string(sc.Action), "block") {
			out.Blocked++
		}
		if len(out.Top) < 8 {
			out.Top = append(out.Top, AnomalyScope{
				Scope:    sc.Scope,
				Tenant:   sc.Tenant,
				Identity: sc.Identity,
				Level:    level,
				Action:   strings.ToLower(string(sc.Action)),
				Score:    sc.Score,
			})
		}
	}
	return out
}

// levelCounts renders the anomaly per-level map skipping the "none" bucket.
func levelCounts(m map[string]int64) []Count {
	filtered := make(map[string]int64, len(m))
	for k, v := range m {
		if strings.EqualFold(k, "none") {
			continue
		}
		filtered[k] = v
	}
	return topCounts(filtered, 0)
}

func riskPosture(rp RiskProvider) *RiskPosture {
	snap := rp.Snapshot()
	out := &RiskPosture{
		TotalScored: snap.TotalScored,
		Blocked:     snap.Blocked,
		Warned:      snap.Warned,
	}
	// Preserve the canonical band order (low→critical) rather than sorting by count.
	for _, band := range []string{"low", "medium", "high", "critical"} {
		out.ByBand = append(out.ByBand, Count{Key: band, Value: snap.ByBand[band]})
	}
	return out
}

func findingsPosture(fp FindingsProvider) *FindingsPosture {
	docs := fp.Documents("", "")
	out := &FindingsPosture{Artifacts: len(docs)}
	sev := map[string]int64{}
	gate := map[string]int64{}
	for i := range docs {
		d := &docs[i]
		if d.HasBlocking() {
			out.WithBlocking++
		}
		for s, n := range d.Counts() {
			sev[string(s)] += int64(n)
		}
		for j := range d.Findings {
			f := &d.Findings[j]
			if f.Suppressed {
				continue
			}
			gate[string(f.Gate)]++
		}
	}
	out.BySeverity = topCounts(sev, 0)
	out.ByGate = topCounts(gate, 0)
	return out
}
