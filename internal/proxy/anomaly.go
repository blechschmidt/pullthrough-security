package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/anomaly"
	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
)

// Behavioral anomaly detection (Task 43) watches the pull *stream* rather than a
// single artifact. Two thin seams integrate it with the gateway:
//
//   - gateAnomaly runs early on the pull path and soft-blocks an identity whose
//     prior traffic has already pushed its scope into a block standing. It reads
//     accumulated state only (never mutates), so the block decision is driven by
//     what the detectors learned from earlier requests.
//   - observeAnomaly runs after the outcome of a pull is known (a served artifact
//     with its byte size, or a 404/410 enumeration miss) and folds the
//     observation into the detectors, emitting a graded notification when an
//     assessment crosses the alert threshold.
//
// Splitting read (gate) from write (observe) keeps the soft-block hysteretic: a
// blocked scope stops feeding the detectors, so its windows eventually cool and
// it is readmitted — at which point a single request re-heats it if the
// anomalous behavior continues, effectively rate-limiting the offending identity
// to roughly one request per window.

// gateAnomaly soft-blocks the request when the caller's scope is currently in a
// block standing. It returns true when the request may proceed and false when it
// has been refused with a 429 response.
func (g *Gateway) gateAnomaly(w http.ResponseWriter, r *http.Request, backend, ecosystem string) bool {
	if g.deps.Anomaly == nil || !g.deps.Anomaly.Enabled() {
		return true
	}
	tenant, identity := anomalyScope(r)
	status := g.deps.Anomaly.Status(tenant, identity)

	// Always surface the current standing so downstream proxies/clients can see it.
	if status.Level != anomaly.LevelNone {
		w.Header().Set("X-Anomaly-Level", string(status.Level))
		w.Header().Set("X-Anomaly-Score", strconv.FormatFloat(status.Score, 'f', 0, 64))
	}

	if status.Action != anomaly.ActionBlock {
		return true
	}

	g.deps.Anomaly.RecordSoftBlock()
	g.deps.Logger.Warn("anomaly gate soft-blocked traffic",
		"backend", backend, "ecosystem", ecosystem, "tenant", tenant, "identity", identity,
		"level", status.Level, "score", status.Score)
	g.auditAnomalyBlock(r, backend, ecosystem, status)
	writeAnomalyBlock(w, status)
	return false
}

// observeAnomaly folds one pull outcome into the detectors and raises a
// notification when the resulting assessment is an alert. It is best-effort and
// never affects the response (the request has already been served or failed).
func (g *Gateway) observeAnomaly(r *http.Request, backend, ecosystem string, resolved *backends.Resolved, bytes int64, notFound bool) {
	if g.deps.Anomaly == nil || !g.deps.Anomaly.Enabled() {
		return
	}
	tenant, identity := anomalyScope(r)
	pkg, namespace := anomalyCoordinate(ecosystem, resolved)

	a := g.deps.Anomaly.Observe(anomaly.Observation{
		Tenant:    tenant,
		Identity:  identity,
		Ecosystem: ecosystem,
		Backend:   backend,
		Namespace: namespace,
		Package:   pkg,
		Bytes:     bytes,
		NotFound:  notFound,
		Time:      time.Now(),
	})
	if !a.Alert {
		return
	}
	g.deps.Logger.Warn("behavioral anomaly detected on pull traffic",
		"backend", backend, "ecosystem", ecosystem, "tenant", tenant, "identity", identity,
		"level", a.Level, "score", a.Score, "action", a.Action, "triggered", a.Triggered)
	g.auditAnomalyAlert(r, backend, ecosystem, a)
	g.notifyAnomaly(r, a)
}

// anomalyScope derives the (tenant, identity) the request is attributed to.
// Authenticated requests key on the principal's team and subject; an
// unauthenticated request falls back to its client IP as the identity so an
// anonymous enumeration sweep is still attributable to a single source.
func anomalyScope(r *http.Request) (tenant, identity string) {
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		tenant, identity = p.Team, p.Subject
	}
	if tenant == "" && identity == "" {
		identity = clientIP(r)
	}
	return tenant, identity
}

// anomalyCoordinate returns the package coordinate (fan-out key) and the derived
// namespace (new-namespace key) for an observation.
func anomalyCoordinate(ecosystem string, resolved *backends.Resolved) (pkg, namespace string) {
	name := resolved.Coordinate.Name
	if name == "" {
		// Fall back to the cache key so a backend that does not populate a
		// structured coordinate still produces a stable distinct-fan-out key.
		name = resolved.CacheKey
	}
	return name, namespaceFor(ecosystem, name)
}

// namespaceFor extracts a coarse namespace/group from a package name for the
// new-namespace detector. The heuristic is intentionally simple and ecosystem-
// agnostic: a scoped/pathed name (npm "@scope/x", Go "github.com/org/m", Maven
// "group:artifact", Docker "org/image") yields its leading group; a bare name
// has no namespace and is ignored by the detector.
func namespaceFor(ecosystem, name string) string {
	if name == "" {
		return ""
	}
	// Maven coordinates arrive as "group:artifact[:version]"; the group is the
	// namespace.
	if strings.EqualFold(ecosystem, "maven") {
		if i := strings.Index(name, ":"); i > 0 {
			return name[:i]
		}
	}
	if i := strings.LastIndex(name, "/"); i > 0 {
		return name[:i]
	}
	return ""
}

// anomalyError is the JSON body returned when the anomaly gate soft-blocks.
type anomalyError struct {
	Error    string  `json:"error"`
	Code     string  `json:"code"`
	Level    string  `json:"level"`
	Score    float64 `json:"score"`
	Detector string  `json:"detector,omitempty"`
}

func writeAnomalyBlock(w http.ResponseWriter, status anomaly.ScopeStatus) {
	body := anomalyError{
		Error: "request temporarily refused: this identity's recent pull traffic was flagged as behaviorally anomalous",
		Code:  "anomaly",
		Level: string(status.Level),
		Score: status.Score,
	}
	if d := topDetector(status.Detectors); d != "" {
		body.Detector = string(d)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Anomaly-Decision", "block")
	h.Set("X-Cache", "BLOCKED")
	// Soft-block: invite the client to retry after the window has had a chance to
	// cool rather than failing hard.
	h.Set("Retry-After", "60")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(body)
}

func (g *Gateway) auditAnomalyAlert(r *http.Request, backend, ecosystem string, a anomaly.Assessment) {
	if g.deps.Audit == nil {
		return
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   audit.DecisionAllow,
		Reason:     "anomaly:" + string(a.Level),
		Detail: map[string]any{
			"level":     string(a.Level),
			"score":     a.Score,
			"action":    string(a.Action),
			"scope":     a.Scope,
			"triggered": detectorStrings(a.Triggered),
			"summary":   a.Summary,
		},
	}
	if a.Block {
		ev.Decision = audit.DecisionDeny
		ev.Status = http.StatusTooManyRequests
	}
	g.applyPrincipal(r, &ev)
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) auditAnomalyBlock(r *http.Request, backend, ecosystem string, status anomaly.ScopeStatus) {
	if g.deps.Audit == nil {
		return
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   audit.DecisionDeny,
		Status:     http.StatusTooManyRequests,
		Reason:     "anomaly-softblock:" + string(status.Level),
		Detail: map[string]any{
			"level":    string(status.Level),
			"score":    status.Score,
			"scope":    status.Scope,
			"detector": string(topDetector(status.Detectors)),
		},
	}
	g.applyPrincipal(r, &ev)
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifyAnomaly(r *http.Request, a anomaly.Assessment) {
	if g.deps.Notify == nil {
		return
	}
	detector := ""
	if len(a.Triggered) > 0 {
		detector = string(a.Triggered[0])
	}
	ev := notify.AnomalyEvent(anomalySeverity(a.Level), a.Scope, detector, string(a.Level),
		a.Score, string(a.Action), a.Summary)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// applyPrincipal copies the authenticated principal's identity onto an audit
// event, if present.
func (g *Gateway) applyPrincipal(r *http.Request, ev *audit.Event) {
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
}

// anomalySeverity maps an anomaly level to a notification severity.
func anomalySeverity(l anomaly.Level) notify.Severity {
	switch l {
	case anomaly.LevelHigh:
		return notify.SeverityHigh
	case anomaly.LevelMedium:
		return notify.SeverityMedium
	case anomaly.LevelLow:
		return notify.SeverityLow
	default:
		return notify.SeverityInfo
	}
}

// topDetector returns the strongest-scoring triggered detector from a scope's
// detector breakdown, or "" when none triggered.
func topDetector(detectors []anomaly.DetectorResult) anomaly.DetectorKind {
	best := anomaly.DetectorKind("")
	var bestScore float64
	for _, d := range detectors {
		if d.Triggered && d.Score >= bestScore {
			best, bestScore = d.Detector, d.Score
		}
	}
	return best
}

func detectorStrings(kinds []anomaly.DetectorKind) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}
