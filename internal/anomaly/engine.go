package anomaly

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine observes the pull stream and produces graded, explainable anomaly
// assessments per tenant/identity scope. A zero Engine is not usable; construct
// one with New. All exported methods are safe for concurrent use.
type Engine struct {
	cfg Config

	mu     sync.Mutex
	scopes map[string]*scopeState

	// Cumulative counters for the admin surface and metrics.
	observed       int64
	alerts         int64
	softBlocks     int64
	byLevel        map[Level]int64
	triggersByType map[DetectorKind]int64

	// history is a most-recent-last ring of recent triggers, bounded by
	// cfg.HistorySize.
	history []Trigger
}

// scopeState is one tenant/identity's accumulated detector state plus its latest
// standing. Access is serialized by Engine.mu.
type scopeState struct {
	tenant   string
	identity string

	fanout      distinctWindow
	newNS       rollingWindow
	knownNS     map[string]struct{}
	offHours    rollingWindow
	enumeration rollingWindow
	egress      byteWindow
	egressBase  baseline

	// last is the most recent assessment's standing, the soft-block gate's read
	// model.
	lastScore     float64
	lastLevel     Level
	lastAction    Action
	lastDetectors []DetectorResult
	updatedAt     time.Time

	// Alert bookkeeping: only re-alert after the cooldown, or immediately on an
	// escalation to a strictly higher level.
	lastAlertLevel Level
	lastAlertAt    time.Time
}

// New constructs an Engine, applying built-in defaults for any unset config
// field and validating the result. It returns an error for an invalid
// configuration. A disabled config still constructs a usable (inert) engine so
// callers can hold a non-nil reference; Enabled reports false.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("anomaly: %w", err)
	}
	return &Engine{
		cfg:            cfg,
		scopes:         make(map[string]*scopeState),
		byLevel:        make(map[Level]int64, 4),
		triggersByType: make(map[DetectorKind]int64, len(allDetectors)),
		history:        make([]Trigger, 0, cfg.HistorySize),
	}, nil
}

// Enabled reports whether the engine is enabled in configuration.
func (e *Engine) Enabled() bool { return e != nil && e.cfg.Enabled }

// Observe folds one pull observation into its scope's online statistics and
// returns the resulting explainable assessment. It is the engine's only mutator.
// Detection is a pure function of the scope's prior state and the observation
// (it never reads the wall clock), so a fixed observation stream yields a fixed
// sequence of assessments.
func (e *Engine) Observe(obs Observation) Assessment {
	if e == nil || !e.cfg.Enabled {
		return Assessment{Scope: obs.scope(), Level: LevelNone, Action: ActionObserve}
	}
	now := obs.Time
	if now.IsZero() {
		now = e.cfg.Now()
	}
	key := obs.scope()
	r := e.cfg.resolve(obs.Tenant)

	e.mu.Lock()
	defer e.mu.Unlock()

	e.evictStaleLocked(now)

	st := e.scopes[key]
	if st == nil {
		st = &scopeState{
			tenant:     obs.Tenant,
			identity:   obs.Identity,
			knownNS:    make(map[string]struct{}),
			egressBase: newBaseline(e.cfg.EgressBaselineAlpha),
		}
		e.scopes[key] = st
		e.enforceScopeCapLocked()
	}

	detectors := e.evaluateLocked(st, obs, r, now)

	// The overall score is the strongest single detector: a behavioral anomaly is
	// dangerous if any one axis is extreme, and summing would let several mild,
	// independent signals masquerade as one severe one.
	var score float64
	for _, d := range detectors {
		if d.Score*100 > score {
			score = d.Score * 100
		}
	}
	score = round2(score)
	level := levelForScore(score, e.cfg.LevelMedium, e.cfg.LevelHigh)

	action := ActionObserve
	if levelRank(level) >= levelRank(r.warnLevel) && levelRank(r.warnLevel) > 0 {
		action = ActionWarn
	}
	if r.blockEnabled() && levelRank(level) >= levelRank(r.blockLevel) {
		action = ActionBlock
	}

	triggered := triggeredDetectors(detectors)
	a := Assessment{
		Tenant:     obs.Tenant,
		Identity:   obs.Identity,
		Scope:      key,
		Score:      score,
		Level:      level,
		Action:     action,
		Block:      action == ActionBlock,
		Warn:       action == ActionWarn,
		Detectors:  detectors,
		Triggered:  triggered,
		ObservedAt: now,
	}
	a.Summary = summarize(a)

	// Decide whether this assessment should raise a notification: it must be at
	// least a warn, and either escalate above the last alerted level or clear the
	// cooldown since the last alert for this scope.
	if action != ActionObserve {
		escalated := levelRank(level) > levelRank(st.lastAlertLevel)
		cooled := st.lastAlertAt.IsZero() || !now.Before(st.lastAlertAt.Add(e.cfg.AlertCooldown))
		if escalated || cooled {
			a.Alert = true
			st.lastAlertLevel = level
			st.lastAlertAt = now
		}
	} else {
		// Returning to nominal clears the alert ratchet so a later recurrence
		// re-alerts immediately rather than waiting out a stale cooldown.
		if level == LevelNone {
			st.lastAlertLevel = LevelNone
		}
	}

	// Update the scope's standing and the engine's cumulative counters.
	st.lastScore = score
	st.lastLevel = level
	st.lastAction = action
	st.lastDetectors = detectors
	st.updatedAt = now

	e.observed++
	e.byLevel[level]++
	for _, k := range triggered {
		e.triggersByType[k]++
	}
	if a.Alert {
		e.alerts++
		e.recordTriggerLocked(a, now)
	}

	return a
}

// Status returns the current standing of a scope without mutating state: the
// soft-block gate consults it before serving a request, so an identity already
// flagged anomalous by its prior traffic is throttled on its next request. An
// unknown scope is nominal.
func (e *Engine) Status(tenant, identity string) ScopeStatus {
	key := Observation{Tenant: tenant, Identity: identity}.scope()
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.scopes[key]
	if st == nil {
		return ScopeStatus{Scope: key, Tenant: tenant, Identity: identity, Level: LevelNone, Action: ActionObserve}
	}
	return st.status(key)
}

// RecordSoftBlock increments the soft-block counter. The gate calls it when it
// actually refuses a request, so the metric reflects enforced blocks rather than
// merely block-level assessments (which are also produced in observe-only mode).
func (e *Engine) RecordSoftBlock() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.softBlocks++
	e.mu.Unlock()
}

// status renders a scope's current standing. Caller holds e.mu.
func (st *scopeState) status(key string) ScopeStatus {
	return ScopeStatus{
		Scope:     key,
		Tenant:    st.tenant,
		Identity:  st.identity,
		Score:     st.lastScore,
		Level:     st.lastLevel,
		Action:    st.lastAction,
		Detectors: st.lastDetectors,
		UpdatedAt: st.updatedAt,
	}
}

// evaluateLocked runs every detector over the observation in canonical order,
// mutating the scope's windows. Caller holds e.mu.
func (e *Engine) evaluateLocked(st *scopeState, obs Observation, r resolved, now time.Time) []DetectorResult {
	out := make([]DetectorResult, 0, len(allDetectors))
	for _, k := range allDetectors {
		out = append(out, e.evalDetector(k, st, obs, r, now))
	}
	return out
}

// evalDetector evaluates a single detector, updating its window. Caller holds e.mu.
func (e *Engine) evalDetector(k DetectorKind, st *scopeState, obs Observation, r resolved, now time.Time) DetectorResult {
	t := r.tunables
	switch k {
	case DetectorFanout:
		// Count distinct packages pulled in the trailing window. A successful or
		// failed pull both count: enumeration of names is itself fan-out.
		n := st.fanout.add(obs.Package, obs.Time, now, e.cfg.Window)
		return mkResult(k, float64(n), float64(t.FanoutWarn),
			ramp{warn: float64(t.FanoutWarn), high: float64(t.FanoutHigh)},
			fmt.Sprintf("%d distinct packages in %s", n, e.cfg.Window))

	case DetectorNewNamespace:
		// A namespace is "new" the first time this scope ever pulls from it. Count
		// how many distinct new namespaces appeared within the window.
		if obs.Namespace != "" {
			if _, seen := st.knownNS[obs.Namespace]; !seen {
				st.knownNS[obs.Namespace] = struct{}{}
				st.newNS.add(obs.Time, now, e.cfg.Window)
			}
		}
		n := st.newNS.count(now, e.cfg.Window)
		return mkResult(k, float64(n), float64(t.NewNamespaceWarn),
			ramp{warn: float64(t.NewNamespaceWarn), high: float64(t.NewNamespaceHigh)},
			fmt.Sprintf("%d new namespaces in %s", n, e.cfg.Window))

	case DetectorOffHours:
		// Count requests that fell within the configured off-hours interval.
		n := 0
		if e.isOffHours(obs.Time) {
			st.offHours.add(obs.Time, now, e.cfg.Window)
		}
		n = st.offHours.count(now, e.cfg.Window)
		return mkResult(k, float64(n), float64(t.OffHoursWarn),
			ramp{warn: float64(t.OffHoursWarn), high: float64(t.OffHoursHigh)},
			fmt.Sprintf("%d off-hours requests in %s", n, e.cfg.Window))

	case DetectorEnumeration:
		// Count 404 / negative-cache outcomes in the window.
		if obs.NotFound {
			st.enumeration.add(obs.Time, now, e.cfg.Window)
		}
		n := st.enumeration.count(now, e.cfg.Window)
		return mkResult(k, float64(n), float64(t.EnumerationWarn),
			ramp{warn: float64(t.EnumerationWarn), high: float64(t.EnumerationHigh)},
			fmt.Sprintf("%d negative lookups in %s", n, e.cfg.Window))

	case DetectorEgress:
		return e.evalEgress(st, obs, r, now)
	}
	return DetectorResult{Detector: k, Level: LevelNone}
}

// evalEgress scores windowed byte volume against the scope's own slowly-adapting
// EWMA baseline. It scores using the baseline *before* folding the current
// sample in, so the very transfer under test does not inflate the baseline it is
// compared against; the sample is then folded for future comparisons. It stays
// silent until warmed up and below a small absolute-volume floor so a quiet
// scope cannot alert on z-score noise.
func (e *Engine) evalEgress(st *scopeState, obs Observation, r resolved, now time.Time) DetectorResult {
	t := r.tunables
	vol := st.egress.add(obs.Bytes, obs.Time, now, e.cfg.Window)
	volF := float64(vol)

	var z float64
	mean := st.egressBase.mean
	if st.egressBase.ready(e.cfg.EgressWarmup) && vol >= e.cfg.EgressMinVolume {
		z = st.egressBase.zscore(volF, 1)
	}
	// Fold this window's volume into the baseline for subsequent observations.
	st.egressBase.update(volF)

	res := mkResult(DetectorEgress, z, t.EgressZWarn,
		ramp{warn: t.EgressZWarn, high: t.EgressZHigh},
		fmt.Sprintf("%s in %s vs baseline %s (z=%.1f)", humanBytes(vol), e.cfg.Window, humanBytes(int64(mean)), z))
	// Report the rolling mean as the baseline for the egress detector rather than
	// the warn cutoff, since that is the meaningful comparison point here.
	res.Baseline = round2(mean)
	return res
}

// mkResult builds a DetectorResult from a raw value, a warn baseline, the
// scoring ramp, and a human detail. It centralizes the score/level/triggered
// derivation so every detector is rendered identically.
func mkResult(k DetectorKind, value, baseline float64, rp ramp, detail string) DetectorResult {
	score, level := rp.eval(value)
	return DetectorResult{
		Detector:  k,
		Score:     round4(score),
		Level:     level,
		Value:     round2(value),
		Baseline:  round2(baseline),
		Triggered: value >= rp.warn,
		Detail:    detail,
	}
}

// isOffHours reports whether t falls inside the configured off-hours interval,
// interpreted in the configured location. A zero-width interval (start == end)
// is treated as "no off-hours", disabling the detector.
func (e *Engine) isOffHours(t time.Time) bool {
	start, end := e.cfg.OffHoursStart, e.cfg.OffHoursEnd
	if start == end {
		return false
	}
	h := t.In(e.cfg.Location).Hour()
	if start < end {
		return h >= start && h < end
	}
	// Wraps past midnight, e.g. start=20 end=6 → [20,24) ∪ [0,6).
	return h >= start || h < end
}

// recordTriggerLocked appends an alerting assessment to the bounded trigger
// ring. Caller holds e.mu.
func (e *Engine) recordTriggerLocked(a Assessment, now time.Time) {
	top := DetectorKind("")
	if len(a.Triggered) > 0 {
		top = a.Triggered[0]
	}
	tr := Trigger{
		Tenant:   a.Tenant,
		Identity: a.Identity,
		Scope:    a.Scope,
		Detector: top,
		Level:    a.Level,
		Action:   a.Action,
		Score:    a.Score,
		Summary:  a.Summary,
		At:       now,
	}
	e.history = append(e.history, tr)
	if len(e.history) > e.cfg.HistorySize {
		e.history = append(e.history[:0], e.history[len(e.history)-e.cfg.HistorySize:]...)
	}
}

// evictStaleLocked drops scopes idle longer than ScopeTTL. Caller holds e.mu.
func (e *Engine) evictStaleLocked(now time.Time) {
	cutoff := now.Add(-e.cfg.ScopeTTL)
	for key, st := range e.scopes {
		if st.updatedAt.Before(cutoff) {
			delete(e.scopes, key)
		}
	}
}

// enforceScopeCapLocked evicts the least-recently-updated scope while the map
// exceeds MaxScopes. Caller holds e.mu. This is an O(n) scan run only when the
// cap is exceeded, which a bounded, healthy deployment never reaches.
func (e *Engine) enforceScopeCapLocked() {
	for len(e.scopes) > e.cfg.MaxScopes {
		var oldestKey string
		var oldest time.Time
		first := true
		for key, st := range e.scopes {
			if first || st.updatedAt.Before(oldest) {
				oldestKey, oldest, first = key, st.updatedAt, false
			}
		}
		delete(e.scopes, oldestKey)
	}
}

// Snapshot returns the cumulative engine state for the admin API and metrics.
// The scopes are returned strongest-score-first and the triggers most-recent
// first.
func (e *Engine) Snapshot() Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()

	byLevel := make(map[string]int64, 4)
	for _, l := range []Level{LevelNone, LevelLow, LevelMedium, LevelHigh} {
		byLevel[string(l)] = e.byLevel[l]
	}
	triggers := make(map[string]int64, len(allDetectors))
	for _, k := range allDetectors {
		triggers[string(k)] = e.triggersByType[k]
	}

	scopes := make([]ScopeStatus, 0, len(e.scopes))
	for key, st := range e.scopes {
		scopes = append(scopes, st.status(key))
	}
	sort.SliceStable(scopes, func(i, j int) bool {
		if scopes[i].Score != scopes[j].Score {
			return scopes[i].Score > scopes[j].Score
		}
		return scopes[i].Scope < scopes[j].Scope
	})

	return Snapshot{
		Enabled:        e.cfg.Enabled,
		Observed:       e.observed,
		Alerts:         e.alerts,
		SoftBlocks:     e.softBlocks,
		ByLevel:        byLevel,
		TriggersByType: triggers,
		Threshold:      ThresholdInfo{WarnLevel: e.cfg.WarnLevel, BlockLevel: e.normalizedBlockLevel()},
		Window:         e.cfg.Window.String(),
		TrackedScopes:  len(e.scopes),
		Scopes:         scopes,
		Recent:         e.recentLocked(0),
	}
}

func (e *Engine) normalizedBlockLevel() Level {
	if e.cfg.BlockLevel == "" {
		return LevelNone
	}
	return e.cfg.BlockLevel
}

// Recent returns up to limit most-recent triggers, most-recent first. A
// non-positive limit returns the full retained history.
func (e *Engine) Recent(limit int) []Trigger {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.recentLocked(limit)
}

func (e *Engine) recentLocked(limit int) []Trigger {
	n := len(e.history)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Trigger, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, e.history[len(e.history)-1-i])
	}
	return out
}

// LevelCounts returns the cumulative count of assessments per level as float
// samples, for the metrics bridge. Every level is always present.
func (e *Engine) LevelCounts() map[string]float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]float64{
		string(LevelNone): 0, string(LevelLow): 0, string(LevelMedium): 0, string(LevelHigh): 0,
	}
	for l, n := range e.byLevel {
		out[string(l)] = float64(n)
	}
	return out
}

// TriggerCounts returns the cumulative trigger count per detector as float
// samples, for the metrics bridge. Every detector is always present.
func (e *Engine) TriggerCounts() map[string]float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]float64, len(allDetectors))
	for _, k := range allDetectors {
		out[string(k)] = float64(e.triggersByType[k])
	}
	return out
}

// DetectorScoreMax returns, per detector, the maximum current score across all
// tracked scopes (0 when no scope is tracked), for a saturation gauge. Every
// detector is always present.
func (e *Engine) DetectorScoreMax() map[string]float64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]float64, len(allDetectors))
	for _, k := range allDetectors {
		out[string(k)] = 0
	}
	for _, st := range e.scopes {
		for _, d := range st.lastDetectors {
			if d.Score > out[string(d.Detector)] {
				out[string(d.Detector)] = d.Score
			}
		}
	}
	return out
}

// Totals exposes the scalar cumulative counters for the metrics bridge.
func (e *Engine) Totals() (observed, alerts, softBlocks int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.observed, e.alerts, e.softBlocks
}

// --- helpers ----------------------------------------------------------------

// triggeredDetectors returns the kinds of the detectors that met their warn
// cutoff, strongest score first.
func triggeredDetectors(detectors []DetectorResult) []DetectorKind {
	ranked := make([]DetectorResult, 0, len(detectors))
	for _, d := range detectors {
		if d.Triggered {
			ranked = append(ranked, d)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].Score > ranked[j].Score })
	out := make([]DetectorKind, 0, len(ranked))
	for _, d := range ranked {
		out = append(out, d.Detector)
	}
	return out
}

// summarize produces a one-line, human-readable explanation naming the
// triggering detectors.
func summarize(a Assessment) string {
	if len(a.Triggered) == 0 {
		return fmt.Sprintf("anomaly %.0f/100 (%s) — no detectors triggered", a.Score, a.Level)
	}
	parts := make([]string, 0, len(a.Triggered))
	byKind := make(map[DetectorKind]DetectorResult, len(a.Detectors))
	for _, d := range a.Detectors {
		byKind[d.Detector] = d
	}
	for _, k := range a.Triggered {
		parts = append(parts, string(k))
		if len(parts) == 3 {
			break
		}
	}
	return fmt.Sprintf("anomaly %.0f/100 (%s) — triggered: %s", a.Score, a.Level, strings.Join(parts, ", "))
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// humanBytes renders a byte count compactly for detail strings.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
