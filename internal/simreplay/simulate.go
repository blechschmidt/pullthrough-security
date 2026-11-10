package simreplay

import (
	"sort"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/riskscore"
)

// Flip classifies how a record's admit/block outcome changed under the candidate.
type Flip string

const (
	FlipNone        Flip = ""
	FlipNowBlocked  Flip = "now-blocked"  // baseline admitted, candidate blocks
	FlipNowAdmitted Flip = "now-admitted" // baseline blocked, candidate admits
)

// Shift classifies how a record's risk band moved under the candidate.
type Shift string

const (
	ShiftNone Shift = ""
	ShiftUp   Shift = "up"   // riskier band
	ShiftDown Shift = "down" // safer band
)

// Options tunes a replay run.
type Options struct {
	// Baseline, when set, recomputes each record's baseline verdict instead of
	// using the verdict captured live. This lets an operator diff two candidate
	// configs (baseline vs candidate) rather than candidate-vs-production.
	Baseline Evaluator
	// IncludeRecords includes per-record diffs in the report. When false the report
	// carries only the summary and per-tenant aggregates (the compact form).
	IncludeRecords bool
	// OnlyChanged, when including records, limits them to records whose verdict
	// changed (a flip, a band shift, or a policy-ruleset change). Defaults applied
	// by the caller; the zero value includes every record.
	OnlyChanged bool
	// MaxRecords caps the number of per-record diffs included (0 = no cap). The cap
	// is applied after filtering, keeping the earliest-captured records.
	MaxRecords int
	// Now stamps the report's GeneratedAt; defaults to time.Now.
	Now func() time.Time
}

// RecordDiff is the per-record outcome of replaying one captured event through
// the candidate configuration.
type RecordDiff struct {
	Seq        int64   `json:"seq"`
	Tenant     string  `json:"tenant,omitempty"`
	Coordinate string  `json:"coordinate,omitempty"`
	Baseline   Verdict `json:"baseline"`
	Candidate  Verdict `json:"candidate"`
	// Changed is true when the candidate's admission-relevant outcome differs from
	// the baseline (flip, band shift, or a change in matched deny rules).
	Changed bool `json:"changed"`
	// Flip is the admit<->block transition, if any.
	Flip Flip `json:"flip,omitempty"`
	// BandShift is the risk-band transition, if any (both engines risk-enabled).
	BandShift Shift `json:"bandShift,omitempty"`
	// ScoreDelta is candidate.RiskScore - baseline.RiskScore (0 when not scored).
	ScoreDelta int `json:"scoreDelta"`
	// NewDenyRules are policy rules that deny under the candidate but did not match
	// in the baseline — the "new policy violations".
	NewDenyRules []string `json:"newDenyRules,omitempty"`
	// ClearedRules are rules that matched in the baseline but no longer match.
	ClearedRules []string `json:"clearedRules,omitempty"`
}

// Summary is the aggregate diff across every replayed record.
type Summary struct {
	Total            int `json:"total"`
	Changed          int `json:"changed"`
	Unchanged        int `json:"unchanged"`
	Flips            int `json:"flips"`
	NowBlocked       int `json:"nowBlocked"`
	NowAdmitted      int `json:"nowAdmitted"`
	BandShifts       int `json:"bandShifts"`
	BandUp           int `json:"bandUp"`
	BandDown         int `json:"bandDown"`
	NewViolations    int `json:"newViolations"`
	BaselineBlocked  int `json:"baselineBlocked"`
	CandidateBlocked int `json:"candidateBlocked"`
}

// TenantDiff aggregates the diff for one tenant, exposing blast radius — the
// fraction of that tenant's captured pulls whose outcome the candidate changes.
type TenantDiff struct {
	Tenant        string  `json:"tenant"`
	Total         int     `json:"total"`
	Changed       int     `json:"changed"`
	NowBlocked    int     `json:"nowBlocked"`
	NowAdmitted   int     `json:"nowAdmitted"`
	BandShifts    int     `json:"bandShifts"`
	NewViolations int     `json:"newViolations"`
	BlastRadius   float64 `json:"blastRadius"` // Changed / Total, rounded to 4 dp
}

// DiffReport is the result of a replay run.
type DiffReport struct {
	GeneratedAt time.Time    `json:"generatedAt"`
	Summary     Summary      `json:"summary"`
	Tenants     []TenantDiff `json:"tenants"`
	Records     []RecordDiff `json:"records,omitempty"`
}

// Run replays every captured record through the candidate evaluator and returns
// the diff against each record's baseline. It is deterministic: records are
// processed in capture order, tenants are emitted lexicographically, and the
// candidate evaluator is required to be pure.
func Run(records []Record, candidate Evaluator, opts Options) DiffReport {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	report := DiffReport{GeneratedAt: now()}
	tenantAgg := map[string]*TenantDiff{}

	// diffs holds every record diff; we filter into report.Records afterward so the
	// summary and per-tenant aggregates always reflect the full corpus.
	diffs := make([]RecordDiff, 0, len(records))

	for _, rec := range records {
		baseline := rec.Baseline
		if opts.Baseline != nil {
			baseline = opts.Baseline.Evaluate(rec.Input)
		}
		cand := candidate.Evaluate(rec.Input)
		d := diffRecord(rec, baseline, cand)
		diffs = append(diffs, d)

		// Summary.
		report.Summary.Total++
		if baseline.Blocked() {
			report.Summary.BaselineBlocked++
		}
		if cand.Blocked() {
			report.Summary.CandidateBlocked++
		}
		if d.Changed {
			report.Summary.Changed++
		} else {
			report.Summary.Unchanged++
		}
		switch d.Flip {
		case FlipNowBlocked:
			report.Summary.Flips++
			report.Summary.NowBlocked++
		case FlipNowAdmitted:
			report.Summary.Flips++
			report.Summary.NowAdmitted++
		}
		switch d.BandShift {
		case ShiftUp:
			report.Summary.BandShifts++
			report.Summary.BandUp++
		case ShiftDown:
			report.Summary.BandShifts++
			report.Summary.BandDown++
		}
		if len(d.NewDenyRules) > 0 {
			report.Summary.NewViolations++
		}

		// Per-tenant aggregate.
		key := rec.Tenant
		td := tenantAgg[key]
		if td == nil {
			td = &TenantDiff{Tenant: key}
			tenantAgg[key] = td
		}
		td.Total++
		if d.Changed {
			td.Changed++
		}
		if d.Flip == FlipNowBlocked {
			td.NowBlocked++
		}
		if d.Flip == FlipNowAdmitted {
			td.NowAdmitted++
		}
		if d.BandShift != ShiftNone {
			td.BandShifts++
		}
		if len(d.NewDenyRules) > 0 {
			td.NewViolations++
		}
	}

	// Emit tenants lexicographically with computed blast radius.
	report.Tenants = make([]TenantDiff, 0, len(tenantAgg))
	for _, td := range tenantAgg {
		if td.Total > 0 {
			td.BlastRadius = round4(float64(td.Changed) / float64(td.Total))
		}
		report.Tenants = append(report.Tenants, *td)
	}
	sort.Slice(report.Tenants, func(i, j int) bool {
		return report.Tenants[i].Tenant < report.Tenants[j].Tenant
	})

	if opts.IncludeRecords {
		report.Records = filterRecords(diffs, opts)
	}
	return report
}

func filterRecords(diffs []RecordDiff, opts Options) []RecordDiff {
	out := make([]RecordDiff, 0, len(diffs))
	for _, d := range diffs {
		if opts.OnlyChanged && !d.Changed {
			continue
		}
		out = append(out, d)
		if opts.MaxRecords > 0 && len(out) >= opts.MaxRecords {
			break
		}
	}
	return out
}

// diffRecord computes the per-record diff of candidate against baseline.
func diffRecord(rec Record, baseline, candidate Verdict) RecordDiff {
	d := RecordDiff{
		Seq:        rec.Seq,
		Tenant:     rec.Tenant,
		Coordinate: rec.Coordinate,
		Baseline:   baseline,
		Candidate:  candidate,
		ScoreDelta: candidate.RiskScore - baseline.RiskScore,
	}

	// Admit/block flip.
	switch {
	case !baseline.Blocked() && candidate.Blocked():
		d.Flip = FlipNowBlocked
	case baseline.Blocked() && !candidate.Blocked():
		d.Flip = FlipNowAdmitted
	}

	// Risk-band shift, only when both verdicts scored risk.
	if baseline.RiskEnabled && candidate.RiskEnabled {
		br, cr := bandRank(baseline.RiskBand), bandRank(candidate.RiskBand)
		switch {
		case cr > br:
			d.BandShift = ShiftUp
		case cr < br:
			d.BandShift = ShiftDown
		}
	}

	// Policy ruleset delta.
	baseSet := baseline.ruleIDSet()
	for _, m := range candidate.PolicyMatches {
		if _, ok := baseSet[m.RuleID]; !ok && m.Action == policyengine.ActionDeny {
			d.NewDenyRules = append(d.NewDenyRules, m.RuleID)
		}
	}
	candSet := candidate.ruleIDSet()
	for _, m := range baseline.PolicyMatches {
		if _, ok := candSet[m.RuleID]; !ok {
			d.ClearedRules = append(d.ClearedRules, m.RuleID)
		}
	}

	d.Changed = d.Flip != FlipNone || d.BandShift != ShiftNone ||
		len(d.NewDenyRules) > 0 || len(d.ClearedRules) > 0
	return d
}

// bandRank ranks a risk band for shift comparison; an empty/unknown band ranks
// below low so an artifact that gains a band still registers as a shift up.
func bandRank(b riskscore.Band) int {
	switch b {
	case riskscore.BandCritical:
		return 3
	case riskscore.BandHigh:
		return 2
	case riskscore.BandMedium:
		return 1
	case riskscore.BandLow:
		return 0
	default:
		return -1
	}
}

func round4(v float64) float64 {
	return float64(int64(v*10000+0.5)) / 10000
}
