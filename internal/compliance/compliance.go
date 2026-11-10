// Package compliance aggregates the proxy's security signals into an operator-
// facing continuous-compliance scorecard for audits.
//
// It periodically captures a Posture — a flat snapshot of the cumulative
// counters owned by the signature-verification (Task 23), provenance (Task 8 /
// 33), vulnerability (Task 15), license (Task 28), secret-detection (Task 29),
// air-gap/mirror (Task 17), and audit-transparency (Task 31) subsystems — and
// maps it onto a configurable control checklist and a SLSA build-level summary.
// The result, a Scorecard, is exposed as JSON/Markdown over the admin API, as a
// signed exportable artifact for auditors, and as per-control Prometheus gauges
// so the existing Grafana bundle can chart the compliance trend.
//
// The package is deliberately decoupled from the concrete subsystems: it takes a
// single Posture value (assembled by the wiring layer from each subsystem's
// snapshot) rather than importing them, which keeps the scorecard logic
// self-contained and trivially testable across mixed-signal fixtures.
package compliance

import (
	"sort"
	"time"
)

// Status is a control's evaluated state.
type Status string

const (
	// StatusPass means the control's posture meets the pass threshold.
	StatusPass Status = "pass"
	// StatusWarn means the posture is degraded but above the failing threshold.
	StatusWarn Status = "warn"
	// StatusFail means the control is not satisfied (below threshold, or a
	// required subsystem is disabled, or tamper was detected).
	StatusFail Status = "fail"
	// StatusNA means the control is not applicable to this deployment (explicitly
	// disabled, or an optional subsystem is off) and is excluded from scoring.
	StatusNA Status = "na"
)

// Posture is a flat, point-in-time capture of the security signals the scorecard
// aggregates. Every field is optional; the per-subsystem Enabled flags record
// whether that subsystem is active so a disabled-but-required control can be
// distinguished from one with no data yet. It carries no references to the
// concrete subsystems, so it can be constructed by the wiring layer or by tests.
type Posture struct {
	// CapturedAt is when the posture was sampled. Zero means "now" at compute time.
	CapturedAt time.Time `json:"capturedAt"`

	// Signature verification (Task 23).
	SigEnabled       bool  `json:"sigEnabled"`
	SigVerified      int64 `json:"sigVerified"`      // artifacts with a trusted signature
	SigUnsigned      int64 `json:"sigUnsigned"`      // artifacts with no signature material
	SigBlocked       int64 `json:"sigBlocked"`       // artifacts blocked by the signature gate
	SigVerifications int64 `json:"sigVerifications"` // total verifications performed

	// Provenance association (Task 8 / 33). The denominator is the number of
	// distinct cached artifacts (version nodes); the numerators count those with a
	// resolved source commit and/or a signer identity.
	ProvenanceEnabled       bool  `json:"provenanceEnabled"`
	ArtifactsTotal          int64 `json:"artifactsTotal"`
	ArtifactsWithProvenance int64 `json:"artifactsWithProvenance"`
	ArtifactsSigned         int64 `json:"artifactsSigned"`

	// Vulnerability gate (Task 15).
	VulnEnabled     bool  `json:"vulnEnabled"`
	VulnScans       int64 `json:"vulnScans"`
	VulnBlocked     int64 `json:"vulnBlocked"`
	VulnQuarantined int64 `json:"vulnQuarantined"`
	VulnCritical    int64 `json:"vulnCritical"`
	VulnHigh        int64 `json:"vulnHigh"`

	// License compliance (Task 28).
	LicenseEnabled   bool  `json:"licenseEnabled"`
	LicenseEvaluated int64 `json:"licenseEvaluated"`
	LicenseAllowed   int64 `json:"licenseAllowed"`
	LicenseDenied    int64 `json:"licenseDenied"`
	LicenseFlagged   int64 `json:"licenseFlagged"`

	// Secret detection (Task 29).
	SecretsEnabled      bool  `json:"secretsEnabled"`
	SecretsDiffsScanned int64 `json:"secretsDiffsScanned"`
	SecretsFindings     int64 `json:"secretsFindings"`

	// Air-gap / mirror sealedness (Task 17). Sealed is true when the proxy is
	// running in offline ("sealed") mode serving only mirrored content.
	Sealed bool `json:"sealed"`

	// Audit transparency (Task 31).
	AuditEnabled              bool  `json:"auditEnabled"`
	AuditTransparency         bool  `json:"auditTransparency"`
	AuditLastSealUnix         int64 `json:"auditLastSealUnix"`
	AuditVerificationFailures int64 `json:"auditVerificationFailures"`
	AuditChainLength          int64 `json:"auditChainLength"`
}

// Control is one evaluated control on the scorecard.
type Control struct {
	// ID is the stable control identifier (used as a metric label).
	ID string `json:"id"`
	// Title is the human-readable control name.
	Title string `json:"title"`
	// Category groups related controls (e.g. "supply-chain", "operational").
	Category string `json:"category"`
	// Frameworks lists the external control references this maps to (SLSA, SOC2).
	Frameworks []string `json:"frameworks,omitempty"`
	// Status is the evaluated state.
	Status Status `json:"status"`
	// Score is the 0..1 posture coverage that drove the status (1 for a satisfied
	// boolean control, 0 for an unsatisfied one).
	Score float64 `json:"score"`
	// Weight is the control's relative weight in the overall score (na controls
	// are excluded).
	Weight float64 `json:"weight"`
	// Required records whether a disabled underlying subsystem fails the control.
	Required bool `json:"required"`
	// Detail is a short human-readable explanation of the status.
	Detail string `json:"detail"`
	// Observed and Threshold are the measured value and the pass threshold, for
	// coverage-style controls (both 0 for boolean controls).
	Observed  float64 `json:"observed"`
	Threshold float64 `json:"threshold"`
}

// SLSASummary maps the posture onto an estimated SLSA build track/level.
type SLSASummary struct {
	// BuildLevel is the achieved SLSA build level (0..3).
	BuildLevel int `json:"buildLevel"`
	// Track is the human-readable track label, e.g. "Build L2".
	Track string `json:"track"`
	// Rationale explains why the level was (not) reached, and what the next level
	// requires.
	Rationale string `json:"rationale"`
	// Estimated is always true: the level is inferred from observed posture, not
	// asserted by a SLSA verifier, so auditors treat it as a self-assessment.
	Estimated bool `json:"estimated"`
}

// Scorecard is the computed compliance report for one posture sample.
type Scorecard struct {
	// GeneratedAt is when the scorecard was computed (UTC).
	GeneratedAt time.Time `json:"generatedAt"`
	// Version is the proxy version the report describes.
	Version string `json:"version,omitempty"`
	// Score is the weighted overall posture score (0..1) across applicable controls.
	Score float64 `json:"score"`
	// Grade is the letter grade derived from Score (A..F).
	Grade string `json:"grade"`
	// Status is the overall rollup: fail if any required control fails, else warn
	// if any control warns, else pass.
	Status Status `json:"status"`
	// Summary counts controls by status.
	Summary StatusCounts `json:"summary"`
	// SLSA is the estimated SLSA build-level summary.
	SLSA SLSASummary `json:"slsa"`
	// Controls is the evaluated control checklist, in a stable order.
	Controls []Control `json:"controls"`
	// Posture is the raw signal snapshot the scorecard was computed from, included
	// so an auditor can independently re-derive the result.
	Posture Posture `json:"posture"`
}

// StatusCounts tallies controls by status.
type StatusCounts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	NA   int `json:"na"`
}

// ControlConfig is the per-control tuning the operator can override.
type ControlConfig struct {
	// Disabled removes the control from the scorecard entirely (status na).
	Disabled bool `yaml:"disabled" json:"disabled"`
	// Required, when true, fails the control if its underlying subsystem is off;
	// when false, a disabled subsystem yields na. Nil keeps the built-in default.
	Required *bool `yaml:"required" json:"required,omitempty"`
	// Weight overrides the control's weight in the overall score (<=0 keeps the
	// default).
	Weight float64 `yaml:"weight" json:"weight,omitempty"`
	// PassThreshold and WarnThreshold override the coverage thresholds for
	// coverage-style controls (0 keeps the default). A control passes at or above
	// PassThreshold, warns at or above WarnThreshold, and fails below it.
	PassThreshold float64 `yaml:"passThreshold" json:"passThreshold,omitempty"`
	WarnThreshold float64 `yaml:"warnThreshold" json:"warnThreshold,omitempty"`
}

// Config tunes scorecard computation. The zero value is usable and yields the
// built-in default checklist.
type Config struct {
	// Version is the proxy version stamped onto each scorecard.
	Version string
	// MaxAuditSealAge bounds how stale the latest audit checkpoint may be before
	// the audit-transparency control warns/fails. Zero uses the default (1h).
	MaxAuditSealAge time.Duration
	// Controls holds per-control overrides keyed by control ID.
	Controls map[string]ControlConfig
	// Now returns the current time; nil uses time.Now. Injectable for tests.
	Now func() time.Time
}

// controlDef is the built-in definition of a control: its identity, framework
// mapping, default weight/requirement/thresholds, and the evaluator that turns a
// Posture into a (status, score, detail) verdict.
type controlDef struct {
	id         string
	title      string
	category   string
	frameworks []string
	required   bool
	weight     float64
	pass       float64 // default pass threshold (coverage controls)
	warn       float64 // default warn threshold (coverage controls)
	eval       func(p Posture, c controlDef, cfg Config) (Status, float64, float64, string)
}

// defaultMaxAuditSealAge is the default staleness bound for the audit-seal
// freshness control.
const defaultMaxAuditSealAge = time.Hour

// controlDefs is the ordered, built-in control checklist.
var controlDefs = []controlDef{
	{
		id: "signature-verification", title: "Verified artifact signatures",
		category: "supply-chain", frameworks: []string{"SLSA Build L2", "SOC2 CC7.1"},
		required: true, weight: 1.5, pass: 0.95, warn: 0.80,
		eval: evalSignature,
	},
	{
		id: "provenance-association", title: "Provenance / source-commit association",
		category: "supply-chain", frameworks: []string{"SLSA Build L1", "SOC2 CC8.1"},
		required: true, weight: 1.5, pass: 0.90, warn: 0.70,
		eval: evalProvenance,
	},
	{
		id: "vulnerability-gate", title: "Vulnerability (CVE) admission gate",
		category: "supply-chain", frameworks: []string{"SOC2 CC7.1"},
		required: true, weight: 1.0, pass: 0.95, warn: 0.85,
		eval: evalVuln,
	},
	{
		id: "license-compliance", title: "License compliance",
		category: "supply-chain", frameworks: []string{"SOC2 CC1.4"},
		required: false, weight: 1.0, pass: 0.95, warn: 0.85,
		eval: evalLicense,
	},
	{
		id: "secret-free", title: "Secret / credential-free commits",
		category: "supply-chain", frameworks: []string{"SOC2 CC6.1"},
		required: true, weight: 1.0, pass: 0.999, warn: 0.99,
		eval: evalSecrets,
	},
	{
		id: "air-gap-sealed", title: "Air-gap / mirror sealedness",
		category: "operational", frameworks: []string{"SOC2 CC6.6"},
		required: false, weight: 0.5,
		eval: evalSealed,
	},
	{
		id: "audit-transparency", title: "Tamper-evident audit log freshness",
		category: "operational", frameworks: []string{"SLSA Build L3", "SOC2 CC7.2"},
		required: true, weight: 1.0,
		eval: evalAudit,
	},
}

// Compute evaluates the posture against the (optionally overridden) control
// checklist and returns the resulting Scorecard.
func Compute(p Posture, cfg Config) Scorecard {
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	if p.CapturedAt.IsZero() {
		p.CapturedAt = now()
	}

	controls := make([]Control, 0, len(controlDefs))
	var weightedSum, weightTotal float64
	var counts StatusCounts

	for _, def := range controlDefs {
		oc := cfg.Controls[def.id]
		required := def.required
		if oc.Required != nil {
			required = *oc.Required
		}
		weight := def.weight
		if oc.Weight > 0 {
			weight = oc.Weight
		}
		effective := def // copy so per-control threshold overrides don't leak
		effective.required = required
		if oc.PassThreshold > 0 {
			effective.pass = oc.PassThreshold
		}
		if oc.WarnThreshold > 0 {
			effective.warn = oc.WarnThreshold
		}

		ctrl := Control{
			ID: def.id, Title: def.title, Category: def.category,
			Frameworks: def.frameworks, Weight: weight, Required: required,
		}

		if oc.Disabled {
			ctrl.Status = StatusNA
			ctrl.Detail = "control disabled by configuration"
		} else {
			status, score, observed, detail := def.eval(p, effective, cfg)
			ctrl.Status, ctrl.Score, ctrl.Observed, ctrl.Detail = status, score, observed, detail
			ctrl.Threshold = effective.pass
		}

		switch ctrl.Status {
		case StatusPass:
			counts.Pass++
		case StatusWarn:
			counts.Warn++
		case StatusFail:
			counts.Fail++
		case StatusNA:
			counts.NA++
		}
		if ctrl.Status != StatusNA {
			weightedSum += ctrl.Score * weight
			weightTotal += weight
		}
		controls = append(controls, ctrl)
	}

	overall := 0.0
	if weightTotal > 0 {
		overall = weightedSum / weightTotal
	}

	card := Scorecard{
		GeneratedAt: now().UTC(),
		Version:     cfg.Version,
		Score:       overall,
		Grade:       grade(overall),
		Status:      rollup(controls),
		Summary:     counts,
		Controls:    controls,
		Posture:     p,
	}
	card.SLSA = slsaSummary(controls)
	return card
}

// rollup derives the overall status: fail if any required control fails, else
// warn if any control warns or a non-required control fails, else pass.
func rollup(controls []Control) Status {
	worst := StatusPass
	for _, c := range controls {
		switch c.Status {
		case StatusFail:
			if c.Required {
				return StatusFail
			}
			if worst == StatusPass {
				worst = StatusWarn
			}
		case StatusWarn:
			if worst == StatusPass {
				worst = StatusWarn
			}
		}
	}
	return worst
}

// grade maps a 0..1 score onto a letter grade.
func grade(score float64) string {
	switch {
	case score >= 0.90:
		return "A"
	case score >= 0.80:
		return "B"
	case score >= 0.70:
		return "C"
	case score >= 0.60:
		return "D"
	default:
		return "F"
	}
}

// controlByID returns the evaluated control with the given id (and whether found).
func controlByID(controls []Control, id string) (Control, bool) {
	for _, c := range controls {
		if c.ID == id {
			return c, true
		}
	}
	return Control{}, false
}

// passOrWarn reports whether a control reached at least a warn (i.e. not fail/na).
func passOrWarn(controls []Control, id string) bool {
	c, ok := controlByID(controls, id)
	return ok && (c.Status == StatusPass || c.Status == StatusWarn)
}

func passed(controls []Control, id string) bool {
	c, ok := controlByID(controls, id)
	return ok && c.Status == StatusPass
}

// slsaSummary infers an estimated SLSA build level from the evaluated controls.
// The mapping is a conservative self-assessment, not a verifier's assertion:
//   - L1 requires provenance to exist (provenance-association satisfied),
//   - L2 additionally requires authenticated provenance (signatures verified),
//   - L3 additionally requires a tamper-evident, fresh audit trail.
func slsaSummary(controls []Control) SLSASummary {
	level := 0
	rationale := "no provenance association established yet"
	if passOrWarn(controls, "provenance-association") {
		level = 1
		rationale = "provenance is associated but signatures are not consistently verified (L2 requires verified signatures)"
		if passed(controls, "signature-verification") {
			level = 2
			rationale = "authenticated provenance verified; a fresh tamper-evident audit trail is required for L3"
			if passed(controls, "audit-transparency") {
				level = 3
				rationale = "authenticated provenance and a fresh tamper-evident audit trail are in place"
			}
		}
	}
	return SLSASummary{
		BuildLevel: level,
		Track:      "Build L" + itoa(level),
		Rationale:  rationale,
		Estimated:  true,
	}
}

// --- per-control evaluators -------------------------------------------------

// coverageStatus classifies a 0..1 coverage value against a control's thresholds.
func coverageStatus(cov float64, def controlDef) Status {
	switch {
	case cov >= def.pass:
		return StatusPass
	case cov >= def.warn:
		return StatusWarn
	default:
		return StatusFail
	}
}

// disabledControl returns the status for a control whose subsystem is off: fail
// when required, na otherwise.
func disabledControl(def controlDef, what string) (Status, float64, float64, string) {
	if def.required {
		return StatusFail, 0, 0, what + " is disabled (control is required)"
	}
	return StatusNA, 0, 0, what + " is disabled"
}

func evalSignature(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if !p.SigEnabled {
		return disabledControl(def, "signature verification")
	}
	evaluated := p.SigVerified + p.SigUnsigned
	if evaluated == 0 {
		return StatusPass, 1, 1, "no artifacts evaluated yet"
	}
	cov := float64(p.SigVerified) / float64(evaluated)
	detail := pctDetail(p.SigVerified, evaluated, "artifacts carry a verified, trusted signature")
	if p.SigBlocked > 0 {
		detail += "; " + itoa64(p.SigBlocked) + " blocked by the gate"
	}
	return coverageStatus(cov, def), cov, cov, detail
}

func evalProvenance(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if !p.ProvenanceEnabled {
		return disabledControl(def, "provenance association")
	}
	if p.ArtifactsTotal == 0 {
		return StatusPass, 1, 1, "no artifacts cached yet"
	}
	cov := float64(p.ArtifactsWithProvenance) / float64(p.ArtifactsTotal)
	detail := pctDetail(p.ArtifactsWithProvenance, p.ArtifactsTotal, "cached artifacts have an associated source commit")
	return coverageStatus(cov, def), cov, cov, detail
}

func evalVuln(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if !p.VulnEnabled {
		return disabledControl(def, "vulnerability scanning")
	}
	if p.VulnScans == 0 {
		return StatusPass, 1, 1, "no artifacts scanned yet"
	}
	clean := p.VulnScans - p.VulnBlocked
	if clean < 0 {
		clean = 0
	}
	cov := float64(clean) / float64(p.VulnScans)
	detail := pctDetail(clean, p.VulnScans, "scanned artifacts passed the vulnerability gate")
	if p.VulnBlocked > 0 {
		detail += "; " + itoa64(p.VulnBlocked) + " blocked"
	}
	if p.VulnQuarantined > 0 {
		detail += ", " + itoa64(p.VulnQuarantined) + " quarantined"
	}
	return coverageStatus(cov, def), cov, cov, detail
}

func evalLicense(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if !p.LicenseEnabled {
		return disabledControl(def, "license compliance")
	}
	if p.LicenseEvaluated == 0 {
		return StatusPass, 1, 1, "no artifacts evaluated yet"
	}
	cov := float64(p.LicenseAllowed) / float64(p.LicenseEvaluated)
	detail := pctDetail(p.LicenseAllowed, p.LicenseEvaluated, "evaluated artifacts are license-clean")
	if p.LicenseDenied > 0 {
		detail += "; " + itoa64(p.LicenseDenied) + " denied"
	}
	if p.LicenseFlagged > 0 {
		detail += ", " + itoa64(p.LicenseFlagged) + " flagged"
	}
	return coverageStatus(cov, def), cov, cov, detail
}

func evalSecrets(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if !p.SecretsEnabled {
		return disabledControl(def, "secret detection")
	}
	if p.SecretsDiffsScanned == 0 {
		return StatusPass, 1, 1, "no commits scanned yet"
	}
	// Coverage is the fraction of scanned diffs that produced no finding. Since the
	// detector reports total findings rather than findings-bearing diffs, we cap
	// the finding count at the diff count so coverage stays in [0,1]; the headline
	// remains "are commits coming through clean of secrets".
	findings := p.SecretsFindings
	if findings > p.SecretsDiffsScanned {
		findings = p.SecretsDiffsScanned
	}
	clean := p.SecretsDiffsScanned - findings
	cov := float64(clean) / float64(p.SecretsDiffsScanned)
	detail := "no secrets detected across " + itoa64(p.SecretsDiffsScanned) + " scanned commit diffs"
	if p.SecretsFindings > 0 {
		detail = itoa64(p.SecretsFindings) + " secret finding(s) across " + itoa64(p.SecretsDiffsScanned) + " scanned commit diffs"
	}
	return coverageStatus(cov, def), cov, cov, detail
}

func evalSealed(p Posture, def controlDef, _ Config) (Status, float64, float64, string) {
	if p.Sealed {
		return StatusPass, 1, 0, "running in sealed (air-gapped) mode; only mirrored content is served"
	}
	// An un-sealed proxy is the normal connected mode, not a failure: report na so
	// it is informational unless an operator explicitly marks the control required.
	if def.required {
		return StatusFail, 0, 0, "proxy is not sealed (air-gapped) but the control is required"
	}
	return StatusNA, 0, 0, "running in connected mode (not air-gapped)"
}

func evalAudit(p Posture, def controlDef, cfg Config) (Status, float64, float64, string) {
	if !p.AuditEnabled {
		return disabledControl(def, "audit logging")
	}
	// Any detected verification failure is a hard fail regardless of freshness: it
	// indicates the tamper-evident chain or a proof did not verify.
	if p.AuditVerificationFailures > 0 {
		return StatusFail, 0, 0, itoa64(p.AuditVerificationFailures) + " audit verification failure(s) detected — possible tampering"
	}
	if !p.AuditTransparency {
		// Hash chain present but no Merkle transparency / signed checkpoints.
		return StatusWarn, 0.5, 0, "audit hash chain active but Merkle transparency (signed checkpoints) is not enabled"
	}
	maxAge := cfg.MaxAuditSealAge
	if maxAge <= 0 {
		maxAge = defaultMaxAuditSealAge
	}
	if p.AuditLastSealUnix == 0 {
		return StatusWarn, 0.5, 0, "transparency enabled but no checkpoint has been sealed yet"
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	age := now().Unix() - p.AuditLastSealUnix
	if age < 0 {
		age = 0
	}
	switch {
	case time.Duration(age)*time.Second <= maxAge:
		return StatusPass, 1, 0, "latest audit checkpoint sealed " + humanizeAge(age) + " ago"
	case time.Duration(age)*time.Second <= 2*maxAge:
		return StatusWarn, 0.5, 0, "latest audit checkpoint is stale (sealed " + humanizeAge(age) + " ago)"
	default:
		return StatusFail, 0, 0, "audit checkpoint sealing has stalled (last seal " + humanizeAge(age) + " ago)"
	}
}

// SortedControlIDs returns the built-in control IDs in their canonical order.
// Useful for callers that pre-register a metric series per control.
func SortedControlIDs() []string {
	ids := make([]string, 0, len(controlDefs))
	for _, d := range controlDefs {
		ids = append(ids, d.id)
	}
	return ids
}

// SortedFrameworks returns the distinct framework references across all controls,
// sorted, for documentation/UX.
func SortedFrameworks() []string {
	seen := map[string]struct{}{}
	for _, d := range controlDefs {
		for _, f := range d.frameworks {
			seen[f] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
