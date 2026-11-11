package llmpkgscan

import (
	"fmt"
	"math"
	"strings"
)

// Disposition is how the gate reads an artifact once the thresholds and the
// deterministic checks have been applied to the model's verdict.
type Disposition string

const (
	// DispositionMalicious: the model called it malicious with enough confidence.
	DispositionMalicious Disposition = "malicious"
	// DispositionSuspicious: flagged, but short of malicious.
	DispositionSuspicious Disposition = "suspicious"
	// DispositionBenign: nothing held against it.
	DispositionBenign Disposition = "benign"
	// DispositionUnscanned: there is no verdict.
	DispositionUnscanned Disposition = "unscanned"
)

// Stable rule identifiers. They mirror the findings catalog (internal/findings)
// without importing it, so this package stays a leaf.
const (
	RuleMaliciousPackage  = "llmpkgscan/malicious-package"
	RuleSuspiciousPackage = "llmpkgscan/suspicious-package"
	RuleScanIncomplete    = "llmpkgscan/scan-incomplete"
)

// Policy codes a refusal carries in X-Policy-Code.
const (
	PolicyCodeMalicious  = "llm-package-malicious"
	PolicyCodeSuspicious = "llm-package-suspicious"
	PolicyCodeUnscanned  = "llm-package-unscanned"
)

// Finding categories.
const (
	CategoryMalicious       = "malicious-package"
	CategorySuspicious      = "suspicious-package"
	CategoryPromptInjection = "prompt-injection"
	CategoryArchiveAnomaly  = "archive-anomaly"
	CategoryScanIncomplete  = "scan-incomplete"
)

// Finding is one result in catalog form.
type Finding struct {
	RuleID   string `json:"ruleId"`
	Category string `json:"category"`
	// Severity is info|low|medium|high|critical.
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	// File and Line locate the finding inside the package, when known.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// maxFindingsPerReport bounds the findings one report emits.
const maxFindingsPerReport = 8

// classify reads a stored verdict under the configured thresholds.
//
// A "malicious" verdict is never read as benign, however unsure the model was:
// below the malicious threshold it is held as suspicious. A "suspicious" verdict
// below the suspicious threshold is the one case a threshold lets through — that
// is what the threshold is for. Two deterministic facts can then only make a
// disposition worse, never better: content that addresses the scanner, and an
// archive built to attack whatever extracts it. Both are established by the
// proxy, after the model has answered, so neither can be argued away by the
// content under review.
func (s *Service) classify(v *Verdict) (Disposition, string) {
	disp, reason := DispositionBenign, "the model found nothing indicating harm"
	switch v.Verdict {
	case VerdictMalicious:
		if v.Confidence >= s.cfg.MaliciousThreshold {
			disp, reason = DispositionMalicious, fmt.Sprintf("the model judged the package malicious (confidence %.2f)", v.Confidence)
		} else {
			// A malicious call the model is unsure of is still a flag: it is held as
			// suspicious however low the confidence.
			disp, reason = DispositionSuspicious, fmt.Sprintf("the model judged the package malicious with confidence %.2f, below the %.2f threshold", v.Confidence, s.cfg.MaliciousThreshold)
		}
	case VerdictSuspicious:
		if v.Confidence >= s.cfg.SuspiciousThreshold {
			disp, reason = DispositionSuspicious, fmt.Sprintf("the model judged the package suspicious (confidence %.2f)", v.Confidence)
		} else {
			reason = fmt.Sprintf("the model's suspicion (confidence %.2f) is below the %.2f threshold", v.Confidence, s.cfg.SuspiciousThreshold)
		}
	}
	if disp == DispositionBenign {
		switch {
		case hasStrongInjection(v.Injection):
			disp, reason = DispositionSuspicious, "the package contains text addressed to the scanner; a clean verdict is not accepted from content that tries to steer its own review"
		case v.StructuralRisk:
			disp, reason = DispositionSuspicious, "the archive is built to attack an extractor (a path or link escaping the package root, or a decompression bomb)"
		}
	}
	return disp, reason
}

// report builds the per-request report for a stored verdict.
func (s *Service) report(art Artifact, v *Verdict) *Report {
	rep := &Report{Artifact: art, Verdict: v}
	rep.Disposition, rep.Reason = s.classify(v)
	rep.Risk = riskFor(rep.Disposition, v.Confidence)
	rep.Findings = findingsFor(rep.Disposition, v)
	return rep
}

// unscanned builds the report for an artifact with no verdict. detail is the
// diagnostic behind the failure; what the report says publicly is the fixed
// sentence for the code.
func (s *Service) unscanned(art Artifact, code, detail string) *Report {
	content := contentAttributable(code)
	reason := publicReason(code)
	rep := &Report{
		Artifact:    art,
		Disposition: DispositionUnscanned,
		Reason:      reason,
		Unscanned:   &Unscanned{Code: code, Reason: reason, Detail: cleanText(detail, 300), Content: content, Transient: transient(code)},
	}
	if content {
		// The artifact itself defeated the scan. That is reported as a finding so
		// it is visible wherever findings are — an artifact that cannot be examined
		// must not look the same as one that was examined and found clean.
		rep.Risk = 25
		rep.Findings = []Finding{{
			RuleID:   RuleScanIncomplete,
			Category: CategoryScanIncomplete,
			Severity: "low",
			Title:    "Package was not examined by the LLM content scan (" + code + ")",
			Detail:   reason,
		}}
	}
	return rep
}

// riskFor maps a disposition onto the ordinal 0..100 risk contribution.
func riskFor(d Disposition, confidence float64) int {
	c := clamp01(confidence)
	switch d {
	case DispositionMalicious:
		return int(math.Round(80 + 20*c))
	case DispositionSuspicious:
		return int(math.Round(40 + 30*c))
	default:
		return 0
	}
}

// findingsFor renders a verdict as catalog findings: one per cited location (so
// a SARIF consumer can annotate the file and line), plus one for each
// deterministic indicator.
func findingsFor(d Disposition, v *Verdict) []Finding {
	if d != DispositionMalicious && d != DispositionSuspicious {
		return nil
	}
	rule, category, severity := RuleSuspiciousPackage, CategorySuspicious, "medium"
	switch {
	case d == DispositionMalicious:
		rule, category, severity = RuleMaliciousPackage, CategoryMalicious, "critical"
	case v.Verdict == VerdictMalicious:
		severity = "high" // called malicious, held as suspicious by the threshold
	}
	title := fmt.Sprintf("LLM content scan: package judged %s (confidence %.2f)", v.Verdict, v.Confidence)
	// The model's reasons are model output, shaped by the package under review.
	// They are carried as detail for the analyst and labeled for what they are.
	detail := ""
	if len(v.Reasons) > 0 {
		detail = "Reasons stated by the model: " + strings.Join(v.Reasons, " ")
	}

	var out []Finding
	modelFlagged := v.Verdict != VerdictBenign
	if modelFlagged {
		for _, ev := range v.Evidence {
			if len(out) >= maxFindingsPerReport-2 {
				break
			}
			out = append(out, Finding{RuleID: rule, Category: category, Severity: severity, Title: title, Detail: detail, File: ev.Path, Line: ev.Line})
		}
		if len(out) == 0 {
			out = append(out, Finding{RuleID: rule, Category: category, Severity: severity, Title: title, Detail: detail})
		}
	}
	if hits := strongHits(v.Injection); len(hits) > 0 {
		h := hits[0]
		rules := make([]string, 0, len(hits))
		seen := map[string]bool{}
		for _, hit := range hits {
			if !seen[hit.Rule] {
				seen[hit.Rule] = true
				rules = append(rules, hit.Rule)
			}
		}
		out = append(out, Finding{
			RuleID:   RuleSuspiciousPackage,
			Category: CategoryPromptInjection,
			Severity: "high",
			Title:    "Package content addresses the scanner (prompt injection)",
			Detail:   "Deterministic indicators: " + strings.Join(rules, ", ") + ".",
			File:     h.Path,
			Line:     h.Line,
		})
	}
	if v.StructuralRisk {
		out = append(out, Finding{
			RuleID:   RuleSuspiciousPackage,
			Category: CategoryArchiveAnomaly,
			Severity: "high",
			Title:    "Archive is built to attack an extractor",
			Detail:   strings.Join(v.Anomalies, "; "),
		})
	}
	return out
}

func strongHits(hits []InjectionHit) []InjectionHit {
	var out []InjectionHit
	for _, h := range hits {
		if h.Strong {
			out = append(out, h)
		}
	}
	return out
}

// refusesDisposition reports whether an action refuses an artifact the gate
// reads as d. It is the action matrix documented on Gate, in one place.
func (a Action) refusesDisposition(d Disposition) bool {
	switch d {
	case DispositionMalicious:
		return a.Refuses()
	case DispositionSuspicious:
		return a == ActionQuarantine
	}
	return false
}

// Standing is how the gate, as configured right now, treats a stored verdict:
// what a pull of those bytes would be told. It is for the read side (the
// dossier, the admin surface): it applies the current thresholds and action to
// a verdict without scanning anything or touching the metrics.
type Standing struct {
	Disposition Disposition `json:"disposition"`
	// Reason is the proxy's one-line explanation of the disposition.
	Reason string `json:"reason"`
	// Action is the configured action.
	Action Action `json:"action"`
	// Refused reports whether a pull of the artifact is refused.
	Refused bool `json:"refused"`
	// Risk is the ordinal 0..100 risk contribution.
	Risk int `json:"risk"`
}

// Standing returns the gate's current reading of a stored verdict. Safe on a
// nil Service (it then reports the verdict's own category and refuses nothing).
func (s *Service) Standing(v *Verdict) Standing {
	if v == nil {
		return Standing{Disposition: DispositionUnscanned}
	}
	if s == nil {
		return Standing{Disposition: Disposition(v.Verdict), Action: ActionAnnotate}
	}
	disp, reason := s.classify(v)
	return Standing{
		Disposition: disp,
		Reason:      reason,
		Action:      s.cfg.Action,
		Refused:     s.cfg.Action.refusesDisposition(disp),
		Risk:        riskFor(disp, v.Confidence),
	}
}

// Outcome is the admission decision.
type Outcome string

const (
	// OutcomeAllow serves the artifact.
	OutcomeAllow Outcome = "allow"
	// OutcomeRefuse refuses it.
	OutcomeRefuse Outcome = "refuse"
)

// Decision is the admission verdict for a report.
type Decision struct {
	Outcome Outcome `json:"outcome"`
	// Action is the configured action the decision reflects, or "fail-open" /
	// "fail-closed" for an unscanned artifact.
	Action string `json:"action"`
	// Evict reports whether the cached artifact should be removed (quarantined).
	Evict bool `json:"evict"`
	// Code is the short machine-readable result: the disposition, or the reason
	// code of an unscanned artifact.
	Code string `json:"code"`
	// PolicyCode is the X-Policy-Code value of a refusal.
	PolicyCode string `json:"policyCode,omitempty"`
	// Reason is a human-readable explanation.
	Reason string `json:"reason"`
}

// Served reports whether the decision permits serving the artifact.
func (d Decision) Served() bool { return d.Outcome == OutcomeAllow }

// Gate applies the configured action and fail mode to a report, folding the
// result into the metrics. A nil report (the gate did not apply) allows.
//
//	disposition   annotate   block            quarantine
//	malicious     serve      refuse + evict   refuse + evict
//	suspicious    serve      serve (advised)  refuse + evict (held for review)
//	benign        serve      serve            serve
//	unscanned     fail mode: open serves, closed refuses (nothing is evicted)
func (s *Service) Gate(rep *Report) Decision {
	if s == nil || rep == nil {
		return Decision{Outcome: OutcomeAllow, Code: string(DispositionBenign)}
	}
	if rep.Unscanned != nil {
		// No verdict: the fail mode decides, whatever the action. Nothing was
		// established about the artifact, so nothing is evicted.
		if s.cfg.FailMode == FailClosed {
			s.failedClosed.Add(1)
			return Decision{
				Outcome:    OutcomeRefuse,
				Action:     "fail-closed",
				Code:       rep.Unscanned.Code,
				PolicyCode: PolicyCodeUnscanned,
				Reason:     "the package could not be scanned (" + rep.Unscanned.Code + "): " + rep.Unscanned.Reason + "; refused under the fail-closed policy",
			}
		}
		s.failedOpen.Add(1)
		return Decision{
			Outcome: OutcomeAllow,
			Action:  "fail-open",
			Code:    rep.Unscanned.Code,
			Reason:  "the package could not be scanned (" + rep.Unscanned.Code + "): " + rep.Unscanned.Reason + "; served under the fail-open policy",
		}
	}

	action := s.cfg.Action
	d := Decision{Outcome: OutcomeAllow, Action: string(action), Code: string(rep.Disposition), Reason: rep.Reason}
	switch rep.Disposition {
	case DispositionMalicious, DispositionSuspicious:
	default:
		d.Code = string(DispositionBenign)
		return d
	}
	if !action.refusesDisposition(rep.Disposition) {
		// Served with the verdict on record: annotate, or a suspicious artifact
		// under block.
		s.annotated.Add(1)
		return d
	}
	// Refused. The artifact is evicted in either mode; what differs is which
	// dispositions get this far.
	if action == ActionQuarantine {
		s.quarantined.Add(1)
	} else {
		s.blocked.Add(1)
	}
	d.Outcome = OutcomeRefuse
	d.Evict = true
	d.PolicyCode = PolicyCodeSuspicious
	if rep.Disposition == DispositionMalicious {
		d.PolicyCode = PolicyCodeMalicious
	}
	return d
}
