package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// GateEvaluator is the production Evaluator: it scores a candidate version by
// running it through the already-built admission gate services and normalizing
// their verdicts into the gate-independent Finding set the advisor compares. It
// re-uses the exact gate logic the serve path uses — the advisor never second-
// guesses a gate, it only orchestrates per-candidate calls — so the advice an
// operator sees is what the live gates would actually decide.
//
// Every gate is optional: a nil service simply contributes no findings for that
// gate, so a deployment with (say) only the vulnerability gate wired still gets
// vuln-driven remediation advice. The zero value is a valid, inert evaluator.
type GateEvaluator struct {
	// Vuln is the vulnerability/VEX gate (Task 15/27). When set, each candidate's
	// coordinate is scanned (coordinate-only, no artifact bytes) and its gating
	// vulnerabilities become findings.
	Vuln *vulnscan.Service
	// License is the license-compliance gate (Task 28). Because it decides on a
	// resolved SPDX expression — which is not derivable from a coordinate alone —
	// it is only consulted when LicenseExpr is also wired to resolve a candidate's
	// license.
	License *license.Service
	// LicenseExpr resolves the SPDX license expression for a candidate version
	// (typically a small registry-metadata fetch). It returns ok=false when the
	// expression is unknown, in which case the license gate is skipped for that
	// candidate rather than guessed.
	LicenseExpr func(ctx context.Context, c Coordinate) (expression string, ok bool)
	// Maturity is the release-cooldown gate (Task 61).
	Maturity *maturity.Service
	// DepFirewall is the dependency-firewall / version-pinning gate (Task 65).
	DepFirewall *depfirewall.Service
}

// Evaluate runs a candidate coordinate through every wired gate and returns the
// normalized findings. It satisfies the Evaluator interface.
func (e *GateEvaluator) Evaluate(ctx context.Context, tenant string, c Coordinate) (CandidateResult, error) {
	res := CandidateResult{Coordinate: c}
	if e == nil {
		return res, nil
	}
	if fs, err := e.evalVuln(ctx, c); err != nil {
		return res, err
	} else {
		res.Findings = append(res.Findings, fs...)
	}
	res.Findings = append(res.Findings, e.evalLicense(ctx, tenant, c)...)
	res.Findings = append(res.Findings, e.evalMaturity(tenant, c)...)
	res.Findings = append(res.Findings, e.evalDepFirewall(tenant, c)...)
	return res, nil
}

// evalVuln scans the candidate and maps its gating vulnerabilities to findings.
// A vulnerability is marked Blocking when the gate as a whole would refuse the
// artifact (Decision.Action == block) and the finding is at least as severe as
// the gating finding the gate selected — i.e. it independently meets the fail
// threshold. Withdrawn and VEX-suppressed vulnerabilities are reported as
// non-blocking so they still appear in the delta without vetoing an upgrade.
func (e *GateEvaluator) evalVuln(ctx context.Context, c Coordinate) ([]Finding, error) {
	if e.Vuln == nil {
		return nil, nil
	}
	if _, ok := vulnscan.OSVEcosystem(c.Ecosystem); !ok {
		// The vulnerability gate cannot assess this ecosystem by coordinate; skip
		// it rather than emit a misleading "clean" signal.
		return nil, nil
	}
	art := vulnscan.Artifact{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version}
	report, err := e.Vuln.Assess(ctx, art, nil)
	if err != nil {
		return nil, fmt.Errorf("vuln scan of %s: %w", c, err)
	}
	decision := e.Vuln.EvaluateReport(report)
	blocks := decision.Action == policy.ActionBlock || decision.Action == policy.ActionQuarantine
	var threshold vulnscan.Severity
	var thresholdCVSS float64
	if decision.Highest != nil {
		threshold = decision.Highest.Severity
		thresholdCVSS = decision.Highest.CVSS
	}
	var out []Finding
	for i := range report.Vulnerabilities {
		v := &report.Vulnerabilities[i]
		if v.Withdrawn {
			continue
		}
		blocking := blocks && !v.Suppressed && meetsThreshold(v, threshold, thresholdCVSS)
		out = append(out, Finding{
			Gate:     GateVuln,
			ID:       v.ID,
			Severity: strings.ToLower(string(v.Severity)),
			Title:    firstNonEmpty(v.Summary, v.Component),
			Blocking: blocking,
			FixedIn:  v.FixedVersions,
		})
	}
	return out, nil
}

// meetsThreshold reports whether a vulnerability is at least as severe as the
// gate's selected gating finding (by severity rank or CVSS), i.e. it would
// independently trip the fail threshold.
func meetsThreshold(v *vulnscan.Vulnerability, threshold vulnscan.Severity, thresholdCVSS float64) bool {
	if threshold == "" && thresholdCVSS == 0 {
		return true // no threshold info: treat every gating-report finding as blocking
	}
	if threshold != "" && v.Severity.AtLeast(threshold) {
		return true
	}
	if thresholdCVSS > 0 && v.CVSS >= thresholdCVSS {
		return true
	}
	return false
}

// evalLicense consults the license gate when an expression resolver is wired.
func (e *GateEvaluator) evalLicense(ctx context.Context, tenant string, c Coordinate) []Finding {
	if e.License == nil || e.LicenseExpr == nil {
		return nil
	}
	expr, ok := e.LicenseExpr(ctx, c)
	if !ok || strings.TrimSpace(expr) == "" {
		return nil
	}
	comp := license.Component{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version, Expression: expr, Primary: true}
	decision := e.License.Evaluate(tenant, []license.Component{comp})
	if decision.Allowed() && len(decision.Findings) == 0 {
		return nil
	}
	blocks := decision.Action == policy.ActionBlock || decision.Action == policy.ActionQuarantine
	var out []Finding
	for _, f := range decision.Findings {
		// A denied license is the blocking finding; review/drift are advisory.
		blocking := blocks && strings.EqualFold(f.Outcome, "denied")
		id := f.License
		if id == "" {
			id = f.Expression
		}
		out = append(out, Finding{
			Gate:     GateLicense,
			ID:       id,
			Severity: licenseSeverity(f.Outcome),
			Title:    f.Reason,
			Blocking: blocking,
		})
	}
	return out
}

// evalMaturity consults the release-cooldown gate.
func (e *GateEvaluator) evalMaturity(tenant string, c Coordinate) []Finding {
	if e.Maturity == nil {
		return nil
	}
	d := e.Maturity.Check(tenant, maturity.Coordinate{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version})
	if !d.Cooling {
		return nil
	}
	return []Finding{{
		Gate:     GateMaturity,
		ID:       "release-cooldown",
		Severity: "medium",
		Title:    d.Reason,
		Blocking: true,
	}}
}

// evalDepFirewall consults the dependency-firewall / version-pinning gate.
func (e *GateEvaluator) evalDepFirewall(tenant string, c Coordinate) []Finding {
	if e.DepFirewall == nil {
		return nil
	}
	d := e.DepFirewall.Check(tenant, depfirewall.Coordinate{Ecosystem: c.Ecosystem, Name: c.Name, Version: c.Version})
	if !d.Blocked {
		return nil
	}
	code := d.Code
	if code == "" {
		code = "firewalled"
	}
	return []Finding{{
		Gate:     GateDepFirewall,
		ID:       code,
		Severity: "high",
		Title:    d.Reason,
		Blocking: true,
	}}
}

// licenseSeverity maps a license outcome to the advisor's severity vocabulary.
func licenseSeverity(outcome string) string {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case "denied":
		return "high"
	case "review":
		return "medium"
	case "drift":
		return "low"
	default:
		return "info"
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
