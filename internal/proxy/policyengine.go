package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/auth"
	"github.com/blechschmidt/pullthrough-security/internal/backends"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/notify"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// The policy-as-code engine (Task 32) is the final aggregating admission gate.
// Rather than re-running every signal-producing gate, it observes the reports
// the upstream gates already computed during this request: each gate records its
// summary into a per-request accumulator stored on the request context, and this
// gate evaluates the operator's declarative rules over the aggregate.
//
// Because it runs after the hard-coded gates, the engine layers on top of them:
// it can turn an otherwise-allowed artifact into a deny via a composite rule
// (e.g. "critical CVE AND unsigned AND no VEX not_affected"), but it never
// re-admits something a hard gate already blocked. Operators wanting the engine
// to be authoritative configure the individual gates as non-blocking (warn) so
// their signals flow through to the engine, which makes the final decision.

type signalsKey struct{}

// admissionSignals accumulates the per-request gate signals feeding the policy
// engine. It is safe for concurrent gate recording (gates run sequentially today,
// but the mutex keeps it correct if that changes).
type admissionSignals struct {
	mu    sync.Mutex
	input policyengine.Input
	// sbom is the CycloneDX bill of materials the vulnerability gate generated for
	// this artifact, retained so the provenance-graph ingestion (Task 33) can model
	// the artifact's dependency edges. Nil when the vuln gate did not run.
	sbom *vulnscan.SBOM
	// risk and policy carry the two verdicts that are not part of the aggregated
	// admission document so the findings-aggregation layer (Task 42) can fold them
	// into the SARIF export. They are stashed by the risk-score and policy-as-code
	// gates as they run; nil when that gate did not run.
	risk   *findings.RiskSignal
	policy *findings.PolicySignal
}

// withAdmissionSignals attaches a fresh signal accumulator to the request,
// seeded with the artifact coordinates and tenant. It returns the request whose
// context carries the accumulator so downstream gates can record into it.
func (g *Gateway) withAdmissionSignals(r *http.Request, name, ecosystem string, resolved *backends.Resolved) *http.Request {
	// The accumulator feeds the policy-as-code engine (Task 32), the supply-chain
	// graph ingestion (Task 33), the unified risk-scoring engine (Task 37), and the
	// SARIF findings-aggregation layer (Task 42); attach it when any consumer is
	// active so the gates have somewhere to record.
	if g.deps.PolicyEngine == nil && g.deps.ProvGraph == nil && g.deps.RiskScore == nil &&
		g.deps.Findings == nil && !g.deps.SimReplay.Enabled() && !g.deps.Extension.Enabled() &&
		!g.deps.RepoScore.Enabled() && !g.deps.SbomDiff.Enabled() && !g.deps.RebuildVerify.Enabled() &&
		!g.deps.BuildProv.Enabled() && !g.deps.Snapshot.Enabled() && !g.deps.Continuity.Enabled() {
		return r
	}
	sig := &admissionSignals{input: policyengine.Input{
		Artifact: policyengine.ArtifactInput{
			Ecosystem: ecosystem,
			Backend:   name,
			Name:      resolved.Coordinate.Name,
			Version:   resolved.Coordinate.Version,
			Digest:    resolved.Digest,
		},
	}}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		sig.input.Tenant = p.Team
	}
	ctx := context.WithValue(r.Context(), signalsKey{}, sig)
	return r.WithContext(ctx)
}

func signalsFrom(ctx context.Context) *admissionSignals {
	s, _ := ctx.Value(signalsKey{}).(*admissionSignals)
	return s
}

// recordNameguardSignal captures the nameguard report for the policy engine.
func recordNameguardSignal(ctx context.Context, report *nameguard.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	in := &policyengine.NameguardInput{Scanned: true, FindingCount: len(report.Findings)}
	worst := -1
	for _, f := range report.Findings {
		in.Findings = append(in.Findings, policyengine.NameguardFinding{
			Kind:     string(f.Kind),
			Severity: string(f.Severity),
			Name:     f.Name,
			Similar:  f.Similar,
			Distance: f.Distance,
		})
		in.Kinds = appendUnique(in.Kinds, string(f.Kind))
		switch f.Kind {
		case nameguard.KindTyposquat:
			in.Typosquat = true
		case nameguard.KindDependencyConfusion:
			in.DependencyConfusion = true
		case nameguard.KindHomoglyph:
			in.Homoglyph = true
		}
		if o := severityOrdinal(string(f.Severity)); o > worst {
			worst = o
			in.MaxSeverity = string(f.Severity)
		}
	}
	s.mu.Lock()
	s.input.Nameguard = in
	s.mu.Unlock()
}

// recordSigverifySignal captures the signature-verification report.
func recordSigverifySignal(ctx context.Context, report *sigverify.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	in := &policyengine.SignatureInput{
		Checked:        true,
		Source:         report.Source,
		HasSignature:   len(report.Signatures) > 0,
		HasAttestation: len(report.Attestations) > 0,
		Verified:       report.VerifiedSignature,
		Attested:       report.VerifiedAttestation,
		Error:          report.Error,
	}
	// Summarize the strongest verified signature (or the first available) for the
	// scalar trust fields rules commonly key on.
	for i := range report.Signatures {
		sr := report.Signatures[i]
		if sr.Verified || in.Identity == "" {
			in.CryptoValid = in.CryptoValid || sr.CryptoValid
			in.Keyless = in.Keyless || sr.Keyless
			in.ChainTrusted = in.ChainTrusted || sr.ChainTrusted
			in.IdentityTrusted = in.IdentityTrusted || sr.IdentityTrusted
			in.RekorVerified = in.RekorVerified || sr.RekorVerified
			if sr.Identity != "" {
				in.Identity = sr.Identity
			}
			if sr.Issuer != "" {
				in.Issuer = sr.Issuer
			}
		}
	}
	for i := range report.Attestations {
		at := report.Attestations[i]
		if at.SLSAProvenance {
			in.SLSAProvenance = true
		}
		in.CryptoValid = in.CryptoValid || at.CryptoValid
		in.ChainTrusted = in.ChainTrusted || at.ChainTrusted
	}
	worst := -1
	for _, f := range report.Findings {
		if o := severityOrdinal(string(f.Severity)); o > worst {
			worst = o
			in.MaxSeverity = string(f.Severity)
		}
	}
	s.mu.Lock()
	s.input.Signature = in
	s.mu.Unlock()
}

// recordVulnSignal captures the vulnerability-scan report after VEX adjudication.
func recordVulnSignal(ctx context.Context, report *vulnscan.Report) {
	s := signalsFrom(ctx)
	if s == nil || report == nil {
		return
	}
	// report.Counts already excludes VEX-suppressed (not_affected/fixed) findings.
	// We surface the suppressed critical count separately so the document's
	// criticalUnresolved (= criticalCount - criticalNotAffected) still equals the
	// post-VEX critical count.
	suppressedCritical := 0
	in := &policyengine.VulnInput{
		Scanned:       true,
		Scanner:       report.Scanner,
		MaxSeverity:   string(report.MaxSeverity),
		MaxCVSS:       report.MaxCVSS,
		Total:         report.Counts.Total(),
		CriticalCount: report.Counts.Critical,
		HighCount:     report.Counts.High,
		MediumCount:   report.Counts.Medium,
		LowCount:      report.Counts.Low,
		UnknownCount:  report.Counts.Unknown,
		VEXSuppressed: report.VEXSuppressed,
		VEXEscalated:  report.VEXEscalated,
		Offline:       report.Offline,
		Error:         report.Error,
	}
	for i := range report.Vulnerabilities {
		v := report.Vulnerabilities[i]
		sev := v.Severity
		if v.Suppressed && v.OriginalSeverity != "" {
			sev = v.OriginalSeverity
		}
		if v.Suppressed && string(v.VEXStatus) == string(vulnscan.VEXNotAffected) && sev == vulnscan.SeverityCritical {
			suppressedCritical++
		}
		// Reachability tallies (Task 118), derived from the report so they are
		// per-artifact (not cumulative). Reachability annotation implies the gate is
		// enabled for this scan.
		if v.Reachability != "" {
			in.ReachabilityEnabled = true
		}
		if !v.Withdrawn && !v.Suppressed {
			switch v.Reachability {
			case vulnscan.ReachabilityReachable:
				in.ReachableCount++
			case vulnscan.ReachabilityUnreachable:
				in.UnreachableCount++
			case vulnscan.ReachabilityUnknown:
				in.ReachUnknownCount++
			}
		}
		if v.ReachSuppressed {
			in.ReachSuppressed++
		}
		if v.ReachOriginalSeverity != "" {
			in.ReachDowngraded++
		}
		in.Findings = append(in.Findings, policyengine.VulnFinding{
			ID:               v.ID,
			Severity:         string(v.Severity),
			CVSS:             v.CVSS,
			Package:          v.Package,
			Version:          v.Version,
			Fixed:            v.FixedVersions,
			VEXStatus:        string(v.VEXStatus),
			VEXJustification: string(v.VEXJustification),
			Suppressed:       v.Suppressed,
			Reachability:     string(v.Reachability),
			ReachSuppressed:  v.ReachSuppressed,
		})
	}
	in.CriticalCount += suppressedCritical
	in.CriticalNotAffected = suppressedCritical
	s.mu.Lock()
	s.input.Vuln = in
	s.sbom = report.SBOM
	s.mu.Unlock()
}

// recordLicenseSignal captures the license-compliance decision.
func recordLicenseSignal(ctx context.Context, d license.Decision) {
	s := signalsFrom(ctx)
	if s == nil {
		return
	}
	in := &policyengine.LicenseInput{
		Evaluated: true,
		Action:    string(d.Action),
		Code:      d.Code,
		Allowed:   !d.Action.Blocked(),
	}
	for _, f := range d.Findings {
		in.Findings = append(in.Findings, policyengine.LicenseFinding{
			Component: f.Component,
			Outcome:   f.Outcome,
			License:   f.License,
			Category:  f.Category,
			Drift:     f.Drift,
		})
		if f.Drift {
			in.DriftDetected = true
		}
		if f.Outcome == "denied" && f.License != "" {
			in.DeniedLicenses = appendUnique(in.DeniedLicenses, f.License)
		}
	}
	s.mu.Lock()
	s.input.License = in
	s.mu.Unlock()
}

// recordProvenanceSignal captures the provenance assessment computed by the
// hard-coded policy gate.
func recordProvenanceSignal(ctx context.Context, a policy.Assessment) {
	s := signalsFrom(ctx)
	if s == nil {
		return
	}
	in := &policyengine.ProvenanceInput{
		Found:             a.Found,
		Confidence:        a.Confidence,
		SignatureVerified: a.SignatureVerified,
		ChainTrusted:      a.ChainTrusted,
		CommitSHA:         a.CommitSHA,
		RepositoryURL:     a.RepositoryURL,
		HasVerdict:        a.HasVerdict,
		RiskScore:         a.RiskScore,
		Malicious:         a.Malicious,
		HighestSeverity:   a.HighestSeverity,
	}
	s.mu.Lock()
	s.input.Provenance = in
	s.mu.Unlock()
}

// gatePolicyEngine evaluates the declarative policy-as-code rules over the
// accumulated admission signals. It returns true when the request may proceed
// (allow, warn, or an audit-mode would-be-deny) and false when the artifact has
// been denied and a 403 response written.
func (g *Gateway) gatePolicyEngine(w http.ResponseWriter, r *http.Request, name, ecosystem string) bool {
	if g.deps.PolicyEngine == nil {
		return true
	}
	s := signalsFrom(r.Context())
	if s == nil {
		return true
	}
	s.mu.Lock()
	in := s.input
	s.mu.Unlock()

	res := g.deps.PolicyEngine.Evaluate(r.Context(), in)
	// Stash the policy verdict on the accumulator so the findings-aggregation
	// layer (Task 42) can include policy violations in the SARIF export.
	s.mu.Lock()
	s.policy = policySignal(res)
	s.mu.Unlock()
	g.auditPolicyEngine(r, name, ecosystem, in, res)

	switch res.EffectiveAction {
	case policyengine.ActionDeny:
		g.deps.Logger.Warn("policy-as-code gate denied artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", in.Artifact.Name,
			"reason", res.Decision.Reason)
		g.notifyPolicyEngine(r, name, ecosystem, in, res)
		writePolicyEngineBlock(w, in, res)
		return false
	case policyengine.ActionWarn:
		g.deps.Logger.Info("policy-as-code gate warning on artifact",
			"backend", name, "ecosystem", ecosystem, "artifact", in.Artifact.Name,
			"reason", res.Decision.Reason)
		w.Header().Set("X-PolicyEngine-Decision", "warn")
		w.Header().Set("X-PolicyEngine-Reason", headerSafe(res.Decision.Reason))
		return true
	default:
		if res.Audited {
			// Audit (dry-run) mode: the policy would have denied, but enforcement is
			// off. Surface the would-be decision in a header for visibility.
			g.deps.Logger.Warn("policy-as-code gate would deny (audit mode); admitting",
				"backend", name, "ecosystem", ecosystem, "artifact", in.Artifact.Name,
				"reason", res.Decision.Reason)
			w.Header().Set("X-PolicyEngine-Decision", "audit-deny")
			w.Header().Set("X-PolicyEngine-Reason", headerSafe(res.Decision.Reason))
		} else if len(res.Decision.Matches) > 0 {
			w.Header().Set("X-PolicyEngine-Decision", "allow")
		}
		return true
	}
}

// policyEngineError is the JSON body returned when the policy engine denies.
type policyEngineError struct {
	Error   string                   `json:"error"`
	Code    string                   `json:"code"`
	Action  string                   `json:"action"`
	Reason  string                   `json:"reason"`
	Mode    string                   `json:"mode"`
	Matches []policyengine.RuleMatch `json:"matches,omitempty"`
}

func writePolicyEngineBlock(w http.ResponseWriter, in policyengine.Input, res policyengine.Result) {
	body := policyEngineError{
		Error:   "artifact blocked by policy-as-code admission rules",
		Code:    "policy-engine",
		Action:  string(res.EffectiveAction),
		Reason:  res.Decision.Reason,
		Mode:    string(res.Mode),
		Matches: res.Decision.Matches,
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-PolicyEngine-Decision", "deny")
	h.Set("X-PolicyEngine-Reason", headerSafe(res.Decision.Reason))
	h.Set("X-Cache", "BLOCKED")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(body)
}

func (g *Gateway) auditPolicyEngine(r *http.Request, backend, ecosystem string, in policyengine.Input, res policyengine.Result) {
	if g.deps.Audit == nil {
		return
	}
	decision := audit.DecisionAllow
	if res.EffectiveAction.Blocked() {
		decision = audit.DecisionDeny
	}
	ruleIDs := make([]string, 0, len(res.Decision.Matches))
	for _, m := range res.Decision.Matches {
		ruleIDs = append(ruleIDs, m.RuleID)
	}
	ev := audit.Event{
		Type:       audit.EventPolicy,
		Method:     r.Method,
		Backend:    backend,
		Ecosystem:  ecosystem,
		Resource:   r.URL.Path,
		RemoteAddr: clientIP(r),
		Decision:   decision,
		Reason:     "policyengine:" + string(res.Decision.Action),
		Detail: map[string]any{
			"action":    string(res.Decision.Action),
			"effective": string(res.EffectiveAction),
			"mode":      string(res.Mode),
			"audited":   res.Audited,
			"package":   in.Artifact.Name,
			"version":   in.Artifact.Version,
			"rules":     ruleIDs,
			"reason":    res.Decision.Reason,
		},
	}
	if res.EffectiveAction.Blocked() {
		ev.Status = http.StatusForbidden
	}
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
		ev.Team = p.Team
	}
	g.logAudit(r.Context(), ev)
}

func (g *Gateway) notifyPolicyEngine(r *http.Request, backend, ecosystem string, in policyengine.Input, res policyengine.Result) {
	if g.deps.Notify == nil {
		return
	}
	coord := in.Artifact.Name
	if in.Artifact.Version != "" {
		coord = in.Artifact.Name + "@" + in.Artifact.Version
	}
	ev := notify.PolicyBlockEvent(ecosystem, backend, coord, "policy-engine", res.Decision.Reason)
	if p, ok := auth.FromContext(r.Context()); ok && p != nil {
		ev.Subject = p.Subject
	}
	g.emit(r.Context(), ev)
}

// severityOrdinal maps a severity label to a comparable ordinal.
func severityOrdinal(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "none", "negligible":
		return 1
	default:
		return 0
	}
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
