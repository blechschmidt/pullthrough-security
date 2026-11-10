package riskscore

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// signalResult is the intermediate output of one signal evaluator: whether the
// signal was applicable for the artifact, its normalized risk sub-score in
// [0,1], and an explainable rendering of the raw value(s).
type signalResult struct {
	present  bool
	subscore float64
	raw      string
	detail   map[string]any
}

// clamp01 constrains v to [0,1].
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// severityScore maps a severity label to a base risk sub-score. It mirrors the
// severity vocabulary used across the proxy (vulnscan, nameguard, sigverify).
func severityScore(s string) float64 {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 1.0
	case "high":
		return 0.75
	case "medium":
		return 0.45
	case "low":
		return 0.20
	case "unknown":
		return 0.30
	case "info", "none", "negligible", "":
		return 0.0
	default:
		return 0.0
	}
}

// evalSignal dispatches to the per-signal evaluator for kind k.
func evalSignal(k SignalKind, s Subject) signalResult {
	switch k {
	case SignalVulnerability:
		return evalVuln(s.Input.Vuln)
	case SignalSignature:
		return evalSignature(s.Input.Signature)
	case SignalLicense:
		return evalLicense(s.Input.License)
	case SignalNameguard:
		return evalNameguard(s.Input.Nameguard)
	case SignalSecret:
		return evalSecret(s.Input.Secret)
	case SignalProvenance:
		return evalProvenance(s.Input.Provenance)
	case SignalQuarantine:
		return evalQuarantine(s.Quarantine)
	case SignalInstallHooks:
		return evalInstallHooks(s.Input.InstallHooks)
	case SignalAVScan:
		return evalAVScan(s.Input.AVScan)
	case SignalContentScan:
		return evalContentScan(s.Input.ContentScan)
	case SignalRepoHealth:
		return evalRepoHealth(s.Input.RepoHealth)
	case SignalRebuildVerify:
		return evalRebuildVerify(s.Input.RebuildVerify)
	case SignalContinuity:
		return evalContinuity(s.Input.Continuity)
	default:
		return signalResult{}
	}
}

// evalContinuity scores the maintainer/publisher continuity verdict (Task 91). A
// detected ownership change (a new maintainer, rotated signing key, or new
// namespace owner) on a previously-seen package is a strong hijack/account-takeover
// precursor; a still-untrusted (within-cooldown) change scores higher than one that
// has already aged in. First-use and an unchanged roster are zero risk. A coordinate
// the gate never evaluated (no publisher metadata) is not applicable.
func evalContinuity(c *policyengine.ContinuityInput) signalResult {
	if c == nil || !c.Evaluated {
		return signalResult{}
	}
	var sub float64
	state := "publisher roster unchanged"
	switch {
	case c.Drift && c.CooldownActive:
		sub, state = 0.85, "maintainer drift (new publisher untrusted, within cooldown)"
	case c.Drift:
		sub, state = 0.65, "maintainer drift (new publisher)"
	case c.FirstUse:
		sub, state = 0.0, "first observation (trust established)"
	}
	if c.Drift && c.NewMaintainers > 1 {
		// Multiple simultaneous new principals is a stronger takeover signal.
		if bumped := sub + 0.05*float64(c.NewMaintainers-1); bumped > sub {
			sub = bumped
		}
	}
	raw := state
	if len(c.Added) > 0 {
		raw = state + ": " + strings.Join(c.Added, ", ")
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"drift":          c.Drift,
			"firstUse":       c.FirstUse,
			"disposition":    orNone(c.Disposition),
			"newMaintainers": c.NewMaintainers,
			"trustedCount":   c.TrustedCount,
			"cooldownActive": c.CooldownActive,
			"added":          c.Added,
			"removed":        c.Removed,
		},
	}
}

// evalRebuildVerify scores the reproducible-build verification verdict (Task 68).
// A confirmed mismatch — the served binary does not derive from its attested
// source commit — is near-maximal risk (supply-chain tampering). A reproducible
// artifact is zero risk. An unattested artifact (no source to rebuild from) is a
// mild risk, consistent with the provenance signal. An unsupported verdict
// (toolchain/source unavailable) is not applicable and excluded from the score,
// so an air-gapped deployment that cannot rebuild does not inflate every score.
func evalRebuildVerify(b *policyengine.RebuildVerifyInput) signalResult {
	if b == nil || !b.Evaluated {
		return signalResult{}
	}
	var sub float64
	var state string
	switch strings.ToLower(strings.TrimSpace(b.Verdict)) {
	case "reproducible":
		sub, state = 0.0, "reproducible"
	case "mismatch":
		sub, state = 0.95, "rebuild MISMATCH (served artifact does not derive from source)"
	case "unattested":
		sub, state = 0.25, "unattested (no source to rebuild from)"
	case "unsupported":
		// Not applicable: cannot verify, do not influence the score.
		return signalResult{}
	default:
		return signalResult{}
	}
	raw := state
	if b.CommitSHA != "" {
		raw = state + " (" + shortSHA(b.CommitSHA) + ")"
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"verdict":        orNone(b.Verdict),
			"reproducible":   b.Reproducible,
			"mismatch":       b.Mismatch,
			"commitSha":      b.CommitSHA,
			"builder":        orNone(b.Builder),
			"upstreamDigest": b.UpstreamDigest,
			"rebuiltDigest":  b.RebuiltDigest,
		},
	}
}

// evalRepoHealth scores the source-repository health signals (Task 63). A repo
// whose health could not be resolved (no local clone, air-gapped) is not
// applicable and excluded from the weighted average — a missing source repo is
// the provenance signal's concern. When resolved, the repository's inverse health
// (risk = 100 - health) is the sub-score, so a poorly-maintained source repo
// (no branch protection, unsigned commits, stale, single-maintainer) raises the
// composite supply-chain risk.
func evalRepoHealth(h *policyengine.RepoHealthInput) signalResult {
	if h == nil || !h.Evaluated || !h.Resolved {
		return signalResult{}
	}
	sub := clamp01(float64(h.Risk) / 100)
	raw := fmt.Sprintf("repo health %d/100 (%s)", h.Health, orNone(h.Grade))
	if len(h.Weak) > 0 {
		raw += "; weak: " + strings.Join(h.Weak, ", ")
	}
	return signalResult{
		present:  true,
		subscore: sub,
		raw:      raw,
		detail: map[string]any{
			"health":            h.Health,
			"risk":              h.Risk,
			"grade":             orNone(h.Grade),
			"branchProtection":  h.BranchProtection,
			"signedCommitRatio": h.SignedCommitRatio,
			"hasCi":             h.HasCI,
			"hasSecurityPolicy": h.HasSecurityPolicy,
			"maintainers":       h.Maintainers,
			"busFactor":         h.BusFactor,
			"lastActivityDays":  h.LastActivityDays,
			"depAutomation":     h.DepAutomation,
			"online":            h.Online,
			"weak":              h.Weak,
		},
	}
}

// evalInstallHooks scores the static install-script / lifecycle-hook risk
// analysis (Task 62). Any matched high-risk pattern is treated as at least
// medium risk regardless of the rule's own label, since an install hook runs
// automatically and pre-import.
func evalInstallHooks(h *policyengine.InstallHooksInput) signalResult {
	if h == nil || !h.Scanned {
		return signalResult{}
	}
	var sub float64
	if h.FindingCount > 0 {
		sub = severityScore(h.MaxSeverity)
		if sub < 0.50 {
			sub = 0.50
		}
	}
	raw := "no risky install hooks"
	if h.HookCount > 0 && h.FindingCount == 0 {
		raw = fmt.Sprintf("%d install hook(s), no risky patterns", h.HookCount)
	}
	if h.FindingCount > 0 {
		raw = fmt.Sprintf("%d risky pattern(s) in %d install hook(s) (maxSeverity=%s)", h.FindingCount, h.HookCount, orNone(h.MaxSeverity))
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"hookCount":    h.HookCount,
			"findingCount": h.FindingCount,
			"maxSeverity":  orNone(h.MaxSeverity),
			"risk":         h.Risk,
		},
	}
}

// evalAVScan scores the antivirus content-scanning gate (Task 136). A positive
// byte-level malware detection is unambiguous, so it drives the sub-score to the
// maximum; a clean completed scan contributes nothing. An engine-unavailable
// (degraded) scan carries no risk signal.
func evalAVScan(a *policyengine.AVScanInput) signalResult {
	if a == nil || !a.Scanned {
		return signalResult{}
	}
	var sub float64
	raw := "antivirus scan clean"
	if a.Infected {
		sub = 1.0
		sig := a.Signature
		if sig == "" {
			sig = "unknown"
		}
		raw = fmt.Sprintf("malware detected: %s", sig)
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"engine":    a.Engine,
			"infected":  a.Infected,
			"signature": a.Signature,
			"risk":      a.Risk,
		},
	}
}

// evalContentScan scores the package-payload static content-analysis gate (Task
// 138). A clean, completed scan contributes nothing; findings drive the subscore
// from the worst severity with a floor so even a single content finding is a
// meaningful signal. A not-inspected artifact (unsupported/unrecognized) is not
// applicable.
func evalContentScan(c *policyengine.ContentScanInput) signalResult {
	if c == nil || !c.Scanned {
		return signalResult{}
	}
	var sub float64
	if c.FindingCount > 0 {
		sub = severityScore(c.MaxSeverity)
		if sub < 0.45 {
			sub = 0.45
		}
	}
	raw := "no suspicious content"
	if c.FindingCount > 0 {
		raw = fmt.Sprintf("%d suspicious content finding(s) across %d file(s) (maxSeverity=%s)",
			c.FindingCount, c.FilesScanned, orNone(c.MaxSeverity))
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"filesScanned": c.FilesScanned,
			"findingCount": c.FindingCount,
			"maxSeverity":  orNone(c.MaxSeverity),
			"categories":   c.Categories,
			"risk":         c.Risk,
		},
	}
}

// evalVuln scores the vulnerability gate. The counts are post-VEX (suppressed
// findings already removed), so the severity base already reflects VEX
// adjudication; finding volume adds a bounded surcharge that can only push the
// score toward 1.
func evalVuln(v *policyengine.VulnInput) signalResult {
	if v == nil || !v.Scanned {
		return signalResult{}
	}
	base := severityScore(v.MaxSeverity)
	// Volume surcharge: many distinct findings are riskier than one, but a single
	// critical already saturates the base, so the surcharge only matters for
	// lower-severity-but-numerous results. It is applied against the headroom
	// (1-base) so it can never reduce the score.
	vol := clamp01(0.10*float64(v.CriticalCount) + 0.04*float64(v.HighCount) + 0.01*float64(v.MediumCount))
	sub := clamp01(base + (1-base)*vol)
	raw := fmt.Sprintf("maxSeverity=%s; %d crit, %d high, %d med, %d low (%d total)",
		orNone(v.MaxSeverity), v.CriticalCount, v.HighCount, v.MediumCount, v.LowCount, v.Total)
	if v.VEXSuppressed > 0 {
		raw += fmt.Sprintf("; %d VEX-suppressed", v.VEXSuppressed)
	}
	// The severity base already reflects any reachability downgrade/suppression
	// (those mutate the scan counts before this point), so no further score
	// adjustment is applied here — the reachability figures are surfaced for
	// explainability. Reporting unreachable/suppressed counts makes it visible why a
	// score is lower than the raw finding volume would suggest.
	if v.ReachabilityEnabled && (v.UnreachableCount > 0 || v.ReachSuppressed > 0) {
		raw += fmt.Sprintf("; %d unreachable", v.UnreachableCount)
		if v.ReachSuppressed > 0 {
			raw += fmt.Sprintf(" (%d suppressed)", v.ReachSuppressed)
		}
	}
	detail := map[string]any{
		"maxSeverity":   orNone(v.MaxSeverity),
		"maxCvss":       v.MaxCVSS,
		"total":         v.Total,
		"critical":      v.CriticalCount,
		"high":          v.HighCount,
		"medium":        v.MediumCount,
		"low":           v.LowCount,
		"vexSuppressed": v.VEXSuppressed,
		"vexEscalated":  v.VEXEscalated,
		"offline":       v.Offline,
	}
	if v.ReachabilityEnabled {
		detail["reachabilityEnabled"] = true
		detail["reachable"] = v.ReachableCount
		detail["unreachable"] = v.UnreachableCount
		detail["reachUnknown"] = v.ReachUnknownCount
		detail["reachSuppressed"] = v.ReachSuppressed
		detail["reachDowngraded"] = v.ReachDowngraded
	}
	return signalResult{
		present:  true,
		subscore: sub,
		raw:      raw,
		detail:   detail,
	}
}

// evalSignature scores signature/attestation verification. The strongest
// posture (verified signature + verified attestation) is zero risk; an unsigned
// or unverifiable artifact is high risk. A verification finding raises the floor.
func evalSignature(s *policyengine.SignatureInput) signalResult {
	if s == nil || !s.Checked {
		return signalResult{}
	}
	var sub float64
	var state string
	switch {
	case s.Verified && s.Attested:
		sub, state = 0.0, "verified signature + attestation"
	case s.Verified:
		sub, state = 0.15, "verified signature"
	case s.Attested:
		sub, state = 0.25, "verified attestation only"
	case s.HasSignature || s.HasAttestation:
		sub, state = 0.70, "signature present but unverified"
	case s.Error != "":
		sub, state = 0.85, "verification error"
	default:
		sub, state = 0.80, "unsigned"
	}
	// A verification finding (e.g. an untrusted identity) raises the floor so a
	// nominally "verified" but flagged signature is not scored as clean.
	if floor := severityScore(s.MaxSeverity) * 0.6; floor > sub {
		sub = floor
	}
	raw := state
	if s.Source != "" {
		raw = s.Source + ": " + state
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"source":         s.Source,
			"hasSignature":   s.HasSignature,
			"hasAttestation": s.HasAttestation,
			"verified":       s.Verified,
			"attested":       s.Attested,
			"keyless":        s.Keyless,
			"slsaProvenance": s.SLSAProvenance,
			"maxSeverity":    orNone(s.MaxSeverity),
		},
	}
}

// evalLicense scores the license-compliance verdict.
func evalLicense(l *policyengine.LicenseInput) signalResult {
	if l == nil || !l.Evaluated {
		return signalResult{}
	}
	action := strings.ToLower(strings.TrimSpace(l.Action))
	code := strings.ToLower(strings.TrimSpace(l.Code))
	var sub float64
	switch {
	case action == "block" || action == "quarantine" || code == "denied":
		sub = 1.0
	case action == "warn" || code == "review" || code == "unknown":
		sub = 0.55
	default:
		sub = 0.0
	}
	if l.DriftDetected && sub < 0.40 {
		// License drift across versions is a supply-chain smell even when the new
		// license is permitted.
		sub = 0.40
	}
	raw := fmt.Sprintf("action=%s, code=%s", orNone(action), orNone(code))
	if l.DriftDetected {
		raw += ", drift"
	}
	if len(l.DeniedLicenses) > 0 {
		raw += "; denied: " + strings.Join(l.DeniedLicenses, ", ")
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"action":         orNone(action),
			"code":           orNone(code),
			"allowed":        l.Allowed,
			"driftDetected":  l.DriftDetected,
			"deniedLicenses": l.DeniedLicenses,
		},
	}
}

// evalNameguard scores typosquat / dependency-confusion / homoglyph detection.
func evalNameguard(n *policyengine.NameguardInput) signalResult {
	if n == nil || !n.Scanned {
		return signalResult{}
	}
	var sub float64
	if n.FindingCount > 0 {
		sub = severityScore(n.MaxSeverity)
		// Typosquat and dependency-confusion are high-confidence attack indicators;
		// floor them regardless of the per-finding severity label.
		switch {
		case n.Typosquat || n.DependencyConfusion:
			if sub < 0.80 {
				sub = 0.80
			}
		case n.Homoglyph:
			if sub < 0.60 {
				sub = 0.60
			}
		}
	}
	raw := "no findings"
	if n.FindingCount > 0 {
		kinds := n.Kinds
		if len(kinds) == 0 {
			kinds = []string{"flagged"}
		}
		raw = fmt.Sprintf("%d finding(s): %s (maxSeverity=%s)", n.FindingCount, strings.Join(kinds, ", "), orNone(n.MaxSeverity))
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"findingCount":        n.FindingCount,
			"maxSeverity":         orNone(n.MaxSeverity),
			"typosquat":           n.Typosquat,
			"dependencyConfusion": n.DependencyConfusion,
			"homoglyph":           n.Homoglyph,
			"kinds":               n.Kinds,
		},
	}
}

// evalSecret scores deterministic secret/credential detection. Any detected
// secret is treated as at least medium risk regardless of the rule's own label.
func evalSecret(s *policyengine.SecretInput) signalResult {
	if s == nil || !s.Scanned {
		return signalResult{}
	}
	var sub float64
	if s.FindingCount > 0 {
		sub = severityScore(s.MaxSeverity)
		if sub < 0.50 {
			sub = 0.50
		}
	}
	raw := "no secrets"
	if s.FindingCount > 0 {
		raw = fmt.Sprintf("%d secret finding(s) (maxSeverity=%s)", s.FindingCount, orNone(s.MaxSeverity))
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"findingCount": s.FindingCount,
			"maxSeverity":  orNone(s.MaxSeverity),
			"risk":         s.Risk,
		},
	}
}

// evalProvenance scores source-provenance completeness joined with the source
// commit's scan verdict. Missing provenance is itself a moderate risk; a
// malicious source commit is maximal.
func evalProvenance(p *policyengine.ProvenanceInput) signalResult {
	if p == nil {
		return signalResult{}
	}
	var sub float64
	var state string
	if !p.Found {
		sub, state = 0.60, "no provenance"
	} else {
		switch strings.ToLower(strings.TrimSpace(p.Confidence)) {
		case "attested":
			sub, state = 0.0, "attested"
		case "claimed":
			sub, state = 0.15, "claimed"
		case "heuristic":
			sub, state = 0.35, "heuristic"
		default:
			sub, state = 0.30, "found"
		}
		if p.HasVerdict {
			if p.Malicious {
				sub, state = 1.0, "malicious source commit"
			} else {
				// Blend the commit's own 0..100 risk score and any severity finding into
				// the provenance sub-score; the worse of the two governs.
				if rs := clamp01(float64(p.RiskScore) / 100); rs > sub {
					sub, state = rs, fmt.Sprintf("commit risk %d", p.RiskScore)
				}
				if sev := severityScore(p.HighestSeverity) * 0.7; sev > sub {
					sub = sev
				}
			}
		}
	}
	raw := state
	if p.CommitSHA != "" {
		raw = state + " (" + shortSHA(p.CommitSHA) + ")"
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"found":             p.Found,
			"confidence":        orNone(p.Confidence),
			"signatureVerified": p.SignatureVerified,
			"chainTrusted":      p.ChainTrusted,
			"hasVerdict":        p.HasVerdict,
			"riskScore":         p.RiskScore,
			"malicious":         p.Malicious,
			"highestSeverity":   orNone(p.HighestSeverity),
			"commitSha":         p.CommitSHA,
		},
	}
}

// evalQuarantine scores the CVE-drift quarantine state. An artifact on
// quarantine hold became vulnerable after caching and is near-maximal risk.
func evalQuarantine(q *QuarantineSignal) signalResult {
	if q == nil {
		return signalResult{}
	}
	var sub float64
	raw := "not quarantined"
	if q.Quarantined {
		sub = 0.90
		raw = "quarantined"
		if q.Advisory != "" {
			raw += " (" + q.Advisory + ")"
		}
	}
	return signalResult{
		present:  true,
		subscore: clamp01(sub),
		raw:      raw,
		detail: map[string]any{
			"quarantined": q.Quarantined,
			"advisory":    q.Advisory,
		},
	}
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
