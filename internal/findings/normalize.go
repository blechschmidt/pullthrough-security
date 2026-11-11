package findings

import (
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/policyengine"
)

// Options tunes normalization. The optional Risk and Policy signals carry the
// two gate verdicts that are not part of the aggregated admission document
// (policyengine.Input) — the unified risk score and the policy-as-code result —
// so the caller (which has them) can fold them into the same SARIF log.
type Options struct {
	// GeneratedAt stamps the document. Zero means the caller will stamp it later
	// (the store stamps on record); the SARIF renderer tolerates a zero time.
	GeneratedAt time.Time
	// Risk, when non-nil and Exceeds, adds a risk-threshold finding.
	Risk *RiskSignal
	// Policy, when non-nil, adds one finding per non-allow matched rule.
	Policy *PolicySignal
}

// FromInput normalizes an aggregated admission document (plus the optional risk
// and policy signals) into a canonical findings Document. It is a pure function:
// the same input always yields the same ordered set of findings, so SARIF output
// is deterministic and golden-testable.
//
// Findings are emitted in a stable gate order (vulnscan, vex, license,
// secretscan, sigverify, nameguard, riskscore, policyengine, provenance) and, in
// each gate, in the order the underlying findings appear in the input.
func FromInput(in policyengine.Input, opts Options) Document {
	d := Document{
		Tenant: in.Tenant,
		Artifact: Artifact{
			Ecosystem:  in.Artifact.Ecosystem,
			Backend:    in.Artifact.Backend,
			Name:       in.Artifact.Name,
			Version:    in.Artifact.Version,
			Digest:     in.Artifact.Digest,
			Coordinate: coordinate(in.Artifact.Name, in.Artifact.Version),
		},
		GeneratedAt: opts.GeneratedAt,
	}
	if in.Provenance != nil {
		d.Artifact.CommitSHA = in.Provenance.CommitSHA
		d.Artifact.RepositoryURL = in.Provenance.RepositoryURL
	}

	coord := d.Artifact.Coordinate
	baseLoc := Location{
		Coordinate:    coord,
		CommitSHA:     d.Artifact.CommitSHA,
		RepositoryURL: d.Artifact.RepositoryURL,
	}

	d.addVuln(in.Vuln, baseLoc)
	d.addLicense(in.License, baseLoc)
	d.addSecret(in.Secret, baseLoc)
	d.addSignature(in.Signature, baseLoc)
	d.addNameguard(in.Nameguard, baseLoc)
	d.addInstallHooks(in.InstallHooks, baseLoc)
	d.addAVScan(in.AVScan, baseLoc)
	d.addContentScan(in.ContentScan, baseLoc)
	d.addLLMPackage(in.LLMPackage, baseLoc)
	d.addContinuity(in.Continuity, baseLoc)
	d.addRebuildVerify(in.RebuildVerify, baseLoc)
	d.addBuildProv(in.BuildProv, baseLoc)
	d.addPyPIAttest(in.PyPIAttest, baseLoc)
	d.addRisk(opts.Risk, baseLoc)
	d.addPolicy(opts.Policy, baseLoc)
	d.addProvenance(in.Provenance, baseLoc)

	return d
}

// add appends a finding, resolving its SARIF level from severity when the caller
// left Level unset.
func (d *Document) add(f Finding) {
	if f.Level == "" {
		f.Level = severityToLevel(f.Severity)
	}
	d.Findings = append(d.Findings, f)
}

func (d *Document) addVuln(v *policyengine.VulnInput, base Location) {
	if v == nil || !v.Scanned {
		return
	}
	for i := range v.Findings {
		f := v.Findings[i]
		sev := normalizeSeverity(f.Severity)
		props := map[string]any{
			"advisory":  f.ID,
			"component": componentCoord(f.Package, f.Version),
			"scanner":   v.Scanner,
		}
		if f.CVSS > 0 {
			props["cvss"] = f.CVSS
		}
		if len(f.Fixed) > 0 {
			props["fixedVersions"] = strings.Join(f.Fixed, ", ")
		}
		if f.ID != "" {
			props["advisoryUrl"] = "https://osv.dev/vulnerability/" + f.ID
		}
		// Reachability attribute (Task 118): surfaced on every finding when the
		// reachability gate annotated the scan.
		if f.Reachability != "" {
			props["reachability"] = f.Reachability
		}
		ruleID := RuleVulnerableDependency
		fin := Finding{
			Gate:       GateVulnscan,
			Severity:   sev,
			Identifier: f.ID,
			Location:   componentLocation(base, f.Package, f.Version),
			Properties: props,
		}
		switch {
		case f.Suppressed:
			// A VEX-adjudicated finding: re-key it to the VEX rule, mark it a SARIF
			// suppression, and downgrade to a note so CI does not fail on it.
			ruleID = RuleSuppressedVuln
			fin.Gate = GateVEX
			fin.Suppressed = true
			fin.Justification = vexJustification(f.VEXStatus, f.VEXJustification)
			fin.Severity = SeverityInfo
			props["vexStatus"] = f.VEXStatus
			if f.VEXJustification != "" {
				props["vexJustification"] = f.VEXJustification
			}
		case f.ReachSuppressed:
			// A finding proven unreachable from the artifact's own code and suppressed
			// by policy: flag it a SARIF suppression and downgrade to a note so CI does
			// not fail on it, while keeping it under the vulnerable-dependency rule for
			// transparency.
			fin.Suppressed = true
			fin.Justification = "unreachable: the vulnerable package is not imported on a reachable path from the artifact"
			fin.Severity = SeverityInfo
		}
		fin.RuleID = ruleID
		fin.Title = vulnTitle(f.ID, f.Package)
		fin.Message = vulnMessage(f)
		d.add(fin)
	}

	// When the scan reported counts but enumerated no per-finding detail (e.g. an
	// offline summary), still surface a single aggregate finding so the artifact's
	// risk is not silently dropped.
	if len(v.Findings) == 0 && v.Total > 0 {
		d.add(Finding{
			RuleID:     RuleVulnerableDependency,
			Gate:       GateVulnscan,
			Severity:   normalizeSeverity(v.MaxSeverity),
			Identifier: "vuln-summary",
			Title:      "Vulnerabilities detected",
			Message:    fmt.Sprintf("%d vulnerabilities detected (max severity %s) by %s.", v.Total, fallback(v.MaxSeverity, "unknown"), fallback(v.Scanner, "scanner")),
			Location:   base,
			Properties: map[string]any{"total": v.Total, "scanner": v.Scanner},
		})
	}
}

func (d *Document) addLicense(l *policyengine.LicenseInput, base Location) {
	if l == nil || !l.Evaluated {
		return
	}
	emittedComponent := false
	for i := range l.Findings {
		f := l.Findings[i]
		// Only the non-clean outcomes (denied/review) and drift warrant a finding.
		outcome := strings.ToLower(strings.TrimSpace(f.Outcome))
		isDrift := f.Drift
		if outcome != "denied" && outcome != "review" && !isDrift {
			continue
		}
		emittedComponent = true
		if outcome == "denied" || outcome == "review" {
			sev := SeverityHigh
			if outcome == "review" {
				sev = SeverityMedium
			}
			d.add(Finding{
				RuleID:     RuleLicenseNonCompliant,
				Gate:       GateLicense,
				Severity:   sev,
				Identifier: f.License,
				Title:      fmt.Sprintf("%s license %q on %s", capitalize(outcome), f.License, fallback(f.Component, "component")),
				Message:    fmt.Sprintf("Component %s declares license %q which the compliance policy marks %q (category %s).", fallback(f.Component, "(unknown)"), fallback(f.License, "(none)"), outcome, fallback(f.Category, "uncategorized")),
				Location:   componentLocationName(base, f.Component),
				Properties: map[string]any{"component": f.Component, "license": f.License, "outcome": outcome, "category": f.Category},
			})
		}
		if isDrift {
			d.add(Finding{
				RuleID:     RuleLicenseDrift,
				Gate:       GateLicense,
				Severity:   SeverityMedium,
				Identifier: f.Component,
				Title:      fmt.Sprintf("License drift on %s", fallback(f.Component, "component")),
				Message:    fmt.Sprintf("Component %s license %q changed from a previously observed value.", fallback(f.Component, "(unknown)"), fallback(f.License, "(none)")),
				Location:   componentLocationName(base, f.Component),
				Properties: map[string]any{"component": f.Component, "license": f.License},
			})
		}
	}

	// If the gate's overall verdict is a block but no per-component finding was
	// emitted (e.g. an artifact-level denial), surface one summary finding.
	if !emittedComponent && (l.Code == "denied" || isBlockAction(l.Action)) {
		d.add(Finding{
			RuleID:     RuleLicenseNonCompliant,
			Gate:       GateLicense,
			Severity:   SeverityHigh,
			Identifier: strings.Join(l.DeniedLicenses, ","),
			Title:      "Non-compliant license",
			Message:    fmt.Sprintf("Artifact license policy verdict %q (worst %s).", fallback(l.Code, l.Action), fallback(l.Worst, "n/a")),
			Location:   base,
			Properties: map[string]any{"code": l.Code, "action": l.Action, "deniedLicenses": l.DeniedLicenses},
		})
	}
}

func (d *Document) addSecret(s *policyengine.SecretInput, base Location) {
	if s == nil || !s.Scanned {
		return
	}
	for i := range s.Findings {
		f := s.Findings[i]
		loc := base
		loc.File = f.File
		d.add(Finding{
			RuleID:     RuleExposedSecret,
			Gate:       GateSecretscan,
			Severity:   normalizeSeverity(f.Severity),
			Identifier: f.RuleID,
			Title:      fmt.Sprintf("Exposed credential (%s)", fallback(f.RuleID, "secret")),
			Message:    fmt.Sprintf("Secret-detection rule %q matched in %s (value redacted).", fallback(f.RuleID, "(rule)"), fallback(f.File, "artifact")),
			Location:   loc,
			Properties: map[string]any{"rule": f.RuleID, "file": f.File},
		})
	}
}

func (d *Document) addSignature(s *policyengine.SignatureInput, base Location) {
	if s == nil || !s.Checked {
		return
	}
	// A verified signature or attestation means authenticity is established; emit
	// nothing. Otherwise surface the unverified-signature finding.
	if s.Verified || s.Attested {
		return
	}
	sev := normalizeSeverity(s.MaxSeverity)
	if sev == SeverityNone {
		sev = SeverityHigh
	}
	reason := signatureReason(s)
	d.add(Finding{
		RuleID:     RuleUnverifiedSignature,
		Gate:       GateSigverify,
		Severity:   sev,
		Identifier: fallback(s.Source, "signature"),
		Title:      "Unverified artifact authenticity",
		Message:    fmt.Sprintf("Signature/attestation verification did not establish trust: %s.", reason),
		Location:   base,
		Properties: map[string]any{
			"source":         s.Source,
			"hasSignature":   s.HasSignature,
			"hasAttestation": s.HasAttestation,
			"slsaProvenance": s.SLSAProvenance,
			"identity":       s.Identity,
			"issuer":         s.Issuer,
			"error":          s.Error,
		},
	})
}

func (d *Document) addNameguard(n *policyengine.NameguardInput, base Location) {
	if n == nil || !n.Scanned {
		return
	}
	for i := range n.Findings {
		f := n.Findings[i]
		ruleID := nameguardRule(f.Kind)
		d.add(Finding{
			RuleID:     ruleID,
			Gate:       GateNameguard,
			Severity:   normalizeSeverity(f.Severity),
			Identifier: f.Name,
			Title:      nameguardTitle(f.Kind, f.Name),
			Message:    nameguardMessage(f),
			Location:   base,
			Properties: map[string]any{"kind": f.Kind, "name": f.Name, "similar": f.Similar, "distance": f.Distance},
		})
	}
}

func (d *Document) addInstallHooks(h *policyengine.InstallHooksInput, base Location) {
	if h == nil || !h.Scanned {
		return
	}
	for i := range h.Findings {
		f := h.Findings[i]
		loc := base
		loc.File = f.File
		d.add(Finding{
			RuleID:     RuleRiskyInstallScript,
			Gate:       GateInstallHooks,
			Severity:   normalizeSeverity(f.Severity),
			Identifier: f.RuleID,
			Title:      fmt.Sprintf("Risky install hook (%s) in %s", fallback(f.RuleID, "pattern"), fallback(f.Hook, "lifecycle script")),
			Message:    fmt.Sprintf("Install/lifecycle hook %s matched the high-risk pattern %q during static analysis (no execution).", fallback(f.Hook, "(hook)"), fallback(f.RuleID, "(rule)")),
			Location:   loc,
			Properties: map[string]any{"rule": f.RuleID, "hook": f.Hook, "file": f.File},
		})
	}
}

func (d *Document) addAVScan(a *policyengine.AVScanInput, base Location) {
	if a == nil || !a.Scanned || !a.Infected {
		return
	}
	sig := fallback(a.Signature, "unknown")
	for i := range a.Findings {
		f := a.Findings[i]
		d.add(Finding{
			RuleID:     RuleMalwareDetected,
			Gate:       GateAVScan,
			Severity:   normalizeSeverity(fallback(f.Severity, "critical")),
			Identifier: fallback(f.Signature, sig),
			Title:      fmt.Sprintf("Malware detected (%s) in artifact payload", fallback(f.Signature, sig)),
			Message:    fmt.Sprintf("The antivirus engine %q matched malware signature %q while scanning the artifact payload.", fallback(a.Engine, "av"), fallback(f.Signature, sig)),
			Location:   base,
			Properties: map[string]any{"signature": fallback(f.Signature, sig), "engine": a.Engine},
		})
	}
}

func (d *Document) addContentScan(c *policyengine.ContentScanInput, base Location) {
	if c == nil || !c.Scanned {
		return
	}
	for i := range c.Findings {
		f := c.Findings[i]
		loc := base
		loc.File = f.File
		loc.Line = f.Line
		cat := fallback(f.Category, "content")
		d.add(Finding{
			RuleID:     RuleSuspiciousContent,
			Gate:       GateContentScan,
			Severity:   normalizeSeverity(f.Severity),
			Identifier: fallback(f.RuleID, cat),
			Title:      fmt.Sprintf("Suspicious package content (%s) in %s", cat, fallback(f.File, "package file")),
			Message:    fmt.Sprintf("Static content analysis flagged %q in %s during the unpack-and-scan of the served package (no execution).", cat, fallback(f.File, "(file)")),
			Location:   loc,
			Properties: map[string]any{"rule": f.RuleID, "category": f.Category, "file": f.File},
		})
	}
}

// addLLMPackage emits the LLM package-content scan's findings: one per location
// the model cited (so a consumer can annotate the file and line), plus one per
// deterministic indicator, plus — for an artifact that made itself unscannable —
// the scan-incomplete note. A benign verdict and an infrastructure failure emit
// nothing.
func (d *Document) addLLMPackage(l *policyengine.LLMPackageInput, base Location) {
	if l == nil {
		return
	}
	for i := range l.Findings {
		f := l.Findings[i]
		loc := base
		loc.File = f.File
		loc.Line = f.Line
		props := map[string]any{
			"category":    f.Category,
			"disposition": l.Disposition,
			"model":       l.Model,
			"mode":        l.Mode,
		}
		if l.Scanned {
			props["verdict"] = l.Verdict
			props["confidence"] = l.Confidence
			props["verifiedEvidence"] = l.VerifiedEvidence
			props["truncated"] = l.Truncated
		}
		if l.Unscanned {
			props["unscannedCode"] = l.UnscannedCode
		}
		if f.Detail != "" {
			props["detail"] = f.Detail
		}
		ruleID := f.RuleID
		if _, known := catalog[ruleID]; !known {
			ruleID = RuleLLMSuspiciousPackage
		}
		message := f.Title
		if f.Detail != "" {
			message += ": " + f.Detail
		}
		d.add(Finding{
			RuleID:     ruleID,
			Gate:       GateLLMPkgScan,
			Severity:   normalizeSeverity(f.Severity),
			Identifier: fallback(f.Category, "llm-verdict"),
			Title:      fallback(f.Title, "LLM package-content scan finding"),
			Message:    fallback(message, "The LLM package-content scan flagged this package."),
			Location:   loc,
			Properties: props,
		})
	}
}

func (d *Document) addContinuity(c *policyengine.ContinuityInput, base Location) {
	// Only a detected ownership drift is actionable; first-use and an unchanged
	// roster are not findings.
	if c == nil || !c.Evaluated || !c.Drift {
		return
	}
	sev := SeverityMedium
	if strings.EqualFold(c.Disposition, "block") {
		sev = SeverityHigh
	}
	added := strings.Join(c.Added, ", ")
	msg := fmt.Sprintf("The publisher identity for this package changed: %d new principal(s) appeared (%s) versus the trust-on-first-use known set of %d. A previously-unseen maintainer, signing key, or namespace owner on an already-known package is a hijack / account-takeover precursor.",
		c.NewMaintainers, fallback(added, "n/a"), c.TrustedCount)
	d.add(Finding{
		RuleID:     RuleMaintainerDrift,
		Gate:       GateContinuity,
		Severity:   sev,
		Identifier: added,
		Title:      "Maintainer/publisher continuity drift",
		Message:    msg,
		Location:   base,
		Properties: map[string]any{
			"added":           c.Added,
			"removed":         c.Removed,
			"newMaintainers":  c.NewMaintainers,
			"trustedCount":    c.TrustedCount,
			"disposition":     c.Disposition,
			"previousVersion": c.PreviousVersion,
			"version":         c.Version,
			"cooldownActive":  c.CooldownActive,
		},
	})
}

func (d *Document) addRebuildVerify(b *policyengine.RebuildVerifyInput, base Location) {
	// Only a confirmed mismatch is actionable; reproducible/unsupported/unattested
	// are not findings (the latter two are covered by the provenance gate).
	if b == nil || !b.Evaluated || !b.Mismatch {
		return
	}
	loc := base
	if b.CommitSHA != "" {
		loc.CommitSHA = b.CommitSHA
	}
	if b.RepositoryURL != "" {
		loc.RepositoryURL = b.RepositoryURL
	}
	d.add(Finding{
		RuleID:     RuleReproducibilityMismatch,
		Gate:       GateRebuildVerify,
		Severity:   SeverityHigh,
		Identifier: b.RebuiltDigest,
		Title:      "Reproducible-build mismatch",
		Message:    fmt.Sprintf("Rebuilding from attested source commit %s produced digest %s, which does not match the upstream-served artifact %s. The served binary does not provably derive from the attested source.", shortSHA(b.CommitSHA), fallback(b.RebuiltDigest, "(none)"), fallback(b.UpstreamDigest, "(none)")),
		Location:   loc,
		Properties: map[string]any{
			"commit":         b.CommitSHA,
			"repository":     b.RepositoryURL,
			"builder":        b.Builder,
			"upstreamDigest": b.UpstreamDigest,
			"rebuiltDigest":  b.RebuiltDigest,
			"reason":         b.Reason,
		},
	})
}

func (d *Document) addBuildProv(b *policyengine.BuildProvInput, base Location) {
	// Two findings are actionable: a confirmed source mismatch (the headline), and
	// a present-but-unverifiable attestation. A clean verified provenance is not a
	// finding. A missing attestation is covered by the provenance gate.
	if b == nil || !b.Checked {
		return
	}
	loc := base
	if b.CommitSHA != "" {
		loc.CommitSHA = b.CommitSHA
	}
	if b.RepositoryURL != "" {
		loc.RepositoryURL = b.RepositoryURL
	}
	if b.Mismatch {
		d.add(Finding{
			RuleID:     RuleProvenanceSourceMismatch,
			Gate:       GateBuildProv,
			Severity:   SeverityCritical,
			Identifier: b.CommitSHA,
			Title:      "Build-provenance source mismatch",
			Message: fmt.Sprintf("The signed build-provenance attestation proves source %s, but the package metadata claims %s. The artifact does not provably derive from the source it advertises.",
				describeProvSource(b.RepositoryURL, b.CommitSHA), describeProvSource(b.ClaimedRepositoryURL, b.ClaimedCommitSHA)),
			Location: loc,
			Properties: map[string]any{
				"source":            b.Source,
				"provenCommit":      b.CommitSHA,
				"provenRepository":  b.RepositoryURL,
				"claimedCommit":     b.ClaimedCommitSHA,
				"claimedRepository": b.ClaimedRepositoryURL,
				"workflowRef":       b.WorkflowRef,
				"builder":           b.Builder,
			},
		})
	}
	if b.Present && !b.Verified {
		d.add(Finding{
			RuleID:     RuleUnverifiedBuildProvenance,
			Gate:       GateBuildProv,
			Severity:   SeverityHigh,
			Title:      "Unverified build provenance",
			Message:    "An inbound build-provenance attestation was present but did not verify (signature invalid or did not bind this artifact's digest).",
			Location:   loc,
			Properties: map[string]any{"source": b.Source, "error": b.Error},
		})
	}
}

func (d *Document) addPyPIAttest(p *policyengine.PyPIAttestInput, base Location) {
	// Two findings are actionable: a digest mismatch (the headline — a valid
	// attestation for a different distribution digest), and a present-but-
	// unverifiable attestation. A clean verified attestation is not a finding, and a
	// missing attestation is not surfaced (most PyPI releases carry none yet).
	if p == nil || !p.Checked {
		return
	}
	if p.DigestMismatch {
		d.add(Finding{
			RuleID:     RulePyPIDigestMismatch,
			Gate:       GatePyPIAttest,
			Severity:   SeverityCritical,
			Identifier: p.Identity,
			Title:      "PyPI attestation digest mismatch",
			Message:    "A cryptographically-valid PyPI PEP 740 attestation was found, but it attests a different distribution digest than the one served. The served file is not the file the publisher attested.",
			Location:   base,
			Properties: map[string]any{
				"source":        p.Source,
				"publisherKind": p.PublisherKind,
				"repository":    p.Repository,
				"workflow":      p.Workflow,
				"identity":      p.Identity,
				"issuer":        p.Issuer,
			},
		})
	}
	if p.Present && !p.Verified && !p.DigestMismatch {
		d.add(Finding{
			RuleID:     RuleUnverifiedPyPIAttestation,
			Gate:       GatePyPIAttest,
			Severity:   SeverityHigh,
			Title:      "Unverified PyPI attestation",
			Message:    "A PyPI PEP 740 attestation was present but did not verify (DSSE signature invalid, or none bound this distribution's digest).",
			Location:   base,
			Properties: map[string]any{"source": p.Source, "error": p.Error},
		})
	}
}

// describeProvSource renders "repo@commit" for a provenance source, tolerating
// empty fields.
func describeProvSource(repo, commit string) string {
	switch {
	case repo != "" && commit != "":
		return repo + "@" + shortSHA(commit)
	case repo != "":
		return repo
	case commit != "":
		return "commit " + shortSHA(commit)
	default:
		return "(unknown)"
	}
}

func (d *Document) addRisk(r *RiskSignal, base Location) {
	if r == nil || !r.Exceeds {
		return
	}
	d.add(Finding{
		RuleID:     RuleRiskThreshold,
		Gate:       GateRiskscore,
		Severity:   bandSeverity(r.Band),
		Identifier: r.Band,
		Title:      fmt.Sprintf("Composite risk %d/100 (%s)", r.Score, r.Band),
		Message:    fallback(r.Summary, fmt.Sprintf("Composite supply-chain risk score %d (%s) met the admission threshold.", r.Score, r.Band)),
		Location:   base,
		Properties: map[string]any{"score": r.Score, "band": r.Band, "action": r.Action},
	})
}

func (d *Document) addPolicy(p *PolicySignal, base Location) {
	if p == nil {
		return
	}
	for _, m := range p.Matches {
		act := strings.ToLower(strings.TrimSpace(m.Action))
		if act == "" || act == "allow" {
			continue
		}
		sev := SeverityHigh
		level := LevelError
		if act == "warn" {
			sev = SeverityMedium
			level = LevelWarning
		}
		d.add(Finding{
			RuleID:     RulePolicyViolation,
			Gate:       GatePolicyEngine,
			Severity:   sev,
			Level:      level,
			Identifier: m.RuleID,
			Title:      fmt.Sprintf("Policy rule %q (%s)", fallback(m.RuleID, "rule"), act),
			Message:    fmt.Sprintf("Policy rule %q evaluated %q: %s", fallback(m.RuleID, "(rule)"), act, fallback(m.Reason, p.Reason)),
			Location:   base,
			Properties: map[string]any{"rule": m.RuleID, "action": act, "reason": fallback(m.Reason, p.Reason)},
		})
	}
}

func (d *Document) addProvenance(p *policyengine.ProvenanceInput, base Location) {
	if p == nil {
		return
	}
	loc := base
	loc.CommitSHA = p.CommitSHA
	loc.RepositoryURL = p.RepositoryURL
	switch {
	case p.Malicious:
		d.add(Finding{
			RuleID:     RuleMaliciousCommit,
			Gate:       GateProvenance,
			Severity:   SeverityCritical,
			Identifier: p.CommitSHA,
			Title:      "Malicious source commit",
			Message:    fmt.Sprintf("Source commit %s (%s) was assessed malicious (highest severity %s, risk %d).", shortSHA(p.CommitSHA), fallback(p.RepositoryURL, "repository"), fallback(p.HighestSeverity, "n/a"), p.RiskScore),
			Location:   loc,
			Properties: map[string]any{"commit": p.CommitSHA, "repository": p.RepositoryURL, "riskScore": p.RiskScore, "highestSeverity": p.HighestSeverity},
		})
	case !p.Found:
		d.add(Finding{
			RuleID:     RuleUnverifiedProvenance,
			Gate:       GateProvenance,
			Severity:   SeverityLow,
			Identifier: "no-provenance",
			Title:      "No build provenance",
			Message:    "No build-provenance association from the artifact to a source commit could be established.",
			Location:   base,
			Properties: map[string]any{"found": false},
		})
	case p.Confidence != "attested" || !p.ChainTrusted:
		d.add(Finding{
			RuleID:     RuleUnverifiedProvenance,
			Gate:       GateProvenance,
			Severity:   SeverityLow,
			Identifier: p.CommitSHA,
			Title:      "Unverified build provenance",
			Message:    fmt.Sprintf("Build provenance to commit %s is %q (chain trusted: %t); it is not a fully-attested, trusted association.", shortSHA(p.CommitSHA), fallback(p.Confidence, "claimed"), p.ChainTrusted),
			Location:   loc,
			Properties: map[string]any{"commit": p.CommitSHA, "confidence": p.Confidence, "chainTrusted": p.ChainTrusted},
		})
	}
}

// --- small rendering helpers -------------------------------------------------

func coordinate(name, version string) string {
	switch {
	case name == "":
		return ""
	case version == "":
		return name
	default:
		return name + "@" + version
	}
}

// componentCoord renders a sub-component coordinate (used inside messages).
func componentCoord(name, version string) string {
	c := coordinate(name, version)
	if c == "" {
		return "(unknown)"
	}
	return c
}

// componentLocation keys a finding to a specific sub-component coordinate when
// the vulnerable package differs from the top-level artifact; otherwise it
// inherits the artifact location.
func componentLocation(base Location, name, version string) Location {
	c := coordinate(name, version)
	if c == "" || c == base.Coordinate {
		return base
	}
	loc := base
	loc.Coordinate = c
	return loc
}

func componentLocationName(base Location, name string) Location {
	if name == "" {
		return base
	}
	loc := base
	loc.Coordinate = name
	return loc
}

func vulnTitle(id, pkg string) string {
	switch {
	case id != "" && pkg != "":
		return fmt.Sprintf("%s in %s", id, pkg)
	case id != "":
		return id
	default:
		return "Vulnerability"
	}
}

func vulnMessage(f policyengine.VulnFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s affects %s", fallback(f.ID, "A vulnerability"), componentCoord(f.Package, f.Version))
	if f.CVSS > 0 {
		fmt.Fprintf(&b, " (CVSS %.1f", f.CVSS)
		if f.Severity != "" {
			fmt.Fprintf(&b, ", %s", strings.ToLower(f.Severity))
		}
		b.WriteString(")")
	} else if f.Severity != "" {
		fmt.Fprintf(&b, " (%s)", strings.ToLower(f.Severity))
	}
	if len(f.Fixed) > 0 {
		fmt.Fprintf(&b, ". Fixed in %s", strings.Join(f.Fixed, ", "))
	}
	b.WriteString(".")
	if f.Suppressed {
		fmt.Fprintf(&b, " Suppressed by VEX (%s).", fallback(f.VEXStatus, "not_affected"))
	}
	return b.String()
}

func vexJustification(status, justification string) string {
	if justification != "" {
		return justification
	}
	if status != "" {
		return "VEX status: " + status
	}
	return "Suppressed by VEX statement"
}

func signatureReason(s *policyengine.SignatureInput) string {
	switch {
	case s.Error != "":
		return s.Error
	case !s.HasSignature && !s.HasAttestation:
		return "no signature or attestation present"
	case !s.ChainTrusted:
		return "signing chain not trusted"
	case !s.IdentityTrusted:
		return "signer identity not trusted"
	default:
		return "verification incomplete"
	}
}

func nameguardRule(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "typosquat":
		return RuleTyposquat
	case "dependency-confusion", "dependencyconfusion":
		return RuleDependencyConfusion
	case "homoglyph":
		return RuleHomoglyph
	default:
		return RuleNameSuspicious
	}
}

func nameguardTitle(kind, name string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "typosquat":
		return fmt.Sprintf("Possible typosquat: %s", name)
	case "dependency-confusion", "dependencyconfusion":
		return fmt.Sprintf("Dependency confusion: %s", name)
	case "homoglyph":
		return fmt.Sprintf("Homoglyph in name: %s", name)
	default:
		return fmt.Sprintf("Suspicious name: %s", name)
	}
}

func nameguardMessage(f policyengine.NameguardFinding) string {
	switch strings.ToLower(strings.TrimSpace(f.Kind)) {
	case "typosquat":
		return fmt.Sprintf("Package %q closely resembles %q (edit distance %d), a typosquatting risk.", f.Name, f.Similar, f.Distance)
	case "dependency-confusion", "dependencyconfusion":
		return fmt.Sprintf("Public package %q shadows internal namespace %q (dependency-confusion risk).", f.Name, f.Similar)
	case "homoglyph":
		return fmt.Sprintf("Package %q contains confusable characters resembling %q.", f.Name, f.Similar)
	default:
		return fmt.Sprintf("Package name %q was flagged as suspicious.", f.Name)
	}
}

// bandSeverity maps a risk band onto the canonical severity scale.
func bandSeverity(band string) Severity {
	switch strings.ToLower(strings.TrimSpace(band)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityMedium
	}
}

func isBlockAction(a string) bool {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case "block", "quarantine", "deny":
		return true
	default:
		return false
	}
}

func fallback(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	if sha == "" {
		return "(unknown)"
	}
	return sha
}
