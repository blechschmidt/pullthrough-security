package presets

// This file holds the embedded, vetted preset bundle definitions. Each preset is
// a self-contained control→gate-setting mapping table. The Clause field on every
// setting cites the standard's control it implements, which doubles as the
// authoritative source for the traceability matrix in docs/compliance-presets.md.
//
// Bump a preset's Version whenever its settings change so an applied baseline is
// pinned exactly in the audit record.

// denySet is the strong-copyleft / non-commercial license deny list shared by
// the stricter presets. It blocks licenses whose obligations are typically
// incompatible with closed-source enterprise distribution.
var denySet = []string{
	"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
	"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BUSL-1.1", "CC-BY-NC-4.0",
}

// slsaL3 targets SLSA v1.0 Build Level 3: verified provenance binding an
// artifact to its source and build, enforced signatures, and a hard CVE floor.
func slsaL3() Preset {
	return Preset{
		Name:        "slsa-l3",
		Title:       "SLSA Build Level 3",
		Description: "Enforce verified provenance, signed artifacts, and a critical-CVE floor per SLSA v1.0 Build Level 3.",
		Version:     "1.0.0",
		Standard:    "SLSA v1.0 (Build Level 3)",
		Settings: []Setting{
			{Path: "sigverify.enabled", Value: true, Desc: "Enable Sigstore/cosign signature verification.",
				Clause: "SLSA Build L2: signed provenance", Controls: []string{ControlSignatureVerification}},
			{Path: "sigverify.requireSignature", Value: true, Desc: "Treat an unsigned artifact as a high-severity finding.",
				Clause: "SLSA Build L2: signed provenance", Controls: []string{ControlSignatureVerification}},
			{Path: "sigverify.action", Value: "block", Desc: "Block artifacts that fail signature verification.",
				Clause: "SLSA Build L2: signed provenance", Controls: []string{ControlSignatureVerification}},

			{Path: "buildProv.enabled", Value: true, Desc: "Enable inbound build-provenance attestation verification.",
				Clause: "SLSA Build L3: provenance", Controls: []string{ControlProvenanceAssociation}},
			{Path: "buildProv.mode", Value: "enforce", Desc: "Enforce (not merely observe) provenance verdicts.",
				Clause: "SLSA Build L3: provenance", Controls: []string{ControlProvenanceAssociation}},
			{Path: "buildProv.requireProvenance", Value: true, Desc: "Require provenance binding version→source commit.",
				Clause: "SLSA Build L3: provenance", Controls: []string{ControlProvenanceAssociation}},
			{Path: "buildProv.action", Value: "block", Desc: "Block artifacts whose provenance is missing or mismatched.",
				Clause: "SLSA Build L3: provenance", Controls: []string{ControlProvenanceAssociation}},

			{Path: "vulnerabilities.enabled", Value: true, Desc: "Enable OSV vulnerability scanning.",
				Clause: "SLSA: known-vuln hygiene", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.failSeverity", Value: "critical", Desc: "Block on unresolved critical CVEs.",
				Clause: "SLSA: known-vuln hygiene", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.action", Value: "block", Desc: "Block (not warn) when the severity floor is met.",
				Clause: "SLSA: known-vuln hygiene", Controls: []string{ControlVulnerabilityGate}},

			{Path: "policyEngine.enabled", Value: true, Desc: "Enable the policy-as-code admission engine.",
				Clause: "SLSA: admission policy", Controls: []string{ControlProvenanceAssociation}},
			{Path: "policyEngine.mode", Value: "enforce", Desc: "Enforce policy decisions.",
				Clause: "SLSA: admission policy"},

			{Path: "riskScore.enabled", Value: true, Desc: "Enable unified supply-chain risk scoring.",
				Clause: "SLSA: risk gating"},
			{Path: "riskScore.thresholdBand", Value: "high", Desc: "Treat high-band risk as the gating threshold.",
				Clause: "SLSA: risk gating"},
			{Path: "riskScore.thresholdAction", Value: "block", Desc: "Block artifacts at/above the threshold band.",
				Clause: "SLSA: risk gating"},
		},
	}
}

// nistSSDF maps NIST SP 800-218 (Secure Software Development Framework)
// practices onto gate settings, emphasising provenance, vulnerability response,
// install-hook scrutiny, and license/secret hygiene.
func nistSSDF() Preset {
	return Preset{
		Name:        "nist-ssdf",
		Title:       "NIST SSDF (SP 800-218)",
		Description: "Map NIST Secure Software Development Framework practices (PW/PS/RV) onto the proxy's admission gates.",
		Version:     "1.0.0",
		Standard:    "NIST SP 800-218 (SSDF v1.1)",
		Settings: []Setting{
			{Path: "sigverify.enabled", Value: true, Desc: "Verify artifact signatures (integrity of acquired components).",
				Clause: "PS.2 / PW.4.4: verify integrity", Controls: []string{ControlSignatureVerification}},
			{Path: "sigverify.action", Value: "block", Desc: "Block artifacts failing signature verification.",
				Clause: "PS.2: protect integrity", Controls: []string{ControlSignatureVerification}},

			{Path: "buildProv.enabled", Value: true, Desc: "Verify build provenance of acquired components.",
				Clause: "PW.4.1: well-secured components", Controls: []string{ControlProvenanceAssociation}},
			{Path: "buildProv.mode", Value: "enforce", Desc: "Enforce provenance verdicts.",
				Clause: "PW.4.1: well-secured components", Controls: []string{ControlProvenanceAssociation}},

			{Path: "vulnerabilities.enabled", Value: true, Desc: "Scan acquired components for known vulnerabilities.",
				Clause: "RV.1.1 / PW.4.4: identify vulnerabilities", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.failSeverity", Value: "high", Desc: "Block on unresolved high+ CVEs.",
				Clause: "RV.1: respond to vulnerabilities", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.action", Value: "block", Desc: "Block when the severity floor is met.",
				Clause: "RV.1: respond to vulnerabilities", Controls: []string{ControlVulnerabilityGate}},

			{Path: "license.enabled", Value: true, Desc: "Evaluate license compliance of acquired components.",
				Clause: "PW.4.1 / PW.4.4: component provenance", Controls: []string{ControlLicenseCompliance}},
			{Path: "license.deny", Value: denySet, Desc: "Deny strong-copyleft / restricted licenses.",
				Clause: "PW.4: reuse well-secured software", Controls: []string{ControlLicenseCompliance}},
			{Path: "license.action", Value: "block", Desc: "Block artifacts carrying a denied license.",
				Clause: "PW.4: reuse well-secured software", Controls: []string{ControlLicenseCompliance}},

			{Path: "installHooks.enabled", Value: true, Desc: "Analyze install/lifecycle hooks for risky behavior.",
				Clause: "PW.4.4: review acquired components"},
			{Path: "installHooks.failSeverity", Value: "high", Desc: "Block on high-severity install-hook findings.",
				Clause: "PW.4.4: review acquired components"},
			{Path: "installHooks.action", Value: "block", Desc: "Block (not warn) at the install-hook floor.",
				Clause: "PW.4.4: review acquired components"},

			{Path: "maturity.enabled", Value: true, Desc: "Apply a release-maturity cooldown to new versions.",
				Clause: "PW.4.1: vet new component versions"},
			{Path: "maturity.defaultCooldown", Value: "72h", Desc: "Quarantine versions younger than 72h.",
				Clause: "PW.4.1: vet new component versions"},

			{Path: "policyEngine.enabled", Value: true, Desc: "Enable policy-as-code admission gating.",
				Clause: "PO.3 / PW.4: enforce policy"},
			{Path: "policyEngine.mode", Value: "enforce", Desc: "Enforce policy decisions.",
				Clause: "PO.3: enforce policy"},

			{Path: "riskScore.enabled", Value: true, Desc: "Enable unified risk scoring.",
				Clause: "RV.2: assess and prioritize"},
			{Path: "riskScore.thresholdBand", Value: "high", Desc: "Gate at the high risk band.",
				Clause: "RV.2: assess and prioritize"},
			{Path: "riskScore.thresholdAction", Value: "block", Desc: "Block at/above the threshold band.",
				Clause: "RV.2: assess and prioritize"},
		},
	}
}

// baselineHardened is a broadly-applicable, defense-in-depth baseline that is
// stricter than the conservative defaults but tuned to minimise false-positive
// blocks (it warns where the standards-driven presets would block on softer
// signals). It maps loosely onto CIS-style hardening guidance.
func baselineHardened() Preset {
	return Preset{
		Name:        "baseline-hardened",
		Title:       "Baseline Hardened",
		Description: "A strong, broadly-applicable defense-in-depth baseline that turns on every admission gate with sensible enforcement.",
		Version:     "1.0.0",
		Standard:    "CIS-style hardening baseline",
		Settings: []Setting{
			{Path: "sigverify.enabled", Value: true, Desc: "Enable signature verification.",
				Clause: "CIS: verify software integrity", Controls: []string{ControlSignatureVerification}},
			{Path: "sigverify.action", Value: "warn", Desc: "Warn (do not hard-block) on signature failures.",
				Clause: "CIS: verify software integrity", Controls: []string{ControlSignatureVerification}},

			{Path: "buildProv.enabled", Value: true, Desc: "Enable build-provenance verification.",
				Clause: "CIS: trace components to source", Controls: []string{ControlProvenanceAssociation}},
			{Path: "buildProv.mode", Value: "observe", Desc: "Observe provenance verdicts (surface, don't block).",
				Clause: "CIS: trace components to source", Controls: []string{ControlProvenanceAssociation}},

			{Path: "vulnerabilities.enabled", Value: true, Desc: "Enable vulnerability scanning.",
				Clause: "CIS: continuous vulnerability management", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.failSeverity", Value: "critical", Desc: "Block only on unresolved critical CVEs.",
				Clause: "CIS: continuous vulnerability management", Controls: []string{ControlVulnerabilityGate}},
			{Path: "vulnerabilities.action", Value: "block", Desc: "Block at the critical floor.",
				Clause: "CIS: continuous vulnerability management", Controls: []string{ControlVulnerabilityGate}},

			{Path: "license.enabled", Value: true, Desc: "Enable license compliance evaluation.",
				Clause: "CIS: software inventory & licensing", Controls: []string{ControlLicenseCompliance}},
			{Path: "license.action", Value: "warn", Desc: "Warn on denied licenses (review-first posture).",
				Clause: "CIS: software inventory & licensing", Controls: []string{ControlLicenseCompliance}},

			{Path: "installHooks.enabled", Value: true, Desc: "Analyze install/lifecycle hooks.",
				Clause: "CIS: malicious code defenses"},
			{Path: "installHooks.failSeverity", Value: "critical", Desc: "Block only on critical install-hook findings.",
				Clause: "CIS: malicious code defenses"},

			{Path: "depfirewall.enabled", Value: true, Desc: "Enable the dependency firewall.",
				Clause: "CIS: allowlisting"},
			{Path: "depfirewall.defaultAction", Value: "allow", Desc: "Allow ungoverned coordinates (rules opt-in).",
				Clause: "CIS: allowlisting"},

			{Path: "maturity.enabled", Value: true, Desc: "Apply a release-maturity cooldown.",
				Clause: "CIS: change management"},
			{Path: "maturity.defaultCooldown", Value: "24h", Desc: "Quarantine versions younger than 24h.",
				Clause: "CIS: change management"},

			{Path: "policyEngine.enabled", Value: true, Desc: "Enable policy-as-code admission gating.",
				Clause: "CIS: enforce policy"},
			{Path: "policyEngine.mode", Value: "enforce", Desc: "Enforce policy decisions.",
				Clause: "CIS: enforce policy"},

			{Path: "riskScore.enabled", Value: true, Desc: "Enable unified risk scoring.",
				Clause: "CIS: risk-based prioritization"},
			{Path: "riskScore.thresholdBand", Value: "critical", Desc: "Gate only at the critical risk band.",
				Clause: "CIS: risk-based prioritization"},
			{Path: "riskScore.thresholdAction", Value: "warn", Desc: "Warn at/above the threshold band.",
				Clause: "CIS: risk-based prioritization"},
		},
	}
}
