package main

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/audit"
	"github.com/blechschmidt/pullthrough-security/internal/compliance"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/provgraph"
	"github.com/blechschmidt/pullthrough-security/internal/secretscan"
	"github.com/blechschmidt/pullthrough-security/internal/sigverify"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// defaultComplianceInterval is the background recomputation cadence when the
// operator does not configure one.
const defaultComplianceInterval = 5 * time.Minute

// buildCompliance constructs the continuous-compliance scorecard service (Task
// 35). It assembles a PostureSource that samples the live cumulative counters of
// the signature, provenance-graph, vulnerability, license, secret-detection,
// air-gap, and audit subsystems on each computation, maps the operator's control
// overrides into the scorecard config, and optionally loads a signing key for the
// exportable auditor artifact. It returns nil when the scorecard is disabled.
func buildCompliance(
	cfg *config.Config,
	sigVerify *sigverify.Service,
	provGraph *provgraph.Service,
	vulnService *vulnscan.Service,
	licenseService *license.Service,
	secretDetector *secretscan.Detector,
	auditLog *audit.Logger,
	logger *slog.Logger,
) (*compliance.Service, error) {
	cc := cfg.Compliance
	if !cc.Enabled {
		logger.Info("compliance scorecard disabled (set compliance.enabled to aggregate the security gates into an audit posture report)")
		return nil, nil
	}

	signer, err := buildComplianceSigner(cc)
	if err != nil {
		return nil, fmt.Errorf("compliance: %w", err)
	}

	provenanceEnabled := cfg.Provenance.Enabled
	sealed := cfg.Cache.Sealed

	source := compliance.PostureFunc(func() compliance.Posture {
		p := compliance.Posture{Sealed: sealed}

		if sigVerify != nil {
			m := sigVerify.Metrics()
			p.SigEnabled = true
			p.SigVerified = m.Verified
			p.SigUnsigned = m.Unsigned
			p.SigBlocked = m.Blocked
			p.SigVerifications = m.Verifications
		}

		// Provenance coverage is derived from the supply-chain graph (Task 33): the
		// number of cached version nodes that resolve to a source commit. The graph
		// is the only subsystem that tracks both the denominator and numerator
		// cheaply; when it is off, coverage is reported as zero data (a no-op pass).
		p.ProvenanceEnabled = provenanceEnabled
		if provGraph != nil {
			snap := provGraph.Snapshot()
			p.ArtifactsTotal = int64(snap.NodesByKind[string(provgraph.NodeVersion)])
			p.ArtifactsWithProvenance = int64(snap.EdgesByKind[string(provgraph.EdgeBuiltFromCommit)])
			p.ArtifactsSigned = int64(snap.EdgesByKind[string(provgraph.EdgeSignedBy)])
		}

		if vulnService != nil {
			m := vulnService.Metrics()
			p.VulnEnabled = true
			p.VulnScans = m.ScansTotal
			p.VulnBlocked = m.Blocked
			p.VulnQuarantined = int64(m.QuarantinedEntries)
			p.VulnCritical = m.VulnCritical
			p.VulnHigh = m.VulnHigh
		}

		if licenseService != nil {
			m := licenseService.Metrics()
			p.LicenseEnabled = true
			p.LicenseEvaluated = m.Evaluated
			p.LicenseAllowed = m.Allowed
			p.LicenseDenied = m.Denied
			p.LicenseFlagged = m.Flagged
		}

		if secretDetector != nil {
			m := secretDetector.Metrics()
			p.SecretsEnabled = true
			p.SecretsDiffsScanned = m.DiffsScanned
			p.SecretsFindings = m.FindingsTotal
		}

		if auditLog != nil {
			st := auditLog.Stats()
			p.AuditEnabled = true
			p.AuditTransparency = auditLog.TransparencyEnabled()
			p.AuditLastSealUnix = st.LastSealUnix
			p.AuditVerificationFailures = int64(st.VerificationFailures)
			p.AuditChainLength = int64(st.ChainLength)
		}

		return p
	})

	interval := cc.Interval
	if interval <= 0 {
		interval = defaultComplianceInterval
	}

	svc := compliance.New(compliance.Options{
		Source:   source,
		Config:   toComplianceConfig(cfg),
		Interval: interval,
		Signer:   signer,
		Logger:   logger,
	})
	card := svc.Latest()
	logger.Info("compliance scorecard enabled",
		"interval", interval,
		"signed", signer != nil,
		"score", card.Score,
		"grade", card.Grade,
		"status", card.Status,
		"slsaLevel", card.SLSA.BuildLevel)
	return svc, nil
}

// buildComplianceSigner loads the optional report-signing key from inline PEM or
// a file path. A missing key is not an error: reports are then exported with a
// digest but no signature.
func buildComplianceSigner(cc config.ComplianceConfig) (*compliance.Signer, error) {
	switch {
	case cc.SigningKey != "":
		return compliance.LoadSigner([]byte(cc.SigningKey))
	case cc.SigningKeyFile != "":
		return compliance.LoadSignerFile(cc.SigningKeyFile)
	default:
		return nil, nil
	}
}

// toComplianceConfig translates the YAML compliance config into the scorecard
// package's Config, including per-control overrides.
func toComplianceConfig(cfg *config.Config) compliance.Config {
	cc := cfg.Compliance
	out := compliance.Config{
		Version:         version,
		MaxAuditSealAge: cc.MaxAuditSealAge,
	}
	if len(cc.Controls) > 0 {
		out.Controls = make(map[string]compliance.ControlConfig, len(cc.Controls))
		for id, oc := range cc.Controls {
			out.Controls[id] = compliance.ControlConfig{
				Disabled:      oc.Disabled,
				Required:      oc.Required,
				Weight:        oc.Weight,
				PassThreshold: oc.PassThreshold,
				WarnThreshold: oc.WarnThreshold,
			}
		}
	}
	return out
}
