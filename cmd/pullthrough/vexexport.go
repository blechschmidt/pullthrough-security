package main

import (
	"log/slog"

	"github.com/blechschmidt/pullthrough-security/internal/approvals"
	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/findings"
	"github.com/blechschmidt/pullthrough-security/internal/metrics"
	"github.com/blechschmidt/pullthrough-security/internal/snapshot"
	"github.com/blechschmidt/pullthrough-security/internal/vexexport"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// buildVEXExporter constructs the outbound VEX authoring service (Task 137) when
// enabled. It wires whichever triage sources are present — the VEX suppression
// corpus (vulnscan), the retained findings, the break-glass grants (approvals),
// and the org snapshots — and resolves an optional signing key. Signing is
// optional: when no key is available the exporter still produces unsigned
// documents. It returns nil when disabled.
func buildVEXExporter(
	cfg *config.Config,
	vulnService *vulnscan.Service,
	findingsStore *findings.Store,
	approvalsSvc *approvals.Service,
	snapshotSvc *snapshot.Service,
	logger *slog.Logger,
) *vexexport.Service {
	vc := cfg.Vulnerabilities.VEX.Export
	if !vc.Enabled {
		return nil
	}

	signer, source := loadVEXExportSigner(cfg)

	var opts []vexexport.Option
	if vulnService != nil {
		opts = append(opts, vexexport.WithCorpus(vulnService))
	}
	if findingsStore != nil {
		opts = append(opts, vexexport.WithFindings(findingsStore))
	}
	if approvalsSvc != nil {
		opts = append(opts, vexexport.WithGrants(approvalsSvc))
	}
	if snapshotSvc != nil {
		opts = append(opts, vexexport.WithSnapshots(snapshotSvc))
	}

	svc := vexexport.New(vexexport.Config{
		Enabled:     true,
		Author:      vc.Author,
		IDNamespace: vc.IDNamespace,
	}, signer, logger, opts...)

	if signer != nil {
		logger.Info("outbound VEX export enabled (signed OpenVEX/CycloneDX; export at {admin}/api/vex/export or `ptctl vex export`)",
			"keyId", signer.KeyID(), "keySource", source, "algorithm", signer.Algorithm())
	} else {
		logger.Info("outbound VEX export enabled, unsigned (set vulnerabilities.vex.export.signingKey[File] or an attest/audit signing key to sign documents)")
	}
	return svc
}

// loadVEXExportSigner resolves the signing key for VEX export, reusing the
// project's signing-key fallback chain: an export-specific key first, then the
// outbound-attestation key, then the audit transparency checkpoint key. It
// returns a nil signer (and empty source) when no key material is configured, or
// when a configured key fails to parse — export then runs unsigned rather than
// failing to start.
func loadVEXExportSigner(cfg *config.Config) (*vexexport.Signer, string) {
	type candidate struct {
		label  string
		inline string
		file   string
	}
	vc := cfg.Vulnerabilities.VEX.Export
	tc := cfg.Audit.Transparency
	for _, c := range []candidate{
		{"vex.export.signingKey", vc.SigningKey, ""},
		{"vex.export.signingKeyFile", "", vc.SigningKeyFile},
		{"attest.signingKey", cfg.Attest.SigningKey, ""},
		{"attest.signingKeyFile", "", cfg.Attest.SigningKeyFile},
		{"audit.transparency.signingKey", tc.SigningKey, ""},
		{"audit.transparency.signingKeyFile", "", tc.SigningKeyFile},
	} {
		switch {
		case c.inline != "":
			if s, err := vexexport.LoadSigner([]byte(c.inline)); err == nil {
				return s, c.label
			}
		case c.file != "":
			if s, err := vexexport.LoadSignerFile(c.file); err == nil {
				return s, c.label
			}
		}
	}
	return nil, ""
}

// bindVEXExportMetrics registers the outbound VEX export counters (Task 137):
// the cumulative exports partitioned by format and signed-ness, the total
// statements emitted, and the error count. Safe with a nil service (disabled).
func bindVEXExportMetrics(c *metrics.Collector, svc *vexexport.Service) {
	if svc == nil {
		return
	}
	c.BindCounterVec("pullthrough_vex_exports_total",
		"Total outbound VEX documents generated, by format (openvex|cyclonedx) and whether signed.",
		[]string{"format", "signed"},
		func() []metrics.LabeledValue {
			m := svc.Metrics()
			out := make([]metrics.LabeledValue, 0, len(m.ByFormat))
			for k, v := range m.ByFormat {
				format, signed := splitFormatKey(k)
				out = append(out, metrics.LabeledValue{Labels: []string{format, signed}, Value: float64(v)})
			}
			return out
		})
	c.BindCounter("pullthrough_vex_export_statements_total",
		"Total VEX statements emitted across all exported documents.",
		func() float64 { return float64(svc.Metrics().StatementsTotal) })
	c.BindCounter("pullthrough_vex_export_errors_total",
		"Total outbound VEX export attempts that failed.",
		func() float64 { return float64(svc.Metrics().ErrorsTotal) })
}

// splitFormatKey splits the "format|signed" metrics key into its label values.
func splitFormatKey(k string) (format, signed string) {
	format, signed = "unknown", "false"
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return k[:i], k[i+1:]
		}
	}
	return k, signed
}
