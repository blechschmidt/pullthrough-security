package main

import (
	"net/http"
	"time"

	"github.com/blechschmidt/pullthrough-security/internal/config"
	"github.com/blechschmidt/pullthrough-security/internal/depfirewall"
	"github.com/blechschmidt/pullthrough-security/internal/license"
	"github.com/blechschmidt/pullthrough-security/internal/maturity"
	"github.com/blechschmidt/pullthrough-security/internal/remediation"
	"github.com/blechschmidt/pullthrough-security/internal/vulnscan"
)

// buildRemediation constructs the automated dependency-remediation advisor
// subsystem (Task 121). It reuses the already-built admission gate services —
// vulnerability/VEX, license, release-cooldown, and dependency-firewall — to
// score candidate upgrade versions, and an HTTP version lister to enumerate the
// candidates from each ecosystem's upstream registry.
//
// It is always constructed (so the admin endpoint and dossier panel report a
// clear "disabled" rather than a missing route), but reports Enabled() only when
// configured on and the version lister + evaluator are wired. A nil return is
// never produced; a disabled config yields an inert Service.
func buildRemediation(
	cfg *config.Config,
	vulnService *vulnscan.Service,
	licenseService *license.Service,
	maturitySvc *maturity.Service,
	depFirewallSvc *depfirewall.Service,
) *remediation.Service {
	rc := cfg.Remediation

	evaluator := &remediation.GateEvaluator{
		Vuln:        vulnService,
		License:     licenseService,
		Maturity:    maturitySvc,
		DepFirewall: depFirewallSvc,
		// LicenseExpr is intentionally unset: a candidate version's SPDX
		// expression is not derivable from its coordinate alone, so the license
		// gate is skipped for candidates until a per-version expression resolver is
		// wired. The vuln/maturity/depfirewall gates — the usual blocking gates —
		// are fully evaluated.
	}

	lister := remediation.NewHTTPVersionLister(
		&http.Client{Timeout: 20 * time.Second},
		rc.UserAgent,
	)
	if len(rc.BaseURLs) > 0 {
		lister.BaseURLs = rc.BaseURLs
	}

	return remediation.NewService(remediation.Config{
		Enabled:           rc.Enabled,
		MaxCandidates:     rc.MaxCandidates,
		IncludePrerelease: rc.IncludePrerelease,
	}, evaluator, lister)
}
