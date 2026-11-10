package remediation

import "context"

// Config configures the remediation-advisor subsystem (Task 121).
type Config struct {
	// Enabled turns on the advisor's admin endpoint, the dossier "suggested fix"
	// panel, and the SARIF fix-suggestion annotation. When false the Service is a
	// no-op (Enabled reports false) and call sites skip it.
	Enabled bool
	// MaxCandidates bounds how many newer versions a single advisory evaluates
	// (default defaultMaxCandidates). A smaller bound trades upgrade reach for
	// lower upstream/scan load and latency.
	MaxCandidates int
	// IncludePrerelease lets advisories consider prerelease versions as upgrade
	// targets (off by default).
	IncludePrerelease bool
}

// Service is the wired remediation advisor: it owns the configured Advisor and
// applies the subsystem's defaults to each request. A nil *Service is a valid
// disabled subsystem, so admin/dossier call sites need no nil guards beyond
// Enabled.
type Service struct {
	cfg     Config
	advisor *Advisor
}

// NewService constructs the subsystem from a config, a gate evaluator, and a
// version lister. A nil evaluator or lister yields a disabled service (Advise
// returns an error) so a half-wired deployment degrades cleanly.
func NewService(cfg Config, eval Evaluator, lister VersionLister) *Service {
	var adv *Advisor
	if eval != nil && lister != nil {
		adv = NewAdvisor(lister, eval, WithMaxCandidates(cfg.MaxCandidates))
	}
	return &Service{cfg: cfg, advisor: adv}
}

// Enabled reports whether the subsystem is active and fully wired.
func (s *Service) Enabled() bool {
	return s != nil && s.cfg.Enabled && s.advisor != nil
}

// Advise computes remediation advice, applying the subsystem's configured
// defaults (candidate bound, prerelease policy) to any request field the caller
// left unset.
func (s *Service) Advise(ctx context.Context, req Request) (*Advice, error) {
	if !s.Enabled() {
		return nil, errDisabled
	}
	if req.MaxCandidates <= 0 {
		req.MaxCandidates = s.cfg.MaxCandidates
	}
	if !req.IncludePrerelease {
		req.IncludePrerelease = s.cfg.IncludePrerelease
	}
	return s.advisor.Advise(ctx, req)
}

// errDisabled is returned by Advise on a disabled/unwired service.
var errDisabled = disabledError("remediation advisor is not enabled")

type disabledError string

func (e disabledError) Error() string { return string(e) }

// Disabled reports whether err is the sentinel "subsystem disabled" error, so a
// handler can map it to a 404 rather than a 500.
func Disabled(err error) bool {
	_, ok := err.(disabledError)
	return ok
}
